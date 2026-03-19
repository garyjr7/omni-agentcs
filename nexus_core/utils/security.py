import asyncio
import dataclasses
import enum
import typing
import re
import os
import pathlib
import datetime
import json
import time
import functools
import logging
from typing import List, Optional, Dict, Any

class SecurityLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclasses.dataclass
class SecurityPolicy:
    level: SecurityLevel = SecurityLevel.MEDIUM
    allow_file_write: bool = True
    allow_file_read: bool = True
    allow_network: bool = False
    allow_subprocess: bool = False
    max_file_size_mb: int = 10
    allowed_paths: List[str] = dataclasses.field(default_factory=lambda: ["./nexus_core","./logs","./output"])
    blocked_paths: List[str] = dataclasses.field(default_factory=lambda: ["/etc","/root","~/.ssh","/proc","/sys"])
    allowed_domains: List[str] = dataclasses.field(default_factory=list)
    max_tokens_per_call: int = 8000
    rate_limit_per_minute: int = 60

    @classmethod
    def strict(cls) -> "SecurityPolicy":
        return cls(level=SecurityLevel.CRITICAL, allow_file_write=False, allow_file_read=False, allow_network=False, allow_subprocess=False)

    @classmethod
    def permissive(cls) -> "SecurityPolicy":
        return cls(level=SecurityLevel.LOW, allow_file_write=True, allow_file_read=True, allow_network=True, allow_subprocess=True)

class SecurityViolationError(Exception):
    def __init__(self, violation_type: str, details: str, agent_id: str = "unknown"):
        super().__init__(f"Security Violation: {violation_type} - {details} (Agent: {agent_id})")

class InputValidator:
    @staticmethod
    def validate_file_path(path: str, policy: SecurityPolicy) -> str:
        normalized_path = os.path.realpath(path)
        if any(blocked in normalized_path for blocked in policy.blocked_paths) or ".." in normalized_path or "\x00" in normalized_path:
            raise SecurityViolationError("File Path Violation", f"Blocked path: {normalized_path}")
        if not any(normalized_path.startswith(allowed) for allowed in policy.allowed_paths):
            raise SecurityViolationError("File Path Violation", f"Path not allowed: {normalized_path}")
        return normalized_path

    @staticmethod
    def validate_content(content: str, policy: SecurityPolicy) -> str:
        if len(content) > policy.max_file_size_mb * 1024 * 1024:
            raise SecurityViolationError("Content Violation", "Content size exceeds limit")
        if policy.level >= SecurityLevel.HIGH:
            dangerous_patterns = ["eval(", "exec(", "__import__(", "subprocess.call", "os.system"]
            if any(pattern in content for pattern in dangerous_patterns):
                raise SecurityViolationError("Content Violation", "Dangerous patterns detected")
        return content.replace("\x00", "")

    @staticmethod
    def validate_url(url: str, policy: SecurityPolicy) -> str:
        if not policy.allow_network:
            raise SecurityViolationError("Network Violation", "Network access not allowed")
        private_ip_patterns = [r"^10\.\d+\.\d+\.\d+$", r"^192\.168\.\d+\.\d+$", r"^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$", r"^127\.\d+\.\d+\.\d+$", r"^0\.0\.0\.0$"]
        if any(re.match(pattern, url) for pattern in private_ip_patterns):
            raise SecurityViolationError("Network Violation", "Private IP address blocked")
        if policy.allowed_domains and not any(url.endswith(domain) for domain in policy.allowed_domains):
            raise SecurityViolationError("Network Violation", "Domain not allowed")
        return url

    @staticmethod
    def validate_command(cmd: str, policy: SecurityPolicy) -> str:
        if not policy.allow_subprocess:
            raise SecurityViolationError("Subprocess Violation", "Subprocess execution not allowed")
        dangerous_commands = ["rm -rf", "chmod 777", "curl | bash", "wget | sh"]
        if any(dangerous in cmd for dangerous in dangerous_commands):
            raise SecurityViolationError("Command Violation", "Dangerous command detected")
        return cmd

@dataclasses.dataclass
class AuditEntry:
    entry_id: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime.datetime = dataclasses.field(default_factory=datetime.datetime.utcnow)
    agent_id: str
    tool_name: str
    args: dict
    blocked: bool
    violation: Optional[str] = None
    duration_ms: float = 0.0

class SecurityMiddleware:
    def __init__(self, policy: SecurityPolicy = None, logger=None, event_bus=None):
        self._policy = policy or SecurityPolicy.medium()
        self._audit_trail: List[AuditEntry] = []
        self._blocked_count: int = 0
        self._allowed_count: int = 0
        self._rate_limiter: Dict[str, List[float]] = {}
        self._logger = logger or logging.getLogger(__name__)
        self._event_bus = event_bus

    async def intercept(self, agent_id: str, tool_name: str, tool_args: dict) -> dict:
        if not self._check_rate_limit(agent_id):
            raise SecurityViolationError("Rate Limit Violation", "Too many requests", agent_id)

        start_time = time.time()
        blocked = False
        violation = None

        try:
            if tool_name == "write_file":
                tool_args['file_path'] = InputValidator.validate_file_path(tool_args['file_path'], self._policy)
                tool_args['content'] = InputValidator.validate_content(tool_args['content'], self._policy)
            elif tool_name == "read_file":
                tool_args['file_path'] = InputValidator.validate_file_path(tool_args['file_path'], self._policy)
            elif tool_name == "fetch_url":
                tool_args['url'] = InputValidator.validate_url(tool_args['url'], self._policy)
            elif tool_name == "run_command":
                tool_args['command'] = InputValidator.validate_command(tool_args['command'], self._policy)
            else:
                raise SecurityViolationError("Unknown Tool", f"Tool {tool_name} is not recognized", agent_id)
        except SecurityViolationError as e:
            blocked = True
            violation = str(e)
            self._blocked_count += 1
            if self._event_bus:
                self._event_bus.publish("security.violation", {
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "violation": violation
                })
            raise
        else:
            self._allowed_count += 1

        duration_ms = (time.time() - start_time) * 1000
        audit_entry = AuditEntry(agent_id=agent_id, tool_name=tool_name, args=tool_args, blocked=blocked, violation=violation, duration_ms=duration_ms)
        self._audit_trail.append(audit_entry)

        return tool_args

    def _check_rate_limit(self, agent_id: str) -> bool:
        now = time.time()
        if agent_id not in self._rate_limiter:
            self._rate_limiter[agent_id] = []
        self._rate_limiter[agent_id] = [timestamp for timestamp in self._rate_limiter[agent_id] if now - timestamp < 60]
        if len(self._rate_limiter[agent_id]) >= self._policy.rate_limit_per_minute:
            return False
        self._rate_limiter[agent_id].append(now)
        return True

    def get_audit_trail(self) -> List[dict]:
        return [dataclasses.asdict(entry) for entry in self._audit_trail]

    def get_blocked_attempts(self) -> List[dict]:
        return [dataclasses.asdict(entry) for entry in self._audit_trail if entry.blocked]

    def get_stats(self) -> dict:
        return {
            "total": len(self._audit_trail),
            "blocked": self._blocked_count,
            "allowed": self._allowed_count,
            "by_agent": {agent_id: len([entry for entry in self._audit_trail if entry.agent_id == agent_id]) for agent_id in set(entry.agent_id for entry in self._audit_trail)}
        }

class SandboxedToolRunner:
    def __init__(self, middleware: SecurityMiddleware, logger=None):
        self._middleware = middleware
        self._logger = logger or logging.getLogger(__name__)

    async def run(self, agent_id: str, tool_name: str, tool_func, tool_args: dict) -> Any:
        try:
            validated_args = await self._middleware.intercept(agent_id, tool_name, tool_args)
            result = await asyncio.wait_for(tool_func(**validated_args), timeout=30)
            return result
        except Exception as e:
            self._logger.error(f"Error executing {tool_name} for agent {agent_id}: {e}", exc_info=True)
            raise SecurityViolationError("Execution Error", str(e), agent_id) from e
