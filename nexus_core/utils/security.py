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
import ipaddress
import socket
import urllib.parse
import uuid
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

    @classmethod
    def medium(cls) -> "SecurityPolicy":
        return cls(level=SecurityLevel.MEDIUM)

class SecurityViolationError(Exception):
    def __init__(self, violation_type: str, details: str, agent_id: str = "unknown"):
        super().__init__(f"Security Violation: {violation_type} - {details} (Agent: {agent_id})")

class InputValidator:
    @staticmethod
    def validate_file_path(path: str, policy: SecurityPolicy) -> str:
        normalized_path = os.path.realpath(path)
        blocked_paths = [os.path.realpath(os.path.expanduser(item)) for item in policy.blocked_paths]
        allowed_paths = [os.path.realpath(os.path.expanduser(item)) for item in policy.allowed_paths]
        if "\x00" in path or any(os.path.commonpath([normalized_path, blocked]) == blocked for blocked in blocked_paths):
            raise SecurityViolationError("File Path Violation", f"Blocked path: {normalized_path}")
        if not any(os.path.commonpath([normalized_path, allowed]) == allowed for allowed in allowed_paths):
            raise SecurityViolationError("File Path Violation", f"Path not allowed: {normalized_path}")
        return normalized_path

    @staticmethod
    def validate_content(content: str, policy: SecurityPolicy) -> str:
        if len(content) > policy.max_file_size_mb * 1024 * 1024:
            raise SecurityViolationError("Content Violation", "Content size exceeds limit")
        if policy.level in {SecurityLevel.HIGH, SecurityLevel.CRITICAL}:
            dangerous_patterns = ["eval(", "exec(", "__import__(", "subprocess.call", "os.system"]
            if any(pattern in content for pattern in dangerous_patterns):
                raise SecurityViolationError("Content Violation", "Dangerous patterns detected")
        return content.replace("\x00", "")

    @staticmethod
    def validate_url(url: str, policy: SecurityPolicy) -> str:
        if not policy.allow_network:
            raise SecurityViolationError("Network Violation", "Network access not allowed")
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise SecurityViolationError("Network Violation", "Only HTTP(S) URLs are allowed")
        hostname = parsed.hostname.rstrip(".").lower()
        if policy.allowed_domains and not any(
            hostname == domain.lower() or hostname.endswith("." + domain.lower())
            for domain in policy.allowed_domains
        ):
            raise SecurityViolationError("Network Violation", "Domain not allowed")
        try:
            addresses = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
        except socket.gaierror as exc:
            raise SecurityViolationError("Network Violation", "Host cannot be resolved") from exc
        if any(not ipaddress.ip_address(address).is_global for address in addresses):
            raise SecurityViolationError("Network Violation", "Private or reserved address blocked")
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
    agent_id: str
    tool_name: str
    args: dict
    blocked: bool
    violation: Optional[str] = None
    duration_ms: float = 0.0
    entry_id: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime.datetime = dataclasses.field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

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
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self._event_bus.publish("security.violation", {
                        "agent_id": agent_id,
                        "tool_name": tool_name,
                        "violation": violation
                    }, source="SecurityInterceptor"))
                except RuntimeError:
                    self._logger.warning("Security event could not be scheduled outside an event loop")
            duration_ms = (time.time() - start_time) * 1000
            self._audit_trail.append(AuditEntry(
                agent_id=agent_id, tool_name=tool_name, args=dict(tool_args),
                blocked=True, violation=violation, duration_ms=duration_ms
            ))
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
