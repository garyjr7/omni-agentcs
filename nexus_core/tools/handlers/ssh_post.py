"""Durable post-exploitation SSH handlers.

Once a credential is validated (``nexus.cred.bruteforce``), the chain continues
inside the host: ``nexus.post.ssh_exec`` runs a single command and
``nexus.post.enum_system`` collects the standard Linux privilege-escalation
surface (identity, users, ``sudo -l``, SUID files, capabilities, cron, listeners).

Design notes:

* The SSH client is a stdlib-independent script run through the sandbox with
  ``python3`` + ``paramiko``; it fails closed (``ssh_unavailable``) when
  paramiko is missing instead of raising.
* ``ssh_exec`` is ``HIGH`` risk (remote command execution) and rejects a
  conservative destructive-command denylist; ``enum_system`` only runs a fixed
  allowlist of read-only commands (``MEDIUM``).
* Connections are short-lived (connect, run, disconnect); no credential is
  persisted by these handlers.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox

SSH_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS
SSH_DEFAULT_PORT = 22
SSH_DEFAULT_TIMEOUT_SECONDS = 120
#: Enumeration walks the filesystem over a possibly high-latency link.
ENUM_DEFAULT_TIMEOUT_SECONDS = 300
SSH_MAX_TIMEOUT_SECONDS = 600
SSH_ENUM_MARKER = "__SUDO__"

#: Fixed, read-only enumeration commands. ``ssh_exec`` runs none of these.
ENUM_COMMANDS: dict[str, str] = {
    "identity": "id",
    "kernel": "uname -a",
    "os_release": "cat /etc/os-release 2>/dev/null",
    "users": "cat /etc/passwd",
    "home": "ls -la ~ 2>/dev/null",
    # Bounded filesystem walks: each is capped remotely so a slow link cannot
    # stall the whole enumeration.
    "suid": "timeout 30 find / -xdev -perm -4000 -type f 2>/dev/null",
    "capabilities": "timeout 20 getcap -r /usr/bin /usr/sbin /bin /sbin 2>/dev/null",
    "cron": "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; crontab -l 2>/dev/null",
    "listening": "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
    # Handled specially by the client: sudo -n -l, falling back to sudo -S -l.
    SSH_ENUM_MARKER: "sudo -n -l",
}

#: Conservative destructive-command denylist for ``ssh_exec`` (case-insensitive).
SSH_FORBIDDEN_TOKENS: tuple[str, ...] = (
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "mkfs",
    ":(){",
    "rm -rf /",
    "dd if=",
    "dd of=",
    "> /dev/sd",
    "iptables -f",
    "userdel",
    "passwd ",
    "chmod 777 /",
)

_SUDO_RULE_RE = re.compile(r"^\s*\((?P<who>[^)]*)\)\s+(?P<command>\S.*)$")

#: Client script. argv layout after ``-c``: mode host port user password payload.
SSH_CLIENT_SCRIPT = r"""
import json, sys

def emit(payload):
    print(json.dumps(payload))

def main():
    mode, host, port, user, password, payload_raw = sys.argv[1:7]
    payload = json.loads(payload_raw)
    try:
        import paramiko
    except Exception as exc:
        emit({"ok": False, "error": "ssh_unavailable", "detail": str(exc)})
        return
    result = {"ok": False, "mode": mode, "host": host, "username": user}
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host,
            port=int(port),
            username=user,
            password=password,
            timeout=20,
            banner_timeout=20,
            auth_timeout=20,
            allow_agent=False,
            look_for_keys=False,
        )
        result["connected"] = True
        if mode == "exec":
            command = payload.get("command", "")
            stdin_data = payload.get("stdin")
            # sudo reads the password from a tty; allocate a pty only when we
            # actually feed stdin, keeping normal commands pty-free.
            stdin, stdout, stderr = client.exec_command(
                command, timeout=payload.get("command_timeout", 60), get_pty=bool(stdin_data)
            )
            if stdin_data:
                stdin.write(stdin_data)
                stdin.flush()
                try:
                    stdin.channel.shutdown_write()
                except Exception:
                    pass
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            code = stdout.channel.recv_exit_status()
            result.update({"ok": True, "command": command, "stdout": out, "stderr": err, "exit_status": code})
        elif mode == "enum":
            commands = payload.get("commands", {})
            command_timeout = payload.get("command_timeout", 60)
            results = {}
            for key, command in commands.items():
                entry = {"command": command}
                try:
                    if key == "__SUDO__":
                        stdin, stdout, stderr = client.exec_command("sudo -n -l", timeout=command_timeout)
                        out = stdout.read().decode("utf-8", "replace")
                        err = stderr.read().decode("utf-8", "replace")
                        code = stdout.channel.recv_exit_status()
                        if code != 0:
                            # Non-interactive sudo failed: feed the password to -S
                            # over a pty (sudo reads the password from the tty).
                            stdin, stdout, stderr = client.exec_command(
                                "sudo -S -l", timeout=command_timeout, get_pty=True
                            )
                            stdin.write(password + "\n")
                            stdin.flush()
                            try:
                                stdin.channel.shutdown_write()
                            except Exception:
                                pass
                            out = stdout.read().decode("utf-8", "replace")
                            err = stderr.read().decode("utf-8", "replace")
                            code = stdout.channel.recv_exit_status()
                        entry.update({"stdout": out, "stderr": err, "exit_status": code})
                    else:
                        stdin, stdout, stderr = client.exec_command(command, timeout=command_timeout)
                        entry["stdout"] = stdout.read().decode("utf-8", "replace")
                        entry["stderr"] = stderr.read().decode("utf-8", "replace")
                        entry["exit_status"] = stdout.channel.recv_exit_status()
                except Exception as exc:
                    entry["error"] = "%s: %s" % (type(exc).__name__, exc)
                results[key] = entry
            result.update({"ok": True, "results": results})
        else:
            result["error"] = "unsupported mode: %s" % mode
    except Exception as exc:
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
    emit(result)

main()
"""


def _validate_text(value: Any, field: str, *, max_length: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    if len(text) > max_length:
        raise ValueError(f"{field} is too long")
    if any(ord(ch) < 0x20 for ch in text):
        raise ValueError(f"{field} contains control characters")
    return text


def _forbidden_command(command: str) -> str | None:
    lowered = command.lower()
    for token in SSH_FORBIDDEN_TOKENS:
        if token in lowered:
            return token
    return None


def parse_sudo_rules(text: str) -> list[dict[str, str]]:
    """Extract ``(who) command`` rules from ``sudo -l`` output."""
    rules: list[dict[str, str]] = []
    for line in (text or "").splitlines():
        match = _SUDO_RULE_RE.match(line)
        if not match:
            continue
        rules.append({"who": match.group("who").strip(), "command": match.group("command").strip()})
    return rules


def ssh_exec_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.ssh_exec``."""
    return ToolDefinition(
        tool_id="nexus.post.ssh_exec",
        name="SSH command execution",
        tenant_id=tenant_id,
        description=(
            "Ejecuta UN comando en un host vía SSH con una credencial ya "
            "validada. HIGH: requiere aprobación; rechaza comandos destructivos."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "minLength": 1, "maxLength": 256},
                "command": {"type": "string", "minLength": 1, "maxLength": 4096},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 600},
            },
            "required": ["target", "username", "password", "command"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        required_permissions=["execute:tool:nexus.post.ssh_exec"],
        timeout_seconds=600,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def enum_system_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.enum_system``."""
    return ToolDefinition(
        tool_id="nexus.post.enum_system",
        name="Linux post-exploitation enumeration",
        tenant_id=tenant_id,
        description=(
            "Con una credencial SSH válida, recolecta la superficie de "
            "escalada: identidad, usuarios, sudo -l, SUID, capabilities, cron."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "minLength": 1, "maxLength": 256},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 900},
            },
            "required": ["target", "username", "password"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.post.enum_system"],
        timeout_seconds=900,
        max_output_bytes=4_000_000,
        scope_target_field="target",
        scope_required=True,
    )


async def _run_ssh_client(
    *, mode: str, host: str, port: int, username: str, password: str, payload: dict, timeout_seconds: int
) -> Any:
    argv = [
        "python3",
        "-c",
        SSH_CLIENT_SCRIPT,
        mode,
        host,
        str(port),
        username,
        password,
        json.dumps(payload),
    ]
    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = sandbox_for_environment(workspace_root, allowed_programs=SSH_ALLOWED_PROGRAMS)
    return await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_SSH_IMAGE",
        default_image="python:3.12-alpine",
    )


def _parse_client_json(stdout: str) -> dict[str, Any]:
    for line in reversed((stdout or "").splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise ValueError("ssh client did not return a JSON result")


async def ssh_exec_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run one command over SSH through the sandbox."""
    target = _validate_text(arguments.get("target"), "target", max_length=255)
    username = _validate_text(arguments.get("username"), "username", max_length=128)
    password = str(arguments.get("password") or "")
    if not password:
        raise ValueError("password is required")
    command = str(arguments.get("command") or "").strip()
    if not command:
        raise ValueError("command is required")
    forbidden = _forbidden_command(command)
    if forbidden is not None:
        raise ValueError(f"command contains a forbidden token: {forbidden!r}")
    # ``sudo`` needs a password on a non-interactive channel. Reuse the login
    # credential (the common case) via ``sudo -S`` and feed it on stdin, so the
    # secret never appears in the remote argv.
    stdin_data: str | None = None
    remote_command = command
    if command.startswith("sudo ") and " -S" not in command[:16]:
        remote_command = "sudo -S " + command[len("sudo ") :]
        stdin_data = password + "\n"
    port = int(arguments.get("port") or SSH_DEFAULT_PORT)
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        SSH_MAX_TIMEOUT_SECONDS,
        max(10, int(requested_timeout) if requested_timeout else SSH_DEFAULT_TIMEOUT_SECONDS),
    )

    result = await _run_ssh_client(
        mode="exec",
        host=target,
        port=port,
        username=username,
        password=password,
        payload={
            "command": remote_command,
            "command_timeout": min(60, timeout_seconds),
            "stdin": stdin_data,
        },
        timeout_seconds=timeout_seconds,
    )
    evidence = {
        "mode": "exec",
        "command": command,
        "sudo_stdin": stdin_data is not None,
        "port": port,
        "username": username,
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "ssh command timed out", "target": target},
            verified=False,
            verification_method="ssh_exec_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )
    try:
        payload = _parse_client_json(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "target": target},
            verified=False,
            verification_method="ssh_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )
    if payload.get("error") == "ssh_unavailable":
        return ToolResult(
            output={"error": "paramiko is not available in the ssh sandbox"},
            verified=False,
            verification_method="ssh_unavailable",
            evidence=evidence,
            exit_code=result.exit_code,
        )
    ok = bool(payload.get("ok")) and bool(payload.get("connected"))
    evidence["exit_status"] = payload.get("exit_status")
    return ToolResult(
        output={
            "target": target,
            "command": command,
            "stdout": payload.get("stdout", ""),
            "stderr": payload.get("stderr", ""),
            "exit_status": payload.get("exit_status"),
        },
        verified=ok,
        verification_method="ssh_exec_completed" if ok else "ssh_exec_failed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


async def enum_system_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Collect the Linux privilege-escalation surface over SSH."""
    target = _validate_text(arguments.get("target"), "target", max_length=255)
    username = _validate_text(arguments.get("username"), "username", max_length=128)
    password = str(arguments.get("password") or "")
    if not password:
        raise ValueError("password is required")
    port = int(arguments.get("port") or SSH_DEFAULT_PORT)
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        SSH_MAX_TIMEOUT_SECONDS,
        max(10, int(requested_timeout) if requested_timeout else ENUM_DEFAULT_TIMEOUT_SECONDS),
    )

    result = await _run_ssh_client(
        mode="enum",
        host=target,
        port=port,
        username=username,
        password=password,
        payload={"commands": ENUM_COMMANDS, "command_timeout": min(90, timeout_seconds)},
        timeout_seconds=timeout_seconds,
    )
    evidence: dict[str, Any] = {
        "mode": "enum",
        "port": port,
        "username": username,
        "commands": sorted(ENUM_COMMANDS),
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "enumeration timed out", "target": target},
            verified=False,
            verification_method="enum_system_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )
    try:
        payload = _parse_client_json(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "target": target},
            verified=False,
            verification_method="enum_system_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )
    if payload.get("error") == "ssh_unavailable":
        return ToolResult(
            output={"error": "paramiko is not available in the ssh sandbox"},
            verified=False,
            verification_method="ssh_unavailable",
            evidence=evidence,
            exit_code=result.exit_code,
        )
    results = payload.get("results") or {}
    sudo_output = (results.get(SSH_ENUM_MARKER) or {}).get("stdout", "")
    sudo_rules = parse_sudo_rules(sudo_output)
    evidence.update(
        {
            "commands_run": len(results),
            "sudo_rules": [rule["command"] for rule in sudo_rules],
        }
    )
    ok = bool(payload.get("ok")) and bool(payload.get("connected"))
    return ToolResult(
        output={
            "target": target,
            "username": username,
            "results": results,
            "sudo_rules": sudo_rules,
        },
        verified=ok,
        verification_method="enum_system_completed" if ok else "enum_system_failed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )
