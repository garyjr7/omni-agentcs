"""Durable ``nexus.win.winrm_exec`` handler: governed command execution over WinRM.

Windows post-exploitation had the same hole SSH covered for Linux: the catalogue
could *find* a Windows credential but had no governed way to use it. Sala #5
(V0-13) and sala #9 both needed to run one command on a compromised Windows host,
which forced the operator out of the audit chain.

This handler wraps NetExec's ``winrm`` protocol, which speaks WS-Man over 5985.
It stays deliberately narrow:

* ONE command per call, executed with ``-x`` (cmd) or ``-X`` (PowerShell);
* the target is emitted *before* ``-u``/``-p`` because those options take
  ``nargs='+'`` and would otherwise swallow it (same measured NetExec trap as
  ``nexus.recon.netexec``);
* a destructive-token guard rejects irreversible host/account destruction, the
  same way ``nexus.post.ssh_exec`` does on Linux. Changing a user's password is
  *not* forbidden: it is the documented escalation primitive on domain hosts;
* ``risk=HIGH`` + ``effect=post_exploitation`` (approval unless trust mode) and
  the sandbox allowlists the resolved ``nxc`` binary; no process is spawned by
  the handler itself.
"""

from __future__ import annotations

import os
import re
from typing import Any

from nexus_core.kernel.credentials import (
    credential_choice_message,
    resolve_credential_for,
)
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult

from ._ad import ad_sandbox, resolve_ad_binary, validate_domain, validate_host, validate_username
from ._exec import run_in_sandbox

WINRM_BINARY_CANDIDATES = ("nxc", "netexec")
WINRM_PROTOCOL = "winrm"
WINRM_SHELLS = ("cmd", "powershell")
WINRM_DEFAULT_SHELL = "cmd"
WINRM_DEFAULT_PORT = 5985
WINRM_DEFAULT_TIMEOUT_SECONDS = 120
WINRM_MAX_TIMEOUT_SECONDS = 900
#: Concurrent NetExec threads. One target, so a handful is plenty.
WINRM_THREADS = 3
WINRM_MAX_COMMAND_CHARS = 4000

#: Irreversible host or account destruction. Deliberately *not* included:
#: password changes (``net user <u> <p> /domain``) or group membership changes,
#: which are the standard escalation steps this tool exists to perform.
WINRM_FORBIDDEN_TOKENS: tuple[str, ...] = (
    "shutdown",
    "reboot",
    "stop-computer",
    "restart-computer",
    "format ",
    "diskpart",
    "vssadmin delete",
    "wbadmin delete",
    "bcdedit",
    "cipher /w",
    "del /f /s /q",
    "del /s /q c:",
    "remove-item -recurse -force c:",
    "/delete",
)

#: NetExec prints ``PROTO  host  port  hostname  message``; the message may itself
#: contain the separator, so only the fixed left columns are stripped.
_NXC_LINE_RE = re.compile(r"^[A-Za-z0-9]+\s+\S+\s+\d+\s+\S+\s+(?P<message>.*)$")
_EXECUTED_RE = re.compile(r"\[\+\]\s*Executed command", re.IGNORECASE)
_AUTH_OK_RE = re.compile(r"\[\+\]\s*\S+\\\S+:\S+")
_FAILURE_RE = re.compile(
    r"(STATUS_LOGON_FAILURE|STATUS_ACCESS_DENIED|Authentication failed|"
    r"invalid credentials|Connection refused|No valid connection)",
    re.IGNORECASE,
)


def winrm_exec_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.win.winrm_exec``."""
    return ToolDefinition(
        tool_id="nexus.win.winrm_exec",
        name="WinRM command execution",
        tenant_id=tenant_id,
        description=(
            "WinRM: un comando con credential_ref (preferido) o password/hash "
            "(manual). HIGH: requiere aprobación; rechaza comandos destructivos."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "domain": {"type": "string", "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "maxLength": 512},
                "credential_ref": {
                    "type": "string",
                    "pattern": "^vault:[a-f0-9]{32}$",
                    "description": (
                        "Handle de una credencial del vault (V1-29). Preferido "
                        "sobre `password`; se resuelve dentro de la tool."
                    ),
                },
                "hash": {"type": "string", "maxLength": 65},
                "command": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": WINRM_MAX_COMMAND_CHARS,
                },
                "shell": {"type": "string", "enum": list(WINRM_SHELLS)},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 10,
                    "maximum": WINRM_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["target", "username", "command"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        effect="post_exploitation",
        required_permissions=["execute:tool:nexus.win.winrm_exec"],
        timeout_seconds=WINRM_MAX_TIMEOUT_SECONDS,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def _forbidden_command(command: str) -> str | None:
    """Return the first forbidden token found in ``command``, or ``None``."""
    lowered = command.lower()
    for token in WINRM_FORBIDDEN_TOKENS:
        if token in lowered:
            return token
    return None


def parse_winrm_output(stdout: str) -> dict[str, Any]:
    """Split a NetExec WinRM transcript into markers and command output.

    Returns ``{"messages": [...], "output": str, "executed": bool,
    "authenticated": bool, "failure": str|None}``. Command output is everything
    printed after the last ``[+] Executed command`` marker.
    """
    messages: list[str] = []
    for raw in (stdout or "").splitlines():
        match = _NXC_LINE_RE.match(raw)
        messages.append(match.group("message") if match else raw)
    transcript = "\n".join(messages)
    executed_index = None
    for index, message in enumerate(messages):
        if _EXECUTED_RE.search(message):
            executed_index = index
    output = ""
    if executed_index is not None:
        output = "\n".join(messages[executed_index + 1 :]).strip()
    failure = None
    match = _FAILURE_RE.search(transcript)
    if match:
        failure = match.group(1)
    return {
        "messages": messages,
        "output": output,
        "executed": executed_index is not None,
        "authenticated": bool(_AUTH_OK_RE.search(transcript)),
        "failure": failure,
    }


async def winrm_exec_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run one command over WinRM through the sandbox."""
    target = validate_host(arguments.get("target"))
    username = validate_username(arguments["username"])
    password = str(arguments.get("password") or "")
    ntlm_hash = str(arguments.get("hash") or "")
    resolved_note = ""
    if not password and not ntlm_hash:
        # Fix 2.2: the engine supplies the credential the engagement already
        # proved for this account, instead of the handler refusing a call whose
        # secret is on the board. Exactly one candidate resolves; zero or several
        # are the caller's to disambiguate with `credential_ref`, and the refusal
        # lists what the board holds so the next turn is not a guess.
        resolved = resolve_credential_for(target, username, WINRM_PROTOCOL, context=context)
        if resolved is None:
            raise ValueError(
                credential_choice_message(
                    tool_id="nexus.win.winrm_exec",
                    host=target,
                    username=username,
                    protocol=WINRM_PROTOCOL,
                    context=context,
                    purpose="ejecutar el comando",
                )
            )
        password = resolved.password
        resolved_note = resolved.evidence_note()
    command = str(arguments.get("command") or "").strip()
    if not command:
        raise ValueError("command is required")
    if "\x00" in command:
        raise ValueError("command must not contain null bytes")
    forbidden = _forbidden_command(command)
    if forbidden is not None:
        raise ValueError(f"command contains a forbidden token: {forbidden!r}")
    shell = str(arguments.get("shell") or WINRM_DEFAULT_SHELL).strip().lower()
    if shell not in WINRM_SHELLS:
        raise ValueError(f"shell is not allowed: {shell!r}")
    domain = validate_domain(arguments["domain"]) if arguments.get("domain") else ""
    port = int(arguments.get("port") or WINRM_DEFAULT_PORT)
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        WINRM_MAX_TIMEOUT_SECONDS,
        max(
            10,
            int(requested_timeout) if requested_timeout else WINRM_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    binary = resolve_ad_binary(*WINRM_BINARY_CANDIDATES)
    if not binary:
        return ToolResult(verification_method="winrm_unavailable")

    # The target goes first: ``-u``/``-p`` take ``nargs='+'`` and would eat it.
    argv = [binary, WINRM_PROTOCOL, "--no-progress", "-t", str(WINRM_THREADS), target]
    if domain:
        argv.extend(["-d", domain])
    argv.extend(["-u", username])
    if password:
        argv.extend(["-p", password])
    if ntlm_hash:
        argv.extend(["-H", ntlm_hash])
    argv.extend(["--port", str(port)])
    argv.extend(["-X" if shell == "powershell" else "-x", command])

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = ad_sandbox(workspace_root, binary)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds + 30,
        image_env="NEXUS_WINRM_IMAGE",
        default_image="winrm",
    )

    evidence: dict[str, Any] = {
        "target": target,
        "domain": domain,
        "username": username,
        "shell": shell,
        "port": port,
        "timeout_seconds": timeout_seconds,
        # The engine resolved it, not the model: the handle is the audit trail.
        **({"credential": resolved_note} if resolved_note else {}),
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "winrm command timed out", "target": target},
            verified=False,
            verification_method="winrm_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    parsed = parse_winrm_output(result.stdout)
    evidence.update(
        {
            "executed": parsed["executed"],
            "authenticated": parsed["authenticated"],
            "failure": parsed["failure"],
        }
    )
    output = {
        "target": target,
        "shell": shell,
        "command": command,
        "authenticated": parsed["authenticated"],
        "executed": parsed["executed"],
        "stdout": parsed["output"],
        "error": parsed["failure"],
        **({"credential": resolved_note} if resolved_note else {}),
    }
    if parsed["executed"]:
        return ToolResult(
            output=output,
            verified=True,
            verification_method="winrm_command_executed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )
    method = (
        "winrm_authentication_failed"
        if not parsed["authenticated"]
        else "winrm_command_failed"
    )
    return ToolResult(
        output=output,
        verified=False,
        verification_method=method,
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=result.stdout,
        stderr=result.stderr,
    )


__all__ = [
    "WINRM_FORBIDDEN_TOKENS",
    "parse_winrm_output",
    "winrm_exec_definition",
    "winrm_exec_handler",
]
