"""Send one command to an open Metasploit session and collect its output.

Post-exploitation is HIGH risk: the gateway forces human approval for every
command unless the operator opted into trust mode. The handler never runs a
shell locally — the only thing it executes is the RPC of the session that the
engagement already opened.
"""

from __future__ import annotations

import os
import re

from nexus_core.integrations.metasploit.client import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
    SESSION_UUID_PATTERN,
)
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.tools.parsers.metasploit import parse_msf_interaction

#: Commands that would detach or kill the session: use the kill tool instead.
TERMINATING_COMMANDS = frozenset(
    {"exit", "quit", "background", "bg", "detach", "sessions -k", "kill"}
)
TERMINATING_HINT = "use nexus.session.kill for termination"
ALLOWLIST_ENV = "NEXUS_SESSION_COMMAND_ALLOWLIST"


def msf_session_interact_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id="nexus.session.interact",
        name="Send command to Metasploit session",
        tenant_id=tenant_id,
        description=(
            "Envía UN comando a una sesión (Meterpreter, shell, powershell) y "
            "devuelve el output. Apropiado para post-explotación: whoami, sysinfo, "
            "hashdump, getsystem, etc. Cada comando requiere aprobación humana "
            "salvo en trust mode."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_uuid": {
                    "type": "string",
                    "pattern": "^" + SESSION_UUID_PATTERN + "$",
                    "minLength": 1,
                    "maxLength": 64,
                },
                "command": {"type": "string", "minLength": 1, "maxLength": 2000},
                "max_wait_seconds": {"type": "integer", "minimum": 5, "maximum": 300},
            },
            "required": ["session_uuid", "command"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        effect="post_exploitation",
        required_permissions=["execute:tool:nexus.session.interact"],
        timeout_seconds=360,
        max_output_bytes=10_000_000,
        scope_target_field=None,
        scope_required=False,
    )


def command_allowlist() -> frozenset[str] | None:
    """Optional first-token allowlist, disabled unless the operator sets it."""
    raw = str(os.getenv(ALLOWLIST_ENV) or "").strip()
    if not raw:
        return None
    return frozenset(item.strip().lower() for item in raw.split(",") if item.strip())


def validated_command(command: object) -> str:
    """Reject null bytes and session-terminating commands."""
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command must be a non-empty string")
    if "\x00" in command:
        raise ValueError("command must not contain null bytes")
    # Only the first command of a multi-line payload decides the session fate.
    head = command.strip().splitlines()[0].strip().lower()
    token = re.split(r"[^A-Za-z0-9_-]", head, maxsplit=1)[0]
    if not token or token in TERMINATING_COMMANDS or token in {"exit", "quit"}:
        raise ValueError(f"command would terminate the session: {TERMINATING_HINT}")
    allowlist = command_allowlist()
    if allowlist is not None and token not in allowlist:
        raise ValueError("command is not in NEXUS_SESSION_COMMAND_ALLOWLIST")
    return command


async def msf_session_interact_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, msf_session_interact_definition().input_schema)
    session_uuid = arguments["session_uuid"]
    if not isinstance(session_uuid, str) or not re.fullmatch(
        SESSION_UUID_PATTERN, session_uuid
    ):
        raise ValueError("invalid session uuid")
    command = validated_command(arguments["command"])
    max_wait = arguments.get("max_wait_seconds", 60)
    if type(max_wait) is not int or not 5 <= max_wait <= 300:
        raise ValueError("max_wait_seconds must be between 5 and 300")
    try:
        config = MetasploitConfig.from_env()
        if not config.password:
            return ToolResult(verification_method="msf_credentials_missing")
        async with MetasploitClient(config) as client:
            if not await client.is_available():
                return ToolResult(verification_method="msf_unavailable")
            sessions = await client.list_sessions()
            if not await client.has_session(session_uuid, sessions):
                return ToolResult(
                    output={"status": "session_dead", "session_uuid": session_uuid},
                    verification_method="msf_session_not_found",
                    evidence={"session_uuid": session_uuid},
                )
            raw = await client.run_in_session(
                session_uuid, command, max_wait_seconds=float(max_wait)
            )
            parsed = parse_msf_interaction(raw, session_uuid, command)
            return ToolResult(
                output=parsed.to_dict(),
                # A command that ran without detaching is a verified observation,
                # even when the output window closed before the command finished.
                verified=parsed.status in {"ok", "timeout"},
                verification_method=f"msf_session_interact_{parsed.status}",
                evidence={
                    "session_uuid": parsed.session_uuid,
                    "command": parsed.command,
                    "status": parsed.status,
                    "output_bytes": parsed.output_bytes,
                    "duration_seconds": parsed.duration_seconds,
                    "raw_sha256": parsed.raw_sha256,
                },
            )
    except MetasploitError as exc:
        return ToolResult(
            output={"status": "rpc_failed", "session_uuid": session_uuid},
            verification_method="msf_rpc_failed",
            evidence={"error_type": type(exc).__name__, "session_uuid": session_uuid},
        )
    except (ValueError, TypeError):
        return ToolResult(verification_method="msf_response_invalid")
