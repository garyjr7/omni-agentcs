"""Termination of one Metasploit session (cleanup at the end of an engagement)."""

from __future__ import annotations

import re

from nexus_core.integrations.metasploit.client import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
)
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.kernel.sessions import SessionRegistry, validate_session_scope

SESSION_UUID_PATTERN = r"[A-Za-z0-9_-]{1,64}"


def msf_session_kill_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id="nexus.session.kill",
        name="Terminate a Metasploit session",
        tenant_id=tenant_id,
        description=(
            "Termina una sesión de Metasploit por UUID. "
            "Apropiado para cleanup al final de un engagement."
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
            },
            "required": ["session_uuid"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        effect="read_only",
        required_permissions=["execute:tool:nexus.session.kill"],
        timeout_seconds=60,
        max_output_bytes=100_000,
        scope_target_field=None,
        scope_required=True,
    )


async def msf_session_kill_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, msf_session_kill_definition().input_schema)
    session_uuid = arguments["session_uuid"]
    if not isinstance(session_uuid, str) or not re.fullmatch(SESSION_UUID_PATTERN, session_uuid):
        raise ValueError("invalid session uuid")
    try:
        validate_session_scope(context)
    except PermissionError:
        return ToolResult(verification_method="session_scope_required")
    registry = SessionRegistry(context.store)
    denied = registry.denial(context, session_uuid)
    if denied is not None:
        return denied
    try:
        config = MetasploitConfig.from_env()
        if not config.password:
            return ToolResult(verification_method="msf_credentials_missing")
        async with MetasploitClient(config) as client:
            if not await client.is_available():
                return ToolResult(verification_method="msf_unavailable")
            result = await client.stop_session(session_uuid)
            outcome = str(result.get("result") or result.get("status") or "").lower()
            if outcome == "success":
                registry.close(context, session_uuid)
            return ToolResult(
                output={"session_uuid": session_uuid, "result": outcome or "unknown"},
                verified=outcome == "success",
                verification_method="msf_session_kill_rpc",
                evidence={"session_uuid": session_uuid, "result": outcome or "unknown"},
            )
    except MetasploitError as exc:
        return ToolResult(
            output={"session_uuid": session_uuid, "status": "rpc_failed"},
            verification_method="msf_rpc_failed",
            evidence={"error_type": type(exc).__name__},
        )
    except (ValueError, TypeError):
        return ToolResult(verification_method="msf_response_invalid")
