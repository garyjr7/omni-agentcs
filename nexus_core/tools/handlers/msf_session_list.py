"""Read-only listing restricted to the current engagement."""

from __future__ import annotations

from nexus_core.integrations.metasploit.client import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
)
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.kernel.sessions import SessionRegistry, validate_session_scope
from nexus_core.tools.parsers.metasploit import parse_msf_sessions

SESSION_TYPES = ("meterpreter", "shell", "powershell", "all")


def msf_session_list_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id="nexus.session.list",
        name="List active Metasploit sessions",
        tenant_id=tenant_id,
        description=(
            "Lista las sesiones activas del engagement actual (Meterpreter, shell). "
            "Solo lectura. Requiere pertenencia registrada y scope vigente."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "filter_type": {"type": "string", "enum": list(SESSION_TYPES)},
            },
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        effect="read_only",
        required_permissions=["execute:tool:nexus.session.list"],
        timeout_seconds=30,
        max_output_bytes=1_000_000,
        scope_target_field=None,
        scope_required=True,
    )


async def msf_session_list_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, msf_session_list_definition().input_schema)
    filter_type = str(arguments.get("filter_type") or "all").lower()
    if filter_type not in SESSION_TYPES:
        raise ValueError("filter_type must be one of meterpreter, shell, powershell, all")
    try:
        validate_session_scope(context)
    except PermissionError:
        return ToolResult(verification_method="session_scope_required")
    registry = SessionRegistry(context.store)
    try:
        config = MetasploitConfig.from_env()
        if not config.password:
            return ToolResult(verification_method="msf_credentials_missing")
        async with MetasploitClient(config) as client:
            if not await client.is_available():
                return ToolResult(verification_method="msf_unavailable")
            raw = await client.list_sessions()
            parsed = parse_msf_sessions(registry.filter_owned(context, raw))
            sessions = [
                session
                for session in parsed.sessions
                if filter_type == "all" or session.type.lower() == filter_type
            ]
            return ToolResult(
                output={
                    "sessions": [session.to_dict() for session in sessions],
                    "count": len(sessions),
                    "total": parsed.count,
                    "filter_type": filter_type,
                    "raw_sha256": parsed.raw_sha256,
                },
                verified=True,
                verification_method="msf_session_list_rpc_parsed",
                evidence={
                    "count": len(sessions),
                    "total": parsed.count,
                    "raw_sha256": parsed.raw_sha256,
                },
            )
    except MetasploitError as exc:
        return ToolResult(
            verification_method="msf_rpc_failed", evidence={"error_type": type(exc).__name__}
        )
    except (ValueError, TypeError):
        return ToolResult(verification_method="msf_response_invalid")
