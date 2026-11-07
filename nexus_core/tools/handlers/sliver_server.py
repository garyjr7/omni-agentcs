"""``nexus.c2.sliver_server``: read-only status of the Sliver team server."""

from __future__ import annotations

from nexus_core.integrations.sliver.client import SliverError
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.tools.handlers.sliver_common import build_client, error_result
from nexus_core.tools.parsers.sliver import parse_sliver_version

TOOL_ID = "nexus.c2.sliver_server"


def sliver_server_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id=TOOL_ID,
        name="Sliver server status",
        tenant_id=tenant_id,
        description=(
            "Estado del team server de Sliver: versión, operadores conectados y "
            "jobs activos. Solo lectura."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        effect="read_only",
        required_permissions=[f"execute:tool:{TOOL_ID}"],
        timeout_seconds=30,
        max_output_bytes=500_000,
        scope_target_field=None,
        scope_required=False,
    )


async def sliver_server_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, sliver_server_definition().input_schema)
    client, failure = build_client()
    if client is None:
        return failure or ToolResult(verification_method="sliver_unavailable")
    try:
        await client.connect()
        version = await client.version()
        operators = await client.operators()
        jobs = await client.list_jobs()
        parsed = parse_sliver_version(
            {"version": version, "operators": operators, "jobs": jobs}
        )
        return ToolResult(
            output=client.redact(parsed.to_dict()),
            verified=bool(parsed.version),
            verification_method="sliver_server_ok",
            evidence={
                "version": parsed.version,
                "operators_count": len(parsed.operators),
                "jobs_count": parsed.jobs_count,
                "raw_sha256": parsed.raw_sha256,
            },
        )
    except SliverError as exc:
        return error_result(exc, tool_id=TOOL_ID)
    except (ValueError, TypeError):
        return ToolResult(verification_method="sliver_response_invalid")
    finally:
        await client.disconnect()
