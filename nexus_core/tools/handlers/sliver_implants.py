"""``nexus.c2.sliver_implants``: list implant builds and generation profiles.

Read-only: it never generates an implant (that needs an active listener and a
valid target, both out of scope for a metadata listing).
"""

from __future__ import annotations

from nexus_core.integrations.sliver.client import SliverError
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.tools.handlers.sliver_common import build_client, error_result

TOOL_ID = "nexus.c2.sliver_implants"
KINDS = ("builds", "profiles", "both")


def sliver_implants_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id=TOOL_ID,
        name="Sliver implant builds and profiles",
        tenant_id=tenant_id,
        description=(
            "Lista builds y profiles de implants. NO genera implants (eso requiere "
            "un listener activo y un target válido). Solo lectura de la metadata "
            "del server."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": list(KINDS),
                    "default": "both",
                },
            },
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        effect="read_only",
        required_permissions=[f"execute:tool:{TOOL_ID}"],
        timeout_seconds=30,
        max_output_bytes=1_000_000,
        scope_target_field=None,
        scope_required=False,
    )


async def sliver_implants_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, sliver_implants_definition().input_schema)
    kind = str(arguments.get("kind") or "both").lower()
    if kind not in KINDS:
        raise ValueError("kind must be one of builds, profiles, both")
    client, failure = build_client()
    if failure is not None:
        return failure
    try:
        await client.connect()
        builds = await client.list_implant_builds() if kind in {"builds", "both"} else {}
        profiles = (
            await client.list_implant_profiles() if kind in {"profiles", "both"} else []
        )
        return ToolResult(
            output=client.redact(
                {
                    "builds": builds,
                    "profiles": profiles,
                    "builds_count": len(builds),
                    "profiles_count": len(profiles),
                    "kind": kind,
                }
            ),
            verified=True,
            verification_method="sliver_implants_listed",
            evidence={
                "builds_count": len(builds),
                "profiles_count": len(profiles),
                "kind": kind,
            },
        )
    except SliverError as exc:
        return error_result(exc, tool_id=TOOL_ID)
    except (ValueError, TypeError):
        return ToolResult(verification_method="sliver_response_invalid")
    finally:
        await client.disconnect()
