"""``nexus.c2.sliver_generate``: build a Sliver implant (HIGH).

Building an implant writes only to the team server's own store; it never touches
a target. The tool is still HIGH because an implant is offensive tooling with a
lasting payload, so the gateway forces human approval unless trust mode is on.

The implant **bytes are never returned**: the result carries only the name,
size and SHA256, and the bytes stay on the team server for ``sliver_deploy``.
"""

from __future__ import annotations

from nexus_core.integrations.sliver.client import SliverError
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.tools.handlers.sliver_common import build_client, error_result

TOOL_ID = "nexus.c2.sliver_generate"
OSES = ("linux", "windows", "darwin")
ARCHS = ("amd64", "arm64", "386")
FORMATS = ("executable", "shared", "shellcode", "service")
BEACON_INTERVAL_MAX = 86400
BEACON_JITTER_MAX = 100
DEFAULT_INTERVAL = 60
DEFAULT_JITTER = 30


def sliver_generate_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id=TOOL_ID,
        name="Generate Sliver implant",
        tenant_id=tenant_id,
        description=(
            "Compila un implante Sliver (session o beacon) para el SO/arquitectura "
            "indicados. Con persistent=true genera un implante de servicio que "
            "arranca al cargar (IsService+RunAtLoad). No toca ningún objetivo y "
            "nunca devuelve los bytes del implante."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "os": {"type": "string", "enum": list(OSES)},
                "arch": {"type": "string", "enum": list(ARCHS)},
                "format": {
                    "type": "string",
                    "enum": list(FORMATS),
                    "default": "executable",
                },
                "beacon": {"type": "boolean", "default": False},
                "interval": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": BEACON_INTERVAL_MAX,
                },
                "jitter": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": BEACON_JITTER_MAX,
                },
                "name": {"type": "string", "maxLength": 64},
                "persistent": {"type": "boolean", "default": False},
            },
            "required": ["os", "arch"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        effect="c2_implant_build",
        required_permissions=[f"execute:tool:{TOOL_ID}"],
        timeout_seconds=300,
        max_output_bytes=100_000,
        scope_target_field=None,
        scope_required=False,
    )


def _generation_arguments(arguments: dict) -> dict:
    """Validate and normalize every generation field before any RPC."""
    os_name = str(arguments.get("os") or "").lower()
    arch = str(arguments.get("arch") or "").lower()
    if os_name not in OSES or arch not in ARCHS:
        raise ValueError("unsupported os/arch")
    implant_format = str(arguments.get("format") or "executable").lower()
    if implant_format not in FORMATS:
        raise ValueError("unsupported format")
    beacon = bool(arguments.get("beacon", False))
    raw_interval = arguments.get("interval")
    raw_jitter = arguments.get("jitter")
    interval = DEFAULT_INTERVAL if raw_interval is None else int(raw_interval)
    jitter = DEFAULT_JITTER if raw_jitter is None else int(raw_jitter)
    if not 1 <= interval <= BEACON_INTERVAL_MAX:
        raise ValueError("interval out of range")
    if not 0 <= jitter <= BEACON_JITTER_MAX:
        raise ValueError("jitter out of range")
    name = str(arguments.get("name") or "")
    if len(name) > 64:
        raise ValueError("name is too long")
    return {
        "os_name": os_name,
        "arch": arch,
        "format": implant_format,
        "beacon": beacon,
        "interval": interval,
        "jitter": jitter,
        "name": name,
        "persistent": bool(arguments.get("persistent", False)),
    }


async def sliver_generate_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, sliver_generate_definition().input_schema)
    generation = _generation_arguments(arguments)
    client, failure = build_client()
    if failure is not None:
        return failure
    try:
        await client.connect()
        info, _data = await client.generate_implant(**generation)
        return ToolResult(
            output=client.redact({"implant": info, "bytes_returned": False}),
            verified=True,
            verification_method="sliver_implant_generated",
            evidence={
                "name": info["name"],
                "sha256": info["sha256"],
                "size": info["size"],
                "os": generation["os_name"],
                "arch": generation["arch"],
                "format": generation["format"],
                "beacon": generation["beacon"],
                "persistent": generation["persistent"],
            },
        )
    except SliverError as exc:
        return error_result(exc, tool_id=TOOL_ID)
    except (ValueError, TypeError):
        return ToolResult(verification_method="sliver_response_invalid")
    finally:
        await client.disconnect()
