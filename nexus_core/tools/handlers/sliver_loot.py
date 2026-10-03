"""``nexus.c2.sliver_loot``: loot inventory and chain of custody (LOW).

Reads the team server's loot store and, with ``record``, registers one entry in
the engagement blackboard as a ``loot`` fact carrying its SHA256 — that fact is
what the report turns into verified, non-repudiable evidence. Nothing here
touches a target, so the tool requires no scope and no approval.
"""

from __future__ import annotations

from nexus_core.integrations.sliver.client import SliverError
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.tools.handlers.sliver_common import build_client, error_result
from nexus_core.tools.parsers.sliver import parse_sliver_loot

TOOL_ID = "nexus.c2.sliver_loot"
ACTIONS = ("list", "get", "record")


def sliver_loot_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id=TOOL_ID,
        name="Sliver loot and chain of custody",
        tenant_id=tenant_id,
        description=(
            "Lista el loot del team server, lee una entrada concreta y, con "
            "record, registra un hecho 'loot' del engagement con su SHA256 para "
            "la cadena de custodia del reporte. No toca objetivos."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": list(ACTIONS), "default": "list"},
                "loot_id": {"type": "string", "maxLength": 128},
                "name": {"type": "string", "maxLength": 256},
                "with_content": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        effect="read_only",
        required_permissions=[f"execute:tool:{TOOL_ID}"],
        timeout_seconds=60,
        max_output_bytes=2_000_000,
        scope_target_field=None,
        scope_required=False,
    )


def _select(entries, *, loot_id: str, name: str):
    for entry in entries:
        if loot_id and entry.loot_id == loot_id:
            return entry
        if name and entry.name == name:
            return entry
    return None


async def sliver_loot_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, sliver_loot_definition().input_schema)
    action = str(arguments.get("action") or "list").lower()
    if action not in ACTIONS:
        raise ValueError("action must be one of list, get, record")
    loot_id = str(arguments.get("loot_id") or "").strip()
    name = str(arguments.get("name") or "").strip()
    if action in {"get", "record"} and not (loot_id or name):
        raise ValueError("get/record require loot_id or name")

    client, failure = build_client()
    if failure is not None:
        return failure
    try:
        await client.connect()
        if action == "get":
            raw = await client.loot_get(loot_id, name=name)
            entries = parse_sliver_loot(raw)
        else:
            entries = parse_sliver_loot(await client.loot_list())

        if action == "list":
            return ToolResult(
                output=client.redact(
                    {"loot": [entry.to_dict() for entry in entries], "count": len(entries)}
                ),
                verified=True,
                verification_method="sliver_loot_listed",
                evidence={"count": len(entries)},
            )

        selected = _select(entries, loot_id=loot_id, name=name)
        if selected is None:
            return ToolResult(verification_method="sliver_loot_not_found")

        if action == "get":
            return ToolResult(
                output=client.redact({"loot": selected.to_dict()}),
                verified=True,
                verification_method="sliver_loot_fetched",
                evidence={
                    "loot_id": selected.loot_id,
                    "sha256": selected.sha256,
                    "size": selected.size,
                },
            )

        # action == "record": persist the chain-of-custody fact.
        store = getattr(context, "store", None)
        engagement_id = getattr(getattr(context, "scope", None), "engagement_id", None)
        if store is None:
            return ToolResult(verification_method="blackboard_store_missing")
        if not engagement_id:
            return ToolResult(verification_method="blackboard_no_engagement")
        created_by = getattr(getattr(context, "identity", None), "subject_id", "agent")
        key = selected.name or selected.loot_id or selected.sha256[:16]
        Blackboard(store).record(
            tenant_id=context.tenant_id,
            engagement_id=engagement_id,
            fact_type="loot",
            key=key,
            value={
                "loot_id": selected.loot_id,
                "kind": selected.kind,
                "sha256": selected.sha256,
                "size": selected.size,
                "file_type": selected.file_type,
            },
            source=TOOL_ID,
            created_by=created_by,
            verified=True,
        )
        return ToolResult(
            output=client.redact(
                {
                    "recorded": {
                        "engagement_id": engagement_id,
                        "key": key,
                        "sha256": selected.sha256,
                    },
                    "loot": selected.to_dict(),
                }
            ),
            verified=True,
            verification_method="sliver_loot_recorded",
            evidence={
                "engagement_id": engagement_id,
                "loot_id": selected.loot_id,
                "sha256": selected.sha256,
                "size": selected.size,
            },
        )
    except SliverError as exc:
        return error_result(exc, tool_id=TOOL_ID)
    except (ValueError, TypeError):
        return ToolResult(verification_method="sliver_response_invalid")
    finally:
        await client.disconnect()
