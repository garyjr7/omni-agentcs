"""``nexus.c2.sliver_sessions``: list Sliver sessions/beacons for the engagement.

A session is only ever shown when it is registered in ``kernel_sessions`` and
belongs to the *current* engagement, so a session opened for another tenant or
engagement can never leak into the view. Newly observed sessions of the current
run are registered (fail-closed: an unregisterable session is not shown).
"""

from __future__ import annotations

from nexus_core.integrations.sliver.client import SliverError
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.kernel.sessions import SessionRegistry, validate_session_scope
from nexus_core.tools.handlers.sliver_common import build_client, error_result, target_host
from nexus_core.tools.parsers.sliver import parse_sliver_sessions

TOOL_ID = "nexus.c2.sliver_sessions"
KINDS = ("sessions", "beacons", "both")


def sliver_sessions_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id=TOOL_ID,
        name="List Sliver sessions and beacons",
        tenant_id=tenant_id,
        description=(
            "Lista sessions (interactivas) y beacons (async) activos. Filtra por "
            "el engagement actual usando kernel_sessions."
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
        max_output_bytes=2_000_000,
        scope_target_field=None,
        scope_required=True,
    )


def _register_new(registry: SessionRegistry, context: RunContext, discovered) -> int:
    """Register the sessions of this run that are not known yet."""
    scope = context.scope
    if scope is None:
        return 0
    registered = 0
    for item in discovered:
        if registry.get(context.tenant_id, item.session_id) is not None:
            continue
        host = target_host(item.remote_address)
        if not host:
            # Without a peer address we cannot bind the session to the scope.
            continue
        try:
            registry.register(
                session_uuid=item.session_id,
                tenant_id=context.tenant_id,
                engagement_id=scope.engagement_id,
                run_id=context.run_id,
                session_type=f"sliver:{item.kind}",
                target_host=host,
                opened_by_tool=TOOL_ID,
            )
            registered += 1
        except (ValueError, PermissionError):
            # An unassignable id stays unregistered and is filtered out below.
            continue
    return registered


async def sliver_sessions_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, sliver_sessions_definition().input_schema)
    kind = str(arguments.get("kind") or "both").lower()
    if kind not in KINDS:
        raise ValueError("kind must be one of sessions, beacons, both")
    try:
        validate_session_scope(context)
    except PermissionError:
        return ToolResult(verification_method="session_scope_required")
    registry = SessionRegistry(context.store)
    client, failure = build_client()
    if client is None:
        return failure or ToolResult(verification_method="sliver_unavailable")
    try:
        await client.connect()
        raw_sessions = await client.list_sessions() if kind in {"sessions", "both"} else []
        raw_beacons = await client.list_beacons() if kind in {"beacons", "both"} else []
        discovered = parse_sliver_sessions(raw_sessions, raw_beacons)
        registered = _register_new(registry, context, discovered)
        owned = [
            item
            for item in discovered
            if registry.denial(context, item.session_id) is None
        ]
        sessions = [item.to_dict() for item in owned if item.kind == "session"]
        beacons = [item.to_dict() for item in owned if item.kind == "beacon"]
        return ToolResult(
            output=client.redact(
                {
                    "sessions": sessions,
                    "beacons": beacons,
                    "count": len(owned),
                    "total_seen": len(discovered),
                    "registered": registered,
                    "kind": kind,
                }
            ),
            verified=True,
            verification_method="sliver_sessions_listed",
            evidence={
                "count": len(owned),
                "total_seen": len(discovered),
                "registered": registered,
                "kind": kind,
            },
        )
    except SliverError as exc:
        return error_result(exc, tool_id=TOOL_ID)
    except (ValueError, TypeError):
        return ToolResult(verification_method="sliver_response_invalid")
    finally:
        await client.disconnect()
