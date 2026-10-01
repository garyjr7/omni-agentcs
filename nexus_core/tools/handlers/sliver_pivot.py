"""``nexus.c2.sliver_pivot``: manage Sliver pivots (portfwd and SOCKS5) (HIGH).

Pivoting changes network reachability, so it is HIGH risk and requires human
approval. As with ``sliver_exec``, the session must be owned by the current
engagement. Only the follow actions are supported:

- ``list``    — current pivot listeners of the session (read-only),
- ``portfwd`` — forward a server-side port to a remote host through the session,
- ``socks5``  — start a SOCKS5 proxy through the session,
- ``kill``    — stop a pivot listener by id.
"""

from __future__ import annotations

import re

from nexus_core.integrations.sliver.client import SliverError
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.kernel.sessions import SessionRegistry, validate_session_scope
from nexus_core.tools.handlers.sliver_common import build_client, error_result
from nexus_core.tools.parsers.sliver import parse_sliver_pivots

TOOL_ID = "nexus.c2.sliver_pivot"
SESSION_ID_PATTERN = r"[A-Za-z0-9_-]{1,64}"
HOST_PATTERN = r"[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?"
ACTIONS = ("portfwd", "socks5", "list", "kill")
KINDS = ("session", "beacon")


def sliver_pivot_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id=TOOL_ID,
        name="Sliver pivot operations",
        tenant_id=tenant_id,
        description=(
            "Gestiona pivots: portfwd (TCP forwarding) y SOCKS5. Requiere "
            "aprobación humana (HIGH)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "pattern": "^" + SESSION_ID_PATTERN + "$",
                    "minLength": 1,
                    "maxLength": 64,
                },
                "action": {"type": "string", "enum": list(ACTIONS)},
                "kind": {"type": "string", "enum": list(KINDS), "default": "session"},
                "bind_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "remote_host": {"type": "string", "maxLength": 255},
                "remote_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "forward_id": {"type": "integer"},
            },
            "required": ["session_id", "action"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        effect="pivoting",
        required_permissions=[f"execute:tool:{TOOL_ID}"],
        timeout_seconds=120,
        max_output_bytes=1_000_000,
        scope_target_field=None,
        scope_required=True,
    )


def _validated_port(value: object, name: str) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return value


def _validated_host(value: object) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 255 or not re.fullmatch(HOST_PATTERN, text):
        raise ValueError("remote_host must be a single IP or hostname")
    return text


async def sliver_pivot_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, sliver_pivot_definition().input_schema)
    session_id = arguments["session_id"]
    if not isinstance(session_id, str) or not re.fullmatch(SESSION_ID_PATTERN, session_id):
        raise ValueError("invalid session id")
    action = str(arguments.get("action") or "").lower()
    if action not in ACTIONS:
        raise ValueError("action must be one of portfwd, socks5, list, kill")
    kind = str(arguments.get("kind") or "session").lower()
    if kind not in KINDS:
        raise ValueError("kind must be one of session, beacon")

    # Validate every action-specific field before touching the network.
    bind_port = arguments.get("bind_port")
    remote_host = None
    remote_port = None
    forward_id = None
    if action == "portfwd":
        if bind_port is None:
            raise ValueError("portfwd requires bind_port")
        bind_port = _validated_port(bind_port, "bind_port")
        if "remote_host" not in arguments or "remote_port" not in arguments:
            raise ValueError("portfwd requires remote_host and remote_port")
        remote_host = _validated_host(arguments.get("remote_host"))
        remote_port = _validated_port(arguments.get("remote_port"), "remote_port")
    elif action == "kill":
        forward_id = arguments.get("forward_id")
        if type(forward_id) is not int or forward_id < 0:
            raise ValueError("kill requires a non-negative forward_id")
    elif bind_port is not None:
        bind_port = _validated_port(bind_port, "bind_port")

    try:
        validate_session_scope(context)
    except PermissionError:
        return ToolResult(verification_method="session_scope_required")
    registry = SessionRegistry(context.store)
    denied = registry.denial(context, session_id)
    if denied is not None:
        return denied
    client, failure = build_client()
    if failure is not None:
        return failure
    try:
        await client.connect()
        if action == "list":
            raw = await client.list_pivots(session_id, kind=kind)
            pivots = parse_sliver_pivots(raw)
        elif action == "portfwd":
            raw = await client.start_portfwd(
                session_id,
                bind_port=bind_port,
                remote_host=remote_host,
                remote_port=remote_port,
                kind=kind,
            )
            pivots = parse_sliver_pivots([{**raw, "kind": "portfwd"}])
        elif action == "socks5":
            raw = await client.start_socks5(session_id, kind=kind)
            pivots = parse_sliver_pivots([{**raw, "kind": "socks5"}])
        else:  # kill
            await client.stop_pivot(session_id, forward_id=forward_id, kind=kind)
            pivots = ()
        return ToolResult(
            output=client.redact(
                {
                    "action": action,
                    "session_id": session_id,
                    "kind": kind,
                    "pivots": [pivot.to_dict() for pivot in pivots],
                    "count": len(pivots),
                }
            ),
            verified=True,
            verification_method=f"sliver_pivot_{action}",
            evidence={
                "action": action,
                "session_id": session_id,
                "count": len(pivots),
                "forward_id": forward_id,
            },
        )
    except SliverError as exc:
        return error_result(exc, tool_id=TOOL_ID)
    except (ValueError, TypeError):
        return ToolResult(verification_method="sliver_response_invalid")
    finally:
        await client.disconnect()
