"""Termination of one durable session (cleanup at the end of an engagement).

``nexus.session.kill`` is the single teardown verb for every transport: MSF and
Sliver are asked to stop the session, a pty/raw listener has its tmux pane killed,
and a webshell row is simply closed. In all cases ``closed_at`` is written so the
registry can never hand the session out again.
"""

from __future__ import annotations

import re

from nexus_core.integrations.metasploit.client import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
)
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.pty_sessions import PtySessionManager
from nexus_core.kernel.schema_validation import validate
from nexus_core.kernel.sessions import (
    SessionRegistry,
    validate_session_scope,
)
from .listener import LISTENER_TRANSPORTS
from .workspace import workspace_root

SESSION_UUID_PATTERN = r"[A-Za-z0-9_-]{1,64}"


def msf_session_kill_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id="nexus.session.kill",
        name="Terminate a session",
        tenant_id=tenant_id,
        description=(
            "Termina una sesión registrada por su session_ref/UUID: cierra el "
            "pane tmux de un canal pty/raw, pide el cierre a MSF/Sliver y marca "
            "closed_at. Apropiado para cleanup al final de un engagement."
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
        effect="post_exploitation",
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
    record = registry.get(context.tenant_id, session_uuid)
    denied = registry.denial(context, session_uuid)
    # A keep-open listener whose peer never connected has no target to
    # scope-check, but it is still a row of this engagement: refusing to close it
    # would leave the tmux pane alive after the operation is over.
    if denied is not None and not (
        record is not None
        and str(record.get("transport") or "") in LISTENER_TRANSPORTS
        and denied.verification_method == "session_not_connected"
    ):
        return denied

    transport = str((record or {}).get("transport") or "msf")
    if transport in LISTENER_TRANSPORTS:
        return await _kill_tmux(context, registry, record or {}, transport)
    if transport == "sliver":
        return await _kill_sliver(context, registry, session_uuid)
    if transport == "webshell":
        registry.close(context, session_uuid)
        return ToolResult(
            output={"session_uuid": session_uuid, "result": "closed"},
            verified=True,
            verification_method="session_kill_registry",
            evidence={"session_uuid": session_uuid, "transport": "webshell"},
        )
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


async def _kill_tmux(
    context: RunContext,
    registry: SessionRegistry,
    record: dict,
    transport: str,
) -> ToolResult:
    """Kill the run-owned tmux pane and close the row."""
    session_ref = str(record.get("id") or "")
    transport_ref = str(record.get("transport_ref") or "")
    manager = PtySessionManager(workspace_root(), context.run_id)
    if not transport_ref or not manager.owns(transport_ref):
        return ToolResult(
            output={"error": "session transport is not owned by this run",
                    "session_ref": session_ref},
            verified=False,
            outcome="denied",
            verification_method="session_transport_ref_foreign",
            evidence={"session_ref": session_ref, "transport": transport},
        )
    result = await manager.kill(transport_ref)
    # ``session_not_found`` means the pane was already gone: the goal (no live
    # channel) holds, so the row is closed as well.
    done = result.error is None or result.error == "session_not_found"
    if done:
        registry.close(context, session_ref)
    return ToolResult(
        output={
            "session_uuid": session_ref,
            "session_ref": session_ref,
            "result": "success" if done else "error",
            "alive": result.alive,
        },
        verified=done,
        verification_method="session_kill_tmux",
        evidence={"session_ref": session_ref, "transport": transport,
                  "transport_ref": transport_ref, "alive": result.alive},
    )


async def _kill_sliver(
    context: RunContext, registry: SessionRegistry, session_uuid: str,
) -> ToolResult:
    """Ask the Sliver team server to terminate the session, then close the row."""
    from nexus_core.integrations.sliver.client import SliverError
    from .sliver_common import build_client, error_result

    client, failure = build_client()
    if failure is not None:
        return failure
    assert client is not None
    try:
        await client.connect()
        await client.kill_session(session_uuid)
        registry.close(context, session_uuid)
        return ToolResult(
            output={"session_uuid": session_uuid, "session_ref": session_uuid,
                    "result": "success"},
            verified=True,
            verification_method="sliver_session_kill_rpc",
            evidence={"session_ref": session_uuid, "transport": "sliver"},
        )
    except SliverError as exc:
        return error_result(exc, tool_id="nexus.session.kill")
    finally:
        await client.disconnect()
