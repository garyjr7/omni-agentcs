"""Read-only, unified session inventory restricted to the current engagement.

Two sources are merged on purpose:

* ``kernel_sessions`` is the durable truth: it carries the ``session_ref`` the
  agent reuses in later turns (a caught reverse shell, a Sliver session, a
  webshell), and its signed-scope/engagement checks are what make a session
  addressable at all.
* the Metasploit RPC is the live truth for MSF sessions, which are addressed by
  their own UUID and are registered by the tool that opened them. The listing
  keeps its historical fail-closed behaviour: a configured daemon that cannot be
  reached is an error, never an "empty" answer.

Live tmux panes of this run are also surfaced, so a PTY started with
``nexus.session.pty`` is visible with a ``session_ref`` even though a local pane
has no remote target to register.
"""

from __future__ import annotations

from typing import Any

from nexus_core.integrations.metasploit.client import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
)
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.pty_sessions import PtySessionManager
from nexus_core.kernel.schema_validation import validate
from nexus_core.kernel.sessions import (
    SESSION_PENDING_TARGET,
    SessionRegistry,
    validate_session_scope,
)
from nexus_core.tools.parsers.metasploit import parse_msf_sessions
from .listener import LISTENER_TRANSPORTS, refresh_listener_session
from .workspace import workspace_root

SESSION_TYPES = ("meterpreter", "shell", "powershell", "all")


def msf_session_list_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id="nexus.session.list",
        name="List active sessions",
        tenant_id=tenant_id,
        description=(
            "Lista las sesiones del engagement actual (MSF en vivo, sesiones "
            "durables de kernel_sessions y panes PTY del run). Cada entrada "
            "incluye un session_ref usable en nexus.post.shell_exec. Solo "
            "lectura. Requiere pertenencia registrada y scope vigente."
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


def _durable_entry(row: dict[str, Any], *, alive: bool) -> dict[str, Any]:
    """Normalize one ``kernel_sessions`` row for the model."""
    session_ref = str(row["id"])
    session_type = str(row.get("session_type") or row.get("transport") or "session")
    return {
        "session_ref": session_ref,
        "uuid": session_ref,
        "transport": str(row.get("transport") or "msf"),
        "session_type": session_type,
        "type": session_type,
        "target_host": row.get("target_host"),
        "transport_ref": row.get("transport_ref"),
        "opened_at": row.get("opened_at"),
        "liveness": row.get("liveness"),
        "alive": alive,
        "durable": True,
    }


def _pty_entry(name: str, created: float | None) -> dict[str, Any]:
    return {
        "session_ref": name,
        "uuid": name,
        "transport": "pty",
        "session_type": "pty",
        "type": "pty",
        "target_host": None,
        "transport_ref": name,
        "created": created,
        "alive": True,
        "durable": False,
    }


async def msf_session_list_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, msf_session_list_definition().input_schema)
    filter_type = str(arguments.get("filter_type") or "all").lower()
    if filter_type not in SESSION_TYPES:
        raise ValueError("filter_type must be one of meterpreter, shell, powershell, all")
    try:
        validate_session_scope(context)
    except PermissionError:
        return ToolResult(verification_method="session_scope_required")
    scope = context.scope
    if scope is None:
        return ToolResult(verification_method="session_scope_required")
    registry = SessionRegistry(context.store)

    # A keep-open listener may have caught its peer since the last turn. Binding
    # it here means the inventory returns the real target instead of ``pending``.
    durable = registry.list_sessions(context.tenant_id, scope.engagement_id)
    for row in durable:
        if str(row.get("transport") or "") in LISTENER_TRANSPORTS:
            status = refresh_listener_session(context, registry, row)
            if status is not None:
                row["listener_status"] = status
                if status.get("peer"):
                    row["target_host"] = str(status["peer"])

    manager = PtySessionManager(workspace_root(), context.run_id)
    durable_refs = {
        str(row.get("transport_ref")) for row in durable if row.get("transport_ref")
    }

    async def pty_entries() -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for live in await manager.list_sessions():
            name = str(live.get("name") or "")
            if not name or name in durable_refs:
                continue
            entries.append(_pty_entry(name, live.get("created")))  # type: ignore[arg-type]
        return entries

    parsed_sessions = []
    raw_sha256: str | None = None
    total = 0
    config = MetasploitConfig.from_env()
    if not config.password:
        # No MSF deployed: the durable registry (plus tmux) is the inventory.
        pass
    else:
        try:
            async with MetasploitClient(config) as client:
                if not await client.is_available():
                    return ToolResult(verification_method="msf_unavailable")
                raw = await client.list_sessions()
                parsed = parse_msf_sessions(registry.filter_owned(context, raw))
                parsed_sessions = list(parsed.sessions)
                raw_sha256 = parsed.raw_sha256
                total = parsed.count
        except MetasploitError as exc:
            return ToolResult(
                verification_method="msf_rpc_failed",
                evidence={"error_type": type(exc).__name__},
            )
        except (ValueError, TypeError):
            return ToolResult(verification_method="msf_response_invalid")

    sessions: list[dict[str, Any]] = []
    live_refs: set[str] = set()
    for session in parsed_sessions:
        record = session.to_dict()
        record["session_ref"] = record.get("uuid") or session.uuid
        record["transport"] = "msf"
        record["durable"] = False
        record["alive"] = True
        sessions.append(record)
        live_refs.add(record["session_ref"])

    # MSF rows are reported through the live RPC only: it is the source that can
    # prove the session still exists, and keeping one view avoids a duplicated
    # entry when both know the same UUID.
    for row in durable:
        if str(row.get("transport") or "msf") == "msf":
            continue
        alive = row.get("closed_at") is None
        if row.get("transport") in LISTENER_TRANSPORTS or row.get("transport") == "pty":
            transport_ref = str(row.get("transport_ref") or "")
            alive = bool(
                transport_ref
                and manager.owns(transport_ref)
                and await manager.exists(transport_ref)
            )
        entry = _durable_entry(row, alive=alive)
        status = row.get("listener_status")
        if isinstance(status, dict):
            entry["listener_status"] = status.get("status")
            entry["peer"] = status.get("peer")
            if row.get("target_host") == SESSION_PENDING_TARGET:
                entry["target_host"] = None
        sessions.append(entry)

    sessions.extend(await pty_entries())
    selected = [
        session
        for session in sessions
        if filter_type == "all"
        or str(session.get("type") or session.get("session_type") or "").lower() == filter_type
    ]

    output: dict[str, Any] = {
        "sessions": selected,
        "count": len(selected),
        "total": max(total, len(sessions)) if parsed_sessions else len(sessions),
        "filter_type": filter_type,
        "durable": sum(1 for s in selected if s.get("durable")),
    }
    if raw_sha256 is not None:
        output["raw_sha256"] = raw_sha256
    evidence: dict[str, Any] = {
        "count": len(selected),
        "total": output["total"],
        "durable": output["durable"],
    }
    if raw_sha256 is not None:
        evidence["raw_sha256"] = raw_sha256
    return ToolResult(
        output=output,
        verified=True,
        verification_method=(
            "session_list_unified" if parsed_sessions else "session_list_registry"
        ),
        evidence=evidence,
    )
