"""Durable ownership checks for sessions; unknown origins are denied."""

from __future__ import annotations

from typing import Any

from .models import RunContext, ToolResult, utc_now
from .scope_loader import scope_signing_secret
from nexus_core.scope import ScopeValidator, ScopeViolation

#: How a durable session is driven. ``pty``/``raw`` are the reverse-shell and
#: tmux channels; the rest name the C2 that owns the session.
SESSION_TRANSPORTS = ("msf", "sliver", "webshell", "pty", "raw")

#: A newly caught reverse shell has no peer until ``accept()`` returns. The row
#: is created with this placeholder so the agent gets its ``session_ref``
#: immediately, and ``denial`` refuses to drive it until the peer is bound to
#: the signed scope by :meth:`SessionRegistry.bind_target`.
SESSION_PENDING_TARGET = "pending"


def transport_for(session_type: str) -> str:
    """Map a legacy ``session_type`` to the transport that drives it."""
    text = str(session_type or "").strip().lower()
    if text.startswith("sliver:"):
        return "sliver"
    if text.startswith("listener:") or text in {"pty", "raw"}:
        return text.rsplit(":", 1)[-1]
    if text == "webshell":
        return "webshell"
    return "msf"


def validate_session_scope(context: RunContext) -> None:
    if context.store is None or context.scope is None:
        raise PermissionError("session operations require a store and engagement")
    if context.scope.tenant_id != context.tenant_id or not context.scope.engagement_id:
        raise PermissionError("session engagement does not belong to tenant")
    from .scope_loader import validate_scope_authentication
    # Context-only operations still authenticate and durably audit lab/denial.
    try:
        validate_scope_authentication(context.scope, context.store, context.tenant_id,
                                      context.trace_id, context.identity.subject_id)
    except ScopeViolation as exc:
        raise PermissionError("session engagement is not valid") from exc


class SessionRegistry:
    def __init__(self, store):
        self.store = store

    def register(self, *, session_uuid: str, tenant_id: str, engagement_id: str,
                 run_id: str, session_type: str, target_host: str,
                 opened_by_tool: str, transport: str | None = None,
                 transport_ref: str | None = None,
                 liveness: str | None = None) -> None:
        if not all((session_uuid, tenant_id, engagement_id, run_id, target_host)):
            raise ValueError("session ownership and target must be explicit")
        transport = str(transport or transport_for(session_type)).strip().lower()
        if transport not in SESSION_TRANSPORTS:
            raise ValueError(f"unsupported session transport: {transport!r}")
        transport_ref = str(transport_ref).strip() if transport_ref else None
        # A durable handle is optional (an MSF session is addressed by its UUID),
        # but when present it is immutable: rebinding a ref would let a row point
        # at another channel after the fact.
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_sessions
                (id,tenant_id,engagement_id,run_id,session_type,target_host,opened_at,
                 opened_by_tool,transport,transport_ref,liveness)
                VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING""",
                (session_uuid, tenant_id, engagement_id, run_id, session_type,
                 target_host, utc_now(), opened_by_tool, transport, transport_ref,
                 liveness or utc_now()),
            )
            row = conn.execute("SELECT * FROM kernel_sessions WHERE id=?", (session_uuid,)).fetchone()
            if (row["tenant_id"], row["engagement_id"], row["run_id"], row["target_host"],
                row["session_type"], row["opened_by_tool"], row["closed_at"],
                row["transport"], row["transport_ref"]) != (
                tenant_id, engagement_id, run_id, target_host, session_type,
                opened_by_tool, None, transport, transport_ref
            ):
                raise PermissionError("session ownership cannot be reassigned")

    def get(self, tenant_id: str, session_uuid: str):
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM kernel_sessions WHERE id=? AND tenant_id=?",
                (session_uuid, tenant_id),
            ).fetchone()
        return dict(row) if row else None

    def list_sessions(
        self, tenant_id: str, engagement_id: str, *, include_closed: bool = False,
    ) -> list[dict[str, Any]]:
        """Durable sessions of one engagement, oldest first."""
        clause = "" if include_closed else " AND closed_at IS NULL"
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM kernel_sessions WHERE tenant_id=? AND engagement_id=?"
                + clause + " ORDER BY opened_at",
                (tenant_id, engagement_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def touch(self, context: RunContext, session_uuid: str,
              liveness: str | None = None) -> bool:
        """Record a heartbeat; returns False when the row is not owned/closed."""
        if context.store is None or context.scope is None:
            return False
        with self.store.connect() as conn:
            cursor = conn.execute(
                """UPDATE kernel_sessions SET liveness=?
                WHERE id=? AND tenant_id=? AND engagement_id=? AND closed_at IS NULL""",
                (liveness or utc_now(), session_uuid, context.tenant_id,
                 context.scope.engagement_id),
            )
        return bool(cursor.rowcount)

    def bind_target(self, context: RunContext, session_uuid: str, target_host: str,
                    *, liveness: str | None = None) -> None:
        """Bind the peer of a pending reverse-shell row to the signed scope.

        Only a row created with :data:`SESSION_PENDING_TARGET` can be bound, and
        the peer must validate against the engagement: a listener that outlived
        its scope cannot promote a connection into a durable session.
        """
        if context.scope is None:
            raise PermissionError("session binding requires an engagement")
        host = str(target_host or "").strip()
        if not host:
            raise ValueError("peer host is required")
        record = self.get(context.tenant_id, session_uuid)
        if not record:
            raise ValueError("session is not registered")
        if record["engagement_id"] != context.scope.engagement_id:
            raise PermissionError("session does not belong to the engagement")
        if record["target_host"] != SESSION_PENDING_TARGET:
            raise PermissionError("session target is already bound")
        ScopeValidator(context.scope, signing_secret=scope_signing_secret()).validate(host)
        with self.store.connect() as conn:
            conn.execute(
                """UPDATE kernel_sessions SET target_host=?, liveness=?
                WHERE id=? AND tenant_id=? AND engagement_id=? AND target_host=?
                AND closed_at IS NULL""",
                (host, liveness or utc_now(), session_uuid, context.tenant_id,
                 context.scope.engagement_id, SESSION_PENDING_TARGET),
            )

    def close(self, context: RunContext, session_uuid: str) -> None:
        with self.store.connect() as conn:
            conn.execute(
                """UPDATE kernel_sessions SET closed_at=? WHERE id=? AND tenant_id=?
                AND engagement_id=? AND closed_at IS NULL""",
                (utc_now(), session_uuid, context.tenant_id, context.scope.engagement_id),
            )

    def denial(self, context: RunContext, session_uuid: str) -> ToolResult | None:
        try:
            validate_session_scope(context)
        except PermissionError:
            return ToolResult(verification_method="session_scope_required")
        record = self.get(context.tenant_id, session_uuid)
        if not record:
            return ToolResult(verification_method="session_not_registered")
        if record["engagement_id"] != context.scope.engagement_id:
            return ToolResult(verification_method="session_engagement_mismatch")
        if record["closed_at"] is not None:
            return ToolResult(verification_method="session_closed")
        if record["target_host"] == SESSION_PENDING_TARGET:
            # The listener has not accepted a peer yet (or the peer was refused),
            # so there is no authorised target to execute against.
            return ToolResult(verification_method="session_not_connected")
        try:
            ScopeValidator(context.scope, signing_secret=scope_signing_secret()).validate(record["target_host"])
        except ScopeViolation:
            return ToolResult(verification_method="session_target_out_of_scope")
        return None

    def filter_owned(self, context: RunContext, raw: dict) -> dict:
        validate_session_scope(context)
        return {
            key: record for key, record in raw.items()
            if isinstance(record, dict)
            and self.denial(context, str(record.get("uuid") or key)) is None
        }
