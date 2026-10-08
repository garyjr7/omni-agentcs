"""Durable ownership checks for sessions; unknown origins are denied."""

from __future__ import annotations

from .models import RunContext, ToolResult, utc_now
from .scope_loader import scope_signing_secret
from nexus_core.scope import ScopeValidator, ScopeViolation


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
                 opened_by_tool: str) -> None:
        if not all((session_uuid, tenant_id, engagement_id, run_id, target_host)):
            raise ValueError("session ownership and target must be explicit")
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_sessions
                (id,tenant_id,engagement_id,run_id,session_type,target_host,opened_at,opened_by_tool)
                VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING""",
                (session_uuid, tenant_id, engagement_id, run_id, session_type,
                 target_host, utc_now(), opened_by_tool),
            )
            row = conn.execute("SELECT * FROM kernel_sessions WHERE id=?", (session_uuid,)).fetchone()
            if (row["tenant_id"], row["engagement_id"], row["run_id"], row["target_host"],
                row["session_type"], row["opened_by_tool"], row["closed_at"]) != (
                tenant_id, engagement_id, run_id, target_host, session_type, opened_by_tool, None
            ):
                raise PermissionError("session ownership cannot be reassigned")

    def get(self, tenant_id: str, session_uuid: str):
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM kernel_sessions WHERE id=? AND tenant_id=?",
                (session_uuid, tenant_id),
            ).fetchone()
        return dict(row) if row else None

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
