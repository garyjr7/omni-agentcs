"""Durable human approval service with separation of duties."""

from __future__ import annotations

from typing import Any, Dict
from uuid import uuid4

from .control_store import ControlStore
from .models import RunContext, utc_now


class ApprovalService:
    def __init__(self, store: ControlStore):
        self.store = store

    def request(self, context: RunContext, action: str) -> Dict[str, Any]:
        approval_id = f"approval_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_approvals
                (id,tenant_id,run_id,action,status,requested_by,created_at)
                VALUES(?,?,?,?,?,?,?)""",
                (approval_id, context.tenant_id, context.run_id, action, "pending",
                 context.identity.subject_id, utc_now()),
            )
        return self.get(approval_id, context.tenant_id)

    def list_pending(self, tenant_id: str) -> list[Dict[str, Any]]:
        """Return the tenant's pending approvals, oldest first."""
        with self.store.connect() as conn:
            rows = conn.execute(
                """SELECT * FROM kernel_approvals
                WHERE tenant_id=? AND status='pending' ORDER BY created_at""",
                (tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get(self, approval_id: str, tenant_id: str) -> Dict[str, Any]:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM kernel_approvals WHERE id=? AND tenant_id=?",
                (approval_id, tenant_id),
            ).fetchone()
        if not row:
            raise KeyError("approval not found")
        return dict(row)

    def decide(
        self,
        approval_id: str,
        tenant_id: str,
        actor_id: str,
        approved: bool,
        reason: str = "",
    ) -> Dict[str, Any]:
        approval = self.get(approval_id, tenant_id)
        if approval["status"] != "pending":
            raise ValueError("approval is already decided")
        if approval["requested_by"] == actor_id:
            raise PermissionError("requester cannot approve their own action")
        status = "approved" if approved else "denied"
        with self.store.connect() as conn:
            conn.execute(
                """UPDATE kernel_approvals SET status=?,decided_by=?,reason=?,decided_at=?
                WHERE id=? AND tenant_id=? AND status='pending'""",
                (status, actor_id, reason, utc_now(), approval_id, tenant_id),
            )
        return self.get(approval_id, tenant_id)

    def verify(
        self,
        approval_id: str,
        context: RunContext,
        expected_action: str,
    ) -> bool:
        approval = self.get(approval_id, context.tenant_id)
        return (
            approval["run_id"] == context.run_id
            and approval["action"] == expected_action
            and approval["status"] == "approved"
            and approval["consumed_at"] is None
        )

    def consume(
        self,
        approval_id: str,
        context: RunContext,
        expected_action: str,
    ) -> bool:
        """Verify *and* consume an approval in one atomic, single-use step.

        Returns ``True`` only the first time a matching, still-approved
        approval for this tenant/run/action is claimed. The row is marked via
        ``consumed_at`` by one conditional UPDATE. Both SQLite and PostgreSQL
        serialize conflicting updates, so only one invocation can succeed. Returns ``False`` when the
        approval is unknown, belongs to another run/action, was denied, or was
        already consumed.
        """
        with self.store.connect() as conn:
            cursor = conn.execute(
                """UPDATE kernel_approvals SET consumed_at=?
                WHERE id=? AND tenant_id=? AND run_id=? AND action=?
                  AND status='approved' AND consumed_at IS NULL""",
                (utc_now(), approval_id, context.tenant_id, context.run_id,
                 expected_action),
            )
            consumed = cursor.rowcount == 1
        return consumed
