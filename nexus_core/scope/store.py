"""Durable persistence for :class:`EngagementScope` records.

Backed by the shared :class:`~nexus_core.kernel.control_store.ControlStore`
(``kernel_engagements`` table). All queries are tenant-scoped.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import utc_now

from .models import EngagementScope, parse_iso8601


class EngagementStore:
    """CRUD for signed engagement scopes, scoped by tenant."""

    def __init__(self, store: ControlStore):
        self.store = store

    def create(self, scope: EngagementScope) -> EngagementScope:
        """Persist a new engagement. ``created_at`` is filled when empty."""
        value = scope if scope.created_at else replace(scope, created_at=utc_now())
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_engagements
                (id,tenant_id,name,client,owner_id,valid_from,valid_until,cidrs,
                 domains,urls,exclusions,notes,signature,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    value.engagement_id,
                    value.tenant_id,
                    value.name,
                    value.client,
                    value.owner_id,
                    value.valid_from,
                    value.valid_until,
                    json.dumps(list(value.cidrs)),
                    json.dumps(list(value.domains)),
                    json.dumps(list(value.urls)),
                    json.dumps(list(value.exclusions)),
                    value.notes,
                    value.signature,
                    value.created_at,
                ),
            )
        return value

    def get(self, tenant_id: str, engagement_id: str) -> EngagementScope | None:
        """Return one engagement, or ``None`` when it does not exist."""
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM kernel_engagements WHERE tenant_id=? AND id=?",
                (tenant_id, engagement_id),
            ).fetchone()
        return self._row_to_scope(row) if row else None

    def get_by_name(self, tenant_id: str, name: str) -> EngagementScope | None:
        """Return one engagement by its tenant-unique display name."""
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM kernel_engagements WHERE tenant_id=? AND name=?",
                (tenant_id, name),
            ).fetchone()
        return self._row_to_scope(row) if row else None

    def list_for_tenant(self, tenant_id: str) -> list[EngagementScope]:
        """Return every engagement owned by a tenant, oldest first."""
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM kernel_engagements WHERE tenant_id=? ORDER BY created_at",
                (tenant_id,),
            ).fetchall()
        return [self._row_to_scope(row) for row in rows]

    def update_signature(self, tenant_id: str, engagement_id: str, signature: str) -> None:
        """Replace the stored signature for an engagement."""
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE kernel_engagements SET signature=? WHERE tenant_id=? AND id=?",
                (signature, tenant_id, engagement_id),
            )

    def delete(self, tenant_id: str, engagement_id: str) -> bool:
        """Delete an engagement; return whether a row was removed."""
        with self.store.connect() as conn:
            removed = conn.execute(
                "DELETE FROM kernel_engagements WHERE tenant_id=? AND id=?",
                (tenant_id, engagement_id),
            )
        return removed.rowcount == 1

    def load_active(self, tenant_id: str) -> EngagementScope | None:
        """Return the engagement currently inside its validity window.

        When several are active, the most recently started one wins.
        """
        now = datetime.now(timezone.utc)
        active: list[tuple[datetime, EngagementScope]] = []
        for scope in self.list_for_tenant(tenant_id):
            try:
                start = parse_iso8601(scope.valid_from)
                end = parse_iso8601(scope.valid_until)
            except ValueError:
                continue
            if start <= now <= end:
                active.append((start, scope))
        if not active:
            return None
        active.sort(key=lambda item: item[0], reverse=True)
        return active[0][1]

    @staticmethod
    def _row_to_scope(row: Any) -> EngagementScope:
        return EngagementScope.from_dict(
            {
                "engagement_id": row["id"],
                "tenant_id": row["tenant_id"],
                "name": row["name"],
                "client": row["client"],
                "owner_id": row["owner_id"],
                "valid_from": row["valid_from"],
                "valid_until": row["valid_until"],
                "cidrs": json.loads(row["cidrs"]),
                "domains": json.loads(row["domains"]),
                "urls": json.loads(row["urls"]),
                "exclusions": json.loads(row["exclusions"]),
                "notes": row["notes"],
                "signature": row["signature"],
                "created_at": row["created_at"],
            }
        )
