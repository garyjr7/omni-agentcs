"""Durable report queries; no capability interpretation or rendering."""

from __future__ import annotations
import json
from typing import Any
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.blackboard import Blackboard


def _load_events(store: Any, tenant_id: str) -> list[dict[str, Any]]:
    try:
        return list(AuditWriter(store).export(tenant_id))
    except Exception:  # noqa: BLE001 - a report is better than an exception
        return []


def _load_messages(store: Any, tenant_id: str) -> list[dict[str, Any]]:
    """Read every conversation message of the tenant, oldest first."""
    try:
        with store.connect() as conn:
            rows = conn.execute(
                """
                SELECT m.sequence, m.id, m.run_id, m.role, m.content, m.metadata,
                       m.created_at
                FROM kernel_messages m
                JOIN kernel_conversations c ON c.id = m.conversation_id
                WHERE m.tenant_id=? AND c.status!='deleted'
                ORDER BY m.sequence
                """,
                (tenant_id,),
            ).fetchall()
    except Exception:  # noqa: BLE001
        return []
    values = []
    for row in rows:
        value = dict(row)
        try:
            value["metadata"] = json.loads(value.get("metadata") or "{}")
        except (TypeError, ValueError):
            value["metadata"] = {}
        values.append(value)
    return values


def _load_runs(store: Any, tenant_id: str) -> list[dict[str, Any]]:
    """Read the runs of the tenant, oldest first (never raises).

    ``kernel_runs.context`` is where the CLI records the engagement a run was
    launched for (``{"source": "omni-headless", "engagement_id": "eng-…"}``), so
    it is the authoritative engagement-to-runs mapping a report needs (V1-42).
    """
    try:
        with store.connect() as conn:
            rows = conn.execute(
                """SELECT id, context, result, created_at, updated_at
                FROM kernel_runs WHERE tenant_id=? ORDER BY created_at""",
                (tenant_id,),
            ).fetchall()
    except Exception:  # noqa: BLE001 - a report is better than an exception
        return []
    values: list[dict[str, Any]] = []
    for row in rows:
        value = dict(row)
        value["run_id"] = str(value.get("id") or "")
        for key in ("context", "result"):
            raw = value.get(key)
            if isinstance(raw, str):
                try:
                    value[key] = json.loads(raw or "{}")
                except (TypeError, ValueError):
                    value[key] = {}
            elif not isinstance(raw, dict):
                value[key] = {}
        values.append(value)
    return values


def _load_artifacts(store: Any, tenant_id: str) -> list[dict[str, Any]]:
    try:
        with store.connect() as conn:
            rows = conn.execute(
                """SELECT id, run_id, media_type, sha256, size_bytes, created_at
                FROM kernel_artifacts WHERE tenant_id=? ORDER BY created_at""",
                (tenant_id,),
            ).fetchall()
    except Exception:  # noqa: BLE001
        return []
    return [dict(row) for row in rows]


def _load_facts(store: Any, tenant_id: str, engagement_id: str) -> list[dict[str, Any]]:
    """Read the engagement blackboard (never raises: facts are best-effort)."""
    try:
        return list(Blackboard(store).list_facts(tenant_id, engagement_id, limit=500))
    except Exception:  # noqa: BLE001 - a broken blackboard must not fail a report
        return []


class ReportRepository:
    def __init__(self, store: Any) -> None:
        self.store = store

    def events(self, tenant_id: str) -> list[dict[str, Any]]:
        return _load_events(self.store, tenant_id)

    def messages(self, tenant_id: str) -> list[dict[str, Any]]:
        return _load_messages(self.store, tenant_id)

    def runs(self, tenant_id: str) -> list[dict[str, Any]]:
        return _load_runs(self.store, tenant_id)

    def artifacts(self, tenant_id: str) -> list[dict[str, Any]]:
        return _load_artifacts(self.store, tenant_id)

    def facts(self, tenant_id: str, engagement_id: str) -> list[dict[str, Any]]:
        return _load_facts(self.store, tenant_id, engagement_id)
