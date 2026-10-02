"""Durable engagement blackboard: typed facts with provenance.

The blackboard is what lets the agent *remember* an engagement across runs and
steps: hosts, services, users, credentials, access, privilege vectors and loot.
Each fact is a typed record with a source (which tool produced it) and a
``verified`` flag, so the planner can trust it instead of re-deriving it.

Storage reuses the durable ``kernel_knowledge_documents`` table (already present
in both the SQLite and PostgreSQL backends) via :class:`KnowledgeStore`, with a
``blackboard/<engagement>/<type>/<key>`` source URI. No schema change is needed.

Secrets are never stored in clear: a credential fact references where the secret
lives (its artifact) rather than embedding it.
"""

from __future__ import annotations

import json
from typing import Any

from .knowledge import KnowledgeStore
from .models import utc_now

#: Fact types the planner understands. ``key`` disambiguates within a type.
FACT_TYPES = (
    "host",
    "service",
    "endpoint",
    "user",
    "email",
    "credential",
    "access",
    "privilege",
    "vulnerability",
    "session",
    "artifact",
    "loot",
    "hint",
)

SOURCE_URI_PREFIX = "blackboard"


def _source_uri(engagement_id: str, fact_type: str, key: str) -> str:
    return f"{SOURCE_URI_PREFIX}/{engagement_id}/{fact_type}/{key}"


class Blackboard:
    """Typed, tenant-scoped fact store for one or more engagements."""

    def __init__(self, store):
        self.store = store
        self.knowledge = KnowledgeStore(store)

    def record(
        self,
        *,
        tenant_id: str,
        engagement_id: str,
        fact_type: str,
        key: str,
        value: dict[str, Any],
        source: str,
        created_by: str,
        verified: bool = True,
        classification: str = "internal",
    ) -> dict[str, Any]:
        """Persist one fact and return its normalized record."""
        if fact_type not in FACT_TYPES:
            raise ValueError(f"unsupported fact type: {fact_type!r}")
        key = str(key).strip()
        if not key:
            raise ValueError("fact key is required")
        record = {
            "engagement_id": engagement_id,
            "fact_type": fact_type,
            "key": key,
            "value": value or {},
            "source": source or "unknown",
            "verified": bool(verified),
            "recorded_at": utc_now(),
        }
        self.knowledge.ingest(
            tenant_id=tenant_id,
            title=key[:200],
            source_uri=_source_uri(engagement_id, fact_type, key),
            content=json.dumps(record, sort_keys=True),
            created_by=created_by,
            classification=classification,
            metadata={
                "engagement_id": engagement_id,
                "fact_type": fact_type,
                "key": key,
                "source": record["source"],
                "verified": record["verified"],
            },
        )
        return record

    def list_facts(
        self,
        tenant_id: str,
        engagement_id: str,
        *,
        fact_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return the latest version of each fact for an engagement."""
        if fact_type is not None and fact_type not in FACT_TYPES:
            raise ValueError(f"unsupported fact type: {fact_type!r}")
        prefix = f"{SOURCE_URI_PREFIX}/{engagement_id}/"
        if fact_type is not None:
            prefix = f"{prefix}{fact_type}/"
        with self.store.connect() as conn:
            rows = conn.execute(
                """SELECT source_uri, content, created_at
                FROM kernel_knowledge_documents
                WHERE tenant_id=? AND source_uri LIKE ?
                ORDER BY created_at DESC LIMIT ?""",
                (tenant_id, prefix + "%", min(limit, 500)),
            ).fetchall()
        # Latest wins per source_uri (a re-recorded fact creates a new row).
        latest: dict[str, dict[str, Any]] = {}
        for row in rows:
            uri = row["source_uri"]
            if uri in latest:
                continue
            try:
                latest[uri] = json.loads(row["content"])
            except (TypeError, json.JSONDecodeError):
                continue
        return list(latest.values())

    def summary(self, tenant_id: str, engagement_id: str) -> dict[str, Any]:
        """Return counts per fact type for prompt/planner consumption."""
        facts = self.list_facts(tenant_id, engagement_id)
        counts: dict[str, int] = {}
        for fact in facts:
            counts[fact["fact_type"]] = counts.get(fact["fact_type"], 0) + 1
        return {"engagement_id": engagement_id, "total": len(facts), "counts": counts}
