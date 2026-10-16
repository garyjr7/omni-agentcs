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
from typing import Any, Literal, TypedDict

from .knowledge import KnowledgeStore
from .serialization import sanitized_object
from .redaction import sanitize_text
from .models import utc_now

#: Fact types the planner understands. ``key`` disambiguates within a type.
FACT_TYPES = (
    "host",
    "service",
    "web_app",
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

#: Safety ceiling on the rows one engagement's fact merge will scan. Each fact
#: maps to one row per distinct content (a re-record adds a row, an identical
#: re-record is deduplicated by ``KnowledgeStore.ingest``), so an engagement
#: reaches this only after thousands of distinct re-writes.
FACT_ROWS_CEILING = 10_000


def _source_uri(engagement_id: str, fact_type: str, key: str) -> str:
    return f"{SOURCE_URI_PREFIX}/{engagement_id}/{fact_type}/{key}"


class Fact(TypedDict):
    fact_type: str
    key: str
    value: dict[str, Any]
    asserted_by: Literal["agent", "verifier"]
    verified: bool
    verification_method: str
    invocation_id: str


def is_verified_fact(fact):
    """Legacy flags without verifier provenance are never trusted."""
    return (isinstance(fact, dict) and fact.get("verified") is True
            and fact.get("asserted_by") == "verifier"
            and bool(fact.get("verification_method")) and bool(fact.get("invocation_id")))


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
        verified: bool = False,
        asserted_by: Literal["agent", "verifier"] = "agent",
        verification_method: str = "",
        invocation_id: str = "",
        classification: str = "internal",
    ) -> dict[str, Any]:
        """Persist one fact and return its normalized record."""
        if fact_type not in FACT_TYPES:
            raise ValueError(f"unsupported fact type: {fact_type!r}")
        key = sanitize_text(str(key).strip())
        engagement_id = sanitize_text(engagement_id)
        if not key:
            raise ValueError("fact key is required")
        if asserted_by not in {"agent", "verifier"}:
            raise ValueError("invalid fact provenance")
        if verified and (asserted_by != "verifier" or not verification_method or not invocation_id):
            raise ValueError("verified facts require verifier, method and invocation_id")
        record = {
            "engagement_id": engagement_id,
            "fact_type": fact_type,
            "key": key,
            "value": value or {},
            "source": source or "unknown",
            "verified": bool(verified),
            "asserted_by": asserted_by,
            "verification_method": verification_method,
            "invocation_id": invocation_id,
            "recorded_at": utc_now(),
        }
        record = sanitized_object(record)
        self.knowledge.ingest(
            tenant_id=tenant_id,
            title=key[:200],
            source_uri=_source_uri(engagement_id, fact_type, key),
            content=json.dumps(record, sort_keys=True),
            created_by=sanitize_text(created_by),
            classification=sanitize_text(classification),
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
        """Return one version of each fact for an engagement.

        A re-recorded fact creates a new row, so several rows share one
        ``source_uri`` and this is the *single* merge point of the blackboard.
        The rule is **verified wins over unverified, regardless of recency; only
        between facts of the same provenance does the latest row win**: a fact
        the engine proved (verifier + method + invocation) can never be shadowed
        by a later re-registration of the same key by the agent.

        Measured in rerun 9 (``run_8f23f9…``): the verifier wrote the validated
        credential ``cred:ssh:lin@10.0.0.1`` (``verified=true``) and the
        agent re-registered the same key one iteration later (``verified=false``,
        ``asserted_by=agent``); the old "latest wins per source_uri" rule let the
        agent's row shadow the verified one, ``is_verified_fact`` stopped
        recognising the credential, ``active_phase`` reopened ``enumeration`` and
        the plan regressed ``[2,6] → [1,6]``. See V1-33.
        """
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
                (tenant_id, prefix + "%", FACT_ROWS_CEILING),
            ).fetchall()
        # Newest row per source_uri, then overridden by the newest *verified* row
        # when one exists (rows arrive newest-first, so the first hit per bucket
        # is the latest of that provenance).
        latest: dict[str, dict[str, Any]] = {}
        verified: dict[str, dict[str, Any]] = {}
        for row in rows:
            uri = row["source_uri"]
            if uri in verified:
                continue
            try:
                fact = sanitized_object(json.loads(row["content"]))
            except (TypeError, ValueError, RecursionError):
                continue
            latest.setdefault(uri, fact)
            if is_verified_fact(fact):
                verified[uri] = fact
        merged = {**latest, **verified}
        return list(merged.values())[: max(1, min(int(limit), 500))]

    def verified_fact(
        self,
        tenant_id: str,
        engagement_id: str,
        *,
        fact_type: str,
        key: str,
    ) -> dict[str, Any] | None:
        """Return the verified fact for ``(fact_type, key)``, else ``None``.

        Used by ``nexus.knowledge.record_fact`` to tell the model that the key it
        is about to register already carries an engine-proven fact (V1-33): the
        registration is still accepted -the agent is never blocked- but it can
        never override what the verifier attested.
        """
        wanted = sanitize_text(str(key).strip())
        if not wanted:
            return None
        for fact in self.list_facts(tenant_id, engagement_id, fact_type=fact_type):
            if is_verified_fact(fact) and str(fact.get("key") or "") == wanted:
                return fact
        return None

    def count(self, tenant_id: str, engagement_id: str) -> int:
        """Number of distinct facts recorded for an engagement (cheap)."""
        prefix = f"{SOURCE_URI_PREFIX}/{engagement_id}/%"
        with self.store.connect() as conn:
            row = conn.execute(
                """SELECT COUNT(DISTINCT source_uri) AS n
                FROM kernel_knowledge_documents
                WHERE tenant_id=? AND source_uri LIKE ?""",
                (tenant_id, prefix),
            ).fetchone()
        return int(row["n"]) if row is not None else 0

    def render(self, tenant_id: str, engagement_id: str, *, limit: int = 40) -> str:
        """Render a compact, prompt-ready list of facts ('' when empty)."""
        facts = self.list_facts(tenant_id, engagement_id, limit=limit)
        if not facts:
            return ""
        lines: list[str] = []
        for fact in facts:
            value = json.dumps(fact.get("value") or {}, sort_keys=True)
            if len(value) > 200:
                value = value[:197] + "..."
            mark = "verificado" if is_verified_fact(fact) else "sin verificar"
            source = fact.get("source", "?")
            lines.append(
                f"- [{fact['fact_type']}] {fact['key']} ({mark}, via {source}): {value}"
            )
        return "\n".join(lines)

    def summary(self, tenant_id: str, engagement_id: str) -> dict[str, Any]:
        """Return counts per fact type for prompt/planner consumption.

        ``counts`` holds only verified facts (the evidence a parser attested, the
        only thing that can advance a phase). ``leads`` holds the agent-recorded,
        unverified facts: they never count as evidence, but they tell the profile
        selector which service is worth testing next - without them a discovered
        ``user`` never reaches the credential profile and the chain dead-ends in
        enumeration.
        """
        facts = self.list_facts(tenant_id, engagement_id)
        counts: dict[str, int] = {}
        leads: dict[str, int] = {}
        for fact in facts:
            bucket = counts if is_verified_fact(fact) else leads
            bucket[fact["fact_type"]] = bucket.get(fact["fact_type"], 0) + 1
        return {
            "engagement_id": engagement_id,
            "total": len(facts),
            "counts": counts,
            "leads": leads,
        }
