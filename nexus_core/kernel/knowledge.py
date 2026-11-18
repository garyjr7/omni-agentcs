"""Tenant-scoped sovereign knowledge with verifiable citations."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import uuid4

from .models import utc_now


class KnowledgeStore:
    CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}

    def __init__(self, store):
        self.store = store

    def ingest(self, *, tenant_id: str, title: str, source_uri: str, content: str,
               created_by: str, classification: str = "internal",
               metadata: dict[str, Any] | None = None,
               engagement_id: str = "",
               edges: list[tuple[str, str]] | None = None) -> dict:
        """Store one document and, in the same transaction, its fact edges.

        ``edges`` is ``(src_uri, relation)``; the destination is this document's
        own URI. An edge whose source is not a stored document is dropped: the
        graph admits no orphans, and a verifier that names a fact the board does
        not have (a hostname instead of the scanned IP, an unverified lead) gets
        no edge instead of a dangling one.
        """
        if classification not in self.CLASSIFICATIONS:
            raise ValueError("unsupported data classification")
        if not content.strip() or not source_uri.strip():
            raise ValueError("knowledge content and source URI are required")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        document = {"id": f"document_{uuid4().hex}", "tenant_id": tenant_id,
                    "title": title[:200], "source_uri": source_uri,
                    "sha256": digest, "classification": classification,
                    "metadata": metadata or {}, "created_by": created_by,
                    "created_at": utc_now()}
        with self.store.connect() as conn:
            existing = conn.execute(
                """SELECT * FROM kernel_knowledge_documents
                WHERE tenant_id=? AND source_uri=? AND sha256=?""",
                (tenant_id, source_uri, digest),
            ).fetchone()
            if existing:
                value = dict(existing)
                value["metadata"] = json.loads(value["metadata"])
                value.pop("content", None)
            else:
                conn.execute(
                    """INSERT INTO kernel_knowledge_documents
                    (id,tenant_id,title,source_uri,content,sha256,classification,metadata,
                     created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (document["id"], tenant_id, document["title"], source_uri, content,
                     digest, classification, json.dumps(document["metadata"]),
                     created_by, document["created_at"]),
                )
                value = document
            self._record_edges(
                conn,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                dst_uri=source_uri,
                edges=edges or (),
                created_at=str(document["created_at"]),
            )
        return value

    @staticmethod
    def _record_edges(
        conn: Any,
        *,
        tenant_id: str,
        engagement_id: str,
        dst_uri: str,
        edges: Any,
        created_at: str,
    ) -> None:
        """Insert the anchors that point at an existing fact (no orphans)."""
        for edge in edges:
            try:
                src_uri, relation = edge
            except (TypeError, ValueError):
                continue
            src = str(src_uri or "").strip()
            rel = " ".join(str(relation or "derived_from").split())[:80]
            if not src or src == dst_uri:
                continue
            exists = conn.execute(
                """SELECT 1 FROM kernel_knowledge_documents
                WHERE tenant_id=? AND source_uri=? LIMIT 1""",
                (tenant_id, src),
            ).fetchone()
            if exists is None:
                continue
            conn.execute(
                """INSERT OR IGNORE INTO kernel_fact_edges
                (id,tenant_id,engagement_id,src_uri,dst_uri,relation,created_at)
                VALUES(?,?,?,?,?,?,?)""",
                (f"edge_{uuid4().hex}", tenant_id, engagement_id, src, dst_uri,
                 rel, created_at),
            )

    def search(self, tenant_id: str, query: str, *, allowed_classifications: set[str],
               limit: int = 10) -> list[dict]:
        allowed = sorted(self.CLASSIFICATIONS.intersection(allowed_classifications))
        if not allowed:
            return []
        placeholders = ",".join("?" for _ in allowed)
        params: list[Any] = [tenant_id, *allowed, f"%{query}%", f"%{query}%", min(limit, 50)]
        with self.store.connect() as conn:
            rows = conn.execute(
                f"""SELECT id,title,source_uri,sha256,classification,
                substr(content,1,1000) AS excerpt,created_at
                FROM kernel_knowledge_documents WHERE tenant_id=?
                AND classification IN ({placeholders}) AND (title LIKE ? OR content LIKE ?)
                ORDER BY created_at DESC LIMIT ?""", tuple(params),
            ).fetchall()
        return [{**dict(row), "citation": {"document_id": row["id"],
                 "source_uri": row["source_uri"], "sha256": row["sha256"]}}
                for row in rows]
