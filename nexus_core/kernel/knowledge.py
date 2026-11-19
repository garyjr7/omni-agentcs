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
               edges: list[tuple[str, str]] | None = None,
               supersede: list[str] | tuple[str, ...] | None = None,
               superseded_by: str = "") -> dict:
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
            if supersede and superseded_by:
                self._mark_superseded(
                    conn,
                    tenant_id=tenant_id,
                    source_uris=supersede,
                    superseded_by=superseded_by,
                    current_document_id=str(value.get("id") or ""),
                )
        return value

    @staticmethod
    def _mark_superseded(
        conn: Any,
        *,
        tenant_id: str,
        source_uris: Any,
        superseded_by: str,
        current_document_id: str,
    ) -> None:
        """Mark every older version of the superseded facts (V0-33).

        A fact document is the durable state, not an immutable artifact: the
        marker has to be visible to ``Blackboard.list_facts`` even for an old
        version whose verified flag would otherwise win the merge. Both the
        content and its digest are rewritten together so a citation never points
        at bytes the row no longer has. The document just written is the only
        row skipped, so a same-key re-record also marks its previous versions.
        """
        for uri in sorted({str(item or "").strip() for item in source_uris or ()}):
            if not uri:
                continue
            rows = conn.execute(
                """SELECT id,content FROM kernel_knowledge_documents
                WHERE tenant_id=? AND source_uri=?""",
                (tenant_id, uri),
            ).fetchall()
            for row in rows:
                if current_document_id and str(row["id"]) == current_document_id:
                    continue
                try:
                    record = json.loads(str(row["content"]))
                except (TypeError, ValueError):
                    continue
                if not isinstance(record, dict):
                    continue
                if str(record.get("superseded_by") or "") == superseded_by:
                    continue
                record["superseded_by"] = superseded_by
                content = json.dumps(record, sort_keys=True)
                digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
                conn.execute(
                    """UPDATE kernel_knowledge_documents
                    SET content=?, sha256=? WHERE id=? AND tenant_id=?""",
                    (content, digest, str(row["id"]), tenant_id),
                )

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
        """Replace the anchors of one fact with the edges just proved (V0-33).

        A fact URI is stable across re-recordings, so appending the anchors of
        the newest version used to leave the old provenance in place: a credential
        found again from another service showed both origins, and the graph
        could no longer say which one was current. When the new record carries
        anchors, the previous rows of that fact are deleted in the same
        transaction and only the new ones remain.

        An empty anchor set does **not** erase provenance: an agent re-registering
        a key the verifier already proved (V1-33) must not hide where it came
        from. Orphan sources are still dropped, and only after the surviving set
        is known - so a bad anchor never wipes a good one.
        """
        resolved: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for edge in edges:
            try:
                src_uri, relation = edge
            except (TypeError, ValueError):
                continue
            src = str(src_uri or "").strip()
            rel = " ".join(str(relation or "derived_from").split())[:80]
            if not src or src == dst_uri or (src, rel) in seen:
                continue
            exists = conn.execute(
                """SELECT 1 FROM kernel_knowledge_documents
                WHERE tenant_id=? AND source_uri=? LIMIT 1""",
                (tenant_id, src),
            ).fetchone()
            if exists is None:
                continue
            seen.add((src, rel))
            resolved.append((src, rel))
        if not resolved:
            return
        conn.execute(
            """DELETE FROM kernel_fact_edges
            WHERE tenant_id=? AND engagement_id=? AND dst_uri=?""",
            (tenant_id, engagement_id, dst_uri),
        )
        for src, rel in resolved:
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
