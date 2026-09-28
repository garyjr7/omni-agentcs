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
               metadata: dict[str, Any] | None = None) -> dict:
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
                return value
            conn.execute(
                """INSERT INTO kernel_knowledge_documents
                (id,tenant_id,title,source_uri,content,sha256,classification,metadata,
                 created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (document["id"], tenant_id, document["title"], source_uri, content,
                 digest, classification, json.dumps(document["metadata"]),
                 created_by, document["created_at"]),
            )
        return document

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
