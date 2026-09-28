"""Content-addressed artifact storage; local now, object storage adapters later."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

from .control_store import ControlStore
from .models import utc_now


class LocalArtifactStore:
    def __init__(self, store: ControlStore, root: str | Path):
        self.store = store
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, tenant_id: str, content: bytes, media_type: str,
            run_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        digest = hashlib.sha256(content).hexdigest()
        artifact_id = f"artifact_{uuid4().hex}"
        directory = self.root / tenant_id / digest[:2]
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / digest
        if not target.exists():
            temporary = directory / f".{digest}.{uuid4().hex}.tmp"
            with temporary.open("wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        now = utc_now()
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_artifacts
                (id,tenant_id,run_id,media_type,storage_uri,sha256,size_bytes,metadata,created_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (artifact_id, tenant_id, run_id, media_type, str(target), digest,
                 len(content), json.dumps(metadata or {}), now),
            )
        return {"id": artifact_id, "sha256": digest, "size_bytes": len(content), "media_type": media_type}

    def get(self, tenant_id: str, artifact_id: str) -> bytes:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT storage_uri,sha256 FROM kernel_artifacts WHERE id=? AND tenant_id=?",
                (artifact_id, tenant_id),
            ).fetchone()
        if not row:
            raise KeyError("artifact not found")
        path = Path(row["storage_uri"]).resolve()
        if self.root not in path.parents:
            raise RuntimeError("artifact path escaped configured storage root")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != row["sha256"]:
            raise RuntimeError("artifact integrity check failed")
        return content
