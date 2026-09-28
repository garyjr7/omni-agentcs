"""Connector enrollment and revocation service using one-time bootstrap tokens."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable
from uuid import uuid4

from .control_store import ControlStore
from .models import utc_now


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ConnectorRegistry:
    def __init__(self, store: ControlStore):
        self.store = store

    def create_enrollment_token(
        self, tenant_id: str, created_by: str, ttl_minutes: int = 10
    ) -> str:
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)).isoformat()
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO connector_enrollment_tokens
                (token_hash,tenant_id,expires_at,created_by,created_at) VALUES(?,?,?,?,?)""",
                (digest(token), tenant_id, expires_at, created_by, utc_now()),
            )
        return token

    def enroll(
        self,
        enrollment_token: str,
        *,
        name: str,
        device_id: str,
        capabilities: Iterable[str],
        allowed_roots: Iterable[str],
        certificate_fingerprint: str | None = None,
    ) -> Dict[str, Any]:
        now = utc_now()
        connector_id = f"connector_{uuid4().hex}"
        credential = secrets.token_urlsafe(48)
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """SELECT tenant_id FROM connector_enrollment_tokens
                WHERE token_hash=? AND used_at IS NULL AND expires_at>?""",
                (digest(enrollment_token), now),
            ).fetchone()
            if not row:
                raise PermissionError("invalid or expired enrollment token")
            conn.execute(
                "UPDATE connector_enrollment_tokens SET used_at=? WHERE token_hash=?",
                (now, digest(enrollment_token)),
            )
            conn.execute(
                """INSERT INTO kernel_connectors
                (id,tenant_id,name,device_id,credential_hash,status,capabilities,
                 allowed_roots,certificate_fingerprint,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (connector_id, row["tenant_id"], name, device_id, digest(credential),
                 "active", json.dumps(sorted(set(capabilities))),
                 json.dumps(sorted(set(allowed_roots))), certificate_fingerprint, now),
            )
        return {"connector_id": connector_id, "credential": credential, "tenant_id": row["tenant_id"]}

    def authenticate(self, connector_id: str, credential: str,
                     certificate_fingerprint: str | None = None) -> Dict[str, Any]:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM kernel_connectors WHERE id=? AND status='active'",
                (connector_id,),
            ).fetchone()
        if not row or not hmac.compare_digest(row["credential_hash"], digest(credential)):
            raise PermissionError("invalid connector credential")
        if row["certificate_fingerprint"] and not hmac.compare_digest(
            row["certificate_fingerprint"], certificate_fingerprint or ""
        ):
            raise PermissionError("connector certificate does not match enrollment")
        value = dict(row)
        value["capabilities"] = json.loads(value["capabilities"])
        value["allowed_roots"] = json.loads(value["allowed_roots"])
        value.pop("credential_hash", None)
        return value

    def heartbeat(self, connector_id: str, credential: str,
                  certificate_fingerprint: str | None = None) -> Dict[str, Any]:
        connector = self.authenticate(connector_id, credential, certificate_fingerprint)
        now = utc_now()
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE kernel_connectors SET last_seen_at=? WHERE id=?", (now, connector_id)
            )
        connector["last_seen_at"] = now
        return connector

    def rotate_credential(self, connector_id: str, credential: str,
                          certificate_fingerprint: str | None = None) -> str:
        self.authenticate(connector_id, credential, certificate_fingerprint)
        replacement = secrets.token_urlsafe(48)
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE kernel_connectors SET credential_hash=?,credential_rotated_at=? WHERE id=?",
                (digest(replacement), utc_now(), connector_id),
            )
        return replacement

    def revoke(self, connector_id: str, tenant_id: str | None = None) -> None:
        now = utc_now()
        with self.store.connect() as conn:
            if tenant_id and tenant_id != "system":
                updated = conn.execute(
                    """UPDATE kernel_connectors SET status='revoked',revoked_at=?
                    WHERE id=? AND tenant_id=?""",
                    (now, connector_id, tenant_id),
                )
            else:
                updated = conn.execute(
                    "UPDATE kernel_connectors SET status='revoked',revoked_at=? WHERE id=?",
                    (now, connector_id),
                )
            if updated.rowcount != 1:
                raise KeyError("connector not found in tenant")
