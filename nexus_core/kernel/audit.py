"""Append-only, hash-chained audit writer."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict
from uuid import uuid4

from .control_store import ControlStore
from .models import utc_now


class AuditWriter:
    def __init__(self, store: ControlStore):
        self.store = store

    def append(
        self,
        *,
        tenant_id: str,
        trace_id: str,
        actor_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: Dict[str, Any],
        decision: str | None = None,
    ) -> str:
        event_id = f"audit_{uuid4().hex}"
        created_at = utc_now()
        sanitized = self._sanitize(payload)
        with self.store.connect() as conn:
            previous = conn.execute(
                "SELECT event_hash FROM kernel_audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous["event_hash"] if previous else ""
            canonical = json.dumps({
                "event_id": event_id,
                "tenant_id": tenant_id,
                "trace_id": trace_id,
                "actor_id": actor_id,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "decision": decision,
                "payload": sanitized,
                "previous_hash": previous_hash,
                "created_at": created_at,
            }, sort_keys=True, separators=(",", ":"))
            event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            conn.execute(
                """INSERT INTO kernel_audit_events
                (event_id,tenant_id,trace_id,actor_id,action,resource_type,resource_id,
                 decision,payload,previous_hash,event_hash,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (event_id, tenant_id, trace_id, actor_id, action, resource_type,
                 resource_id, decision, json.dumps(sanitized, sort_keys=True),
                 previous_hash, event_hash, created_at),
            )
        return event_id

    def export(self, tenant_id: str, *, trace_id: str | None = None,
               run_id: str | None = None) -> list[Dict[str, Any]]:
        clauses = ["tenant_id=?"]
        params: list[Any] = [tenant_id]
        if trace_id:
            clauses.append("trace_id=?")
            params.append(trace_id)
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM kernel_audit_events WHERE " + " AND ".join(clauses) + " ORDER BY sequence",
                tuple(params),
            ).fetchall()
        values = []
        for row in rows:
            value = dict(row)
            value["payload"] = json.loads(value["payload"])
            if run_id and value["payload"].get("run_id") != run_id:
                continue
            values.append(value)
        return values

    def verify_chain(self) -> tuple[bool, int | None]:
        """Verify the global append chain; return the first corrupt sequence."""
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM kernel_audit_events ORDER BY sequence"
            ).fetchall()
        previous_hash = ""
        for row in rows:
            value = dict(row)
            canonical = json.dumps({
                "event_id": value["event_id"], "tenant_id": value["tenant_id"],
                "trace_id": value["trace_id"], "actor_id": value["actor_id"],
                "action": value["action"], "resource_type": value["resource_type"],
                "resource_id": value["resource_id"], "decision": value["decision"],
                "payload": json.loads(value["payload"]), "previous_hash": previous_hash,
                "created_at": value["created_at"],
            }, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if value["previous_hash"] != previous_hash or not hmac.compare_digest(value["event_hash"], expected):
                return False, value["sequence"]
            previous_hash = value["event_hash"]
        return True, None

    #: Field names whose values are always credentials and must never be
    #: persisted in cleartext. The criterion is the *field name*, not the
    #: value, so integrity digests (``content_sha256``, ``raw_sha256``,
    #: ``event_hash``) are deliberately absent from this set. In AD/impacket
    #: contexts a ``hash`` can authenticate via pass-the-hash, so it is treated
    #: like a password.
    SECRET_TERMS = frozenset({
        "password", "passwd", "pwd", "secret", "token",
        "api_key", "apikey", "authorization", "auth",
        "hash", "hashes", "ntlm_hash", "lm_hash", "nthash",
        "password_hash", "credential", "credentials",
        "private_key", "privatekey", "ssh_key", "sshkey",
        "bearer", "cookie", "session_id",
    })

    @classmethod
    def _sanitize(cls, value: Any) -> Any:
        secret_terms = cls.SECRET_TERMS
        if isinstance(value, dict):
            return {
                key: "[REDACTED]" if key.lower() in secret_terms else cls._sanitize(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._sanitize(item) for item in value]
        return value
