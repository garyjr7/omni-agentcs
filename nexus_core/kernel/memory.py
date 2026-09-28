"""Tenant-scoped durable memory and knowledge records.

This store deliberately uses lexical search. A future vector backend is an
optional index, never the source of truth, so offline and private deployments
remain fully functional.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from .models import utc_now


class MemoryStore:
    def __init__(self, store):
        self.store = store

    def save_message(self, tenant_id: str, agent_id: str, agent_name: str,
                     role: str, content: str, session_id: str | None = None,
                     classification: str = "internal",
                     retention_days: int | None = None) -> str:
        if not content.strip():
            raise ValueError("memory content cannot be empty")
        expires_at = None
        if retention_days is not None:
            if retention_days < 1:
                raise ValueError("retention_days must be positive")
            expires_at = (datetime.now(timezone.utc) + timedelta(days=retention_days)).isoformat()
        memory_id = f"mem_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_memories
                (id,tenant_id,agent_id,agent_name,session_id,role,content,
                 classification,tokens_est,expires_at,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (memory_id, tenant_id, agent_id, agent_name, session_id, role,
                 content, classification, int(len(content.split()) * 1.3),
                 expires_at, utc_now()),
            )
        return memory_id

    def context(self, tenant_id: str, agent_id: str, session_id: str | None = None,
                limit: int = 20) -> list[dict]:
        params: list[object] = [tenant_id, agent_id, utc_now()]
        session = ""
        if session_id is not None:
            session = " AND session_id=?"
            params.append(session_id)
        params.append(limit)
        with self.store.connect() as conn:
            rows = conn.execute(
                f"""SELECT id,role,content,session_id,classification,created_at
                FROM kernel_memories WHERE tenant_id=? AND agent_id=?
                AND (expires_at IS NULL OR expires_at>?) {session}
                ORDER BY created_at DESC LIMIT ?""",
                tuple(params),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def search(self, tenant_id: str, agent_id: str, query: str,
               limit: int = 10) -> list[dict]:
        with self.store.connect() as conn:
            rows = conn.execute(
                """SELECT id,role,content,session_id,classification,created_at
                FROM kernel_memories WHERE tenant_id=? AND agent_id=?
                AND (expires_at IS NULL OR expires_at>?) AND content LIKE ?
                ORDER BY created_at DESC LIMIT ?""",
                (tenant_id, agent_id, utc_now(), f"%{query}%", limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def save_summary(self, tenant_id: str, agent_id: str, summary: str,
                     session_id: str | None = None, msg_count: int = 0,
                     classification: str = "internal") -> str:
        summary_id = f"summary_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_memory_summaries
                (id,tenant_id,agent_id,session_id,summary,msg_count,
                 classification,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                (summary_id, tenant_id, agent_id, session_id, summary, msg_count,
                 classification, None, utc_now()),
            )
        return summary_id

    def summary(self, tenant_id: str, agent_id: str,
                session_id: str | None = None) -> str | None:
        clause = " AND session_id=?" if session_id is not None else ""
        params = [tenant_id, agent_id, utc_now()]
        if session_id is not None:
            params.append(session_id)
        with self.store.connect() as conn:
            row = conn.execute(
                f"""SELECT summary FROM kernel_memory_summaries
                WHERE tenant_id=? AND agent_id=?
                AND (expires_at IS NULL OR expires_at>?) {clause}
                ORDER BY created_at DESC LIMIT 1""", tuple(params),
            ).fetchone()
        return row["summary"] if row else None

    def clear(self, tenant_id: str, agent_id: str,
              session_id: str | None = None) -> int:
        clause = " AND session_id=?" if session_id is not None else ""
        params: tuple[object, ...] = (tenant_id, agent_id)
        if session_id is not None:
            params += (session_id,)
        with self.store.connect() as conn:
            cursor = conn.execute(
                f"DELETE FROM kernel_memories WHERE tenant_id=? AND agent_id=?{clause}",
                params,
            )
            conn.execute(
                f"DELETE FROM kernel_memory_summaries WHERE tenant_id=? AND agent_id=?{clause}",
                params,
            )
            return cursor.rowcount

    def purge_expired(self, tenant_id: str) -> int:
        with self.store.connect() as conn:
            cursor = conn.execute(
                "DELETE FROM kernel_memories WHERE tenant_id=? AND expires_at<=?",
                (tenant_id, utc_now()),
            )
            conn.execute(
                "DELETE FROM kernel_memory_summaries WHERE tenant_id=? AND expires_at<=?",
                (tenant_id, utc_now()),
            )
            return cursor.rowcount

    def agents(self, tenant_id: str) -> list[dict]:
        with self.store.connect() as conn:
            rows = conn.execute(
                """SELECT agent_id,MAX(agent_name) AS agent_name,COUNT(*) AS total_msgs,
                SUM(tokens_est) AS total_tokens,MAX(created_at) AS last_activity
                FROM kernel_memories WHERE tenant_id=?
                AND (expires_at IS NULL OR expires_at>?) GROUP BY agent_id
                ORDER BY last_activity DESC""", (tenant_id, utc_now()),
            ).fetchall()
        return [dict(row) for row in rows]

    def stats(self, tenant_id: str, agent_id: str) -> dict:
        with self.store.connect() as conn:
            total = conn.execute(
                """SELECT COUNT(*) AS total_messages,
                COALESCE(SUM(tokens_est),0) AS total_tokens_est
                FROM kernel_memories WHERE tenant_id=? AND agent_id=?
                AND (expires_at IS NULL OR expires_at>?)""",
                (tenant_id, agent_id, utc_now()),
            ).fetchone()
        return dict(total)
