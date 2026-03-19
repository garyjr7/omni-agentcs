import os, sqlite3, json, logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("nexus.memory")

def _db_path():
    return os.getenv("NEXUS_DB_PATH",
        str(Path(__file__).parent.parent.parent / "data" / "nexus_pro.db"))

def _get_conn():
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    return conn

def init_memory_table():
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_memory (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id   TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                session_id TEXT,
                role       TEXT NOT NULL,
                content    TEXT NOT NULL,
                summary    TEXT,
                tokens_est INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS memory_summaries (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id   TEXT NOT NULL,
                session_id TEXT,
                summary    TEXT NOT NULL,
                msg_count  INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mem_agent ON agent_memory(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mem_session ON agent_memory(session_id)")
        conn.commit()

def save_message(agent_id: str, agent_name: str, role: str,
                 content: str, session_id: str = None) -> int:
    tokens_est = len(content.split()) * 1.3
    with _get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO agent_memory
               (agent_id, agent_name, session_id, role, content, tokens_est)
               VALUES (?,?,?,?,?,?)""",
            (agent_id, agent_name, session_id, role, content, int(tokens_est))
        )
        conn.commit()
        return cur.lastrowid

def get_context(agent_id: str, session_id: str = None,
                limit: int = 20) -> list:
    """Obtiene las últimas N interacciones del agente."""
    with _get_conn() as conn:
        if session_id:
            rows = conn.execute(
                """SELECT role, content, created_at FROM agent_memory
                   WHERE agent_id=? AND session_id=?
                   ORDER BY id DESC LIMIT ?""",
                (agent_id, session_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT role, content, created_at FROM agent_memory
                   WHERE agent_id=?
                   ORDER BY id DESC LIMIT ?""",
                (agent_id, limit)
            ).fetchall()
        return [dict(r) for r in reversed(rows)]

def get_summary(agent_id: str, session_id: str = None) -> Optional[str]:
    """Obtiene el último resumen de contexto."""
    with _get_conn() as conn:
        if session_id:
            row = conn.execute(
                """SELECT summary FROM memory_summaries
                   WHERE agent_id=? AND session_id=?
                   ORDER BY id DESC LIMIT 1""",
                (agent_id, session_id)
            ).fetchone()
        else:
            row = conn.execute(
                """SELECT summary FROM memory_summaries
                   WHERE agent_id=?
                   ORDER BY id DESC LIMIT 1""",
                (agent_id,)
            ).fetchone()
        return row["summary"] if row else None

def save_summary(agent_id: str, summary: str,
                 session_id: str = None, msg_count: int = 0):
    with _get_conn() as conn:
        conn.execute(
            """INSERT INTO memory_summaries
               (agent_id, session_id, summary, msg_count)
               VALUES (?,?,?,?)""",
            (agent_id, session_id, summary, msg_count)
        )
        conn.commit()

def get_agent_stats(agent_id: str) -> dict:
    with _get_conn() as conn:
        total = conn.execute(
            "SELECT COUNT(*) as c, SUM(tokens_est) as t FROM agent_memory WHERE agent_id=?",
            (agent_id,)
        ).fetchone()
        sessions = conn.execute(
            """SELECT session_id, COUNT(*) as msgs, MAX(created_at) as last
               FROM agent_memory WHERE agent_id=? AND session_id IS NOT NULL
               GROUP BY session_id ORDER BY last DESC LIMIT 10""",
            (agent_id,)
        ).fetchall()
        return {
            "total_messages": total["c"] or 0,
            "total_tokens_est": int(total["t"] or 0),
            "sessions": [dict(s) for s in sessions]
        }

def list_agents_with_memory() -> list:
    with _get_conn() as conn:
        rows = conn.execute(
            """SELECT agent_id, agent_name,
                      COUNT(*) as total_msgs,
                      SUM(tokens_est) as total_tokens,
                      MAX(created_at) as last_activity
               FROM agent_memory
               GROUP BY agent_id
               ORDER BY last_activity DESC"""
        ).fetchall()
        return [dict(r) for r in rows]

def clear_agent_memory(agent_id: str, session_id: str = None) -> int:
    with _get_conn() as conn:
        if session_id:
            cur = conn.execute(
                "DELETE FROM agent_memory WHERE agent_id=? AND session_id=?",
                (agent_id, session_id)
            )
        else:
            cur = conn.execute(
                "DELETE FROM agent_memory WHERE agent_id=?", (agent_id,)
            )
        conn.commit()
        return cur.rowcount

def search_memory(agent_id: str, query: str, limit: int = 10) -> list:
    """Búsqueda simple por contenido."""
    with _get_conn() as conn:
        rows = conn.execute(
            """SELECT role, content, session_id, created_at
               FROM agent_memory
               WHERE agent_id=? AND content LIKE ?
               ORDER BY id DESC LIMIT ?""",
            (agent_id, f"%{query}%", limit)
        ).fetchall()
        return [dict(r) for r in rows]
