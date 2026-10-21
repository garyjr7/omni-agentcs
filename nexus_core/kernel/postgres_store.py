"""PostgreSQL implementation of the NEXUS durable control store."""

from __future__ import annotations

import re
from types import TracebackType
from typing import TYPE_CHECKING, Any, Sequence

from .control_store import SCHEMA, ControlStore
from .database import DatabaseConnection
from .models import utc_now

if TYPE_CHECKING:
    from psycopg import Connection, Cursor


class _PostgresConnection:
    def __init__(self, connection: Connection[dict[str, Any]]) -> None:
        self.connection = connection

    @staticmethod
    def _query(sql: str) -> str:
        sql = sql.replace("BEGIN IMMEDIATE", "BEGIN")
        ignored = bool(re.search(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", sql, re.IGNORECASE))
        sql = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", sql, flags=re.IGNORECASE)
        sql = sql.replace("?", "%s")
        if ignored:
            sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
        return sql

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Cursor[dict[str, Any]]:
        return self.connection.execute(self._query(sql), params)

    def executescript(self, sql: str) -> Cursor[dict[str, Any]]:
        return self.connection.execute(sql)

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> _PostgresConnection:
        self.connection.__enter__()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None,
        exc: BaseException | None, traceback: TracebackType | None,
    ) -> None:
        return self.connection.__exit__(exc_type, exc, traceback)


class PostgresControlStore(ControlStore):
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.path = None

    def connect(self) -> _PostgresConnection:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("psycopg is required for PostgreSQL control store") from exc
        return _PostgresConnection(
            psycopg.connect(self.database_url, row_factory=dict_row)
        )

    def _lock_transaction(self, conn: DatabaseConnection, key: str) -> None:
        # READ COMMITTED gives reads *after* a lock wait a fresh snapshot.
        # ON CONFLICT also serializes concurrent creation of the first lock row.
        conn.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        conn.execute(
            "INSERT INTO kernel_transaction_locks(lock_key) VALUES(?) "
            "ON CONFLICT(lock_key) DO NOTHING", (key,),
        )
        conn.execute(
            "SELECT lock_key FROM kernel_transaction_locks WHERE lock_key=? FOR UPDATE",
            (key,),
        )

    @property
    def active_lease_sql(self) -> str:
        return "CAST(lease_until AS TIMESTAMPTZ) > clock_timestamp()"

    @property
    def task_row_lock_sql(self) -> str:
        return " FOR UPDATE"

    def initialize(self) -> None:
        schema = SCHEMA.replace(
            "sequence INTEGER PRIMARY KEY AUTOINCREMENT",
            "sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY",
        )
        with self.connect() as conn:
            conn.executescript(schema)
            conn.execute(
                "ALTER TABLE kernel_approvals ADD COLUMN IF NOT EXISTS consumed_at TEXT"
            )
            conn.execute(
                "ALTER TABLE kernel_tasks ADD COLUMN IF NOT EXISTS "
                "lease_generation BIGINT NOT NULL DEFAULT 0"
            )
            conn.execute(
                "ALTER TABLE kernel_sessions ADD COLUMN IF NOT EXISTS "
                "transport TEXT NOT NULL DEFAULT 'msf'"
            )
            conn.execute(
                "ALTER TABLE kernel_sessions ADD COLUMN IF NOT EXISTS transport_ref TEXT"
            )
            conn.execute(
                "ALTER TABLE kernel_sessions ADD COLUMN IF NOT EXISTS liveness TEXT"
            )
            # Same backfill as SQLite: pre-P1 rows only carried ``session_type``.
            for transport, session_type in (
                ("sliver", "sliver:%"), ("webshell", "webshell"),
                ("pty", "pty"), ("raw", "raw"), ("raw", "listener:raw"),
                ("pty", "listener:pty"),
            ):
                if session_type.endswith("%"):
                    conn.execute(
                        "UPDATE kernel_sessions SET transport=? "
                        "WHERE transport='msf' AND session_type LIKE ?",
                        (transport, session_type),
                    )
                else:
                    conn.execute(
                        "UPDATE kernel_sessions SET transport=? "
                        "WHERE transport='msf' AND session_type=?",
                        (transport, session_type),
                    )
            conn.execute(
                """INSERT INTO kernel_tenants(id,name,created_at) VALUES(?,?,?)
                ON CONFLICT(id) DO NOTHING""",
                ("system", "NEXUS System", utc_now()),
            )

    def migrate_legacy_users(self) -> int:
        return 0
