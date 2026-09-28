"""PostgreSQL implementation of the NEXUS durable control store."""

from __future__ import annotations

import re

from .control_store import SCHEMA, ControlStore
from .models import utc_now


class _PostgresConnection:
    def __init__(self, connection):
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

    def execute(self, sql: str, params=()):
        return self.connection.execute(self._query(sql), params)

    def executescript(self, sql: str):
        return self.connection.execute(sql)

    def __enter__(self):
        self.connection.__enter__()
        return self

    def __exit__(self, exc_type, exc, traceback):
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

    def initialize(self) -> None:
        schema = SCHEMA.replace(
            "sequence INTEGER PRIMARY KEY AUTOINCREMENT",
            "sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY",
        )
        with self.connect() as conn:
            conn.executescript(schema)
            conn.execute(
                """INSERT INTO kernel_tenants(id,name,created_at) VALUES(?,?,?)
                ON CONFLICT(id) DO NOTHING""",
                ("system", "NEXUS System", utc_now()),
            )

    def migrate_legacy_users(self) -> int:
        return 0
