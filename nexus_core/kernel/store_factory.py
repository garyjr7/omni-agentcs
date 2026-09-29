"""Control-store backend selection.

SQLite is intentionally limited to offline development and single-node tests.
Production requires PostgreSQL.
"""

from __future__ import annotations

import os
from pathlib import Path

from .control_store import ControlStore


def get_control_store(
    sqlite_path: str | Path | None = None,
    database_url: str | None = None,
):
    url = database_url if database_url is not None else os.getenv("DATABASE_URL", "")
    if url.startswith(("postgresql://", "postgres://")):
        from .postgres_store import PostgresControlStore

        return PostgresControlStore(url)
    if url and not url.startswith("sqlite://"):
        raise ValueError("DATABASE_URL must use postgresql:// or sqlite://")
    if url.startswith("sqlite:///"):
        sqlite_path = url.removeprefix("sqlite:///")
    if sqlite_path is None:
        from nexus_core.config.loader import effective_db_path, load_config
        from nexus_core.config.xdg import resolve_xdg_paths
        paths = resolve_xdg_paths()
        sqlite_path = effective_db_path(load_config(paths), paths)
    environment = os.getenv("NEXUS_ENV", "development").lower()
    if environment == "production" and not os.getenv("NEXUS_ALLOW_SQLITE_PRODUCTION"):
        raise RuntimeError("PostgreSQL DATABASE_URL is required in production")
    return ControlStore(sqlite_path)
