"""Shared filesystem configuration for NEXUS Core."""
import os
from pathlib import Path


DEFAULT_NEXUS_ROOT = Path(__file__).resolve().parent.parent


def _resolve_env_path(name: str, default: str | Path, base: Path) -> Path:
    path = Path(os.getenv(name, str(default))).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve()


NEXUS_ROOT = _resolve_env_path("NEXUS_ROOT", DEFAULT_NEXUS_ROOT, DEFAULT_NEXUS_ROOT)
NEXUS_DATA_PATH = _resolve_env_path(
    "NEXUS_DATA_PATH",
    os.getenv("NEXUS_DATA_DIR", "data"),
    NEXUS_ROOT,
)
NEXUS_DB_PATH = _resolve_env_path(
    "NEXUS_DB_PATH",
    NEXUS_DATA_PATH / "nexus_pro.db",
    NEXUS_ROOT,
)

REPORTS_DIR = NEXUS_DATA_PATH / "reports"
PENTEST_DIR = NEXUS_DATA_PATH / "pentest"
CHROMA_PATH = NEXUS_DATA_PATH / "junior_memory_db"
LEGACY_DATABASE_PATH = NEXUS_DATA_PATH / "database.db"
