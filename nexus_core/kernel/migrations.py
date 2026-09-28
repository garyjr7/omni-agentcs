"""Minimal reversible migration runner for control-plane schema changes."""

from __future__ import annotations

from dataclasses import dataclass

from .models import utc_now


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    up: str
    down: str


class MigrationRunner:
    def __init__(self, store, migrations: tuple[Migration, ...]):
        versions = [migration.version for migration in migrations]
        if versions != sorted(set(versions)):
            raise ValueError("migration versions must be unique and ordered")
        self.store = store
        self.migrations = migrations

    def applied(self) -> set[int]:
        with self.store.connect() as conn:
            rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
        return {int(row["version"]) for row in rows}

    def upgrade(self, target: int | None = None) -> list[int]:
        completed = self.applied()
        changed = []
        for migration in self.migrations:
            if migration.version in completed or (
                target is not None and migration.version > target
            ):
                continue
            with self.store.connect() as conn:
                conn.executescript(migration.up)
                conn.execute(
                    "INSERT INTO schema_migrations(version,name,applied_at) VALUES(?,?,?)",
                    (migration.version, migration.name, utc_now()),
                )
            changed.append(migration.version)
        return changed

    def downgrade(self, target: int) -> list[int]:
        completed = self.applied()
        changed = []
        for migration in reversed(self.migrations):
            if migration.version <= target or migration.version not in completed:
                continue
            with self.store.connect() as conn:
                conn.executescript(migration.down)
                conn.execute(
                    "DELETE FROM schema_migrations WHERE version=?", (migration.version,)
                )
            changed.append(migration.version)
        return changed
