"""Offline-safe backup and restore operations for single-node NEXUS."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def safe_members(archive: tarfile.TarFile, destination: Path):
    root = destination.resolve()
    for member in archive.getmembers():
        target = (destination / member.name).resolve()
        if target != root and root not in target.parents:
            raise ValueError(f"unsafe archive member: {member.name}")
        yield member


def backup(args) -> None:
    database = Path(args.database).resolve()
    if not database.exists():
        raise FileNotFoundError(database)
    output = Path(args.output).resolve() if args.output else (
        ROOT / ".backups" / f"nexus_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.tar.gz"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary)
        snapshot = staging / "control.db"
        with sqlite3.connect(database) as source, sqlite3.connect(snapshot) as target:
            source.backup(target)
        manifest = {
            "format": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "database_sha256": digest(snapshot),
            "source_database": database.name,
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        with tarfile.open(output, "w:gz") as archive:
            archive.add(snapshot, arcname="control.db")
            archive.add(staging / "manifest.json", arcname="manifest.json")
    print(output)


def restore(args) -> None:
    archive_path = Path(args.archive).resolve()
    destination = Path(args.database).resolve()
    if destination.exists() and not args.force:
        raise FileExistsError("destination exists; pass --force after isolating the service")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary)
        with tarfile.open(archive_path, "r:gz") as archive:
            archive.extractall(staging, members=safe_members(archive, staging), filter="data")
        manifest = json.loads((staging / "manifest.json").read_text(encoding="utf-8"))
        snapshot = staging / "control.db"
        if digest(snapshot) != manifest["database_sha256"]:
            raise ValueError("backup checksum mismatch")
        with sqlite3.connect(snapshot) as source:
            if source.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("backup database integrity check failed")
        temporary_target = destination.with_suffix(destination.suffix + ".restore")
        shutil.copy2(snapshot, temporary_target)
        os.replace(temporary_target, destination)
    print(destination)


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    actions = command.add_subparsers(dest="action", required=True)
    create = actions.add_parser("backup")
    create.add_argument("--database", default=os.getenv("NEXUS_DB_PATH", ROOT / "data/nexus_pro.db"))
    create.add_argument("--output")
    create.set_defaults(handler=backup)
    recover = actions.add_parser("restore")
    recover.add_argument("archive")
    recover.add_argument("--database", required=True)
    recover.add_argument("--force", action="store_true")
    recover.set_defaults(handler=restore)
    return command


if __name__ == "__main__":
    arguments = parser().parse_args()
    arguments.handler(arguments)
