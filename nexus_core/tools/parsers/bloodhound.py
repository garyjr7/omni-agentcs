"""Parser de los ficheros JSON de BloodHound.py → estructura estable.

``bloodhound-python`` escribe varios ficheros (``<prefix>_users.json``,
``<prefix>_computers.json``, ...). El parser lee cada JSON, cuenta sus registros
y calcula su SHA-256; no reconstruye el grafo ni inventa relaciones.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ._jsonl import sha256_text


@dataclass(frozen=True)
class BloodHoundFile:
    """Un fichero de salida de BloodHound."""

    name: str
    collection: str
    record_count: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the file."""
        return {
            "name": self.name,
            "collection": self.collection,
            "record_count": self.record_count,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class BloodHoundResult:
    """Resumen normalizado de una recolección de BloodHound."""

    files: tuple[BloodHoundFile, ...]
    total_records: int
    raw_json_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "file_count": len(self.files),
            "total_records": self.total_records,
            "files": [item.to_dict() for item in self.files],
            "raw_json_sha256": self.raw_json_sha256,
        }


def _collection_from_name(name: str) -> str:
    """Derive the collection label from a ``<prefix>_<collection>.json`` name."""
    stem = name.rsplit("/", 1)[-1]
    if stem.endswith(".json"):
        stem = stem[: -len(".json")]
    parts = stem.rsplit("_", 1)
    return parts[-1] if len(parts) == 2 else stem


def _record_count(document: Any) -> int:
    if isinstance(document, list):
        return len(document)
    if isinstance(document, dict):
        for key in ("data", "objects", "results"):
            value = document.get(key)
            if isinstance(value, list):
                return len(value)
        return 1
    return 0


def parse_bloodhound_outputs(files: dict[str, str]) -> BloodHoundResult:
    """Parse the JSON files emitted by ``bloodhound-python``.

    ``files`` maps a file name to its text. An empty mapping is a valid
    "nothing collected" outcome; malformed JSON raises ``ValueError``.
    """
    parsed: list[BloodHoundFile] = []
    combined = []
    total = 0
    for name in sorted(files):
        text = files[name]
        try:
            document = json.loads(text)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"invalid bloodhound json in {name}: {exc}") from exc
        count = _record_count(document)
        total += count
        parsed.append(
            BloodHoundFile(
                name=name,
                collection=_collection_from_name(name),
                record_count=count,
                sha256=sha256_text(text),
            )
        )
        combined.append(text)
    return BloodHoundResult(
        files=tuple(parsed),
        total_records=total,
        raw_json_sha256=sha256_text("\n".join(combined)),
    )
