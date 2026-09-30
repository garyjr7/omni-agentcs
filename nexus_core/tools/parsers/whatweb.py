"""Parser del log JSON de whatweb → estructura estable.

``whatweb --log-json=FILE`` escribe una **lista** de objetos, uno por target,
con un diccionario ``plugins`` donde cada plugin aporta sus evidencias
(``version``, ``string``, ``os``, ...). No se hace regex sobre la salida
humana: sólo se interpreta el JSON.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ._jsonl import sha256_text, to_int


@dataclass(frozen=True)
class WhatwebFingerprint:
    """Un plugin/fingerprint detectado en un target."""

    name: str
    version: str | None
    confidence: float
    details: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the fingerprint."""
        return {
            "name": self.name,
            "version": self.version,
            "confidence": self.confidence,
            "details": self.details,
        }


@dataclass(frozen=True)
class WhatwebTarget:
    """Un target con sus fingerprints."""

    url: str
    http_status: int | None
    fingerprints: tuple[WhatwebFingerprint, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the target."""
        return {
            "url": self.url,
            "http_status": self.http_status,
            "fingerprints": [item.to_dict() for item in self.fingerprints],
        }


@dataclass(frozen=True)
class WhatwebResult:
    """Resultado normalizado de una ejecución de whatweb."""

    targets: tuple[WhatwebTarget, ...]
    duration_seconds: float
    raw_json_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "count": len(self.targets),
            "targets": [target.to_dict() for target in self.targets],
            "duration_seconds": self.duration_seconds,
            "raw_json_sha256": self.raw_json_sha256,
        }


def empty_whatweb_result() -> WhatwebResult:
    """Return an empty result (no target fingerprinted)."""
    return WhatwebResult(
        targets=(), duration_seconds=0.0, raw_json_sha256=sha256_text("")
    )


def _first_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, str) and item.strip():
                return item.strip()
    return None


def _fingerprint(name: str, plugin: Any) -> WhatwebFingerprint:
    if not isinstance(plugin, dict):
        return WhatwebFingerprint(name=name, version=None, confidence=1.0, details="")
    version = _first_str(plugin.get("version"))
    details = (
        _first_str(plugin.get("string"))
        or _first_str(plugin.get("os"))
        or version
        or ""
    )
    return WhatwebFingerprint(
        name=name, version=version, confidence=1.0, details=details
    )


def _target_from(record: dict[str, Any]) -> WhatwebTarget:
    plugins = record.get("plugins")
    entries = plugins if isinstance(plugins, dict) else {}
    fingerprints = tuple(
        _fingerprint(str(name), plugin) for name, plugin in entries.items()
    )
    raw_status = record.get("http_status")
    status = to_int(raw_status) if raw_status not in (None, "") else None
    return WhatwebTarget(
        url=str(record.get("target") or "").strip(),
        http_status=status,
        fingerprints=fingerprints,
    )


def parse_whatweb_json(text: str, duration_seconds: float = 0.0) -> WhatwebResult:
    """Parse the JSON emitted by ``whatweb --log-json``.

    An empty payload is a valid "nothing scanned" outcome. Invalid JSON or a
    root that is neither a list nor an object raises ``ValueError``.
    """
    if not isinstance(text, str) or not text.strip():
        return empty_whatweb_result()
    try:
        document = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid whatweb json: {exc}") from exc

    if isinstance(document, dict):
        records = [document]
    elif isinstance(document, list):
        records = [item for item in document if isinstance(item, dict)]
    else:
        raise ValueError("whatweb json root must be a list or an object")

    targets = tuple(_target_from(record) for record in records)
    return WhatwebResult(
        targets=targets,
        duration_seconds=duration_seconds,
        raw_json_sha256=sha256_text(text),
    )
