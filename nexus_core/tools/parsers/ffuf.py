"""Parser de ffuf JSON → JSON estructurado.

ffuf puede emitir dos formatos válidos:

* ``-json`` → **NDJSON**, un objeto por match en stdout.
* ``-of json -o <file>`` → un único objeto ``{"results": [...]}``.

El parser acepta ambos (y una lista JSON suelta) para no acoplarse al flag
elegido por el handler.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ._jsonl import count_by, first_str, iter_json_lines, sha256_text, to_int


@dataclass(frozen=True)
class FfufMatch:
    """Un path/entrada que pasó los matchers de ffuf."""

    url: str
    host: str
    status: int
    length: int
    words: int
    lines: int
    content_type: str
    redirect_location: str
    duration_ms: int
    input: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the match."""
        return {
            "url": self.url,
            "host": self.host,
            "status": self.status,
            "length": self.length,
            "words": self.words,
            "lines": self.lines,
            "content_type": self.content_type,
            "redirect_location": self.redirect_location,
            "duration_ms": self.duration_ms,
            "input": dict(self.input),
        }


@dataclass(frozen=True)
class FfufResult:
    """Resultado de un fuzzing de rutas/directorios."""

    matches: tuple[FfufMatch, ...]
    status_counts: dict[str, int]
    malformed_lines: int
    raw_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "count": len(self.matches),
            "status_counts": dict(self.status_counts),
            "malformed_lines": self.malformed_lines,
            "matches": [match.to_dict() for match in self.matches],
            "raw_sha256": self.raw_sha256,
        }


def empty_ffuf_result(reason: str = "") -> FfufResult:
    """Return an empty result (no entry matched)."""
    _ = reason
    return FfufResult(
        matches=(),
        status_counts={},
        malformed_lines=0,
        raw_sha256=sha256_text(""),
    )


def _match_from(record: dict[str, Any]) -> FfufMatch:
    raw_input = record.get("input")
    entries = dict(raw_input) if isinstance(raw_input, dict) else {}
    duration = record.get("duration")
    try:
        duration_ms = int(float(duration)) // 1_000_000 if duration is not None else 0
    except (TypeError, ValueError):
        duration_ms = 0
    return FfufMatch(
        url=first_str(record, "url", "host"),
        host=first_str(record, "host"),
        status=to_int(record.get("status")),
        length=to_int(record.get("length")),
        words=to_int(record.get("words")),
        lines=to_int(record.get("lines")),
        content_type=first_str(record, "content-type", "content_type"),
        redirect_location=first_str(record, "redirectlocation", "redirect_location"),
        duration_ms=duration_ms,
        input=entries,
    )


def _envelope_records(text: str) -> list[dict[str, Any]] | None:
    """Return the records of a single-document ffuf payload, if it is one."""
    try:
        document = json.loads(text)
    except (ValueError, TypeError):
        return None
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    if isinstance(document, dict):
        for key in ("results", "matches", "entries"):
            value = document.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [document]
    return None


def parse_ffuf_output(text: str) -> FfufResult:
    """Parse ffuf JSON/NDJSON output into a :class:`FfufResult`.

    An empty payload is a valid "no matches" outcome; a non-empty payload with
    no parsable match raises ``ValueError``.
    """
    if not isinstance(text, str) or not text.strip():
        return empty_ffuf_result()

    malformed = 0
    records = _envelope_records(text)
    if records is None:
        records, malformed = iter_json_lines(text)

    matches = tuple(_match_from(record) for record in records)
    matches = tuple(match for match in matches if match.url or match.status)
    if not matches:
        raise ValueError("invalid ffuf output: no match could be parsed")

    as_records = [match.to_dict() for match in matches]
    return FfufResult(
        matches=matches,
        status_counts=count_by(as_records, "status"),
        malformed_lines=malformed,
        raw_sha256=sha256_text(text),
    )
