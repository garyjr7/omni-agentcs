"""Parser de searchsploit JSON → estructura estable.

``searchsploit --json`` devuelve un único objeto con dos listas de resultados
(exploits y shellcodes). El parser nunca hace regex sobre la tabla ASCII: sólo
interpreta el JSON, de modo que un cambio de columnas no puede producir
hallazgos falsos.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ._jsonl import sha256_text


@dataclass(frozen=True)
class ExploitEntry:
    """Una entrada de Exploit-DB (exploit o shellcode)."""

    title: str
    edb_id: str
    date: str | None
    author: str | None
    type: str | None
    platform: str | None
    path: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the entry."""
        return {
            "title": self.title,
            "edb_id": self.edb_id,
            "date": self.date,
            "author": self.author,
            "type": self.type,
            "platform": self.platform,
            "path": self.path,
        }


@dataclass(frozen=True)
class SearchsploitResult:
    """Resultado de una búsqueda local en Exploit-DB."""

    query: str
    exploits: tuple[ExploitEntry, ...]
    shellcodes: tuple[ExploitEntry, ...]
    total: int
    raw_json_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "query": self.query,
            "total": self.total,
            "exploits": [entry.to_dict() for entry in self.exploits],
            "shellcodes": [entry.to_dict() for entry in self.shellcodes],
            "raw_json_sha256": self.raw_json_sha256,
        }


def _optional_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _entry(record: dict[str, Any]) -> ExploitEntry:
    return ExploitEntry(
        title=str(record.get("Title") or "").strip(),
        edb_id=str(record.get("EDB-ID") or record.get("EDB_ID") or "").strip(),
        date=(
            _optional_str(record.get("Date_Published"))
            or _optional_str(record.get("Date"))
            or _optional_str(record.get("Date_Added"))
        ),
        author=_optional_str(record.get("Author")),
        type=_optional_str(record.get("Type")),
        platform=_optional_str(record.get("Platform")),
        path=str(record.get("Path") or "").strip(),
    )


def empty_searchsploit_result(query: str = "") -> SearchsploitResult:
    """Return an empty result (no entry matched)."""
    return SearchsploitResult(
        query=query,
        exploits=(),
        shellcodes=(),
        total=0,
        raw_json_sha256=sha256_text(""),
    )


def parse_searchsploit_json(text: str, query: str = "") -> SearchsploitResult:
    """Parse ``searchsploit --json`` output into a :class:`SearchsploitResult`.

    An empty payload is a valid "no results" outcome. A malformed payload or a
    non-object root raises ``ValueError``.
    """
    if not isinstance(text, str) or not text.strip():
        return empty_searchsploit_result(query)
    try:
        document = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid searchsploit json: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("searchsploit json root must be an object")

    exploits = tuple(
        _entry(item)
        for item in document.get("RESULTS_EXPLOIT") or []
        if isinstance(item, dict)
    )
    shellcodes = tuple(
        _entry(item)
        for item in document.get("RESULTS_SHELLCODE") or []
        if isinstance(item, dict)
    )
    resolved_query = str(query).strip() or str(document.get("SEARCH") or "").strip()
    return SearchsploitResult(
        query=resolved_query,
        exploits=exploits,
        shellcodes=shellcodes,
        total=len(exploits) + len(shellcodes),
        raw_json_sha256=sha256_text(text),
    )
