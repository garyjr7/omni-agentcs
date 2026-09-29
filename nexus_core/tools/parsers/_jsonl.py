"""Tolerant helpers shared by the recon/web output parsers.

The ProjectDiscovery tools emit newline-delimited JSON (``-json`` / ``-jsonl``).
Real runs interleave banner noise, warnings and blank lines, so the parsers
below never trust that every line is valid JSON: they collect the records that
do parse, count the ones that do not, and only raise when a non-empty payload
yielded no usable record at all.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_text(text: str) -> str:
    """Return the SHA-256 of ``text``, used to fingerprint raw tool output."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def loads_object(line: str) -> dict[str, Any] | None:
    """Parse one line into a JSON object, or ``None`` if it is not one."""
    stripped = line.strip()
    if not stripped:
        return None
    try:
        value = json.loads(stripped)
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def iter_json_lines(text: str) -> tuple[list[dict[str, Any]], int]:
    """Parse newline-delimited JSON.

    Returns ``(records, malformed_lines)``: objects that parsed and a count of
    non-empty lines that did not.
    """
    records: list[dict[str, Any]] = []
    malformed = 0
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        record = loads_object(line)
        if record is None:
            malformed += 1
            continue
        records.append(record)
    return records, malformed


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def to_int(value: Any, default: int = 0) -> int:
    """Coerce tool output to ``int`` without ever raising."""
    return _to_int(value, default)


def first_str(record: dict[str, Any], *keys: str) -> str:
    """Return the first non-empty string among ``keys`` (``""`` otherwise)."""
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def string_tuple(value: Any) -> tuple[str, ...]:
    """Normalize a JSON value (list, string or missing) into a string tuple."""
    if value is None:
        return ()
    if isinstance(value, str):
        parts = [item.strip() for item in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
        parts = [str(item).strip() for item in value]
    else:
        parts = [str(value).strip()]
    return tuple(part for part in parts if part)


def count_by(records: list[dict[str, Any]], key: str) -> dict[str, int]:
    """Count occurrences of ``record[key]``, keyed by string, sorted by count."""
    counts: dict[str, int] = {}
    for record in records:
        value = record.get(key)
        if value in (None, ""):
            continue
        counts[str(value)] = counts.get(str(value), 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))
