"""Parser de la salida de gobuster (modo dir/vhost/dns) → estructura estable.

La salida en modo ``dir`` es una línea por hit::

    index.html           (Status: 200) [Size: 6974]
    images               (Status: 301) [Size: 318] [--> http://host/images/]

Es la única excepción a "no regex sobre stdout": gobuster no ofrece salida JSON
estable y el formato de línea es acotado y documentado. La regex es estricta
(ancla a ``(Status: N)``) y tolera que el binario omita el slash inicial, que es
exactamente lo que hace gobuster 3.8.2.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ._jsonl import sha256_text, to_int

GOBUSTER_LINE_RE = re.compile(
    r"^(?P<path>/?\S+)\s+"
    r"\(Status:\s+(?P<status>\d+)\)"
    r"(?:\s+\[Size:\s+(?P<size>\d+)\])?"
    r"(?:\s+\[-->\s+(?P<redirect>\S+)\])?\s*$"
)


@dataclass(frozen=True)
class GobusterHit:
    """Un path/entrada que gobuster consideró existente."""

    path: str
    status: int
    size: int | None
    redirect: str | None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the hit."""
        return {
            "path": self.path,
            "status": self.status,
            "size": self.size,
            "redirect": self.redirect,
        }


@dataclass(frozen=True)
class GobusterResult:
    """Resultado normalizado de una ejecución de gobuster."""

    mode: str
    target: str
    hits: tuple[GobusterHit, ...]
    duration_seconds: float
    raw_output_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "mode": self.mode,
            "target": self.target,
            "count": len(self.hits),
            "hits": [hit.to_dict() for hit in self.hits],
            "duration_seconds": self.duration_seconds,
            "raw_output_sha256": self.raw_output_sha256,
        }


def empty_gobuster_result(mode: str = "dir", target: str = "") -> GobusterResult:
    """Return an empty result (no hit matched)."""
    return GobusterResult(
        mode=mode,
        target=target,
        hits=(),
        duration_seconds=0.0,
        raw_output_sha256=sha256_text(""),
    )


def _hit_from(match: re.Match[str]) -> GobusterHit:
    size = match.group("size")
    return GobusterHit(
        path=match.group("path"),
        status=to_int(match.group("status")),
        size=int(size) if size is not None else None,
        redirect=match.group("redirect"),
    )


def parse_gobuster_output(
    text: str,
    mode: str = "dir",
    target: str = "",
    duration_seconds: float = 0.0,
) -> GobusterResult:
    """Parse gobuster text output into a :class:`GobusterResult`.

    Empty output (no hits) and banner-only output are valid. A payload that
    looks like a hit line (``(Status:``) but cannot be parsed raises
    ``ValueError`` rather than silently dropping evidence.
    """
    if not isinstance(text, str) or not text.strip():
        return empty_gobuster_result(mode, target)

    hits: list[GobusterHit] = []
    unparsed = 0
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        match = GOBUSTER_LINE_RE.match(line)
        if match is not None:
            hits.append(_hit_from(match))
        elif "(Status:" in line:
            unparsed += 1

    if unparsed and not hits:
        raise ValueError("invalid gobuster output: hit line could not be parsed")

    return GobusterResult(
        mode=mode,
        target=target,
        hits=tuple(hits),
        duration_seconds=duration_seconds,
        raw_output_sha256=sha256_text(text),
    )
