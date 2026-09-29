"""Parser de subfinder JSONL → JSON estructurado.

`subfinder -silent -json` emite una línea JSON por subdominio descubierto, con
`host` (y opcionalmente `input`, `source`, `sources`). El parser tolera además
líneas planas (una salida muy antigua o un `-silent` sin `-json`) siempre que
tengan forma de hostname.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ._jsonl import first_str, iter_json_lines, sha256_text, string_tuple

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9_*][A-Za-z0-9_.*-]*\.[A-Za-z]{2,}$")


@dataclass(frozen=True)
class SubfinderResult:
    """Subdominios descubiertos pasivamente para un dominio."""

    domain: str
    subdomains: tuple[str, ...]
    sources: tuple[str, ...]
    records: tuple[dict[str, Any], ...]
    malformed_lines: int
    raw_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "domain": self.domain,
            "count": len(self.subdomains),
            "subdomains": list(self.subdomains),
            "sources": list(self.sources),
            "malformed_lines": self.malformed_lines,
            "raw_sha256": self.raw_sha256,
        }


def empty_subfinder_result(domain: str, reason: str = "") -> SubfinderResult:
    """Return an empty result (used when the run produced nothing usable)."""
    return SubfinderResult(
        domain=domain,
        subdomains=(),
        sources=(reason,) if reason else (),
        records=(),
        malformed_lines=0,
        raw_sha256=sha256_text(""),
    )


def parse_subfinder_jsonl(text: str, domain: str = "") -> SubfinderResult:
    """Parse ``subfinder -json`` output into a :class:`SubfinderResult`.

    Raises ``ValueError`` when the payload is non-empty but no subdomain could
    be extracted from it.
    """
    if not isinstance(text, str) or not text.strip():
        return empty_subfinder_result(domain)

    records, malformed = iter_json_lines(text)
    subdomains: list[str] = []
    for record in records:
        host = first_str(record, "host", "subdomain", "name", "domain")
        if host and host not in subdomains:
            subdomains.append(host)

    if not records:
        # No JSON at all: accept a plain `-silent` listing if it looks like hosts.
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if _HOSTNAME_RE.match(stripped):
                if stripped not in subdomains:
                    subdomains.append(stripped)
            else:
                malformed += 1

    if not subdomains:
        raise ValueError("invalid subfinder output: no subdomains could be parsed")

    sources: list[str] = []
    for record in records:
        for source in string_tuple(record.get("sources")) + string_tuple(record.get("source")):
            if source not in sources:
                sources.append(source)

    return SubfinderResult(
        domain=domain,
        subdomains=tuple(subdomains),
        sources=tuple(sources),
        records=tuple(records),
        malformed_lines=malformed,
        raw_sha256=sha256_text(text),
    )
