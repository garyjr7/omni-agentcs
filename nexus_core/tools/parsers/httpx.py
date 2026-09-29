"""Parser de httpx (ProjectDiscovery) JSONL → JSON estructurado.

`httpx -json` emite una línea JSON por host probado con `url`, `status_code`,
`title`, `tech`, `content_length`, `webserver`, `cname`, `cdn_name`, etc.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._jsonl import count_by, first_str, iter_json_lines, sha256_text, string_tuple, to_int


@dataclass(frozen=True)
class HttpxProbe:
    """Un host HTTP probado (una línea de `httpx -json`)."""

    url: str
    status_code: int
    title: str
    tech: tuple[str, ...]
    content_length: int
    webserver: str
    host: str
    cdn: str
    cname: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the probe."""
        return {
            "url": self.url,
            "status_code": self.status_code,
            "title": self.title,
            "tech": list(self.tech),
            "content_length": self.content_length,
            "webserver": self.webserver,
            "host": self.host,
            "cdn": self.cdn,
            "cname": list(self.cname),
        }


@dataclass(frozen=True)
class HttpxResult:
    """Resultado de un fingerprinting HTTP multi-target."""

    probes: tuple[HttpxProbe, ...]
    status_counts: dict[str, int]
    tech: tuple[str, ...]
    malformed_lines: int
    raw_sha256: str

    @property
    def hosts_alive(self) -> int:
        """Number of probed URLs that answered (any status code)."""
        return len(self.probes)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "count": len(self.probes),
            "hosts_alive": self.hosts_alive,
            "status_counts": dict(self.status_counts),
            "tech": list(self.tech),
            "malformed_lines": self.malformed_lines,
            "probes": [probe.to_dict() for probe in self.probes],
            "raw_sha256": self.raw_sha256,
        }


def empty_httpx_result(reason: str = "") -> HttpxResult:
    """Return an empty result (no endpoint answered)."""
    _ = reason
    return HttpxResult(
        probes=(),
        status_counts={},
        tech=(),
        malformed_lines=0,
        raw_sha256=sha256_text(""),
    )


def parse_httpx_jsonl(text: str) -> HttpxResult:
    """Parse ``httpx -json`` output into an :class:`HttpxResult`.

    Raises ``ValueError`` when the payload is non-empty but no probe could be
    extracted from it.
    """
    if not isinstance(text, str) or not text.strip():
        return empty_httpx_result()

    records, malformed = iter_json_lines(text)
    probes: list[HttpxProbe] = []
    tech: list[str] = []
    for record in records:
        url = first_str(record, "url", "input", "host")
        probe_tech = string_tuple(record.get("tech"))
        for item in probe_tech:
            if item not in tech:
                tech.append(item)
        probes.append(
            HttpxProbe(
                url=url,
                status_code=to_int(record.get("status_code") or record.get("status-code")),
                title=first_str(record, "title"),
                tech=probe_tech,
                content_length=to_int(
                    record.get("content_length") or record.get("content-length")
                ),
                webserver=first_str(record, "webserver", "web-server"),
                host=first_str(record, "host"),
                cdn=first_str(record, "cdn_name", "cdn-name", "cdn"),
                cname=string_tuple(record.get("cname")),
            )
        )

    if not probes:
        raise ValueError("invalid httpx output: no probe could be parsed")

    as_records = [probe.to_dict() for probe in probes]
    return HttpxResult(
        probes=tuple(probes),
        status_counts=count_by(as_records, "status_code"),
        tech=tuple(tech),
        malformed_lines=malformed,
        raw_sha256=sha256_text(text),
    )
