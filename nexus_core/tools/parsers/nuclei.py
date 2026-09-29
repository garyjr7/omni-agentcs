"""Parser de nuclei JSONL → JSON estructurado.

`nuclei -jsonl` emite una línea JSON por finding, con `template-id`, `info`
(`name`, `severity`, `tags`), `host`, `matched-at`, `type`, etc.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._jsonl import count_by, first_str, iter_json_lines, sha256_text, string_tuple

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")


@dataclass(frozen=True)
class NucleiFinding:
    """Un finding de nuclei (una línea de `nuclei -jsonl`)."""

    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    finding_type: str
    tags: tuple[str, ...]
    matcher_name: str
    extracted: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the finding."""
        return {
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "host": self.host,
            "matched_at": self.matched_at,
            "type": self.finding_type,
            "tags": list(self.tags),
            "matcher_name": self.matcher_name,
            "extracted": list(self.extracted),
        }


@dataclass(frozen=True)
class NucleiResult:
    """Resultado de un escaneo de vulnerabilidades con templates."""

    findings: tuple[NucleiFinding, ...]
    severity_counts: dict[str, int]
    malformed_lines: int
    raw_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "count": len(self.findings),
            "severity_counts": dict(self.severity_counts),
            "malformed_lines": self.malformed_lines,
            "findings": [finding.to_dict() for finding in self.findings],
            "raw_sha256": self.raw_sha256,
        }


def empty_nuclei_result(reason: str = "") -> NucleiResult:
    """Return an empty result (no template matched)."""
    _ = reason
    return NucleiResult(
        findings=(),
        severity_counts={},
        malformed_lines=0,
        raw_sha256=sha256_text(""),
    )


def _finding_from(record: dict[str, Any]) -> NucleiFinding:
    info = record.get("info") if isinstance(record.get("info"), dict) else {}
    return NucleiFinding(
        template_id=first_str(record, "template-id", "template_id", "templateID"),
        name=first_str(info, "name") or first_str(record, "name"),
        severity=first_str(info, "severity") or first_str(record, "severity") or "unknown",
        host=first_str(record, "host", "ip"),
        matched_at=first_str(record, "matched-at", "matched_at", "matched"),
        finding_type=first_str(record, "type"),
        tags=string_tuple(info.get("tags")) or string_tuple(record.get("tags")),
        matcher_name=first_str(record, "matcher-name", "matcher_name"),
        extracted=string_tuple(record.get("extracted-results"))
        or string_tuple(record.get("extracted_results")),
    )


def parse_nuclei_jsonl(text: str) -> NucleiResult:
    """Parse ``nuclei -jsonl`` output into a :class:`NucleiResult`.

    An empty payload is a valid "no findings" outcome; a non-empty payload with
    no parsable finding raises ``ValueError``.
    """
    if not isinstance(text, str) or not text.strip():
        return empty_nuclei_result()

    records, malformed = iter_json_lines(text)
    findings = tuple(_finding_from(record) for record in records)
    if not findings:
        raise ValueError("invalid nuclei output: no finding could be parsed")

    as_records = [finding.to_dict() for finding in findings]
    severity_counts = count_by(as_records, "severity")
    ordered = {
        severity: severity_counts[severity]
        for severity in SEVERITY_ORDER
        if severity in severity_counts
    }
    for severity, count in severity_counts.items():
        ordered.setdefault(severity, count)
    return NucleiResult(
        findings=findings,
        severity_counts=ordered,
        malformed_lines=malformed,
        raw_sha256=sha256_text(text),
    )
