"""Parser de la salida JSON de dalfox → estructura estable.

dalfox ``--format json`` escribe un **array** JSON (con un objeto vacío de
relleno) y también admite ``jsonl`` (NDJSON). El parser acepta ambos y filtra
los objetos vacíos, que no son hallazgos.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ._jsonl import first_str, iter_json_lines, sha256_text

#: Valores de ``type`` que dalfox usa para un hallazgo (``V`` en v2.13).
DALFOX_VULN_TYPES = {"v", "vuln", "vulnerable", "vulnerability"}


@dataclass(frozen=True)
class DalfoxFinding:
    """Un hallazgo XSS reportado por dalfox."""

    method: str
    url: str
    param: str
    payload: str
    evidence: str
    inject_type: str
    cwe: str
    severity: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the finding."""
        return {
            "method": self.method,
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "inject_type": self.inject_type,
            "cwe": self.cwe,
            "severity": self.severity,
            "message": self.message,
        }


@dataclass(frozen=True)
class DalfoxResult:
    """Resultado normalizado de una ejecución de dalfox."""

    target: str
    findings: tuple[DalfoxFinding, ...]
    duration_seconds: float
    raw_json_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "target": self.target,
            "count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "duration_seconds": self.duration_seconds,
            "raw_json_sha256": self.raw_json_sha256,
        }


def empty_dalfox_result(target: str = "") -> DalfoxResult:
    """Return an empty result (no XSS found)."""
    return DalfoxResult(
        target=target,
        findings=(),
        duration_seconds=0.0,
        raw_json_sha256=sha256_text(""),
    )


def _is_finding(record: dict[str, Any]) -> bool:
    """A record is a finding when it carries payload/param evidence."""
    if str(record.get("type") or "").strip().lower() in DALFOX_VULN_TYPES:
        return True
    return any(first_str(record, key) for key in ("param", "payload", "data"))


def _finding_from(record: dict[str, Any]) -> DalfoxFinding:
    return DalfoxFinding(
        method=first_str(record, "method") or "GET",
        url=first_str(record, "data", "url", "target"),
        param=first_str(record, "param"),
        payload=first_str(record, "payload"),
        evidence=first_str(record, "evidence"),
        inject_type=first_str(record, "inject_type"),
        cwe=first_str(record, "cwe"),
        severity=first_str(record, "severity"),
        message=first_str(record, "message_str", "message"),
    )


def parse_dalfox_json(
    text: str, target: str = "", duration_seconds: float = 0.0
) -> DalfoxResult:
    """Parse dalfox JSON (array) or NDJSON output into a :class:`DalfoxResult`.

    ``[{}]`` (dalfox's "no findings" placeholder) is a valid empty result.
    Malformed JSON raises ``ValueError``.
    """
    if not isinstance(text, str) or not text.strip():
        return empty_dalfox_result(target)

    records: list[dict[str, Any]] | None = None
    try:
        document = json.loads(text)
    except (ValueError, TypeError):
        document = None

    if isinstance(document, list):
        records = [item for item in document if isinstance(item, dict)]
    elif isinstance(document, dict):
        records = [document]

    if records is None:
        records, malformed = iter_json_lines(text)
        if not records and malformed:
            raise ValueError("invalid dalfox output: no JSON record could be parsed")

    findings = tuple(_finding_from(record) for record in records if _is_finding(record))
    return DalfoxResult(
        target=target,
        findings=findings,
        duration_seconds=duration_seconds,
        raw_json_sha256=sha256_text(text),
    )
