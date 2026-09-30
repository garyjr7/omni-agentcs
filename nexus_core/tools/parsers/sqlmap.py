"""Parser de la salida de sqlmap → estructura estable.

sqlmap no escribe un log utilizable en ``--output-dir`` cuando el target no es
inyectable (el fichero ``log`` queda vacío). La señal real está en **stdout**,
con líneas ``[HH:MM:SS] [LEVEL] mensaje`` separadas por ``\\r``/``\\n`` y, a
menudo, con secuencias ANSI. El parser normaliza cada línea y reconoce los
mensajes documentados en el propio código de sqlmap:

* ``the back-end DBMS is <dbms>``
* ``<place> parameter '<p>' is vulnerable``
* ``Parameter: <p> (<PLACE>)`` + ``Type:`` / ``Title:`` / ``Payload:``
* ``all tested parameters do not appear to be injectable``
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ._jsonl import sha256_text

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_TIME_PREFIX_RE = re.compile(r"^\[\d{2}:\d{2}:\d{2}\]\s*")
_DBMS_RE = re.compile(r"the back-end DBMS is\s+(?P<dbms>.+?)\s*$", re.IGNORECASE)
_DBMS_COLON_RE = re.compile(
    r"back-end DBMS:\s*(?P<dbms>[A-Za-z0-9 ._-]+)", re.IGNORECASE
)
_VULN_RE = re.compile(
    r"(?:(?P<place>GET|POST|Cookie)\s+)?parameter\s+'(?P<param>[^']+)'\s+is\s+vulnerable",
    re.IGNORECASE,
)
_PARAM_RE = re.compile(
    r"^Parameter:\s+(?P<param>\S+)\s+\((?P<place>[A-Za-z]+)\)\s*$", re.IGNORECASE
)
_TYPE_RE = re.compile(r"^Type:\s+(?P<type>.+?)\s*$", re.IGNORECASE)
_TITLE_RE = re.compile(r"^Title:\s+(?P<title>.+?)\s*$", re.IGNORECASE)
_PAYLOAD_RE = re.compile(r"^Payload:\s+(?P<payload>.+?)\s*$", re.IGNORECASE)
_NOT_INJECTABLE_RE = re.compile(
    r"(all tested parameters do not appear to be injectable"
    r"|does not seem to be injectable"
    r"|all tested parameters appear to be not injectable)",
    re.IGNORECASE,
)
_RECOGNIZED_RE = re.compile(r"\[(?:INFO|WARNING|CRITICAL|ERROR)\]", re.IGNORECASE)


@dataclass(frozen=True)
class SqlmapFinding:
    """Una inyección SQL confirmada por sqlmap."""

    parameter: str
    method: str
    dbms: str | None
    injection_type: str
    payload: str
    title: str
    severity: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the finding."""
        return {
            "parameter": self.parameter,
            "method": self.method,
            "dbms": self.dbms,
            "injection_type": self.injection_type,
            "payload": self.payload,
            "title": self.title,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class SqlmapResult:
    """Resultado normalizado de una ejecución de sqlmap."""

    target_url: str
    vulnerable: bool
    findings: tuple[SqlmapFinding, ...]
    dbms_detected: str | None
    duration_seconds: float
    raw_log_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "target_url": self.target_url,
            "vulnerable": self.vulnerable,
            "count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "dbms_detected": self.dbms_detected,
            "duration_seconds": self.duration_seconds,
            "raw_log_sha256": self.raw_log_sha256,
        }


def empty_sqlmap_result(target_url: str = "") -> SqlmapResult:
    """Return an empty result (nothing recognized as vulnerable)."""
    return SqlmapResult(
        target_url=target_url,
        vulnerable=False,
        findings=(),
        dbms_detected=None,
        duration_seconds=0.0,
        raw_log_sha256=sha256_text(""),
    )


def _clean(line: str) -> str:
    return _TIME_PREFIX_RE.sub("", _ANSI_RE.sub("", line)).strip()


def parse_sqlmap_output(
    text: str,
    target_url: str = "",
    duration_seconds: float = 0.0,
) -> SqlmapResult:
    """Parse sqlmap stdout into a :class:`SqlmapResult`.

    Empty output yields an empty result. A non-empty payload with no recognizable
    sqlmap line at all raises ``ValueError`` (unrelated program output must not
    be reported as a clean scan).
    """
    if not isinstance(text, str) or not text.strip():
        return empty_sqlmap_result(target_url)

    lines = [_clean(line) for line in re.split(r"[\r\n]+", text)]
    lines = [line for line in lines if line]

    dbms: str | None = None
    vulnerable_params: list[tuple[str, str]] = []
    blocks: list[dict[str, str]] = []
    recognized = False

    current: dict[str, str] | None = None
    for line in lines:
        if _RECOGNIZED_RE.search(line) or _NOT_INJECTABLE_RE.search(line):
            recognized = True

        match = _DBMS_RE.search(line) or _DBMS_COLON_RE.search(line)
        if match:
            dbms = match.group("dbms").strip()

        match = _VULN_RE.search(line)
        if match:
            vulnerable_params.append(
                ((match.group("param") or "").strip(), (match.group("place") or "GET").upper())
            )
            continue

        match = _PARAM_RE.match(line)
        if match:
            current = {
                "param": match.group("param"),
                "place": (match.group("place") or "GET").upper(),
                "type": "",
                "title": "",
                "payload": "",
            }
            blocks.append(current)
            continue

        if current is not None:
            match = _TYPE_RE.match(line)
            if match:
                current["type"] = match.group("type")
                continue
            match = _TITLE_RE.match(line)
            if match:
                current["title"] = match.group("title")
                continue
            match = _PAYLOAD_RE.match(line)
            if match:
                current["payload"] = match.group("payload")
                continue

    if not recognized and not blocks and not vulnerable_params:
        raise ValueError("unrecognized sqlmap output")

    findings: list[SqlmapFinding] = []
    seen: set[tuple[str, str]] = set()

    for block in blocks:
        key = (block["param"], block["place"])
        seen.add(key)
        findings.append(
            SqlmapFinding(
                parameter=block["param"],
                method=block["place"],
                dbms=dbms,
                injection_type=block["type"] or "SQL injection",
                payload=block["payload"],
                title=block["title"]
                or f"SQL injection in parameter '{block['param']}' ({block['place']})",
                severity="high",
            )
        )

    for param, place in vulnerable_params:
        key = (param, place)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            SqlmapFinding(
                parameter=param,
                method=place,
                dbms=dbms,
                injection_type="SQL injection",
                payload="",
                title=f"SQL injection in parameter '{param}' ({place})",
                severity="high",
            )
        )

    return SqlmapResult(
        target_url=target_url,
        vulnerable=bool(findings),
        findings=tuple(findings),
        dbms_detected=dbms,
        duration_seconds=duration_seconds,
        raw_log_sha256=sha256_text(text),
    )
