"""Parser de la salida de texto de nikto → estructura estable.

nikto no ofrece JSON estable en la versión que trae Kali (2.6.1 sí acepta
``-Format json``, pero la salida por stdout sigue siendo la única que llega al
handler sin escribir fuera del workspace), así que se parsea el formato de línea
documentado::

    + Target IP:          10.64.182.188
    + Target Hostname:    10.64.182.188
    + Target Port:        80
    + Server: Apache/2.4.41 (Ubuntu)
    + /login: This might be interesting.
    + OSVDB-3092: /login: This might be interesting...
    + 7918 requests: 0 error(s) and 20 item(s) reported on remote host

El parser distingue **cabecera** (campos ``Target *``/``Server``/``Start Time``/
``End Time``) del **hallazgo**, extrae el identificador (``OSVDB-n``/``CVE-…``)
cuando existe y separa ``path`` de mensaje. La presencia de la cabecera es lo que
prueba que nikto **habló** con el objetivo; sin ella el resultado es
``connected=False`` y el handler declara el negativo (no un "éxito" vacío).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ._jsonl import sha256_text, to_int

#: Campos de la cabecera del informe. ``Target IP``/``Hostname``/``Port`` prueban
#: que el escaneo llegó a hablar con el objetivo.
NIKTO_HEADER_RE = re.compile(
    r"^\+\s+(?P<field>Target IP|Target Hostname|Target Port|Start Time|End Time|Server):"
    r"\s*(?P<value>.+?)\s*$"
)
#: ``+ 7918 requests: 0 error(s) and 20 item(s) reported on remote host``.
#: Cuando ``-maxtime`` corta el escaneo la misma línea empieza por
#: ``Scan terminated:`` y no trae el contador de peticiones; el conteo de items
#: sigue siendo evidencia válida (medido en RUN_sala12).
NIKTO_TOTALS_RE = re.compile(
    r"^\+\s+(?:(?P<requests>[\d,]+)\s+requests:|Scan terminated:)\s*"
    r"(?P<errors>[\d,]+)\s+error(?:s|\(s\))\s+and\s+"
    r"(?P<items>[\d,]+)\s+item(?:s|\(s\))\s+reported"
)
#: Línea de cierre ``+ 1 host(s) tested`` / arranque ``+ Nikto v2.1.6``.
NIKTO_NOISE_RE = re.compile(r"^\+\s+(?:Nikto v|End Time|Start Time|\d+ host\(s\) tested)")
#: ``+ OSVDB-3092: /login: mensaje``, ``+ CVE-2021-43798: /public/…: mensaje`` o el
#: formato moderno de nikto 2.6, ``+ [001736] /login/: This might be interesting.``
#: (id numérico entre corchetes, el que emite el binario actual).
NIKTO_ID_RE = re.compile(
    r"^(?:(?P<identifier>OSVDB-\d+|CVE-\d{4}-\d+|[A-Z]+-\d+):\s*(?P<rest>.*)"
    r"|\[(?P<bracket>\d{4,6})\]\s*(?P<bracket_rest>.*))$"
)
#: El prefijo de ruta aparece cuando el hallazgo referencia un recurso concreto.
NIKTO_PATH_RE = re.compile(r"^(?P<path>/[^\s:]*)\s*:\s*(?P<message>.+)$")
NIKTO_MAX_FINDINGS = 500


@dataclass(frozen=True)
class NiktoFinding:
    """Un hallazgo de nikto normalizado."""

    identifier: str
    path: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the finding."""
        return {"id": self.identifier, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class NiktoReport:
    """Resultado normalizado de una ejecución de nikto."""

    target_ip: str
    hostname: str
    ports: tuple[str, ...]
    server: str
    findings: tuple[NiktoFinding, ...]
    requests: int | None
    items: int | None
    connected: bool
    raw_output_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the report."""
        return {
            "target_ip": self.target_ip,
            "hostname": self.hostname,
            "ports": list(self.ports),
            "server": self.server,
            "findings": [finding.to_dict() for finding in self.findings],
            "count": len(self.findings),
            "requests": self.requests,
            "items": self.items,
            "connected": self.connected,
            "raw_output_sha256": self.raw_output_sha256,
        }


def _split_finding(body: str) -> NiktoFinding:
    """Split ``[ID:] [/path:] message`` into the normalized finding."""
    identifier = ""
    rest = body
    match = NIKTO_ID_RE.match(body)
    if match is not None:
        identifier = match.group("identifier") or match.group("bracket") or ""
        rest = (match.group("rest") or match.group("bracket_rest") or "").strip()
    path = ""
    path_match = NIKTO_PATH_RE.match(rest)
    if path_match is not None:
        path = path_match.group("path")
        rest = path_match.group("message").strip()
    return NiktoFinding(identifier=identifier, path=path, message=rest)


def parse_nikto_report(text: str) -> NiktoReport:
    """Parse nikto stdout into a :class:`NiktoReport`.

    Banner-only or empty output is a valid (unconnected) report; a line that
    looks like a finding (``+ …``) is always carried through, so evidence is
    never silently dropped.
    """
    raw = text if isinstance(text, str) else ""
    if not raw.strip():
        return NiktoReport("", "", (), "", (), None, None, False, sha256_text(""))

    target_ip = ""
    hostname = ""
    server = ""
    ports: list[str] = []
    findings: list[NiktoFinding] = []
    requests: int | None = None
    items: int | None = None

    for line in raw.splitlines():
        stripped = line.rstrip()
        if not stripped.startswith("+"):
            continue
        header = NIKTO_HEADER_RE.match(stripped)
        if header is not None:
            field = header.group("field")
            value = header.group("value").strip()
            if field == "Target IP":
                target_ip = value
            elif field == "Target Hostname":
                hostname = value
            elif field == "Target Port":
                ports = [item.strip() for item in value.split(",") if item.strip()]
            elif field == "Server":
                server = value
            continue
        totals = NIKTO_TOTALS_RE.match(stripped)
        if totals is not None:
            raw_requests = totals.group("requests")
            if raw_requests:
                requests = to_int(raw_requests.replace(",", ""))
            items = to_int(totals.group("items").replace(",", ""))
            continue
        if NIKTO_NOISE_RE.match(stripped):
            continue
        body = stripped[1:].strip()
        if not body:
            continue
        if len(findings) < NIKTO_MAX_FINDINGS:
            findings.append(_split_finding(body))

    connected = bool(target_ip or hostname or server)
    return NiktoReport(
        target_ip=target_ip,
        hostname=hostname,
        ports=tuple(ports),
        server=server,
        findings=tuple(findings),
        requests=requests,
        items=items,
        connected=connected,
        raw_output_sha256=sha256_text(raw),
    )


__all__ = [
    "NIKTO_MAX_FINDINGS",
    "NiktoFinding",
    "NiktoReport",
    "parse_nikto_report",
]
