"""Parser determinista de la salida de NetExec (nxc) → estructura estable.

NetExec no ofrece JSON estable. El parser reconoce la línea canónica
``PROTOCOLO  host  puerto  [hostname]  mensaje`` que emite por host, y separa
los mensajes de estado (``[*]``/``[+]``/``[-]``) de las filas de enumeración
(shares, usuarios, grupos, sesiones, discos). Nunca inventa hallazgos: guarda
el texto observado tal cual, sin reconstruirlo.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ._jsonl import sha256_text

_PROTOCOLS = frozenset(
    {"SMB", "LDAP", "WINRM", "MSSQL", "SSH", "RDP", "FTP", "WMI", "NFS", "VNC"}
)
_ROW_RE = re.compile(
    r"^(?P<proto>[A-Z]+)\s+(?P<target>\S+)\s+(?P<port>\d+)(?:\s+(?P<rest>.*))?$"
)
_STATUS_RE = re.compile(r"^\[(?P<mark>[*+\-!])\]\s*(?P<text>.*)$")


@dataclass(frozen=True)
class NetExecEntry:
    """Una línea interpretada de NetExec."""

    protocol: str
    target: str
    port: int
    host: str
    kind: str
    mark: str
    text: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the entry."""
        return {
            "protocol": self.protocol,
            "target": self.target,
            "port": self.port,
            "host": self.host,
            "kind": self.kind,
            "mark": self.mark,
            "text": self.text,
        }


@dataclass(frozen=True)
class NetExecResult:
    """Resultado normalizado de una ejecución de NetExec."""

    protocol: str
    entries: tuple[NetExecEntry, ...]
    targets: tuple[str, ...]
    raw_output_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "protocol": self.protocol,
            "count": len(self.entries),
            "targets": list(self.targets),
            "entries": [entry.to_dict() for entry in self.entries],
            "raw_output_sha256": self.raw_output_sha256,
        }


def empty_netexec_result(protocol: str = "smb") -> NetExecResult:
    """Return an empty result (no parseable line)."""
    return NetExecResult(
        protocol=protocol,
        entries=(),
        targets=(),
        raw_output_sha256=sha256_text(""),
    )


def parse_netexec_output(text: str, protocol: str = "smb") -> NetExecResult:
    """Parse NetExec text output into a :class:`NetExecResult`.

    Empty output is a valid "nothing observed" outcome; banner and progress
    noise is skipped because it does not match the row grammar.
    """
    if not isinstance(text, str) or not text.strip():
        return empty_netexec_result(protocol)

    entries: list[NetExecEntry] = []
    targets: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        match = _ROW_RE.match(line)
        if match is None or match.group("proto") not in _PROTOCOLS:
            continue
        target = match.group("target")
        if target not in targets:
            targets.append(target)
        rest = (match.group("rest") or "").strip()
        host = ""
        message = rest
        if rest and not rest.startswith("["):
            parts = rest.split(maxsplit=1)
            host = parts[0]
            message = parts[1] if len(parts) > 1 else ""
        status = _STATUS_RE.match(message)
        if status is not None:
            entries.append(
                NetExecEntry(
                    protocol=match.group("proto"),
                    target=target,
                    port=int(match.group("port")),
                    host=host,
                    kind="status",
                    mark=status.group("mark"),
                    text=status.group("text").strip(),
                )
            )
        elif message:
            entries.append(
                NetExecEntry(
                    protocol=match.group("proto"),
                    target=target,
                    port=int(match.group("port")),
                    host=host,
                    kind="entry",
                    mark="",
                    text=message,
                )
            )
    return NetExecResult(
        protocol=protocol,
        entries=tuple(entries),
        targets=tuple(targets),
        raw_output_sha256=sha256_text(text),
    )
