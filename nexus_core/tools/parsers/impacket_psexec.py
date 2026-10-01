"""Parser de la salida de psexec de Impacket → estructura estable.

``psexec.py`` (basado en RemComSvc) ejecuta un comando remoto y devuelve su
salida. El parser no interpreta un intérprete interactivo: conserva las líneas
observadas y su fingerprint, sin inventar sesiones ni procesos.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._jsonl import sha256_text


@dataclass(frozen=True)
class PsExecResult:
    """Resultado normalizado de una ejecución de psexec."""

    command: str
    lines: tuple[str, ...]
    connected: bool
    raw_output_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the result."""
        return {
            "command": self.command,
            "line_count": len(self.lines),
            "connected": self.connected,
            "lines": list(self.lines),
            "raw_output_sha256": self.raw_output_sha256,
        }


def parse_psexec_output(text: str, command: str = "") -> PsExecResult:
    """Parse psexec output: keep the observed lines verbatim.

    Empty output is a valid "command produced nothing" outcome.
    """
    if not isinstance(text, str) or not text.strip():
        return PsExecResult(
            command=command, lines=(), connected=False, raw_output_sha256=sha256_text("")
        )
    lines = tuple(line.rstrip() for line in text.splitlines() if line.strip())
    return PsExecResult(
        command=command,
        lines=lines,
        connected=bool(lines),
        raw_output_sha256=sha256_text(text),
    )
