"""Parser ``text`` de ``nexus.system.execute_and_parse``.

El caso que no tiene schema: salida de una herramienta sin parser propio. No
inventa estructura — cuenta líneas y entrega una vista acotada, dejando el
volcado completo en el artifact del shell.
"""

from __future__ import annotations

import re
from typing import Any

PARSER_NAME = "text"

#: Máximo de líneas que viajan en la observación. El artifact conserva todas.
MAX_LINES = 200

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def parse(raw: str) -> dict[str, Any]:
    """Split *raw* into stripped lines and a bounded preview."""
    cleaned = _ANSI_RE.sub("", str(raw or ""))
    lines = [line.rstrip() for line in cleaned.splitlines()]
    non_empty = [line for line in lines if line.strip()]
    return {
        "parser": PARSER_NAME,
        "line_count": len(lines),
        "non_empty_line_count": len(non_empty),
        "preview": non_empty[:MAX_LINES],
        "truncated": len(non_empty) > MAX_LINES,
    }


def summary(parsed: dict[str, Any]) -> str:
    """``42 líneas`` — the count is the honest fact about an unknown schema."""
    total = int(parsed.get("non_empty_line_count") or 0)
    body = f"{total} línea(s)"
    preview = parsed.get("preview") or []
    if preview:
        first = " ".join(str(preview[0]).split())
        if first:
            body += f" · {first[:80]}"
    return body


__all__ = ["MAX_LINES", "PARSER_NAME", "parse", "summary"]
