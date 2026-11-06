"""Registro cerrado de parsers de salida para ``nexus.system.execute_and_parse``.

El agente no elige un parser libre: ``parser_name`` tiene que ser uno de
:data:`PARSER_NAMES`. Un registro cerrado mantiene la observación estable y
auditable — el contrato de datos no puede cambiar porque el modelo invente un
nombre — y permite añadir un parser nuevo sin tocar el handler.

Cada parser recibe el **stdout completo** (el artifact del shell, nunca el
resumen de 60 líneas) y devuelve un ``dict`` JSON-serializable con la clave
``parser``. ``summarize`` produce la línea corta que lee el humano en el TUI.
"""

from __future__ import annotations

from typing import Any, Callable

from . import nmap, text

#: Versión del contrato de parseo propio de este registro. Distinta de
#: ``nexus_core.tools.parsers.PARSERS_VERSION`` (el parseo de las tools fijas):
#: esta cubre lo que el modelo pide parsear en tiempo de ejecución.
OUTPUT_PARSERS_VERSION = "1.0.0"

#: El registro. Añadir un parser es añadirlo aquí, nunca aceptar un nombre
#: arbitrario desde los argumentos de la tool.
PARSERS: dict[str, Callable[[str], dict[str, Any]]] = {
    nmap.PARSER_NAME: nmap.parse,
    text.PARSER_NAME: text.parse,
}

#: Nombres aceptados por ``parser_name`` (lo que el prompt puede anunciar).
PARSER_NAMES: tuple[str, ...] = tuple(sorted(PARSERS))


def parse_output(parser_name: str, raw: str) -> dict[str, Any]:
    """Parse *raw* with the closed registry; raises ``ValueError`` if unknown.

    The message names every accepted parser so the next turn can correct itself
    instead of guessing a second invented name.
    """
    parser = PARSERS.get(str(parser_name or "").strip().lower())
    if parser is None:
        raise ValueError(
            f"unknown parser '{parser_name}'; known parsers: {', '.join(PARSER_NAMES)}"
        )
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("there is no output to parse")
    return parser(raw)


def summarize(parsed: dict[str, Any]) -> str:
    """One human line about *parsed* (never an exception)."""
    name = str(parsed.get("parser") or "")
    if name == nmap.PARSER_NAME:
        return nmap.summary(parsed)
    if name == text.PARSER_NAME:
        return text.summary(parsed)
    return f"{len(parsed)} campo(s) parseados"


__all__ = [
    "OUTPUT_PARSERS_VERSION",
    "PARSERS",
    "PARSER_NAMES",
    "parse_output",
    "summarize",
]
