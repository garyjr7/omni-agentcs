"""Human-readable CLI errors.

Provider SDKs put request/response bodies in ``str(exc)``.  A 401 from OpenAI
therefore reaches the REPL as ``Error code: 401 - {'error': {...}}``, which is a
diagnostic for a log, not something an operator should have to read.  This
module is the single translation point: it classifies the failure, keeps the
useful provider/status information and returns actionable Spanish prose.

The raw exception is never rendered.  It is still available to the logger and
the durable audit trail through the caller.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Sequence

from . import render

_AUTH_CODES = frozenset({401, 403})
_RATE_CODES = frozenset({429})
_QUOTA_CODES = frozenset({402})
_UNAVAILABLE_CODES = frozenset({500, 502, 503})
_TIMEOUT_CODES = frozenset({408, 504})

_RAW_PAYLOAD_MARKERS = ("{", "}", '"error"', "Error code:", "body=", "response=")


@dataclass(frozen=True)
class UserError:
    """The text the operator sees for one failure."""

    title: str
    summary: str
    hints: tuple[str, ...] = ()

    def lines(self) -> tuple[str, ...]:
        return (self.summary, *self.hints)


def _causes(exc: BaseException) -> list[BaseException]:
    """The exception and its wrapped causes, without cycles."""
    seen: set[int] = set()
    current: BaseException | None = exc
    result: list[BaseException] = []
    while current is not None and id(current) not in seen and len(result) < 8:
        seen.add(id(current))
        result.append(current)
        current = current.__cause__ or current.__context__
    return result


def _status_code(exc: BaseException) -> int | None:
    """HTTP status carried by the exception or any wrapped cause."""
    for item in _causes(exc):
        raw = getattr(item, "status_code", None)
        if isinstance(raw, int):
            return raw
        response = getattr(item, "response", None)
        raw = getattr(response, "status_code", None)
        if isinstance(raw, int):
            return raw
    return None


def _chain_causes(exc: BaseException) -> list[dict[str, Any]]:
    """``LLMChainExhausted.causes`` without importing the LLM layer eagerly."""
    try:
        from nexus_core.llm.abstraction import LLMChainExhausted

        if isinstance(exc, LLMChainExhausted):
            return [dict(cause) for cause in exc.causes]
    except Exception:  # noqa: BLE001 - this module must work without the SDK
        return []
    return []


def _provider_names(exc: BaseException) -> str:
    """Human label of the provider(s) involved, when it is known."""
    names = [
        str(cause.get("provider") or "").strip()
        for cause in _chain_causes(exc)
        if str(cause.get("provider") or "").strip()
    ]
    if names:
        return ", ".join(dict.fromkeys(names))
    config = getattr(exc, "config", None)
    provider = getattr(config, "provider", None)
    value = getattr(provider, "value", provider)
    return str(value or "").strip()


def _message(exc: BaseException) -> str:
    """A short provider message, or an empty string when it is a raw payload."""
    if _chain_causes(exc):
        # The chain already gives us the provider, status and failure class.
        # Its cause messages can still contain the SDK body, so do not use them.
        return ""
    raw = " ".join(str(exc or "").split())
    if not raw or any(marker in raw for marker in _RAW_PAYLOAD_MARKERS):
        return ""
    return raw[:240]


def _status_from_text(text: str) -> int | None:
    match = re.search(r"\b(401|402|403|408|429|500|502|503|504)\b", str(text or ""))
    if match:
        return int(match.group(1))
    lowered = str(text or "").lower()
    if "authentication" in lowered or "unauthorized" in lowered:
        return 401
    if "rate limit" in lowered or "too many requests" in lowered:
        return 429
    return None


def clean_detail(text: Any, *, limit: int = 240) -> str:
    """Sanitize a provider/tool string for a transcript.

    JSON/YAML-ish payloads and SDK ``Error code:`` wrappers are dropped.  The
    caller may still log the original object; this function is only for text
    that reaches a human.
    """
    raw = " ".join(str(text or "").split())
    if not raw or any(marker in raw for marker in _RAW_PAYLOAD_MARKERS):
        return ""
    return raw[:limit]


def _build(
    *,
    status: int | None,
    detail: str,
    provider: str,
    operation: str,
) -> UserError:
    lowered = detail.lower()
    who = provider or "el proveedor"

    if status in _AUTH_CODES:
        return UserError(
            "⚠️ Error de autenticación",
            f"{who.capitalize()} rechazó la API key"
            + (f" (HTTP {status})." if status else "."),
            (
                "La clave puede haber expirado, estar revocada o no tener permisos.",
                "Actualízala con: omni auth login <proveedor>",
                "Después reintenta la consulta o repite el objetivo.",
            ),
        )

    if status in _QUOTA_CODES or (
        status in _RATE_CODES
        and any(word in lowered for word in ("quota", "billing", "credit", "balance"))
    ):
        return UserError(
            "⚠️ Cuota del proveedor agotada",
            f"{who.capitalize()} no tiene cuota o saldo disponible"
            + (f" (HTTP {status})." if status else "."),
            (
                "Revisa el plan, el saldo o la facturación de tu cuenta.",
                "Cuando la cuenta vuelva a tener cuota, reintenta la operación.",
            ),
        )

    if status in _RATE_CODES:
        return UserError(
            "⚠️ Límite de peticiones alcanzado",
            f"{who.capitalize()} pidió esperar antes de aceptar otra petición (HTTP 429).",
            (
                "Espera unos segundos y reintenta; el límite suele ser por minuto.",
                "Si persiste, revisa el plan o la cuota de tu cuenta.",
            ),
        )

    if status in _TIMEOUT_CODES or "timeout" in lowered or "timed out" in lowered:
        return UserError(
            "⚠️ El proveedor no respondió a tiempo",
            f"No llegó respuesta de {who} antes del límite de tiempo.",
            (
                "Revisa tu conexión, el proxy y la URL base del proveedor.",
                "Si el problema continúa, cambia de proveedor o modelo.",
            ),
        )

    if status in _UNAVAILABLE_CODES:
        return UserError(
            "⚠️ El proveedor no está disponible",
            f"{who.capitalize()} devolvió un error temporal"
            + (f" (HTTP {status})." if status else "."),
            (
                "Reintenta en unos minutos.",
                "Si tienes una cadena de fallback configurada, Omni ya intentó el siguiente proveedor.",
            ),
        )

    if (
        isinstance(status, int)
        and status not in {*_AUTH_CODES, *_QUOTA_CODES, *_RATE_CODES, *_TIMEOUT_CODES, *_UNAVAILABLE_CODES}
        and "json" in lowered
    ):
        return UserError(
            "⚠️ Respuesta inválida del modelo",
            "El modelo respondió algo que no es JSON válido.",
            (
                "Omni no pudo interpretar la acción; reintenta la consulta.",
                "Si se repite, cambia de modelo o de proveedor.",
            ),
        )

    if "invalid json" in lowered or "json inválido" in lowered:
        return UserError(
            "⚠️ Respuesta inválida del modelo",
            "El modelo respondió algo que no es JSON válido.",
            (
                "Omni no pudo interpretar la acción; reintenta la consulta.",
                "Si se repite, cambia de modelo o de proveedor.",
            ),
        )

    if (
        "api key" in lowered
        or "no llm provider configured" in lowered
        or "provider not configured" in lowered
    ):
        return UserError(
            "⚠️ Configuración del proveedor incompleta",
            "Falta una API key o no hay un proveedor por defecto configurado.",
            (
                "Configura una clave con: omni auth login <proveedor>",
                "O revisa las variables de entorno y ejecuta: omni doctor",
            ),
        )

    if "connection" in lowered or "connect" in lowered or "network" in lowered:
        return UserError(
            "⚠️ No se pudo contactar al proveedor",
            f"No se pudo abrir una conexión con {who}.",
            (
                "Revisa tu conexión, el proxy y el firewall.",
                "Si usas un endpoint compatible, comprueba su URL base.",
            ),
        )

    summary = f"No se pudo completar {operation}."
    if detail:
        summary = f"{summary} {detail}"
    return UserError(
        "⚠️ Error del proveedor",
        summary,
        (
            "Ejecuta `omni doctor` para revisar configuración y conectividad.",
            "Si el fallo apareció tras caducar o cambiar una clave, ejecuta: omni auth login <proveedor>",
            "El detalle técnico completo está en el log; no se muestra aquí para evitar volcar JSON del proveedor.",
        ),
    )


def describe_error(exc: BaseException, *, operation: str = "la operación") -> UserError:
    """Translate one exception into an actionable, JSON-free message."""
    detail = _message(exc)
    return _build(
        status=_status_code(exc) or _status_from_text(detail),
        detail=detail,
        provider=_provider_names(exc),
        operation=operation,
    )


def describe_provider_failure(detail: Any, *, operation: str = "la operación") -> UserError:
    """Translate a terminal ``provider_error`` summary from the run result.

    The ReAct coordinator deliberately stores a short terminal summary, not the
    provider exception.  This still recognizes the common status/class text so
    a failed run gets the same clean panel as ``/ask``.
    """
    text = clean_detail(detail)
    return _build(
        status=_status_from_text(text),
        detail=text,
        provider="",
        operation=operation,
    )


def _show(session: Any, error: UserError) -> None:
    tui = getattr(session, "_tui", None) if session is not None else None
    if getattr(tui, "use_tui", False):
        from .tui.presentation import error_panel

        width = int(getattr(tui, "text_width", 100) or 100)
        tui.append_scrollback(
            error_panel(
                error.title,
                list(error.lines()),
                width=width,
                no_color=bool(getattr(session, "no_color", False)),
            )
            + "\n\n"
        )
        return
    render.write(render.paint(error.title, render.RED, render.BOLD))
    for line in error.lines():
        render.write(f"  {line}")


def report_error(
    session: Any,
    exc: BaseException,
    *,
    operation: str = "la operación",
) -> UserError:
    """Render ``exc`` as a clean panel (TUI) or a short block (plain CLI)."""
    error = describe_error(exc, operation=operation)
    _show(session, error)
    return error


def report_provider_failure(
    session: Any,
    detail: Any,
    *,
    operation: str = "el objetivo",
) -> UserError:
    """Render a terminal provider failure that arrived as a result summary."""
    error = describe_provider_failure(detail, operation=operation)
    _show(session, error)
    return error


def report_plain_error(
    exc: BaseException,
    *,
    operation: str = "la operación",
) -> UserError:
    """Render an error before a session exists (provider construction, CLI)."""
    error = describe_error(exc, operation=operation)
    _show(None, error)
    return error


__all__: Sequence[str] = (
    "UserError",
    "clean_detail",
    "describe_error",
    "describe_provider_failure",
    "report_error",
    "report_plain_error",
    "report_provider_failure",
)
