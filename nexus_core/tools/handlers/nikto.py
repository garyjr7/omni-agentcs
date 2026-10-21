"""Durable ``nexus.recon.nikto`` handler: web server scan *con* evasión gobernada.

Esta tool nace de ``RUN_sala12`` (THM *Intrusion Detection*): la sala enseña a
bajar el ruido de un escaneo web con las técnicas del propio nikto
(``-Tuning``, ``-evasion``, ``-Pause``, ``-useragent``) y a medir la reacción de
un NIDS. Antes de la tool el paso "nikto con tuning de evasión" sólo se podía
hacer a mano, fuera del scope firmado y sin auditoría (``V0-40``).

La tool **no** promete invisibilidad: lo que hace es (a) exponer los knobs de
evasión como argumentos validados —nunca flags libres—, (b) declarar el
``noise_level`` real y (c) guardar en evidencia los parámetros de evasión usados.
Medido en la sala: los espaciadores de petición (``-evasion 6,a,b``) y el UA falso
**no** reducen el número de peticiones; lo único que los baja de verdad es
``-Pause`` (ritmo) y ``-Tuning`` (menos familias de pruebas). Además el
User-Agent por defecto de nikto es una firma que el NIDS reconoce, así que el
handler acepta ``user_agent`` para romper esa firma concreta.

Toda la ejecución pasa por ``sandbox_for_environment`` (nunca lanza procesos el
propio handler) y por scope firmado + policy + audit como el resto de recon.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlsplit

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.tools.parsers.nikto import parse_nikto_report

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox

NIKTO_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS + ("nikto",)

NIKTO_DEFAULT_TIMEOUT_SECONDS = 900
NIKTO_MAX_TIMEOUT_SECONDS = 1800
NIKTO_DEFAULT_REQUEST_TIMEOUT = 10
NIKTO_MAX_REQUEST_TIMEOUT = 60
NIKTO_MAX_PAUSE_SECONDS = 30
NIKTO_MIN_MAXTIME_SECONDS = 30
NIKTO_MAX_MAXTIME_SECONDS = 1800
NIKTO_DEFAULT_MAXTIME_SECONDS = 600

#: Grupos de pruebas de nikto (``-Tuning``): ``x`` invierte la selección.
NIKTO_TUNING_CHARS = "0123456789abcx"
#: Evasión de IDS (``-evasion``): 1-8 codifican la URI, 6/A/B son *request
#: spacers* (TAB, CR, 0x0b) y ``R`` rota el User-Agent por petición.
NIKTO_EVASION_CHARS = "12345678ABR"
#: Flags que el handler fija por seguridad/opsec y que el modelo no puede cambiar.
NIKTO_MANAGED_FLAGS: tuple[str, ...] = (
    "-host",
    "-port",
    "-maxtime",
    "-nointeractive",
    "-nolookup",
    "-nocheck",
)

_TARGET_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]]+$")
_PORT_RE = re.compile(r"^\d{1,5}$")


def _validate_target(value: Any) -> str:
    """Return a host/IP target without shell metacharacters."""
    text = str(value or "").strip()
    if not text or len(text) > 255:
        raise ValueError("target is required and must be at most 255 characters")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise ValueError("target contains control characters")
    if not _TARGET_RE.fullmatch(text):
        raise ValueError(f"target contains unsupported characters: {text!r}")
    return text


def _parse_target(value: Any) -> tuple[str, str, bool]:
    """Return ``(host, port_from_url, secure)`` from a host or an http(s) URL.

    ``nexus.recon.nikto`` declares ``target`` as a host, but the model reads a
    port-80 service as ``http://host`` (run V10 against HackPark, 2026-10-21,
    iteration 9): the URL was rejected as "unsupported characters" and the turn
    was lost. The URL already carries host, port and TLS, so they are used
    instead of refused; a bare host keeps the strict character check.
    """
    text = str(value or "").strip()
    if "://" not in text:
        return _validate_target(text), "", False
    scheme = text.partition("://")[0].strip().lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"target scheme must be http or https: {scheme!r}")
    parts = urlsplit(text)
    host = str(parts.hostname or "")
    if not host:
        raise ValueError("target URL has no host")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = str(parts.port) if parts.port else ""
    except ValueError as exc:
        raise ValueError("target URL carries an invalid port") from exc
    if port and not _PORT_RE.fullmatch(port):
        raise ValueError(f"target URL carries an invalid port: {port!r}")
    port = port or ("443" if scheme == "https" else "80")
    return _validate_target(host), port, scheme == "https"


def _validate_ports(value: Any) -> str:
    """Return a canonical ``80,3000`` port list (order preserved, unique)."""
    if value in (None, ""):
        return ""
    raw = value if isinstance(value, (list, tuple)) else str(value).split(",")
    ports: list[str] = []
    for item in raw:
        token = str(item).strip()
        if not token:
            continue
        if not _PORT_RE.fullmatch(token) or not 1 <= int(token) <= 65535:
            raise ValueError(f"invalid port: {token!r}")
        if token not in ports:
            ports.append(token)
    if not ports:
        raise ValueError("ports must contain at least one port")
    if len(ports) > 16:
        raise ValueError("at most 16 ports per nikto run")
    return ",".join(ports)


def _validate_chars(value: Any, field: str, allowed: str) -> str:
    """Return a de-duplicated subset of ``allowed`` (nikto rejects the rest)."""
    if value in (None, ""):
        return ""
    if not isinstance(value, (str, list, tuple)):
        raise ValueError(f"{field} must be a string of option characters")
    raw = value if isinstance(value, str) else "".join(str(item) for item in value)
    token = raw.replace(",", "").strip()
    if not token:
        return ""
    invalid = sorted({ch for ch in token if ch not in allowed})
    if invalid:
        raise ValueError(f"invalid {field} characters: {''.join(invalid)} (allowed: {allowed})")
    ordered: list[str] = []
    for ch in token:
        if ch not in ordered:
            ordered.append(ch)
    return "".join(ordered)


def _validate_user_agent(value: Any) -> str:
    """Return a header-safe User-Agent string (no control characters)."""
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) > 255:
        raise ValueError("user_agent is too long")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise ValueError("user_agent contains control characters")
    return text


def nikto_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.nikto``."""
    return ToolDefinition(
        tool_id="nexus.recon.nikto",
        effect="read_only",
        name="Nikto web server scan with evasion",
        tenant_id=tenant_id,
        description=(
            "Escanea un servidor web con nikto y devuelve los hallazgos "
            "normalizados (id OSVDB/CVE, ruta y mensaje). Expone los controles de "
            "*evasión* de nikto como argumentos validados: tuning (familias de "
            "pruebas), evasion (codificación de URI y espaciadores de petición "
            "6/A/B), pause (ritmo entre pruebas) y user_agent (romper la firma del "
            "UA por defecto). Es ruidoso: noise_level siempre 'high'."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "ports": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                    "description": "Lista de puertos separados por comas (p. ej. \"80,3000\").",
                },
                "ssl": {"type": "boolean"},
                "tuning": {
                    "type": "string",
                    "maxLength": 16,
                    "description": "Caracteres de -Tuning (1-9, 0, a, b, c, x).",
                },
                "evasion": {
                    "type": "string",
                    "maxLength": 16,
                    "description": "Caracteres de -evasion (1-8, A, B, R). 6/A/B son espaciadores.",
                },
                "pause": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": NIKTO_MAX_PAUSE_SECONDS,
                    "description": "Segundos de pausa entre pruebas (-Pause): baja el ritmo real.",
                },
                "user_agent": {"type": "string", "maxLength": 255},
                "request_timeout": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": NIKTO_MAX_REQUEST_TIMEOUT,
                },
                "maxtime_seconds": {
                    "type": "integer",
                    "minimum": NIKTO_MIN_MAXTIME_SECONDS,
                    "maximum": NIKTO_MAX_MAXTIME_SECONDS,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": NIKTO_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.recon.nikto"],
        timeout_seconds=NIKTO_MAX_TIMEOUT_SECONDS,
        max_output_bytes=3_000_000,
        scope_target_field="target",
        scope_required=True,
    )


async def nikto_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run one allowlisted nikto scan through the sandbox and parse it."""
    target, url_port, url_secure = _parse_target(arguments.get("target"))
    ports = _validate_ports(arguments.get("ports")) or url_port
    ssl = bool(arguments.get("ssl", False)) or url_secure
    tuning = _validate_chars(arguments.get("tuning"), "tuning", NIKTO_TUNING_CHARS)
    evasion = _validate_chars(arguments.get("evasion"), "evasion", NIKTO_EVASION_CHARS)
    user_agent = _validate_user_agent(arguments.get("user_agent"))
    pause = min(
        NIKTO_MAX_PAUSE_SECONDS, max(0, int(arguments.get("pause") or 0))
    )
    request_timeout = min(
        NIKTO_MAX_REQUEST_TIMEOUT,
        max(1, int(arguments.get("request_timeout") or NIKTO_DEFAULT_REQUEST_TIMEOUT)),
    )
    requested_maxtime = arguments.get("maxtime_seconds")
    maxtime_seconds = min(
        NIKTO_MAX_MAXTIME_SECONDS,
        max(
            NIKTO_MIN_MAXTIME_SECONDS,
            int(requested_maxtime) if requested_maxtime else NIKTO_DEFAULT_MAXTIME_SECONDS,
        ),
    )
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        NIKTO_MAX_TIMEOUT_SECONDS,
        max(
            30,
            int(requested_timeout) if requested_timeout else NIKTO_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    # ``-nolookup``/``-nocheck`` are opsec defaults, not cosmetic: they stop the
    # scan from resolving external names and from phoning home for updates. Both
    # show up in the audit trail as handler-managed flags.
    argv = [
        "nikto",
        "-host",
        target,
        "-nointeractive",
        "-nolookup",
        "-nocheck",
        "-maxtime",
        f"{maxtime_seconds}s",
        "-timeout",
        str(request_timeout),
    ]
    if ports:
        argv.extend(["-port", ports])
    if ssl:
        argv.append("-ssl")
    if pause:
        argv.extend(["-Pause", str(pause)])
    if tuning:
        argv.extend(["-Tuning", tuning])
    if evasion:
        argv.extend(["-evasion", evasion])
    if user_agent:
        argv.extend(["-useragent", user_agent])

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = sandbox_for_environment(workspace_root, allowed_programs=NIKTO_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_NIKTO_IMAGE",
        default_image="ghcr.io/sullo/nikto",
    )

    # nikto is a signature-heavy scanner: the request volume is high regardless
    # of the obfuscation knobs, so the honest level is always "high" and the
    # evasion parameters travel separately in the evidence.
    noise_level = "high"
    warnings = [
        "nikto generates hundreds to thousands of requests: evasion does not lower volume"
    ]
    if not (pause or tuning):
        warnings.append("no -Pause/-Tuning: the loudest profile nikto can run")
    evidence: dict[str, Any] = {
        "target": target,
        "ports": ports or "80",
        "ssl": ssl,
        "tuning": tuning or None,
        "evasion": evasion or None,
        "pause_seconds": pause or None,
        "user_agent": user_agent or None,
        "maxtime_seconds": maxtime_seconds,
        "request_timeout": request_timeout,
        "timeout_seconds": timeout_seconds,
        "noise_level": noise_level,
        "managed_flags": list(NIKTO_MANAGED_FLAGS),
        "warnings": sorted(warnings),
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "nikto run timed out", "target": target, "noise_level": noise_level},
            verified=False,
            verification_method="nikto_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    try:
        report = parse_nikto_report(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "target": target},
            verified=False,
            verification_method="nikto_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    evidence.update(
        {
            "connected": report.connected,
            "count": len(report.findings),
            "requests": report.requests,
            "items": report.items,
            "server": report.server or None,
            "raw_output_sha256": report.raw_output_sha256,
        }
    )
    if not report.connected:
        # No ``Target IP``/``Hostname``/``Server`` line means nikto never got a
        # response: a declared negative instead of an empty "success".
        return ToolResult(
            output={
                "target": target,
                "ports": ports or "80",
                "noise_level": noise_level,
                "connected": False,
                "count": 0,
                "findings": [],
                "error": "nikto could not reach the target",
            },
            verified=False,
            verification_method="nikto_no_target",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    return ToolResult(
        output={
            "target": target,
            "ports": ports or "80",
            "server": report.server,
            "noise_level": noise_level,
            "evasion": evasion or None,
            "tuning": tuning or None,
            "count": len(report.findings),
            "requests": report.requests,
            "items": report.items,
            "findings": [finding.to_dict() for finding in report.findings],
        },
        verified=True,
        verification_method="nikto_text_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


__all__ = [
    "NIKTO_EVASION_CHARS",
    "NIKTO_TUNING_CHARS",
    "nikto_definition",
    "nikto_handler",
]
