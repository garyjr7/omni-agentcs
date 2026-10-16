"""Durable ``nexus.post.pivot_bruteforce``: credentials for a *pivoted* service.

The "Internal" assessment turned up a Jenkins instance listening on
``127.0.0.1:8080`` (and ``172.17.0.2:8080`` from the host's Docker bridge) — a
service that is **not** reachable from the operator's host at all, only from
inside the compromised box. That is the normal shape of an internal assessment,
and OMNI had no primitive for it:

* ``nexus.web.request`` / ``nexus.web.wp_bruteforce`` cannot reach it, and
  widening the engagement's external scope to ``127.0.0.1`` would authorise the
  *operator's* loopback, which is a different (and wrong) thing.
* A local port-forward cannot be owned by a tool invocation: the sandbox kills
  its process group when the call returns, so a tunnel started inside a handler
  is dead before the next tool runs.

The honest model is therefore the one this tool implements: **the request is
made from the authorised host**. The tool logs in over SSH (the scoped,
authorised primitive), uploads a wordlist slice and a tiny stdlib client over
SFTP, runs the credential attack *on the target*, cleans the artefacts up and
returns the validated credential. Nothing ever connects to the pivoted service
from the operator's machine, so the scope stays exactly as signed: one SSH host.

It is the internal-service counterpart of ``nexus.cred.bruteforce`` and it
deliberately sends **one credential per request** (a form login is stateful; see
``.handlers._wp`` for the WordPress lesson on why batching credential attempts
against a stateful endpoint produces silent false negatives).
"""

from __future__ import annotations

from nexus_core.tools.output_files import read_output_text

import json
import os
import re
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox, safe_run_id
from ._pivot import PIVOT_CLIENT_SCRIPT, PIVOT_HTTP_REMOTE_SCRIPT, PIVOT_REMOTE_SCRIPT
from .ffuf import resolve_wordlist
from .workspace import workspace_root

PIVOT_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS

PIVOT_DEFAULT_SSH_PORT = 22
PIVOT_DEFAULT_WORKERS = 10
PIVOT_MAX_WORKERS = 40
PIVOT_DEFAULT_ATTEMPTS = 2_000
PIVOT_MAX_ATTEMPTS = 200_000
PIVOT_DEFAULT_TIMEOUT_SECONDS = 600
PIVOT_MAX_TIMEOUT_SECONDS = 1800
PIVOT_MAX_FIELDS = 10
PIVOT_MAX_MARKER_CHARS = 200


def pivot_bruteforce_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.pivot_bruteforce``."""
    return ToolDefinition(
        tool_id="nexus.post.pivot_bruteforce",
        effect="pivoting",
        name="Credential attack against a pivoted service",
        tenant_id=tenant_id,
        description=(
            "Con una credencial SSH ya validada, ataca un formulario HTTP que "
            "solo es alcanzable desde dentro del host (p. ej. Jenkins en "
            "127.0.0.1:8080): sube la wordlist por SFTP, prueba una contraseña "
            "por petición en el objetivo y devuelve la credencial validada. "
            "HIGH: requiere aprobación."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "minLength": 1, "maxLength": 256},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "form_url": {"type": "string", "minLength": 8, "maxLength": 512},
                "session_url": {
                    "type": "string", "minLength": 8, "maxLength": 512,
                    "description": (
                        "Página que se visita primero para obtener la cookie de "
                        "sesión y los campos ocultos del formulario (por defecto, "
                        "form_url). Sin sesión, muchos servidores responden 403 a "
                        "TODOS los intentos."
                    ),
                },
                "form_username": {"type": "string", "minLength": 1, "maxLength": 128},
                "form_user_field": {"type": "string", "minLength": 1, "maxLength": 64},
                "form_pass_field": {"type": "string", "minLength": 1, "maxLength": 64},
                "extra_fields": {
                    "type": "object",
                    "maxProperties": PIVOT_MAX_FIELDS,
                    "additionalProperties": {"type": "string", "maxLength": 256},
                },
                "failure_marker": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": PIVOT_MAX_MARKER_CHARS,
                    "description": (
                        "Texto que aparece en la respuesta cuando la credencial "
                        "es RECHAZADA (p. ej. 'Invalid username or password'). "
                        "Verificarlo en preflight evita declarar éxito contra un "
                        "servicio que rechaza todo."
                    ),
                },
                "success_marker": {
                    "type": "string",
                    "maxLength": PIVOT_MAX_MARKER_CHARS,
                    "description": "Texto que debe aparecer en una respuesta aceptada.",
                },
                "password_file": {"type": "string", "minLength": 1, "maxLength": 1024},
                "offset": {"type": "integer", "minimum": 0, "maximum": PIVOT_MAX_ATTEMPTS},
                "max_attempts": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": PIVOT_MAX_ATTEMPTS,
                },
                "workers": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": PIVOT_MAX_WORKERS,
                    "description": "Hilos del cliente remoto (1 intento por petición).",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": PIVOT_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": [
                "target",
                "username",
                "password",
                "form_url",
                "form_username",
                "failure_marker",
                "password_file",
            ],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        required_permissions=["execute:tool:nexus.post.pivot_bruteforce"],
        timeout_seconds=PIVOT_MAX_TIMEOUT_SECONDS,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def _slice_wordlist(source: str, dest: str, offset: int, limit: int) -> int:
    """Copy ``limit`` non-empty lines of ``source`` starting at ``offset``."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    count = 0
    with open(source, encoding="utf-8", errors="replace") as reader, open(
        dest, "w", encoding="utf-8"
    ) as writer:
        for index, line in enumerate(reader):
            if index < offset:
                continue
            token = line.rstrip("\r\n")
            if not token:
                continue
            writer.write(token + "\n")
            count += 1
            if count >= limit:
                break
    return count


def _text(value: Any, field: str, *, max_length: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    if len(text) > max_length:
        raise ValueError(f"{field} is too long")
    if any(ord(ch) < 0x20 for ch in text):
        raise ValueError(f"{field} contains control characters")
    return text


async def pivot_bruteforce_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Attack an internal HTTP form through an authorised SSH host."""
    target = _text(arguments.get("target"), "target", max_length=255)
    ssh_username = _text(arguments.get("username"), "username", max_length=128)
    ssh_password = str(arguments.get("password") or "")
    if not ssh_password:
        raise ValueError("password is required")
    form_url = _text(arguments.get("form_url"), "form_url", max_length=512)
    if not form_url.lower().startswith(("http://", "https://")):
        raise ValueError("form_url must be http(s)")
    form_username = _text(arguments.get("form_username"), "form_username", max_length=128)
    failure_marker = _text(
        arguments.get("failure_marker"), "failure_marker", max_length=PIVOT_MAX_MARKER_CHARS
    )
    success_marker = str(arguments.get("success_marker") or "")[:PIVOT_MAX_MARKER_CHARS]

    extra_fields = arguments.get("extra_fields") or {}
    if not isinstance(extra_fields, dict):
        raise TypeError("extra_fields must be an object")
    if len(extra_fields) > PIVOT_MAX_FIELDS:
        raise ValueError("too many extra_fields")
    extra_fields = {str(key): str(value) for key, value in extra_fields.items()}

    port = int(arguments.get("port") or PIVOT_DEFAULT_SSH_PORT)
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    workers = min(PIVOT_MAX_WORKERS, max(1, int(arguments.get("workers") or PIVOT_DEFAULT_WORKERS)))
    offset = max(0, int(arguments.get("offset") or 0))
    max_attempts = min(
        PIVOT_MAX_ATTEMPTS,
        max(1, int(arguments.get("max_attempts") or PIVOT_DEFAULT_ATTEMPTS)),
    )
    requested = arguments.get("timeout_seconds")
    timeout_seconds = min(
        PIVOT_MAX_TIMEOUT_SECONDS,
        max(30, int(requested) if requested else PIVOT_DEFAULT_TIMEOUT_SECONDS),
    )

    root = workspace_root()
    source = resolve_wordlist(root, str(arguments.get("password_file") or ""))
    run_id = safe_run_id(context)
    run_dir = Path(root) / f"pivot_{run_id}"
    wordlist_path = run_dir / "wordlist.txt"
    progress_path = run_dir / "progress.ndjson"
    result_path = run_dir / "result.json"
    for stale in (progress_path, result_path):
        try:
            stale.unlink(missing_ok=True)
        except OSError:
            pass
    attempts = _slice_wordlist(source, str(wordlist_path), offset, max_attempts)
    if attempts == 0:
        raise ValueError("password_file has no usable entries at that offset")

    session_url = str(arguments.get("session_url") or "").strip() or None
    if session_url and not session_url.lower().startswith(("http://", "https://")):
        raise ValueError("session_url must be http(s)")

    payload = {
        "form_url": form_url,
        "session_url": session_url,
        "form_username": form_username,
        "user_field": str(arguments.get("form_user_field") or "j_username"),
        "pass_field": str(arguments.get("form_pass_field") or "j_password"),
        "extra_fields": extra_fields,
        "failure_marker": failure_marker,
        "success_marker": success_marker,
        "workers": workers,
        "progress_path": str(progress_path),
        "result_path": str(result_path),
        "wordlist_path": str(wordlist_path),
    }
    argv = [
        "python3",
        "-c",
        PIVOT_CLIENT_SCRIPT,
        target,
        str(port),
        ssh_username,
        ssh_password,
        json.dumps(payload),
        PIVOT_REMOTE_SCRIPT,
        # The client clamps this for the remote exec_command; it must stay
        # below the sandbox timeout so the client can still clean up.
        str(float(max(30, timeout_seconds - 20))),
    ]
    sandbox = sandbox_for_environment(root, allowed_programs=PIVOT_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=float(timeout_seconds),
        image_env="NEXUS_SSH_IMAGE",
        default_image="python:3.12-alpine",
    )

    outcome = _last_json_object(result.stdout)
    if outcome is None and result_path.exists():
        try:
            outcome = json.loads(read_output_text(result_path))
        except (OSError, ValueError):
            outcome = None

    evidence: dict[str, Any] = {
        "noise_level": "high",
        "target": target,
        "form_url": form_url,
        "form_username": form_username,
        "attempts": attempts,
        "offset": offset,
        "workers": workers,
        "wordlist": source,
        "timeout_seconds": timeout_seconds,
        # The pivoted endpoint is reached from the authorised host, never from
        # the operator's machine, so the signed scope is unchanged.
        "reachable_from": "target",
    }
    if outcome is None:
        return ToolResult(
            output={
                "error": "pivot bruteforce produced no result",
                "target": target,
                "form_url": form_url,
                "attempts": attempts,
            },
            verified=False,
            # ``_unavailable`` is the gateway's provider-failure vocabulary: the
            # harness never produced a verdict, which is a broken transport (or a
            # broken image), not a "no credentials" answer.
            verification_method="pivot_bruteforce_unavailable",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
        )

    evidence.update(
        {
            "session": outcome.get("session"),
            "statuses": outcome.get("statuses"),
            "tested": outcome.get("tested"),
            "elapsed_seconds": outcome.get("elapsed_seconds"),
            "rate_per_second": outcome.get("rate_per_second"),
            "preflight": outcome.get("preflight"),
            "errors": (outcome.get("errors") or [])[:5],
        }
    )
    found = outcome.get("password")
    validated = bool(found) and bool((outcome.get("verification") or {}).get("ok"))
    preflight_ok = bool((outcome.get("preflight") or {}).get("ok"))
    walled = any("rejected before" in str(item) for item in outcome.get("errors") or ())
    if validated:
        # The credential exists: the post-condition of the attack is met.
        verified = True
        method = "pivot_credential_validated"
    elif preflight_ok and not walled:
        # A completed sweep against a form that provably rejects a wrong
        # password is a trustworthy NEGATIVE: the post-condition is the sweep,
        # and ``valid_credentials`` stays empty either way.
        verified = True
        method = "pivot_bruteforce_completed"
    else:
        # Never let "nothing found" hide an untested sweep: the endpoint was
        # rejected at transport level (CSRF, session, wrong action URL) or the
        # rejection marker does not describe this form.
        verified = False
        method = "pivot_bruteforce_unavailable"
    return ToolResult(
        output={
            "target": target,
            "form_url": form_url,
            "form_username": form_username,
            "session": outcome.get("session"),
            "statuses": outcome.get("statuses"),
            "tested": outcome.get("tested"),
            "total": outcome.get("total"),
            "rate_per_second": outcome.get("rate_per_second"),
            "elapsed_seconds": outcome.get("elapsed_seconds"),
            "preflight": outcome.get("preflight"),
            "valid_credentials": (
                [{"username": form_username, "password": found, "service": "http-pivot"}]
                if validated
                else []
            ),
            "preflight_ok": preflight_ok,
            "transport_rejected_every_attempt": walled,
            "verification": outcome.get("verification"),
            "errors": (outcome.get("errors") or [])[:5],
        },
        verified=verified,
        verification_method=method,
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
        timed_out=result.timed_out,
    )


def _last_json_object(text: str) -> dict[str, Any] | None:
    """Return the last JSON object printed on ``text`` (client stdout)."""
    for line in reversed((text or "").strip().splitlines()):
        candidate = line.strip()
        if not candidate.startswith("{"):
            continue
        try:
            payload = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def pivot_http_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.pivot_http``."""
    return ToolDefinition(
        tool_id="nexus.post.pivot_http",
        effect="pivoting",
        name="HTTP request from a compromised host",
        tenant_id=tenant_id,
        description=(
            "Hace UNA petición HTTP *desde* un host ya comprometido, con "
            "sesión persistida (login de formulario, cookie y token CSRF), para "
            "alcanzar aplicaciones internas (p. ej. consola de scripts de "
            "Jenkins en 127.0.0.1:8080). Devuelve estado, cabecera Location y "
            "cuerpo acotado. HIGH: requiere aprobación."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "minLength": 1, "maxLength": 256},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "url": {"type": "string", "minLength": 8, "maxLength": 512},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "HEAD"]},
                "body": {"type": "string", "maxLength": 65536},
                "content_type": {"type": "string", "maxLength": 128},
                "headers": {
                    "type": "object",
                    "maxProperties": PIVOT_MAX_FIELDS,
                    "additionalProperties": {"type": "string", "maxLength": 512},
                },
                "session_url": {"type": "string", "maxLength": 512},
                "login_url": {"type": "string", "maxLength": 512},
                "login_username": {"type": "string", "maxLength": 128},
                "login_password": {"type": "string", "maxLength": 256},
                "login_user_field": {"type": "string", "maxLength": 64},
                "login_password_field": {"type": "string", "maxLength": 64},
                "login_extra_fields": {
                    "type": "object",
                    "maxProperties": PIVOT_MAX_FIELDS,
                    "additionalProperties": {"type": "string", "maxLength": 256},
                },
                "login_failure_marker": {
                    "type": "string",
                    "maxLength": PIVOT_MAX_MARKER_CHARS,
                    "description": (
                        "Texto que aparece cuando el login es RECHAZADO; si se "
                        "indica, el handler aborta en vez de enviar la petición "
                        "sin sesión."
                    ),
                },
                "token_url": {
                    "type": "string",
                    "maxLength": 512,
                    "description": "URL (con sesión) de la que extraer un token CSRF.",
                },
                "token_field": {"type": "string", "maxLength": 64},
                "token_header": {"type": "string", "maxLength": 64},
                "max_body_bytes": {"type": "integer", "minimum": 256, "maximum": 200000},
                "request_timeout": {"type": "integer", "minimum": 5, "maximum": 120},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": PIVOT_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["target", "username", "password", "url"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        required_permissions=["execute:tool:nexus.post.pivot_http"],
        timeout_seconds=PIVOT_MAX_TIMEOUT_SECONDS,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def _http_config(arguments: dict) -> dict[str, Any]:
    """Validate and normalize the request/ session description."""
    url = _text(arguments.get("url"), "url", max_length=512)
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("url must be http(s)")
    method = str(arguments.get("method") or "GET").upper()
    if method not in {"GET", "POST", "PUT", "HEAD"}:
        raise ValueError("unsupported method")
    for field in ("session_url", "login_url", "token_url"):
        value = str(arguments.get(field) or "").strip()
        if value and not value.lower().startswith(("http://", "https://")):
            raise ValueError(f"{field} must be http(s)")
    headers = arguments.get("headers") or {}
    if not isinstance(headers, dict):
        raise TypeError("headers must be an object")
    if len(headers) > PIVOT_MAX_FIELDS:
        raise ValueError("too many headers")
    for key, value in headers.items():
        # Header injection guard: a newline would let the model add its own
        # request line or extra headers.
        if not re.fullmatch(r"[A-Za-z0-9-]+", str(key)) or "\n" in str(value) or "\r" in str(value):
            raise ValueError("invalid header")
    return {
        "url": url,
        "method": method,
        "body": str(arguments.get("body") or ""),
        "content_type": str(arguments.get("content_type") or ""),
        "headers": {str(k): str(v) for k, v in headers.items()},
        "session_url": str(arguments.get("session_url") or "").strip() or None,
        "login_url": str(arguments.get("login_url") or "").strip() or None,
        "login_username": str(arguments.get("login_username") or ""),
        "login_password": str(arguments.get("login_password") or ""),
        "login_user_field": str(arguments.get("login_user_field") or ""),
        "login_password_field": str(arguments.get("login_password_field") or ""),
        "login_extra_fields": {
            str(k): str(v) for k, v in (arguments.get("login_extra_fields") or {}).items()
        },
        "login_failure_marker": str(arguments.get("login_failure_marker") or ""),
        "token_url": str(arguments.get("token_url") or "").strip() or None,
        "token_field": str(arguments.get("token_field") or ""),
        "token_header": str(arguments.get("token_header") or ""),
        "max_body_bytes": int(arguments.get("max_body_bytes") or 20000),
        "request_timeout": int(arguments.get("request_timeout") or 30),
    }


async def pivot_http_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Perform one HTTP request from an authorised host, optionally logged in."""
    target = _text(arguments.get("target"), "target", max_length=255)
    ssh_username = _text(arguments.get("username"), "username", max_length=128)
    ssh_password = str(arguments.get("password") or "")
    if not ssh_password:
        raise ValueError("password is required")
    port = int(arguments.get("port") or PIVOT_DEFAULT_SSH_PORT)
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    requested = arguments.get("timeout_seconds")
    timeout_seconds = min(
        PIVOT_MAX_TIMEOUT_SECONDS,
        max(30, int(requested) if requested else PIVOT_DEFAULT_TIMEOUT_SECONDS),
    )

    config = _http_config(arguments)
    root = workspace_root()
    # A single request has nothing to upload: the client skips the SFTP
    # wordlist step entirely, so the tool leaves no local or remote artefact.
    config["wordlist_path"] = None
    argv = [
        "python3",
        "-c",
        PIVOT_CLIENT_SCRIPT,
        target,
        str(port),
        ssh_username,
        ssh_password,
        json.dumps(config),
        PIVOT_HTTP_REMOTE_SCRIPT,
        str(float(max(30, timeout_seconds - 20))),
    ]

    sandbox = sandbox_for_environment(root, allowed_programs=PIVOT_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=float(timeout_seconds),
        image_env="NEXUS_SSH_IMAGE",
        default_image="python:3.12-alpine",
    )
    outcome = _last_json_object(result.stdout)
    evidence: dict[str, Any] = {
        "noise_level": "high",
        "target": target,
        "url": config["url"],
        "method": config["method"],
        "reachable_from": "target",
        "timeout_seconds": timeout_seconds,
    }
    if outcome is None:
        return ToolResult(
            output={"error": "pivot request produced no result", "target": target, "url": config["url"]},
            verified=False,
            verification_method="pivot_http_unavailable",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
        )

    errors = [str(item) for item in outcome.get("errors") or ()]
    status = outcome.get("status")
    ok = status is not None and not errors
    evidence.update(
        {
            "status": status,
            "body_length": outcome.get("body_length"),
            "login": outcome.get("login"),
            "session": outcome.get("session"),
            "errors": errors[:5],
        }
    )
    return ToolResult(
        output={
            "target": target,
            "url": config["url"],
            "method": config["method"],
            "status": status,
            "location": outcome.get("location"),
            "body": outcome.get("body"),
            "body_length": outcome.get("body_length"),
            "truncated": outcome.get("truncated"),
            "session": outcome.get("session"),
            "login": outcome.get("login"),
            "errors": errors[:5],
        },
        verified=ok,
        # Same post-condition vocabulary as ``nexus.web.request``: an answer from
        # a live server is the observation; the operator interprets the body.
        verification_method="pivot_http_response_received" if ok else "pivot_http_unavailable",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
        timed_out=result.timed_out,
    )


__all__ = [
    "pivot_bruteforce_definition",
    "pivot_bruteforce_handler",
    "pivot_http_definition",
    "pivot_http_handler",
]
