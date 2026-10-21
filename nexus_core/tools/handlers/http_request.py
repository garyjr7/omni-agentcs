"""Durable ``nexus.web.request`` handler: one scoped HTTP request.

This is the missing manual primitive between *recon* and *post-exploitation*:
the classic web chain is ``gobuster -> find upload panel -> upload a webshell ->
trigger it with a query parameter``. Before this tool the motor could discover
``/panel/`` and ``/uploads/`` but had no governed way to *send* the exploit or
to *drive* the shell afterwards (B-ROOTME-1 of ``RUN_sala02``).

The handler never talks to the network itself: it runs a tiny stdlib
``urllib`` client through ``sandbox_for_environment`` (``python3`` is already in
the recon program allowlist), so execution stays inside the same contract as the
rest of the durable tools. It supports:

* arbitrary method (``GET``/``POST``/``PUT``/``OPTIONS``/``HEAD``/``DELETE``);
* custom headers;
* a raw text or base64 body;
* a **multipart file upload** whose file must live inside the engagement
  workspace (same confinement as ``nexus.workspace.read``).

The response body is returned as a bounded preview plus its sha256, so a
webshell command output travels back in the same observation without shipping
unbounded bytes into the agent context. The tool is read-mostly but can carry an
exploit, so the noise/risk is MEDIUM and every call still passes the signed
scope, policy, approval and audit gate.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.redaction import redact_result, secrets_for_redaction
from nexus_core.kernel.sandbox import sandbox_for_environment

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox
from .workspace import resolve_workspace_path, workspace_root

HTTP_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS
HTTP_DEFAULT_TIMEOUT_SECONDS = 30
HTTP_MAX_TIMEOUT_SECONDS = 300

#: Response bytes carried back in the observation (before the sha256 pass).
HTTP_DEFAULT_MAX_RESPONSE_BYTES = 65_536
HTTP_MAX_RESPONSE_BYTES = 1_000_000

#: Methods the operator may invoke. ``DELETE`` is included because it is a
#: legitimate part of some web chains, but it is not destructive at the file
#: level beyond what the target already exposes.
HTTP_ALLOWED_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")

#: Cap on custom headers (argv transport + header-injection surface).
HTTP_MAX_HEADERS = 20
HTTP_MAX_HEADER_VALUE = 4096
#: Cap on the ``Cookie`` header this call may send (one line, no CRLF).
HTTP_MAX_COOKIE_CHARS = 4096
#: Cap on extra multipart form fields sent alongside a file upload.
HTTP_MAX_FORM_FIELDS = 20
#: Cap on the raw text body carried through argv.
HTTP_MAX_DATA_CHARS = 262_144
HTTP_MAX_DATA_B64_CHARS = 524_288

#: stdlib client executed inside the sandbox. argv layout (after ``-c``):
#: method url headers_json data_b64 upload_json follow max_bytes timeout save_path
#: insecure.
#: ``upload_json`` is ``null`` or ``{"field","filename","content_type","path"}``.
#: ``insecure`` (``1``/``0``) disables TLS certificate verification for exactly
#: one request; it is an explicit operator opt-in, never a default.
HTTP_CLIENT_SCRIPT = r"""
import base64, hashlib, json, os, ssl, sys, time, tempfile, urllib.error, urllib.parse, urllib.request, uuid


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    allow_same_origin = False
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Returning None tells urllib to hand back the original 3xx response
        # instead of chasing the redirect (keeps the forensic status code).
        if self.allow_same_origin:
            old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
            if (old.scheme, old.hostname, old.port) == (new.scheme, new.hostname, new.port):
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        return None


def _get_all(headers, name):
    # Every value of a repeated header (Set-Cookie cannot be joined).
    if headers is None:
        return []
    getter = getattr(headers, "get_all", None)
    if getter is not None:
        try:
            return [str(value) for value in (getter(name) or [])]
        except Exception:
            return []
    return [str(value) for key, value in headers.items() if key.lower() == name.lower()]


def _build_upload(upload):
    boundary = "----OmniBoundary" + uuid.uuid4().hex
    field = upload["field"]
    filename = upload.get("filename") or "upload.bin"
    content_type = upload.get("content_type") or "application/octet-stream"
    size = os.path.getsize(upload["path"])
    if size > 268435456:
        raise ValueError("upload exceeds 256 MiB")
    crlf = "\r\n"
    parts = []
    # Plain form fields first (a panel often validates $_POST["submit"] before
    # it moves the file), then the file part, then the closing boundary.
    for name, value in (upload.get("fields") or {}).items():
        parts.append(
            ("--" + boundary + crlf
             + 'Content-Disposition: form-data; name="' + name + '"' + crlf + crlf
             + str(value) + crlf).encode("utf-8")
        )
    parts.append(
        ("--" + boundary + crlf
         + 'Content-Disposition: form-data; name="' + field + '"; filename="'
         + filename + '"' + crlf
         + "Content-Type: " + content_type + crlf + crlf).encode("utf-8")
    )
    prefix = b"".join(parts)
    suffix = (crlf + "--" + boundary + "--" + crlf).encode("utf-8")
    raw_mode = upload.get("mode") == "raw"
    if raw_mode:
        prefix, suffix = b"", b""
    def chunks():
        yield prefix
        with open(upload["path"], "rb") as handle:
            remaining = size
            while remaining:
                chunk = handle.read(min(65536, remaining))
                if not chunk:
                    raise OSError("upload source changed")
                remaining -= len(chunk)
                yield chunk
        yield suffix
    return (content_type if raw_mode else "multipart/form-data; boundary=" + boundary,
            chunks(), size, len(prefix) + size + len(suffix))


def main():
    (method, url, headers_json, data_b64, upload_json, follow, max_bytes, timeout,
     save_path, insecure) = sys.argv[1:11]
    method = method.upper()
    headers = json.loads(headers_json or "{}")
    follow = follow == "1"
    insecure = insecure == "1"
    max_bytes = max(1, int(max_bytes))
    timeout = float(timeout)
    body = base64.b64decode(data_b64) if data_b64 else None
    uploaded = None
    upload = json.loads(upload_json) if upload_json and upload_json != "null" else None
    if upload:
        content_type, body, size, wire_size = _build_upload(upload)
        headers = {k: v for k, v in headers.items() if k.lower() not in {"content-length", "transfer-encoding"}}
        headers["Content-Length"] = str(wire_size)
        headers["Content-Type"] = content_type
        uploaded = {
            "field": upload["field"],
            "filename": upload.get("filename"),
            "content_type": upload.get("content_type"),
            "size": size,
        }
        if method in ("GET", "HEAD"):
            method = "POST"

    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    # The default context verifies certificates (fail-closed). ``insecure`` only
    # swaps in an unverified context when the operator asked for it on this call,
    # which is what a lab target with a self-signed cert requires.
    redirect = _NoRedirect()
    redirect.allow_same_origin = follow
    handlers = [redirect]
    if insecure:
        handlers.append(
            urllib.request.HTTPSHandler(context=ssl._create_unverified_context())
        )
    opener = urllib.request.build_opener(*handlers)
    started = time.time()
    status = None
    reason = ""
    response_headers = {}
    # ``headers`` keeps the last value per name (a plain dict), which silently
    # drops repeated headers. ``Set-Cookie`` is the one that matters: a login
    # response carries JSESSIONID *and* csrf, and a session-carrying chain needs
    # both. Preserve every value in ``set_cookie`` so multi-step flows work.
    set_cookie = []
    raw = b""
    saved = None
    body_bytes = 0
    digest = hashlib.sha256()
    download_limit = int(sys.argv[11]) if len(sys.argv) > 11 else 268435456
    complete = False
    def drain(response):
        nonlocal raw, saved, body_bytes, complete
        temporary = None
        handle = None
        try:
            if save_path:
                parent = os.path.dirname(save_path)
                os.makedirs(parent, exist_ok=True)
                staging = sys.argv[12] if len(sys.argv) > 12 else parent
                fd, temporary = tempfile.mkstemp(prefix=".http-", dir=staging)
                handle = os.fdopen(fd, "wb")
            limit = download_limit if save_path else max_bytes
            while body_bytes <= limit:
                chunk = response.read(min(65536, limit + 1 - body_bytes))
                if not chunk:
                    complete = True
                    break
                body_bytes += len(chunk)
                digest.update(chunk)
                raw += chunk[:max(0, max_bytes - len(raw))]
                if body_bytes > limit:
                    break
                if handle:
                    handle.write(chunk)
            expected = response.headers.get("Content-Length") or response.headers.get("content-length")
            if complete and method != "HEAD" and expected is not None:
                complete = expected.isdigit() and body_bytes == int(expected)
            if handle:
                handle.flush()
                os.fsync(handle.fileno())
                handle.close()
                handle = None
                if complete:
                    os.replace(temporary, save_path)
                    temporary = None
                    saved = {"path": save_path, "bytes": body_bytes,
                             "sha256": digest.hexdigest(), "complete": True}
                else:
                    saved = {"error": "download_limit_exceeded" if body_bytes > limit else "incomplete_response", "complete": False}
        finally:
            if handle:
                handle.close()
            if temporary:
                os.unlink(temporary)
    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            reason = response.reason or ""
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            set_cookie = _get_all(response.headers, "Set-Cookie")
            drain(response)
    except urllib.error.HTTPError as exc:
        status = exc.code
        reason = getattr(exc, "reason", "") or ""
        try:
            response_headers = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
            set_cookie = _get_all(exc.headers, "Set-Cookie")
        except Exception:
            response_headers = {}
        try:
            drain(exc)
        finally:
            exc.close()
    except Exception as exc:
        print(json.dumps({
            "ok": False,
            "url": url,
            "method": method,
            "error": "%s: %s" % (type(exc).__name__, exc),
        }))
        return

    elapsed_ms = int((time.time() - started) * 1000)
    truncated = body_bytes > max_bytes
    preview_bytes = raw
    print(json.dumps({
        "ok": not save_path or complete,
        "body_complete": complete,
        "error": (saved or {}).get("error"),
        "url": url,
        "method": method,
        "status": status,
        "reason": reason,
        "headers": response_headers,
        "set_cookie": set_cookie,
        "content_type": response_headers.get("content-type"),
        "content_length_header": response_headers.get("content-length"),
        "body_bytes": body_bytes,
        "body_sha256": digest.hexdigest(),
        "body_preview": preview_bytes.decode("utf-8", "replace"),
        "preview_truncated": truncated,
        "elapsed_ms": elapsed_ms,
        "uploaded": uploaded,
        "saved": saved,
    }))


main()
"""


def http_request_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.web.request``."""
    return ToolDefinition(
        tool_id="nexus.web.request",
        effect="target_write",
        name="Scoped HTTP request",
        tenant_id=tenant_id,
        description=(
            "Envía UNA petición HTTP(S) a un target dentro del scope: método, "
            "cabeceras, body y subida de archivo multipart (desde el workspace). "
            "Devuelve status, cabeceras y un preview acotado del body con sha256. "
            "Es el primitivo manual para subir un webshell y accionarlo (p. ej. "
            "GET /uploads/shell.phtml?cmd=id). Pasa por scope, policy y audit."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 3, "maxLength": 2048},
                "method": {"type": "string", "enum": list(HTTP_ALLOWED_METHODS)},
                "headers": {
                    "type": "object",
                    "maxProperties": HTTP_MAX_HEADERS,
                    "additionalProperties": {"type": "string", "maxLength": HTTP_MAX_HEADER_VALUE},
                },
                # A session cookie is the one thing a form login leaves behind,
                # and without it the request is anonymous: Brute It v7 had the
                # validated ``admin`` credential and every panel request still
                # came back unauthenticated (iteration 22).
                "cookie": {
                    "type": "string",
                    "maxLength": HTTP_MAX_COOKIE_CHARS,
                    "description": (
                        "Valor literal de la cabecera Cookie (p. ej. "
                        "'PHPSESSID=abc; csrf=def'). Prefiere `session_ref` si la "
                        "sesión la abrió el motor."
                    ),
                },
                "session_ref": {
                    "type": "string",
                    "pattern": "^vault:[a-f0-9]{32}$",
                    "description": (
                        "Handle de una sesión guardada en el vault (lo devuelve "
                        "nexus.cred.bruteforce al validar un login de formulario). "
                        "El motor lo resuelve y envía la cabecera Cookie; el "
                        "valor no entra en el contexto del modelo."
                    ),
                },
                "data": {"type": "string", "maxLength": HTTP_MAX_DATA_CHARS},
                "data_base64": {"type": "string", "maxLength": HTTP_MAX_DATA_B64_CHARS},
                "upload": {
                    "type": "object",
                    "properties": {
                        "mode": {"type": "string", "enum": ["multipart", "raw"]},
                        "field": {"type": "string", "minLength": 1, "maxLength": 128},
                        "filename": {"type": "string", "maxLength": 255},
                        "content_type": {"type": "string", "maxLength": 128},
                        "path": {"type": "string", "minLength": 1, "maxLength": 4096},
                        "fields": {
                            "type": "object",
                            "maxProperties": HTTP_MAX_FORM_FIELDS,
                            "additionalProperties": {"type": "string", "maxLength": HTTP_MAX_HEADER_VALUE},
                        },
                    },
                    "required": ["field", "path"],
                    "additionalProperties": False,
                },
                "follow_redirects": {"type": "boolean"},
                "insecure": {
                    "type": "boolean",
                    "description": (
                        "Desactiva la verificación del certificado TLS SOLO para esta "
                        "petición (objetivos con certificado autofirmado o que no "
                        "coincide con el host). Por defecto false y queda en evidencia."
                    ),
                },
                "save_path": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 4096,
                    "description": (
                        "Ruta RELATIVA dentro del workspace donde guardar el cuerpo "
                        "crudo de la respuesta (útil para binarios: objetos git, "
                        "jarfiles). Evita exponer bytes no imprimibles en el contexto."
                    ),
                },
                "max_download_bytes": {"type": "integer", "minimum": 1, "maximum": 268435456},
                "max_response_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": HTTP_MAX_RESPONSE_BYTES,
                },
                "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": HTTP_MAX_TIMEOUT_SECONDS},
            },
            "required": ["url"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.web.request"],
        timeout_seconds=300,
        max_output_bytes=2_000_000,
        scope_target_field="url",
        scope_required=True,
    )


def _validate_url(value: Any) -> str:
    """Return a normalized ``http(s)`` URL or raise ``ValueError``."""
    text = str(value or "").strip()
    if not text:
        raise ValueError("url is required")
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"}:
        raise ValueError(f"url scheme must be http or https: {text!r}")
    if not parts.netloc:
        raise ValueError(f"url has no host: {text!r}")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise ValueError("url contains control characters")
    return text


def _validate_headers(value: Any) -> dict[str, str]:
    """Return a header mapping with control-character-free keys and values."""
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise ValueError("headers must be an object")
    if len(value) > HTTP_MAX_HEADERS:
        raise ValueError(f"too many headers: {len(value)} > {HTTP_MAX_HEADERS}")
    cleaned: dict[str, str] = {}
    for key, raw in value.items():
        name = str(key).strip()
        if not name or ":" in name:
            raise ValueError(f"invalid header name: {key!r}")
        text = str(raw)
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name + text):
            raise ValueError(f"header {name!r} contains control characters")
        cleaned[name] = text
    return cleaned


def _sanitize_token(value: Any, field: str, *, max_length: int) -> str:
    """Return a stripped token free of quotes/control chars (header injection)."""
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    if len(text) > max_length:
        raise ValueError(f"{field} is too long")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F or ch in '"\\' for ch in text):
        raise ValueError(f"{field} contains invalid characters")
    return text


def _build_upload_spec(value: Any, root: str) -> dict[str, Any]:
    """Validate the multipart upload object and confine its path to the workspace."""
    if not isinstance(value, dict):
        raise ValueError("upload must be an object")
    field = _sanitize_token(value.get("field"), "upload.field", max_length=128)
    filename = os.path.basename(str(value.get("filename") or "upload.bin"))
    filename = _sanitize_token(filename, "upload.filename", max_length=255)
    content_type = str(value.get("content_type") or "application/octet-stream").strip()
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in content_type):
        raise ValueError("upload.content_type contains control characters")
    path = resolve_workspace_path(str(value.get("path") or ""), root=root)
    raw_fields = value.get("fields") or {}
    if not isinstance(raw_fields, dict):
        raise ValueError("upload.fields must be an object")
    if len(raw_fields) > HTTP_MAX_FORM_FIELDS:
        raise ValueError(f"too many form fields: {len(raw_fields)} > {HTTP_MAX_FORM_FIELDS}")
    fields: dict[str, str] = {}
    for key, raw in raw_fields.items():
        name = _sanitize_token(key, "upload.fields name", max_length=128)
        text = str(raw)
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
            raise ValueError(f"upload field {name!r} contains control characters")
        fields[name] = text
    return {
        "mode": str(value.get("mode", "multipart")),
        "field": field,
        "filename": filename,
        "content_type": content_type,
        "path": str(path),
        "fields": fields,
    }


def _resolve_save_path(value: Any, root: str) -> str:
    """Return an absolute workspace path for a download, or ``""`` when unset.

    The download target is confined to the engagement workspace exactly like the
    upload source: an absolute path or a ``..`` escape is refused, so this can
    never become an arbitrary file write.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    if "\x00" in text:
        raise ValueError("save_path contains a NUL byte")
    if os.path.isabs(text):
        raise ValueError("save_path must be relative to the workspace")
    root_path = Path(root).resolve()
    candidate = (root_path / text).resolve()
    if candidate == root_path or root_path not in candidate.parents:
        raise ValueError("save_path must name a file inside the engagement workspace")
    return str(candidate)


def _parse_last_json(stdout: str) -> dict[str, Any]:
    """Return the last JSON object printed by the client, else raise ``ValueError``."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return dict(payload)
    raise ValueError("http client did not return a JSON result")


def _cookie_pairs(set_cookie: Any) -> dict[str, str]:
    """``{name: value}`` from raw ``Set-Cookie`` values (attributes dropped).

    ``set_cookie`` keeps the raw header -what a browser would store- while this
    mapping is the shape the model can paste into the next request without
    re-parsing ``Path``/``HttpOnly`` attributes.
    """
    cookies: dict[str, str] = {}
    for raw in set_cookie or ():
        first = str(raw).split(";", 1)[0].strip()
        name, separator, value = first.partition("=")
        if separator and name.strip():
            cookies[name.strip()] = value.strip()
    return cookies


async def _http_request_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Send one scoped HTTP(S) request through the sandbox and parse the result."""
    from nexus_core.kernel.schema_validation import validate

    validate(arguments, http_request_definition().input_schema)
    url = _validate_url(arguments.get("url"))
    method = str(arguments.get("method") or "GET").strip().upper()
    if method not in HTTP_ALLOWED_METHODS:
        raise ValueError(f"http method is not allowed: {method!r}")
    headers = _validate_headers(arguments.get("headers"))
    # A login leaves a cookie behind; without a way to send it back every later
    # request is anonymous no matter how well the credential was validated (Brute
    # It v7, iteration 22). ``session_ref`` is the vault handle the credential
    # tool returns, so the cookie value never has to enter the model's context.
    session_ref = str(arguments.get("session_ref") or "").strip()
    cookie_sent = ""
    if session_ref:
        from nexus_core.kernel.secret_store import default_secret_store, is_secret_ref

        if not is_secret_ref(session_ref):
            raise ValueError("session_ref must be a vault:<hex> handle")
        try:
            cookie_sent = default_secret_store().get(
                session_ref, tenant_id=context.tenant_id
            ).decode("utf-8").strip()
        except KeyError:
            raise ValueError(f"unknown session_ref: {session_ref}") from None
    manual_cookie = str(arguments.get("cookie") or "").strip()
    if manual_cookie:
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in manual_cookie):
            raise ValueError("cookie contains control characters")
        cookie_sent = "; ".join(part for part in (cookie_sent, manual_cookie) if part)
    if cookie_sent:
        headers = {key: value for key, value in headers.items() if key.lower() != "cookie"}
        headers["Cookie"] = cookie_sent

    data = arguments.get("data")
    data_b64 = arguments.get("data_base64")
    if data is not None and data_b64:
        raise ValueError("pass either 'data' or 'data_base64', not both")
    if data is not None:
        encoded_data = base64.b64encode(str(data).encode("utf-8")).decode("ascii")
    else:
        encoded_data = str(data_b64 or "")
        if encoded_data:
            try:
                base64.b64decode(encoded_data, validate=True)
            except Exception as exc:  # noqa: BLE001 - normalise to a ValueError
                raise ValueError(f"data_base64 is not valid base64: {exc}") from None

    root = workspace_root()
    upload = _build_upload_spec(arguments["upload"], root) if arguments.get("upload") else None
    save_path = _resolve_save_path(arguments.get("save_path"), root)

    requested_max = arguments.get("max_response_bytes")
    max_bytes = min(
        HTTP_MAX_RESPONSE_BYTES,
        max(1, int(requested_max) if requested_max else HTTP_DEFAULT_MAX_RESPONSE_BYTES),
    )
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        HTTP_MAX_TIMEOUT_SECONDS,
        max(5, int(requested_timeout) if requested_timeout else HTTP_DEFAULT_TIMEOUT_SECONDS),
    )
    follow = bool(arguments.get("follow_redirects", False))
    download_limit = int(arguments.get("max_download_bytes", 268435456))
    if not 1 <= download_limit <= 268435456:
        raise ValueError("max_download_bytes must be between 1 and 268435456")
    insecure = bool(arguments.get("insecure", False))

    argv = [
        "python3",
        "-c",
        HTTP_CLIENT_SCRIPT,
        method,
        url,
        json.dumps(headers),
        encoded_data,
        json.dumps(upload) if upload else "null",
        "1" if follow else "0",
        str(max_bytes),
        str(timeout_seconds),
        save_path,
        "1" if insecure else "0",
        str(download_limit),
    ]
    sandbox = sandbox_for_environment(root, allowed_programs=HTTP_ALLOWED_PROGRAMS)
    staging: tempfile.TemporaryDirectory[str] | None = None
    if save_path:
        parent = Path(save_path).parent
        parent.mkdir(parents=True, exist_ok=True)
        staging = tempfile.TemporaryDirectory(prefix=".http-download-", dir=parent)
        argv.append(staging.name)
    try:
        result = await run_in_sandbox(
            sandbox,
            argv,
            timeout_seconds=timeout_seconds,
            image_env="NEXUS_HTTP_IMAGE",
            default_image="python:3.12-alpine",
        )
    finally:
        # The sandbox has reaped the process before returning/cancelling. Clean
        # partial files even when SIGTERM/SIGKILL skipped the client's finally.
        if staging is not None:
            staging.cleanup()


    noise_level = "medium" if (upload or method not in {"GET", "HEAD"}) else "low"
    evidence: dict[str, Any] = {
        "url": url,
        "method": method,
        "host": urlsplit(url).hostname,
        "noise_level": noise_level,
        "follow_redirects": follow,
        "insecure": insecure,
        "upload": upload is not None,
        "save_path": save_path or None,
        "timeout_seconds": timeout_seconds,
        "max_response_bytes": max_bytes,
        "cookie_sent": bool(cookie_sent),
        "session_ref": session_ref or None,
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "http request timed out", "url": url, "method": method},
            verified=False,
            verification_method="http_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    try:
        payload = _parse_last_json(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "url": url, "method": method},
            verified=False,
            verification_method="http_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    ok = bool(payload.get("ok")) and result.exit_code == 0
    response_cookies = _cookie_pairs(payload.get("set_cookie"))
    if ok:
        evidence.update(
            {
                "status": payload.get("status"),
                "content_type": payload.get("content_type"),
                "body_complete": payload.get("body_complete"),
            "body_bytes": payload.get("body_bytes"),
                "body_sha256": payload.get("body_sha256"),
                "preview_truncated": payload.get("preview_truncated"),
                "elapsed_ms": payload.get("elapsed_ms"),
                "set_cookie_count": len(payload.get("set_cookie") or ()),
            }
        )
        if upload:
            evidence["uploaded_bytes"] = (payload.get("uploaded") or {}).get("size")
        if save_path:
            evidence["saved_path"] = (payload.get("saved") or {}).get("path")
            evidence["saved_bytes"] = (payload.get("saved") or {}).get("bytes")
    else:
        evidence["error"] = payload.get("error")

    return ToolResult(
        output={
            "url": url,
            "method": payload.get("method", method),
            "status": payload.get("status"),
            "reason": payload.get("reason"),
            "headers": payload.get("headers") or {},
            "set_cookie": payload.get("set_cookie") or [],
            # Same values, parsed: what a follow-up call sends in ``cookie``.
            "response_cookies": response_cookies,
            "content_type": payload.get("content_type"),
            "body_complete": payload.get("body_complete"),
            "body_bytes": payload.get("body_bytes"),
            "body_sha256": payload.get("body_sha256"),
            "body_preview": payload.get("body_preview"),
            "preview_truncated": payload.get("preview_truncated"),
            "elapsed_ms": payload.get("elapsed_ms"),
            "uploaded": payload.get("uploaded"),
            "saved": payload.get("saved"),
            "error": payload.get("error"),
        },
        verified=ok,
        verification_method="http_response_received" if ok else "http_request_failed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


async def http_request_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Redact every known vault secret from the response before it is returned.

    A page can echo a password the engine proved earlier (a login form, a
    diagnostic page, a redirect with the credential in the query). The handler
    knows the engagement's verified credential facts, so it removes those values
    from the preview, the evidence and the raw stdout -the same boundary SSH
    already applies (V1-6/V1-46).
    """
    result = await _http_request_handler(arguments, context)
    return redact_result(result, secrets_for_redaction(context, arguments))


__all__ = [
    "HTTP_ALLOWED_METHODS",
    "HTTP_CLIENT_SCRIPT",
    "http_request_definition",
    "http_request_handler",
]
