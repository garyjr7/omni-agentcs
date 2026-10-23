"""Durable ``nexus.post.http_server`` handler: host a payload for the target.

Why this tool exists (run de HackSmarter, 2026-10-23): the run found Dell
OpenManage on TCP/1311, downloaded ``49750.py`` (CVE-2020-5377, SSRF -> file read)
with ``nexus.exploit.find_and_prepare`` and then burned thirteen turns trying to
make the victim fetch a file back from ``targetmachine=127.0.0.1`` /
``targetmachine=192.168.144.132`` with hand-written ``curl`` calls. Nothing in the
catalogue could *serve* a file to the target, so there was no legal way to satisfy
the exploit's precondition: an HTTP server the victim can download from.

The tool answers exactly that: it starts ``python3 -m http.server`` bound to
``0.0.0.0`` over one directory **inside the engagement workspace**, keeps it alive
for the rest of the run, and returns the operator's reachable address (``tun0``,
or ``MSF_LHOST`` when the operator configured it) so the model knows what to put
in ``targetmachine``/``lhost`` instead of guessing ``127.0.0.1``.

Design notes
------------
* The server is a *persistent process*, which ``sandbox.run`` cannot express (it
  owns the lifetime of its children and waits for them). It is started through
  ``PtySessionManager`` -the same tmux substrate as ``nexus.session.pty`` and the
  ``keep_open`` listener- so it goes through ``sandbox_for_environment``, dies
  with the run's tmux server, and its pane keeps the bind error for the operator.
* ``directory`` is resolved (symlinks included) and confined to the workspace
  root: the model cannot turn this into "publish /etc" to the target.
* The post-condition is the server's own answer: the handler issues a local
  ``GET /`` and only reports ``verified`` when a ``SimpleHTTP`` server responds.
  A port held by an unrelated process is a determinate negative
  (``http_server_port_conflict``), not a success.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import shlex
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.pty_sessions import PtySessionManager
from nexus_core.kernel.sandbox import OCISandbox

from .workspace import workspace_root

HTTP_SERVER_TOOL_ID = "nexus.post.http_server"
#: Below 1024 the bind needs root, so a doomed call is refused before it runs.
HTTP_SERVER_MIN_PORT = 1024
HTTP_SERVER_MAX_PORT = 65535
HTTP_SERVER_DEFAULT_PORT = 8000
HTTP_SERVER_BIND_HOST = "0.0.0.0"
#: Long enough for a cold ``python3`` start, short enough not to burn a turn.
HTTP_SERVER_PROBE_TIMEOUT_SECONDS = 4.0
HTTP_SERVER_PROBE_ATTEMPTS = 16
HTTP_SERVER_PROBE_SLEEP_SECONDS = 0.25
#: Bytes of the served body kept as evidence of the answer.
HTTP_SERVER_PROBE_MAX_BYTES = 2048
#: The stdlib server identifies itself; a different banner means another
#: process owns the port and the call did not do what it said.
HTTP_SERVER_SIGNATURE = "SimpleHTTP"


def http_server_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.http_server``."""
    return ToolDefinition(
        tool_id=HTTP_SERVER_TOOL_ID,
        name="HTTP file server for the target",
        tenant_id=tenant_id,
        description=(
            "Servidor HTTP del atacante (python3 -m http.server) para que el "
            "objetivo descargue un payload (SSRF/targetmachine). Devuelve tu IP "
            "alcanzable (tun0) y el puerto; ponla en targetmachine/lhost, "
            "NUNCA 127.0.0.1. LOW: no requiere aprobación."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "minimum": HTTP_SERVER_MIN_PORT,
                    "maximum": HTTP_SERVER_MAX_PORT,
                },
                "directory": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 512,
                    "description": (
                        "Directorio del workspace a publicar (por defecto la "
                        "raíz del workspace)."
                    ),
                },
            },
            "required": ["port"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        effect="post_exploitation",
        required_permissions=[f"execute:tool:{HTTP_SERVER_TOOL_ID}"],
        timeout_seconds=60,
        max_output_bytes=1_000_000,
        scope_target_field=None,
        scope_required=False,
    )


def _resolve_directory(value: Any, root: str) -> Path:
    """Resolve ``value`` inside the workspace root; raise ``ValueError`` if not."""
    text = str(value or "").strip()
    if "\x00" in text:
        raise ValueError("directory contains a NUL byte")
    base = Path(root).resolve()
    candidate = Path(text) if text else base
    if not candidate.is_absolute():
        candidate = base / candidate
    if not candidate.exists():
        raise ValueError(f"directory not found in workspace: {text or '.'}")
    resolved = candidate.resolve()
    if resolved != base and base not in resolved.parents:
        raise ValueError(f"directory escapes the engagement workspace: {text}")
    if not resolved.is_dir():
        raise ValueError(f"not a directory: {text}")
    return resolved


def server_argv(port: int, directory: Path) -> list[str]:
    """The exact argv the pane runs (no shell interpolation of the path)."""
    return [
        "python3",
        "-m",
        "http.server",
        str(int(port)),
        "--bind",
        HTTP_SERVER_BIND_HOST,
        "--directory",
        str(directory),
    ]


def attacker_ip(*, environ: dict[str, str] | None = None) -> tuple[str | None, str | None]:
    """The address the target can reach us at, and where it came from.

    ``MSF_LHOST`` wins because the operator already declared it as the callback
    address of this engagement; otherwise the ``tun0`` detection of the wizard
    (``ip -o -4 addr show tun0``) is reused unchanged. ``None`` means no address
    could be resolved and the model has to be told so -never ``127.0.0.1``-.
    """
    source = environ if environ is not None else os.environ
    configured = str(source.get("MSF_LHOST") or "").strip()
    if configured:
        return configured, "MSF_LHOST"
    try:
        from nexus_core.cli.wizard import detect_tun0_ip

        detected = detect_tun0_ip()
    except Exception:  # noqa: BLE001 - detection is best-effort, never fatal
        detected = None
    if detected:
        return detected, "tun0"
    return None, None


def _probe_once(port: int, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{int(port)}/", headers={"User-Agent": "omni-http-server-probe"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(HTTP_SERVER_PROBE_MAX_BYTES)
            return {
                "ok": True,
                "status": int(response.status),
                "server": str(response.headers.get("Server") or ""),
                "body": body.decode("utf-8", "replace"),
            }
    except urllib.error.HTTPError as exc:  # a served 404 is still an answer
        body = exc.read(HTTP_SERVER_PROBE_MAX_BYTES) if exc.fp else b""
        return {
            "ok": True,
            "status": int(exc.code),
            "server": str(exc.headers.get("Server") or "") if exc.headers else "",
            "body": body.decode("utf-8", "replace"),
        }
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _probe_server(port: int) -> dict[str, Any]:
    """Poll ``http://127.0.0.1:<port>/`` until it answers or the budget ends."""
    last: dict[str, Any] = {"ok": False, "error": "no attempt"}
    for _ in range(HTTP_SERVER_PROBE_ATTEMPTS):
        last = _probe_once(port, HTTP_SERVER_PROBE_TIMEOUT_SECONDS / 4)
        if last["ok"]:
            return last
        # The server is a detached process: give it a moment to bind.
        time.sleep(HTTP_SERVER_PROBE_SLEEP_SECONDS)
    return last


def _next_steps(
    *, port: int, address: str | None, workspace_dir: str, session_ref: str,
) -> list[str]:
    """What the model does with the server it just started."""
    if address:
        host_line = (
            f"Pon {address} (puerto {port}) en el parámetro que espera el "
            "objetivo: targetmachine, lhost, LHOST o la URL del callback."
        )
    else:
        host_line = (
            "No se pudo resolver una IP alcanzable (ni MSF_LHOST ni tun0): "
            "exporta MSF_LHOST=<tu IP> y vuelve a llamar antes de disparar el "
            "exploit."
        )
    return [
        host_line,
        (
            "NO uses 127.0.0.1 ni localhost: la víctima se descargaría el fichero "
            "a sí misma y el exploit falla (run HackSmarter, 13 turnos perdidos)."
        ),
        (
            f"Sirve {workspace_dir} en http://0.0.0.0:{port}/ (sesión "
            f"{session_ref}); deja ahí el fichero que el exploit debe descargar."
        ),
        (
            "Dispara el exploit (nexus.shell.exec con el PoC, o nexus.web.request) "
            "y verifica la descarga en la salida; después registra el hecho."
        ),
    ]


async def http_server_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Start the stdlib file server in tmux and prove it answers."""
    port = int(arguments.get("port") or 0)
    if not HTTP_SERVER_MIN_PORT <= port <= HTTP_SERVER_MAX_PORT:
        raise ValueError(
            f"port must be between {HTTP_SERVER_MIN_PORT} and {HTTP_SERVER_MAX_PORT} "
            "(below 1024 needs root)"
        )
    root = workspace_root()
    directory = _resolve_directory(arguments.get("directory"), root)
    try:
        relative_dir = directory.relative_to(Path(root).resolve()).as_posix() or "."
    except ValueError:  # pragma: no cover - _resolve_directory already refused
        relative_dir = "."

    manager = PtySessionManager(root, context.run_id)
    if isinstance(manager.sandbox(), OCISandbox):
        # The pane would live inside a container the target cannot route to.
        return ToolResult(
            output={
                "error": "http_server requires a persistent local sandbox",
                "reason": "http_server_requires_persistent_sandbox",
                "port": port,
            },
            verified=False,
            outcome="unavailable",
            verification_method="http_server_requires_persistent_sandbox",
        )

    session_name = f"http-{port}"
    command = " ".join(shlex.quote(part) for part in server_argv(port, directory))
    started = await manager.start(command, session_name)
    probe = await asyncio.to_thread(_probe_server, port)
    if started.already_running and not probe.get("ok"):
        # A dead reuse of the name: restart once before declaring anything.
        await manager.kill(session_name)
        started = await manager.start(command, session_name)
        probe = await asyncio.to_thread(_probe_server, port)

    if not started.alive:
        pane = await manager.capture(session_name, lines=40)
        return ToolResult(
            output={
                "error": started.error or "http server exited",
                "port": port,
                "directory": relative_dir,
                "pane": pane.output,
            },
            verified=False,
            verification_method="http_server_start_failed",
            evidence={"port": port, "directory": relative_dir,
                      "error": started.error, "noise_level": "medium"},
        )

    address, address_source = attacker_ip()
    if not probe.get("ok"):
        pane = await manager.capture(session_name, lines=40)
        await manager.kill(session_name)
        return ToolResult(
            output={
                "error": probe.get("error") or "the server did not answer",
                "port": port,
                "directory": relative_dir,
                "pane": pane.output,
            },
            verified=False,
            verification_method="http_server_not_serving",
            evidence={"port": port, "directory": relative_dir,
                      "probe_error": probe.get("error"), "session_ref": started.session_id},
        )

    server_header = str(probe.get("server") or "")
    if HTTP_SERVER_SIGNATURE not in server_header:
        # Something else holds the port: the call did not start *our* server.
        await manager.kill(session_name)
        return ToolResult(
            output={
                "error": f"port {port} is served by another process",
                "port": port,
                "server": server_header,
            },
            verified=False,
            outcome="negative",
            verification_method="http_server_port_conflict",
            evidence={"port": port, "server": server_header,
                      "http_status": probe.get("status")},
        )

    body = str(probe.get("body") or "")
    url = f"http://{address}:{port}/" if address else f"http://<tu-IP>:{port}/"
    return ToolResult(
        output={
            "session_ref": started.session_id,
            "port": port,
            "bind_host": HTTP_SERVER_BIND_HOST,
            "directory": relative_dir,
            "attacker_ip": address,
            "attacker_ip_source": address_source,
            "targetmachine": address,
            "url": url,
            "status": "serving",
            "http_status": probe.get("status"),
            "server": server_header,
            "body_preview": body,
            "next_steps": _next_steps(
                port=port, address=address, workspace_dir=relative_dir,
                session_ref=started.session_id,
            ),
        },
        verified=True,
        verification_method="http_server_serving",
        evidence={
            "port": port,
            "directory": relative_dir,
            "session_ref": started.session_id,
            "http_status": probe.get("status"),
            "server": server_header,
            "body_bytes": len(body.encode("utf-8")),
            "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "attacker_ip": address,
            "attacker_ip_source": address_source,
            "noise_level": "medium",
        },
    )


__all__ = [
    "HTTP_SERVER_BIND_HOST",
    "HTTP_SERVER_TOOL_ID",
    "attacker_ip",
    "http_server_definition",
    "http_server_handler",
    "server_argv",
]
