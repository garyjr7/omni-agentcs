"""Unit tests for the durable HTTP request handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
import http.server
import json
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import http_request as http_module
from nexus_core.tools.handlers.http_request import (
    http_request_definition,
    http_request_handler,
)


class FakeSandbox:
    def __init__(self, result: SandboxResult):
        self.result = result
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append((list(argv), timeout_seconds))
        return self.result


@contextlib.contextmanager
def _fake_sandbox(result: SandboxResult):
    sandbox = FakeSandbox(result)
    with mock.patch.object(
        http_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(http_request_handler(arguments, _context()))


def _sandbox_for(payload: dict, exit_code: int = 0) -> SandboxResult:
    return SandboxResult(exit_code, json.dumps(payload) + "\n", "")


def _ok_payload(**overrides) -> dict:
    payload = {
        "ok": True,
        "url": "http://203.0.113.10/",
        "method": "GET",
        "status": 200,
        "reason": "OK",
        "headers": {"content-type": "text/html"},
        "content_type": "text/html",
        "body_bytes": 12,
        "body_sha256": "a" * 64,
        "body_preview": "<html></html>",
        "preview_truncated": False,
        "elapsed_ms": 5,
        "uploaded": None,
    }
    payload.update(overrides)
    return payload


# ------------------------------------------------------------------ definition
def test_definition_declares_scope_and_methods():
    definition = http_request_definition()
    assert definition.scope_target_field == "url"
    assert definition.scope_required is True
    assert set(definition.input_schema["properties"]["method"]["enum"]) == {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
    }


# --------------------------------------------------------------------- handler
def test_handler_runs_python_client_in_sandbox():
    with _fake_sandbox(_sandbox_for(_ok_payload())) as sandbox:
        result = _run({"url": "http://203.0.113.10/"})
    argv = sandbox.calls[0][0]
    assert argv[0] == "python3" and argv[1] == "-c"
    assert argv[3] == "GET"
    assert argv[4] == "http://203.0.113.10/"
    assert result.verified is True
    assert result.verification_method == "http_response_received"
    assert result.output["status"] == 200


def test_handler_never_spawns_subprocess_directly():
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"url": "http://203.0.113.10/"})


def test_upload_builds_spec_and_marks_noise_medium(tmp_path, monkeypatch):
    shell = tmp_path / "shell.phtml"
    shell.write_text("<?php system($_GET['cmd']); ?>", encoding="utf-8")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    payload = _ok_payload(
        method="POST",
        status=200,
        uploaded={"field": "fileUpload", "filename": "shell.phtml", "size": 34},
    )
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run(
            {
                "url": "http://203.0.113.10/panel/",
                "method": "POST",
                "upload": {
                    "field": "fileUpload",
                    "filename": "shell.phtml",
                    "path": "shell.phtml",
                },
            }
        )
    argv = sandbox.calls[0][0]
    upload_spec = json.loads(argv[7])
    assert upload_spec["field"] == "fileUpload"
    assert upload_spec["path"] == str(shell.resolve())
    assert result.verified is True
    assert result.evidence["upload"] is True
    assert result.evidence["noise_level"] == "medium"


def test_upload_extra_form_fields_are_carried(tmp_path, monkeypatch):
    shell = tmp_path / "shell.phtml"
    shell.write_text("<?php system($_GET['cmd']); ?>", encoding="utf-8")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_ok_payload(method="POST", uploaded=None))) as sandbox:
        _run(
            {
                "url": "http://203.0.113.10/panel/",
                "method": "POST",
                "upload": {
                    "field": "fileUpload",
                    "filename": "shell.phtml",
                    "path": "shell.phtml",
                    "fields": {"submit": "Upload"},
                },
            }
        )
    upload_spec = json.loads(sandbox.calls[0][0][7])
    assert upload_spec["fields"] == {"submit": "Upload"}


def test_upload_path_outside_workspace_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path / "ws"))
    (tmp_path / "ws").mkdir()
    outsider = tmp_path / "outside.txt"
    outsider.write_text("x", encoding="utf-8")
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with pytest.raises(ValueError):
            _run(
                {
                    "url": "http://203.0.113.10/panel/",
                    "upload": {"field": "f", "path": str(outsider)},
                }
            )


def test_save_path_is_passed_and_confined(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_ok_payload())) as sandbox:
        _run({"url": "http://203.0.113.10/.git/index", "save_path": "git/index"})
    argv = sandbox.calls[0][0]
    assert argv[11] == str((tmp_path / "git" / "index").resolve())


def test_save_path_escape_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with pytest.raises(ValueError):
            _run({"url": "http://203.0.113.10/", "save_path": "../escape.bin"})
        with pytest.raises(ValueError):
            _run({"url": "http://203.0.113.10/", "save_path": "/etc/passwd"})


def test_non_http_url_is_rejected():
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with pytest.raises(ValueError):
            _run({"url": "ftp://203.0.113.10/file"})


def test_data_and_data_base64_are_mutually_exclusive():
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with pytest.raises(ValueError):
            _run({"url": "http://203.0.113.10/", "data": "a", "data_base64": "YQ=="})


def test_invalid_base64_is_rejected():
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with pytest.raises(ValueError):
            _run({"url": "http://203.0.113.10/", "data_base64": "not base64!!"})


def test_control_characters_in_headers_are_rejected():
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with pytest.raises(ValueError):
            _run({"url": "http://203.0.113.10/", "headers": {"X-Test": "ok\r\nInjected: 1"}})


def test_client_error_payload_is_not_verified():
    payload = {"ok": False, "url": "http://203.0.113.10/", "error": "URLError: refused"}
    with _fake_sandbox(_sandbox_for(payload, exit_code=0)):
        result = _run({"url": "http://203.0.113.10/"})
    assert result.verified is False
    assert result.verification_method == "http_request_failed"


def test_unparseable_output_is_not_verified():
    with _fake_sandbox(SandboxResult(0, "not json at all\n", "")):
        result = _run({"url": "http://203.0.113.10/"})
    assert result.verified is False
    assert result.verification_method == "http_parse_failed"


def test_timeout_is_not_verified():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"url": "http://203.0.113.10/"})
    assert result.verified is False
    assert result.verification_method == "http_timeout"


# ------------------------------------------------------- TLS verification opt-in
def test_insecure_flag_is_appended_to_argv_and_evidenced():
    """The opt-in must reach the client and stay visible in the audit evidence."""
    with _fake_sandbox(_sandbox_for(_ok_payload())) as sandbox:
        result = _run({"url": "https://203.0.113.10/", "insecure": True})
    assert sandbox.calls[0][0][12] == "1"
    assert result.evidence["insecure"] is True


def test_tls_verification_stays_on_by_default():
    with _fake_sandbox(_sandbox_for(_ok_payload())) as sandbox:
        result = _run({"url": "https://203.0.113.10/"})
    assert sandbox.calls[0][0][12] == "0"
    assert result.evidence["insecure"] is False


def test_definition_exposes_the_insecure_opt_in():
    definition = http_request_definition()
    assert definition.input_schema["properties"]["insecure"]["type"] == "boolean"


OPENSSL = shutil.which("openssl")


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    """Minimal 200 handler that never logs to stderr."""

    def do_GET(self):  # noqa: N802 - stdlib naming
        body = b"<html>ok</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # noqa: ARG002 - silence the server
        return


@pytest.fixture(scope="module")
def self_signed_https_server():
    """A local HTTPS endpoint whose certificate no trust store knows about."""
    if OPENSSL is None:
        pytest.skip("openssl is required to mint a self-signed certificate")
    with tempfile.TemporaryDirectory() as tmp:
        cert = Path(tmp) / "cert.pem"
        key = Path(tmp) / "key.pem"
        subprocess.run(
            [
                OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1",
                "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ],
            check=True,
            capture_output=True,
        )
        server = http.server.HTTPServer(("127.0.0.1", 0), _QuietHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            yield f"https://localhost:{server.server_address[1]}/"
        finally:
            server.shutdown()
            server.server_close()


def _run_client_script(url: str, *, insecure: bool) -> dict:
    """Execute the *shipped* client exactly like the handler does, no mocks."""
    argv = [
        sys.executable, "-c", http_module.HTTP_CLIENT_SCRIPT, "GET", url,
        "{}", "", "null", "0", "65536", "20", "", "1" if insecure else "0",
    ]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    payloads = [line for line in proc.stdout.splitlines() if line.startswith("{")]
    assert payloads, proc.stdout + proc.stderr
    return json.loads(payloads[-1])


def test_shipped_client_fails_closed_on_a_self_signed_certificate(self_signed_https_server):
    payload = _run_client_script(self_signed_https_server, insecure=False)
    assert payload["ok"] is False
    assert "CERTIFICATE_VERIFY_FAILED" in payload["error"]


def test_shipped_client_accepts_a_self_signed_certificate_when_insecure(self_signed_https_server):
    payload = _run_client_script(self_signed_https_server, insecure=True)
    assert payload["ok"] is True
    assert payload["status"] == 200
    assert "ok" in payload["body_preview"]


# ------------------------------------------------------- repeated Set-Cookie
def test_repeated_set_cookie_headers_are_preserved_in_output():
    cookies = ["JSESSIONID=node01abc.node0;Path=/;HttpOnly", "csrf=Tok3n;Path=/;HttpOnly"]
    with _fake_sandbox(_sandbox_for(_ok_payload(set_cookie=cookies))):
        result = _run({"url": "http://203.0.113.10/login.jsp"})
    assert result.output["set_cookie"] == cookies
    assert result.evidence["set_cookie_count"] == 2


class _TwoCookieHandler(http.server.BaseHTTPRequestHandler):
    """Sets two cookies the way a login response does (JSESSIONID + csrf)."""

    def do_GET(self):  # noqa: N802 - stdlib naming
        body = b"ok"
        self.send_response(200)
        self.send_header("Set-Cookie", "JSESSIONID=node01abc.node0;Path=/;HttpOnly")
        self.send_header("Set-Cookie", "csrf=Tok3n;Path=/;HttpOnly")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # noqa: ARG002 - silence the server
        return


def test_shipped_client_keeps_every_cookie_of_a_login_response():
    server = http.server.HTTPServer(("127.0.0.1", 0), _TwoCookieHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/login.jsp"
        payload = _run_client_script(url, insecure=False)
    finally:
        server.shutdown()
        server.server_close()
    assert len(payload["set_cookie"]) == 2
    joined = " ".join(payload["set_cookie"])
    assert "JSESSIONID=" in joined and "csrf=" in joined


# ------------------------------------------------------------------ csrf_mode
_VIEWSTATE = "VS-abc/123=="
_EVENTVALIDATION = "EV-def/456=="
_SESSION_COOKIE = "ASP.NET_SessionId=s3ss10n"


class _CsrfLoginHandler(http.server.BaseHTTPRequestHandler):
    """ASP.NET WebForms-shaped login: tokens and session cookie are required."""

    def _send(self, status: int, body: str, *, cookie: str | None = None) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):  # noqa: N802 - stdlib naming
        if not self.path.startswith("/Account/login.aspx"):
            self._send(404, "not found")
            return
        self._send(
            200,
            (
                '<html><body><form method="post" action="/Account/login.aspx">'
                f'<input type="hidden" name="__VIEWSTATE" value="{_VIEWSTATE}">'
                f'<input type="hidden" name="__EVENTVALIDATION" value="{_EVENTVALIDATION}">'
                '<input type="hidden" name="__VIEWSTATEGENERATOR" value="CA0B0334">'
                '<input name="ctl00$MainContent$LoginUser$UserName">'
                '<input name="ctl00$MainContent$LoginUser$Password" type="password">'
                "</form></body></html>"
            ),
            cookie=f"{_SESSION_COOKIE}; path=/; HttpOnly",
        )

    def do_POST(self):  # noqa: N802 - stdlib naming
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        from urllib.parse import parse_qs

        fields = parse_qs(body)
        cookie = self.headers.get("Cookie") or ""
        tokens_ok = (
            fields.get("__VIEWSTATE") == [_VIEWSTATE]
            and fields.get("__EVENTVALIDATION") == [_EVENTVALIDATION]
        )
        password = (fields.get("ctl00$MainContent$LoginUser$Password") or [""])[0]
        if tokens_ok and _SESSION_COOKIE in cookie and password == "hackpark":
            self._send(200, "Welcome admin")
        else:
            self._send(403, "Login failed")

    def log_message(self, *args):  # noqa: ARG002 - silence the server
        return


def _run_client_with_csrf(
    url: str, data: str, *, csrf: bool = True, form_url: str = ""
) -> dict:
    """Execute the shipped client against a real local server (csrf on/off)."""
    import base64
    import sys as _sys

    argv = [
        _sys.executable, "-c", http_module.HTTP_CLIENT_SCRIPT, "POST", url,
        "{}", base64.b64encode(data.encode()).decode(), "null", "0", "65536",
        "20", "", "0", "268435456", "", "1" if csrf else "0", form_url,
    ]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    payloads = [line for line in proc.stdout.splitlines() if line.startswith("{")]
    assert payloads, proc.stdout + proc.stderr
    return json.loads(payloads[-1])


def _csrf_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _CsrfLoginHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/Account/login.aspx"


def test_aspnet_form_rejects_a_post_without_its_tokens():
    server, url = _csrf_server()
    try:
        payload = _run_client_with_csrf(
            url, "ctl00$MainContent$LoginUser$Password=hackpark", csrf=False
        )
    finally:
        server.shutdown()
        server.server_close()
    assert payload["status"] == 403
    assert "Login failed" in payload["body_preview"]


def test_csrf_mode_extracts_viewstate_and_reuses_the_session_cookie():
    server, url = _csrf_server()
    try:
        payload = _run_client_with_csrf(
            url,
            "ctl00$MainContent$LoginUser$UserName=admin"
            "&ctl00$MainContent$LoginUser$Password=hackpark",
        )
    finally:
        server.shutdown()
        server.server_close()
    assert payload["ok"] is True
    assert payload["status"] == 200
    assert "Welcome admin" in payload["body_preview"]
    assert payload["csrf"]["fields"] == [
        "__VIEWSTATE", "__EVENTVALIDATION", "__VIEWSTATEGENERATOR"
    ]
    assert payload["csrf"]["cookie_names"] == ["ASP.NET_SessionId"]


def test_csrf_mode_can_fetch_a_different_form_url():
    server, url = _csrf_server()
    try:
        payload = _run_client_with_csrf(
            url + "?ReturnURL=/admin",
            "ctl00$MainContent$LoginUser$Password=hackpark",
            form_url=url,
        )
    finally:
        server.shutdown()
        server.server_close()
    # The POST carries a query string the form page does not have; the tokens
    # were fetched from the explicit ``csrf_form_url``.
    assert payload["status"] == 200
    assert payload["csrf"]["form_url"] == url


def test_handler_passes_csrf_flags_in_fixed_argv_positions(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    payload = _ok_payload(
        method="POST",
        status=200,
        csrf={"status": 200, "fields": ["__VIEWSTATE", "__EVENTVALIDATION"]},
    )
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run(
            {
                "url": "http://203.0.113.10/Account/login.aspx",
                "method": "POST",
                "data": "user=admin&pass=x",
                "csrf_mode": True,
            }
        )
    argv = sandbox.calls[0][0]
    assert argv[14] == ""  # no download staging dir
    assert argv[15] == "1"
    assert argv[16] == ""
    assert result.evidence["csrf_mode"] is True
    assert result.evidence["csrf_fields"] == ["__VIEWSTATE", "__EVENTVALIDATION"]
    assert result.output["csrf"]["status"] == 200


def test_csrf_form_url_requires_csrf_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with pytest.raises(ValueError):
            _run(
                {
                    "url": "http://203.0.113.10/Account/login.aspx",
                    "csrf_form_url": "http://203.0.113.10/Account/login.aspx",
                }
            )
