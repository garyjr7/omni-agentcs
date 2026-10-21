"""Fixes of the Brute It v7 run: the DTO enum, slices, sessions, keys and john.

Every test here names the measured turn it protects:

* ``invalid_failure_string`` reached the ``ToolResultDTO`` literal and Pydantic
  rejected it (v7, iterations 9-12): the fix is parity with the taxonomy, and
  the test fails if a new outcome is added to one side only.
* an unbounded ``rockyou`` sweep ran 890 s and the loop killed it (v7,
  iteration 16): a bounded slice by default, with ``next_start_at``.
* ``admin`` was validated and could not be used because the panel wanted a
  cookie (v7, iteration 22): the login session is captured and travelable.
* the panel handed out an RSA key and no SSH tool could carry it (v7,
  iteration 25).
* the hash/key never had a cracking step (v7, iteration 28).
"""

from __future__ import annotations

import asyncio
import contextlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.kernel.models import (
    COMPLETED_OUTCOMES,
    OUTCOME_TAXONOMY,
    Identity,
    RunContext,
    ToolResult,
)
from nexus_core.kernel.sandbox import SandboxResult

#: A real (tiny) RSA key: only the armour is needed by the stub client test.
SAMPLE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
-----END RSA PRIVATE KEY-----
"""


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


class SequencedSandbox:
    """A sandbox whose answer depends on which program the handler launched."""

    def __init__(self, answers: dict[str, SandboxResult]):
        self.answers = answers
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30, **kwargs):
        self.calls.append(list(argv))
        program = argv[0]
        if program == "python3":
            script = argv[2] if len(argv) > 2 else ""
            if script and script == self.answers.get("probe_script"):
                return self.answers["probe"]
            return self.answers.get("python", SandboxResult(0, "", ""))
        return self.answers.get(program, SandboxResult(0, "", ""))


@contextlib.contextmanager
def _patch_sandbox(module, sandbox):
    with mock.patch.object(module, "sandbox_for_environment", lambda *a, **k: sandbox):
        yield sandbox


# ------------------------------------------------------------------- FIX 0
def test_the_result_dto_accepts_every_taxonomy_outcome():
    """A value the taxonomy allows must not be rejected at the DTO boundary."""
    from nexus_core.kernel.domain_dto import ToolResultDTO

    declared = set(OUTCOME_TAXONOMY) | {"success"}
    annotation = ToolResultDTO.model_fields["outcome"].annotation
    assert set(getattr(annotation, "__args__", ())) == declared
    for outcome in sorted(OUTCOME_TAXONOMY):
        result = ToolResult(output={"probe": outcome}, verified=False, outcome=outcome)
        assert result.to_dto().outcome == outcome


def test_partial_is_determinate_but_promotes_nothing():
    """A finished slice is an observation about the slice, never about the target."""
    assert "partial" in COMPLETED_OUTCOMES
    result = ToolResult(output={"attempts": 5000}, verified=False, outcome="partial")
    assert result.completed is True


# ------------------------------------------------------------------- FIX 5
def _slice_workspace(tmp_path: Path) -> None:
    (tmp_path / "words.txt").write_text(
        "\n".join(f"pw{index}" for index in range(6)) + "\n", encoding="utf-8"
    )


def _slice_run(tmp_path, monkeypatch, *, attempts: int, start_at: int = 0):
    from nexus_core.tools.handlers import cred_bruteforce as module

    _slice_workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    seen: dict[str, list[str]] = {}

    class ReadingSandbox(SequencedSandbox):
        async def run(self, argv, *, timeout_seconds: float = 30, **kwargs):
            if argv[0] == "hydra":
                path = argv[argv.index("-P") + 1]
                seen["wordlist"] = Path(path).read_text(encoding="utf-8").splitlines()
            return await super().run(argv, timeout_seconds=timeout_seconds, **kwargs)

    sandbox = ReadingSandbox({"hydra": SandboxResult(0, "0 valid password found\n", "")})
    with _patch_sandbox(module, sandbox):
        result = asyncio.run(
            module.cred_bruteforce_handler(
                {
                    "target": "10.67.149.76",
                    "service": "ssh",
                    "username": "john",
                    "password_file": "words.txt",
                    "max_attempts": attempts,
                    "start_at": start_at,
                    "timeout_seconds": 60,
                },
                _context(),
            )
        )
    return result, seen["wordlist"]


def test_a_slice_that_leaves_entries_is_partial(tmp_path, monkeypatch):
    """v7 iteration 16: there is more list, so there is no verdict yet."""
    result, wordlist = _slice_run(tmp_path, monkeypatch, attempts=2)
    assert result.outcome == "partial"
    assert result.verified is False
    assert result.output["next_start_at"] == 2
    assert result.output["wordlist_completed"] is False
    assert "start_at=2" in result.output["message"]
    assert wordlist == ["pw0", "pw1"]
    # No barrier: the branch stays open for the next slice.
    assert "barrier_recorded" not in result.evidence


def test_the_next_slice_starts_at_the_reported_offset(tmp_path, monkeypatch):
    result, wordlist = _slice_run(tmp_path, monkeypatch, attempts=2, start_at=2)
    assert wordlist == ["pw2", "pw3"]
    assert result.output["next_start_at"] == 4
    assert result.outcome == "partial"


def test_the_last_slice_is_a_negative(tmp_path, monkeypatch):
    """The offset reaches the end of the file: now it *is* a verdict."""
    result, wordlist = _slice_run(tmp_path, monkeypatch, attempts=2, start_at=4)
    assert wordlist == ["pw4", "pw5"]
    assert result.outcome == "negative"
    assert result.output["wordlist_completed"] is True
    assert "message" in result.output


def test_the_default_slice_is_published_in_the_contract():
    from nexus_core.tools.handlers.cred_bruteforce import (
        CRED_DEFAULT_MAX_ATTEMPTS,
        cred_bruteforce_definition,
    )

    schema = cred_bruteforce_definition().input_schema
    assert schema["properties"]["max_attempts"]["default"] == CRED_DEFAULT_MAX_ATTEMPTS
    assert schema["properties"]["start_at"]["default"] == 0
    assert "maximum" not in schema["properties"]["max_attempts"]


# ------------------------------------------------------------------- FIX 6
def _http_payload(**overrides) -> dict:
    payload = {
        "ok": True,
        "status": 200,
        "reason": "OK",
        "headers": {"set-cookie": "PHPSESSID=abc; Path=/"},
        "set_cookie": ["PHPSESSID=abc; Path=/", "csrf=xyz; HttpOnly"],
        "content_type": "text/html",
        "body_complete": True,
        "body_bytes": 2,
        "body_sha256": "0" * 64,
        "body_preview": "ok",
        "preview_truncated": False,
        "elapsed_ms": 3,
    }
    payload.update(overrides)
    return payload


def _http_run(tmp_path, monkeypatch, arguments: dict):
    from nexus_core.tools.handlers import http_request as module

    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    sandbox = SequencedSandbox(
        {"python": SandboxResult(0, json.dumps(_http_payload()), "")}
    )
    with _patch_sandbox(module, sandbox):
        result = asyncio.run(module.http_request_handler(arguments, _context()))
    return result, sandbox.calls[0]


def test_web_request_sends_the_cookie_header_and_parses_the_response(tmp_path, monkeypatch):
    result, argv = _http_run(
        tmp_path,
        monkeypatch,
        {"url": "http://10.67.149.76/admin/panel/", "cookie": "PHPSESSID=abc"},
    )
    # argv: python3 -c <script> <method> <url> <headers_json> ...
    headers = json.loads(argv[5])
    assert headers["Cookie"] == "PHPSESSID=abc"
    # Both shapes travel: the raw header and the parsed name/value map.
    assert result.output["set_cookie"][0].startswith("PHPSESSID=abc")
    assert result.output["response_cookies"] == {"PHPSESSID": "abc", "csrf": "xyz"}
    assert result.evidence["cookie_sent"] is True


def test_web_request_resolves_a_session_ref_without_the_value_in_the_prompt(
    tmp_path, monkeypatch
):
    from nexus_core.kernel.secret_store import default_secret_store

    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    handle = default_secret_store().put(b"PHPSESSID=s3cr3t", kind="session")
    result, argv = _http_run(
        tmp_path,
        monkeypatch,
        {"url": "http://10.67.149.76/admin/panel/", "session_ref": handle},
    )
    assert json.loads(argv[5])["Cookie"] == "PHPSESSID=s3cr3t"
    assert result.evidence["session_ref"] == handle
    assert "s3cr3t" not in json.dumps(result.output)


def test_an_unknown_session_ref_fails_before_the_request(tmp_path, monkeypatch):
    from nexus_core.tools.handlers import http_request as module

    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    sandbox = SequencedSandbox({"python": SandboxResult(0, "{}", "")})
    with _patch_sandbox(module, sandbox), pytest.raises(ValueError, match="unknown session_ref"):
        asyncio.run(
            module.http_request_handler(
                {
                    "url": "http://10.67.149.76/admin/",
                    "session_ref": "vault:" + "0" * 32,
                },
                _context(),
            )
        )
    assert sandbox.calls == []


def _session_answers(probe: dict, hit: str, session: dict) -> dict:
    return {
        "probe_script": None,  # filled by the caller with CRED_PROBE_SCRIPT
        "probe": SandboxResult(0, json.dumps(probe), ""),
        "hydra": SandboxResult(0, hit, ""),
        "python": SandboxResult(0, json.dumps(session), ""),
    }


def test_a_form_hit_captures_the_panel_session(tmp_path, monkeypatch):
    """v7 iteration 20: hydra proved ``admin``; the panel still answered 401."""
    from nexus_core.kernel.secret_store import default_secret_store
    from nexus_core.tools.handlers import cred_bruteforce as module

    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    _slice_workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    answers = _session_answers(
        {"ok": True, "baseline_status": 200, "failure_status": 200,
         "in_baseline": False, "in_failure": True},
        "[80][http-post-form] host: 10.67.149.76   login: admin   password: xavier\n",
        {"ok": True, "baseline_status": 200, "failure_status": 302,
         "in_baseline": False, "in_failure": False,
         "set_cookie": ["PHPSESSID=s3cr3t; Path=/"]},
    )
    answers["probe_script"] = module.CRED_PROBE_SCRIPT

    class CaptureSandbox(SequencedSandbox):
        """The third call is the confirmation login; the second hydra."""

        async def run(self, argv, *, timeout_seconds: float = 30, **kwargs):
            if argv[0] == "python3" and argv[2] == module.CRED_PROBE_SCRIPT:
                self.calls.append(list(argv))
                index = sum(
                    1 for call in self.calls if call[0] == "python3" and call[2] == argv[2]
                )
                return answers["probe"] if index == 1 else answers["python"]
            return await super().run(argv, timeout_seconds=timeout_seconds, **kwargs)

    sandbox = CaptureSandbox(answers)
    with _patch_sandbox(module, sandbox):
        result = asyncio.run(
            module.cred_bruteforce_handler(
                {
                    "target": "10.67.149.76",
                    "service": "http-post-form",
                    "port": 80,
                    "username": "admin",
                    "password_file": "words.txt",
                    "form_url": "/admin/",
                    "form_params": "user=^USER^&pass=^PASS^&submit=Login",
                    "failure_string": "Invalid credentials",
                    "max_attempts": 50,
                },
                _context(),
            )
        )
    assert result.verified is True
    session = result.output["session"]
    assert session["verified"] is True
    assert session["cookies"] == ["PHPSESSID"]
    handle = session["session_ref"]
    assert default_secret_store().get(handle, tenant_id="system") == b"PHPSESSID=s3cr3t"
    assert result.evidence["session_verified"] is True


def test_a_rejected_login_never_claims_a_session(tmp_path, monkeypatch):
    from nexus_core.tools.handlers import cred_bruteforce as module

    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    _slice_workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    answers = _session_answers(
        {"ok": True, "in_baseline": False, "in_failure": True},
        "[80][http-post-form] host: 10.67.149.76   login: admin   password: xavier\n",
        {"ok": True, "in_baseline": False, "in_failure": True,
         "set_cookie": ["PHPSESSID=stale; Path=/"]},
    )
    answers["probe_script"] = module.CRED_PROBE_SCRIPT

    class CaptureSandbox(SequencedSandbox):
        async def run(self, argv, *, timeout_seconds: float = 30, **kwargs):
            if argv[0] == "python3" and argv[2] == module.CRED_PROBE_SCRIPT:
                self.calls.append(list(argv))
                index = sum(
                    1 for call in self.calls if call[0] == "python3" and call[2] == argv[2]
                )
                return answers["probe"] if index == 1 else answers["python"]
            return await super().run(argv, timeout_seconds=timeout_seconds, **kwargs)

    with _patch_sandbox(module, CaptureSandbox(answers)):
        result = asyncio.run(
            module.cred_bruteforce_handler(
                {
                    "target": "10.67.149.76",
                    "service": "http-post-form",
                    "port": 80,
                    "username": "admin",
                    "password_file": "words.txt",
                    "form_url": "/admin/",
                    "form_params": "user=^USER^&pass=^PASS^",
                    "failure_string": "Invalid credentials",
                    "max_attempts": 50,
                },
                _context(),
            )
        )
    assert result.output["session"]["verified"] is False
    assert result.output["session"]["reason"] == "failure_marker_still_present"
    assert "session_ref" not in result.output["session"]


class _RedirectCookieFormHandler(http.server.BaseHTTPRequestHandler):
    """A panel that answers ``302 + Set-Cookie`` on success, like most do."""

    def do_GET(self):  # noqa: N802 - stdlib naming
        if self.path.startswith("/admin/panel"):
            cookie = self.headers.get("Cookie") or ""
            if "PHPSESSID=s3cr3t" in cookie:
                self._send(200, b"<h1>Panel</h1>", None)
                return
            self._send(302, b"", "/admin/")
            return
        self._send(200, b"<form>Admin Login Page</form>", None)

    def do_POST(self):  # noqa: N802 - stdlib naming
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        if "pass=xavier" in body:
            self._send(302, b"", "/admin/panel/", cookie="PHPSESSID=s3cr3t; Path=/")
        else:
            self._send(200, b"<div>Invalid credentials</div>", None)

    def _send(self, status: int, body: bytes, location: str | None, *, cookie: str | None = None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        if location:
            self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # noqa: ARG002 - silence the server
        return


def test_a_redirecting_login_still_yields_its_cookie():
    """The measured shape: 302 -> /panel with the session on the 302 itself.

    Following the redirect silently dropped the ``Set-Cookie`` and the capture
    reported ``no_set_cookie`` (first E2E of the fix). The probe now stops at
    the 302, keeps the cookie and reads the failure marker on the next page.
    """
    from nexus_core.tools.handlers import cred_bruteforce as module

    server = http.server.HTTPServer(("127.0.0.1", 0), _RedirectCookieFormHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/admin/"
        proc = subprocess.run(
            [sys.executable, "-c", module.CRED_PROBE_SCRIPT, url, "POST", url,
             "user=admin&pass=xavier", "Invalid credentials", "10"],
            capture_output=True, text=True, timeout=60,
        )
    finally:
        server.shutdown()
        server.server_close()
    payload = json.loads(proc.stdout.splitlines()[-1])
    assert payload["set_cookie"] == ["PHPSESSID=s3cr3t; Path=/"]
    assert payload["in_failure"] is False
    assert payload["failure_status"] == 200  # the page the redirect landed on


class _CookieFormHandler(http.server.BaseHTTPRequestHandler):
    """A panel that only sets ``PHPSESSID`` when the credentials are right."""

    def do_GET(self):  # noqa: N802 - stdlib naming
        self._send(b"<form>Admin Login Page</form>", cookie=None)

    def do_POST(self):  # noqa: N802 - stdlib naming
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        if "pass=xavier" in body:
            self._send(b"<h1>Panel</h1>", cookie="PHPSESSID=s3cr3t; Path=/")
        else:
            self._send(b"<div>Invalid credentials</div>", cookie=None)

    def _send(self, body: bytes, *, cookie: str | None) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # noqa: ARG002 - silence the server
        return


def test_the_shipped_probe_returns_the_session_cookie_of_a_real_login():
    """The probe script now reports ``set_cookie``: the session's only carrier."""
    from nexus_core.tools.handlers import cred_bruteforce as module

    server = http.server.HTTPServer(("127.0.0.1", 0), _CookieFormHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/admin/"
        good = subprocess.run(
            [sys.executable, "-c", module.CRED_PROBE_SCRIPT, url, "POST", url,
             "user=admin&pass=xavier", "Invalid credentials", "10"],
            capture_output=True, text=True, timeout=60,
        )
        bad = subprocess.run(
            [sys.executable, "-c", module.CRED_PROBE_SCRIPT, url, "POST", url,
             "user=admin&pass=wrong", "Invalid credentials", "10"],
            capture_output=True, text=True, timeout=60,
        )
    finally:
        server.shutdown()
        server.server_close()
    assert good.returncode == 0, good.stderr
    payload = json.loads(good.stdout.splitlines()[-1])
    assert payload["in_failure"] is False
    assert payload["set_cookie"] == ["PHPSESSID=s3cr3t; Path=/"]
    # A rejected login sets nothing: the capture can tell them apart.
    assert json.loads(bad.stdout.splitlines()[-1])["set_cookie"] == []


# ------------------------------------------------------------------- FIX 7
def test_the_three_ssh_tools_declare_key_authentication():
    from nexus_core.tools.handlers.ssh_post import (
        enum_system_definition,
        ssh_exec_definition,
        ssh_upload_definition,
    )

    for definition in (ssh_exec_definition(), enum_system_definition(), ssh_upload_definition()):
        properties = definition.input_schema["properties"]
        assert "private_key" in properties, definition.tool_id
        assert "passphrase" in properties, definition.tool_id


def test_ssh_exec_carries_the_key_instead_of_the_password(monkeypatch):
    from nexus_core.tools.handlers import ssh_post as module

    sandbox = SequencedSandbox(
        {"python": SandboxResult(0, json.dumps({
            "ok": True, "connected": True, "mode": "exec",
            "stdout": "uid=0(root) gid=0(root)", "stderr": "", "exit_status": 0,
        }), "")}
    )
    with _patch_sandbox(module, sandbox):
        result = asyncio.run(
            module.ssh_exec_handler(
                {
                    "target": "10.67.149.76",
                    "username": "john",
                    "command": "id",
                    "private_key": SAMPLE_KEY,
                    "passphrase": "brutepass",
                },
                _context(),
            )
        )
    argv = sandbox.calls[0]
    payload = json.loads(argv[8])
    assert payload["private_key"] == SAMPLE_KEY
    assert payload["passphrase"] == "brutepass"
    # A passphrase is not the account password: it must not reach sudo -S.
    assert argv[7] == ""
    assert result.evidence["auth"] == "private_key"
    assert result.verified is True


def test_a_resolved_credential_ref_becomes_the_key_passphrase(monkeypatch):
    """The gateway puts a ``credential_ref`` in ``password``; here that is a passphrase."""
    from nexus_core.tools.handlers import ssh_post as module

    sandbox = SequencedSandbox(
        {"python": SandboxResult(0, json.dumps({
            "ok": True, "connected": True, "mode": "exec",
            "stdout": "john", "stderr": "", "exit_status": 0,
        }), "")}
    )
    with _patch_sandbox(module, sandbox):
        asyncio.run(
            module.ssh_exec_handler(
                {
                    "target": "10.67.149.76",
                    "username": "john",
                    "command": "whoami",
                    "private_key": SAMPLE_KEY,
                    "password": "cracked-passphrase",
                },
                _context(),
            )
        )
    payload = json.loads(sandbox.calls[0][8])
    assert payload["passphrase"] == "cracked-passphrase"
    assert sandbox.calls[0][7] == ""


def test_the_shipped_ssh_client_logs_in_with_the_key(tmp_path):
    """Run the real client script against a stub paramiko: no network, real code.

    The stub refuses a password-only ``connect`` and records which key it parsed,
    so passing this test means the shipped script routed the PEM into
    ``connect(pkey=...)`` with the passphrase, not into ``password=``.
    """
    from nexus_core.tools.handlers.ssh_post import SSH_CLIENT_SCRIPT

    stub_dir = tmp_path / "stubs"
    stub_dir.mkdir()
    marker = tmp_path / "connect.json"
    (stub_dir / "paramiko.py").write_text(
        f"""
import json
MARKER = {str(marker)!r}
class _Key:
    def __init__(self, text, password):
        self.text, self.password = text, password
    @classmethod
    def from_private_key_string(cls, text, password=None):
        if "PRIVATE KEY" not in text:
            raise ValueError("not a key")
        return cls(text, password)
class RSAKey(_Key): pass
class Ed25519Key(_Key): pass
class ECDSAKey(_Key): pass
class AutoAddPolicy: pass
class _Channel:
    def recv_exit_status(self): return 0
    def shutdown_write(self): pass
class _Stream:
    def __init__(self, data): self.data = data
    def read(self): return self.data
    def write(self, data): pass
    def flush(self): pass
    channel = _Channel()
class SSHClient:
    def set_missing_host_key_policy(self, policy): pass
    def connect(self, **kwargs):
        pkey = kwargs.get("pkey")
        json.dump({{"has_pkey": pkey is not None,
                   "key_password": getattr(pkey, "password", None),
                   "password": kwargs.get("password")}}, open(MARKER, "w"))
        if pkey is None:
            raise RuntimeError("password auth is not allowed here")
    def exec_command(self, command, timeout=None, get_pty=False):
        return _Stream(b""), _Stream(b"uid=0(root)\\n"), _Stream(b"")
    def close(self): pass
""",
        encoding="utf-8",
    )
    payload = {"command": "id", "command_timeout": 30, "stdin": None,
               "private_key": SAMPLE_KEY, "passphrase": "brutepass"}
    env = dict(os.environ, PYTHONPATH=str(stub_dir))
    proc = subprocess.run(
        [sys.executable, "-c", SSH_CLIENT_SCRIPT, "exec", "127.0.0.1", "22",
         "john", "", json.dumps(payload)],
        capture_output=True, text=True, timeout=60, env=env,
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.splitlines()[-1])
    assert result["connected"] is True
    recorded = json.loads(marker.read_text(encoding="utf-8"))
    assert recorded["has_pkey"] is True
    assert recorded["key_password"] == "brutepass"
    assert recorded["password"] is None


# ------------------------------------------------------------------- FIX 8
def test_detect_hash_type_names_the_common_shapes():
    from nexus_core.tools.handlers.crack_hash import detect_hash_type

    assert detect_hash_type("5f4dcc3b5aa765d61d8327deb882cf99") == "md5"
    assert detect_hash_type("user:5f4dcc3b5aa765d61d8327deb882cf99") == "md5"
    assert detect_hash_type("$6$rounds=5000$abc$def") == "sha512crypt"
    assert detect_hash_type("$2y$10$abc") == "bcrypt"
    assert detect_hash_type(SAMPLE_KEY) == "ssh"
    assert detect_hash_type("definitely not a hash") == ""


def test_crack_hash_rejects_an_unrecognisable_shape():
    from nexus_core.tools.handlers.crack_hash import crack_hash_handler

    with pytest.raises(ValueError, match="could not be autodetected"):
        asyncio.run(
            crack_hash_handler({"hash_content": "definitely not a hash"}, _context())
        )


def test_crack_hash_is_registered_in_the_runtime_catalog():
    from nexus_core.tools.registry import durable_tool_definitions

    definition, handler = durable_tool_definitions()["nexus.post.crack_hash"]
    assert definition.effect == "credential_access"
    assert definition.scope_required is False  # offline: the target is never hit
    assert callable(handler)


JOHN = shutil.which("john") or ("/usr/sbin/john" if os.path.exists("/usr/sbin/john") else "")


@pytest.mark.skipif(not JOHN, reason="john is not installed on this host")
def test_john_cracks_an_md5_and_only_the_vault_handle_travels(tmp_path, monkeypatch):
    """End to end with the real binary: the plaintext never enters the result."""
    from nexus_core.kernel.secret_store import default_secret_store
    from nexus_core.tools.handlers.crack_hash import crack_hash_handler

    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    (tmp_path / "wl.txt").write_text("123456\npassword\nletmein\n", encoding="utf-8")
    result = asyncio.run(
        crack_hash_handler(
            {
                "hash_content": "brute:5f4dcc3b5aa765d61d8327deb882cf99",
                "wordlist": "wl.txt",
                "username": "brute",
            },
            _context(),
        )
    )
    assert result.verified is True
    assert result.verification_method == "crack_hash_john_show"
    assert result.output["cracked_count"] == 1
    credential = result.output["valid_credentials"][0]
    assert credential["username"] == "brute"
    assert "password" not in credential
    assert "password" not in json.dumps(result.output)
    assert default_secret_store().get(credential["secret_ref"], tenant_id="system") == b"password"


@pytest.mark.skipif(not JOHN, reason="john is not installed on this host")
def test_john_returns_a_negative_when_the_wordlist_misses(tmp_path, monkeypatch):
    from nexus_core.tools.handlers.crack_hash import crack_hash_handler

    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    (tmp_path / "wl.txt").write_text("123456\nletmein\n", encoding="utf-8")
    result = asyncio.run(
        crack_hash_handler(
            {
                "hash_content": "brute:5f4dcc3b5aa765d61d8327deb882cf99",
                "wordlist": "wl.txt",
            },
            _context(),
        )
    )
    assert result.verified is False
    assert result.outcome == "negative"
    assert result.output["valid_credentials"] == []


def test_the_verifier_promotes_a_cracked_hash_as_a_credential(tmp_path, monkeypatch):
    from nexus_core.kernel.fact_verification import derive_assertions
    from nexus_core.kernel.secret_store import default_secret_store

    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    handle = default_secret_store().put(b"brutepass")
    result = ToolResult(
        output={
            "hash_type": "ssh",
            "target": "10.67.149.76",
            "valid_credentials": [{"username": "john", "secret_ref": handle}],
        },
        verified=True,
        verification_method="crack_hash_john_show",
    )
    rows = derive_assertions(
        "nexus.post.crack_hash", {}, result, SimpleNamespace(invocation_id="i", run_id="r")
    )
    credential = next(row for row in rows if row["fact_type"] == "credential")
    assert credential["key"] == "10.67.149.76"
    assert credential["value"]["username"] == "john"
    assert credential["value"]["secret_ref"] == handle
    assert credential["value"]["service"] == "ssh"
    assert "password" not in credential["value"]


# ------------------------------------------------- workspace.search (v7 iter 27)
def test_workspace_search_keeps_the_matches_of_a_dirty_walk(tmp_path, monkeypatch):
    """``grep`` exits 2 after an unreadable file; the matches are still results."""
    from nexus_core.tools.handlers import workspace as module

    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    dirty = SandboxResult(2, "./ssh_pw.txt:2:password\n./wl.txt:4:password1\n",
                          "grep: ./root-only: Permission denied\n")
    # ``search_argv`` prefers ``rg`` when it is installed: answer both names.
    sandbox = SequencedSandbox({"grep": dirty, "rg": dirty})
    with _patch_sandbox(module, sandbox):
        result = asyncio.run(module.workspace_search_handler({"query": "password"}, _context()))
    assert result.verified is True
    assert "./ssh_pw.txt:2:password" in result.output["matches"]
    assert result.evidence["exit_code"] == 2
    assert result.evidence["match_count"] == 2


def test_workspace_search_with_no_matches_and_an_error_stays_unverified(tmp_path, monkeypatch):
    from nexus_core.tools.handlers import workspace as module

    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    broken = SandboxResult(2, "", "grep: .: No such file or directory\n")
    sandbox = SequencedSandbox({"grep": broken, "rg": broken})
    with _patch_sandbox(module, sandbox):
        result = asyncio.run(module.workspace_search_handler({"query": "password"}, _context()))
    assert result.verified is False
