"""Unit tests for the governed NetNTLM capture listener (sandbox mocked)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import ntlm_capture as ntlm_module
from nexus_core.tools.handlers.ntlm_capture import (
    ntlm_capture_definition,
    ntlm_capture_handler,
)


class FakeSandbox:
    def __init__(self, result: SandboxResult):
        self.result = result
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append((list(argv), timeout_seconds))
        return self.result


@contextlib.contextmanager
def _fake_sandbox(result: SandboxResult, *, peer_in_scope: bool = True):
    sandbox = FakeSandbox(result)
    with mock.patch.object(
        ntlm_module, "sandbox_for_environment", lambda *a, **k: sandbox
    ), mock.patch.object(
        ntlm_module, "validate_session_scope", lambda ctx: None
    ), mock.patch.object(
        ntlm_module, "_peer_in_scope", lambda ctx, peer: peer_in_scope
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(ntlm_capture_handler(arguments, _context()))


def _sandbox_for(payload: dict, exit_code: int = 0) -> SandboxResult:
    return SandboxResult(exit_code, json.dumps(payload) + "\n", "")


def _capture_payload(peer: str = "203.0.113.10", **overrides) -> dict:
    payload = {
        "ok": True,
        "bound": True,
        "port": 8081,
        "peer": peer,
        "peers": [peer],
        "connections": 2,
        "requests": 3,
        "status": "ok",
        "challenge": "0123456789abcdef",
        "bytes": 512,
        "sha256": "b" * 64,
        "transcript": "GET /a.png HTTP/1.1\r\nHost: 203.0.113.5\r\n\r\n",
        "elapsed_ms": 900,
        "captured": True,
        "hash_type": "netntlmv2",
        "hash": "buse::WINDCORP:0123456789abcdef:1111111111111111:2222222222222222",
        "username": "buse",
        "domain": "WINDCORP",
    }
    payload.update(overrides)
    return payload


# ------------------------------------------------------------------ definition
def test_definition_is_high_risk_post_exploitation_and_engagement_scoped():
    definition = ntlm_capture_definition()
    assert definition.tool_id == "nexus.post.ntlm_capture"
    assert definition.risk.value == "high"
    assert definition.effect == "post_exploitation"
    assert definition.scope_required is True
    assert definition.scope_target_field is None
    assert definition.input_schema["required"] == ["port"]


def test_client_script_is_valid_python():
    """The embedded stdlib catcher must at least compile (it is shipped verbatim)."""
    compile(ntlm_module.NTLM_CAPTURE_CLIENT_SCRIPT, "<ntlm_capture>", "exec")


# --------------------------------------------------------------------- handler
def test_handler_runs_python_client_in_sandbox_and_persists_the_hash(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_capture_payload())) as sandbox:
        result = _run({"port": 8081, "target_name": "WINDCORP"})
    argv = sandbox.calls[0][0]
    assert argv[0] == "python3" and argv[1] == "-c"
    assert argv[3] == "0.0.0.0" and argv[4] == "8081"
    assert argv[10] == "WINDCORP"
    assert len(argv[9]) == 16  # server challenge, 8 bytes hex
    assert result.verified is True
    assert result.verification_method == "ntlm_capture_hash"
    assert result.output["hash"].startswith("buse::WINDCORP:")
    assert result.evidence["hash_type"] == "netntlmv2"
    artifacts = list(tmp_path.glob("ntlm_capture_*.hash"))
    assert artifacts and artifacts[0].read_text().startswith("buse::WINDCORP:")
    assert list(tmp_path.glob("ntlm_capture_*.txt"))


def test_handler_reports_no_hash_when_nothing_was_captured(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    payload = _capture_payload(captured=False)
    for key in ("hash_type", "hash", "username", "domain"):
        payload.pop(key)
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"port": 8081})
    assert result.verified is False
    assert result.verification_method == "ntlm_capture_no_hash"
    # The exchange finished without a recoverable hash (V0-22).
    assert result.outcome == "negative"
    assert result.output["captured"] is False
    assert not list(tmp_path.glob("ntlm_capture_*.hash"))


def test_handler_distinguishes_no_connection_from_a_refused_peer(tmp_path, monkeypatch):
    """"Nobody took the bait" must never read as "we refused a peer".

    sala10 measured a live run where the listener bound, the window elapsed and
    no host ever connected; it was reported with the *same* method name and the
    same "out-of-scope host" message as a run that really did have to refuse an
    inbound authentication. Only the second case is a governance event.
    """
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    payload = _capture_payload(peer="", peers=[], connections=0, requests=0)
    for key in ("hash_type", "hash", "username", "domain"):
        payload.pop(key)
    # ``peer_in_scope=False`` proves the no-connection path never consults scope.
    with _fake_sandbox(_sandbox_for(payload), peer_in_scope=False):
        result = _run({"port": 8081})
    assert result.verified is False
    assert result.verification_method == "ntlm_capture_no_connection"
    # "Nobody took the bait" is a recorded observation, not a failure (V0-22).
    assert result.outcome == "negative"
    assert result.evidence["connections"] == 0
    assert "out-of-scope" not in str(result.output)
    assert not list(tmp_path.glob("ntlm_capture_*.hash"))


def test_handler_refuses_an_out_of_scope_peer(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_capture_payload(peer="192.0.2.7")), peer_in_scope=False):
        result = _run({"port": 8081})
    assert result.verified is False
    assert result.verification_method == "ntlm_capture_peer_out_of_scope"
    assert result.evidence["peer"] == "192.0.2.7"
    assert not list(tmp_path.glob("ntlm_capture_*.hash"))


def test_handler_reports_a_bind_failure():
    payload = {"ok": False, "bound": False, "port": 8081, "error": "PermissionError: 13"}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"port": 8081})
    assert result.verified is False
    assert result.verification_method == "ntlm_capture_bind_failed"


# ------------------------------------------------------- shipped client script
def _type3(user: str = "buse", domain: str = "WINDCORP", host: str = "FIRE") -> bytes:
    """Build a minimal NTLMSSP type-3 message the catcher has to parse."""
    lm = b"\x00" * 24
    nt = b"\x11" * 16 + b"\x22" * 32  # NTProofStr + blob ⇒ NetNTLMv2
    blobs = [lm, nt, domain.encode("utf-16-le"), user.encode("utf-16-le"),
             host.encode("utf-16-le")]
    offset = 72
    fields = b""
    for blob in blobs:
        fields += struct.pack("<HHI", len(blob), len(blob), offset)
        offset += len(blob)
    fields += struct.pack("<HHI", 0, 0, offset)  # session key (empty) keeps the layout
    return b"NTLMSSP\x00" + struct.pack("<I", 3) + fields + b"\x00" * 12 + b"".join(blobs)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _get(port: int, token: str | None) -> str:
    request = f"GET /a.png HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
    if token:
        request += f"Authorization: NTLM {token}\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall((request + "\r\n").encode())
        chunks = []
        while True:
            data = conn.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", "replace")


def test_shipped_catcher_labels_a_probe_then_handshake_as_captured():
    """End-to-end run of the real script: a bare probe must not relabel the run.

    The live sala #9 run returned ``status=no_ntlm`` *next to* ``captured=true``
    because the status tracked the last connection instead of the whole capture.
    """
    import base64

    port = _free_port()
    argv = [sys.executable, "-c", ntlm_module.NTLM_CAPTURE_CLIENT_SCRIPT, "127.0.0.1",
            str(port), "20", "2", "4", "65536", "0123456789abcdef", "WINDCORP", "", ""]
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if process.poll() is not None:
                    raise AssertionError(process.stderr.read())
                time.sleep(0.05)
        # 1) a bare probe (its own connection, no NTLM at all)
        assert "401" in _get(port, None)
        # 2) the handshake: type 1 on one connection, type 3 on the next
        type1 = base64.b64encode(b"NTLMSSP\x00" + struct.pack("<I", 1) + b"\x00" * 12 * 4)
        assert "WWW-Authenticate: NTLM" in _get(port, type1.decode())
        type3 = base64.b64encode(_type3()).decode()
        assert "200" in _get(port, type3)
        stdout, stderr = process.communicate(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()
    payload = json.loads([line for line in stdout.splitlines() if line.startswith("{")][-1])
    assert payload["captured"] is True, stderr
    assert payload["status"] == "captured"
    assert payload["username"] == "buse" and payload["domain"] == "WINDCORP"
    assert payload["hash_type"] == "netntlmv2"
    assert payload["hash"].startswith("buse::WINDCORP:0123456789abcdef:")
    assert payload["connections"] >= 2 and payload["requests"] >= 3


# ------------------------------------------------------- TLS (poisoned https bait)
def _tls_cert_pair(tmp_path) -> tuple[str, str]:
    """Generate a throwaway PEM pair with the system openssl."""
    key = tmp_path / "key.pem"
    cert = tmp_path / "crt.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "2",
         "-subj", "/CN=selfservice.windcorp.thm",
         "-addext", "subjectAltName=DNS:selfservice.windcorp.thm"],
        check=True, capture_output=True, timeout=60,
    )
    return str(cert), str(key)


def _get_tls(port: int, token: str | None) -> str:
    import ssl

    context = ssl._create_unverified_context()
    request = "GET / HTTP/1.1\r\nHost: selfservice.windcorp.thm\r\n"
    if token:
        request += f"Authorization: NTLM {token}\r\n"
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    with context.wrap_socket(raw, server_hostname="selfservice.windcorp.thm") as conn:
        conn.sendall((request + "\r\n").encode())
        chunks = []
        while True:
            data = conn.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", "replace")


def test_shipped_catcher_serves_tls_and_captures_the_hash(tmp_path):
    """sala10: the victim reaches the poisoned name over https and aborts the
    handshake unless the real certificate is presented, so NTLM was never offered
    while the catcher could only speak plain HTTP. The shipped script is run for
    real here, with the certificate, over TLS."""
    import base64

    cert, key = _tls_cert_pair(tmp_path)
    port = _free_port()
    argv = [sys.executable, "-c", ntlm_module.NTLM_CAPTURE_CLIENT_SCRIPT, "127.0.0.1",
            str(port), "25", "3", "4", "65536", "0123456789abcdef", "WINDCORP",
            cert, key]
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if process.poll() is not None:
                    raise AssertionError(process.stderr.read())
                time.sleep(0.05)
        assert "401" in _get_tls(port, None)
        type1 = base64.b64encode(b"NTLMSSP\x00" + struct.pack("<I", 1) + b"\x00" * 12 * 4)
        assert "WWW-Authenticate: NTLM" in _get_tls(port, type1.decode())
        type3 = base64.b64encode(_type3()).decode()
        assert "200" in _get_tls(port, type3)
        stdout, stderr = process.communicate(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()
    payload = json.loads([line for line in stdout.splitlines() if line.startswith("{")][-1])
    assert payload["tls"] is True, stderr
    assert payload["captured"] is True, stderr
    assert payload["username"] == "buse" and payload["domain"] == "WINDCORP"
    assert payload["hash_type"] == "netntlmv2"


def test_handler_passes_the_tls_pair_to_the_sandbox_and_records_it(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    cert, key = _tls_cert_pair(tmp_path)
    (tmp_path / "certs").mkdir(exist_ok=True)
    (tmp_path / "certs" / "crt.pem").write_text(Path(cert).read_text())
    (tmp_path / "certs" / "key.pem").write_text(Path(key).read_text())
    payload = _capture_payload(captured=False, tls=True)
    for field in ("hash_type", "hash", "username", "domain"):
        payload.pop(field)
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run({"port": 443, "tls_cert": "certs/crt.pem", "tls_key": "certs/key.pem"})
    argv = sandbox.calls[0][0]
    assert argv[11].endswith("certs/crt.pem") and argv[12].endswith("certs/key.pem")
    assert result.evidence["tls"] is True
    assert result.evidence["tls_cert"] == "crt.pem"
    assert len(result.evidence["tls_cert_sha256"]) == 64
    assert result.output["tls"] is True


def test_handler_requires_both_halves_of_the_tls_pair(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_capture_payload())):
        with pytest.raises(ValueError, match="tls_cert and tls_key"):
            _run({"port": 443, "tls_cert": "certs/crt.pem"})


def test_handler_refuses_a_tls_pair_that_does_not_load(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / "certs").mkdir()
    (tmp_path / "certs" / "crt.pem").write_text("not a certificate")
    (tmp_path / "certs" / "key.pem").write_text("not a key")
    with _fake_sandbox(_sandbox_for(_capture_payload())):
        with pytest.raises(ValueError, match="do not load as a pair"):
            _run({"port": 443, "tls_cert": "certs/crt.pem", "tls_key": "certs/key.pem"})


def test_handler_refuses_a_tls_path_outside_the_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    outside = tmp_path.parent / "outside.key"
    outside.write_text("x")
    with _fake_sandbox(_sandbox_for(_capture_payload())):
        with pytest.raises(ValueError, match="workspace"):
            _run({"port": 443, "tls_cert": "../outside.key", "tls_key": "../outside.key"})


def test_handler_requires_an_engagement_scope():
    class _Unscoped:
        scope = None

    with mock.patch.object(
        ntlm_module,
        "validate_session_scope",
        mock.Mock(side_effect=PermissionError("scope required")),
    ):
        result = asyncio.run(
            ntlm_capture_handler({"port": 8081}, _context())
        )
    assert result.verified is False
    assert result.verification_method == "ntlm_capture_scope_required"
