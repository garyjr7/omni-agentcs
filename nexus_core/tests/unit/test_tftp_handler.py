"""Unit tests for the durable TFTP (payload-delivery) handler.

The shipped client is exercised for real against a local UDP server that
records the wire traffic, so the RFC 1350 framing (WRQ/RRQ opcodes, octet mode,
512-byte DATA blocks, ACK semantics and the terminating short block) is
asserted instead of assumed.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import socket
import struct
import subprocess
import sys
import threading
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import tftp as tftp_module
from nexus_core.tools.handlers.tftp import (
    TFTP_SCRIPT,
    tftp_definition,
    tftp_handler,
    validate_remote_name,
)

OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR = 1, 2, 3, 4, 5


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
    with mock.patch.object(tftp_module, "sandbox_for_environment", lambda *a, **k: sandbox):
        yield sandbox


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A workspace with a small payload file, exported as the handler root."""
    (tmp_path / "payload.txt").write_bytes(b"DELAY 500\nGUI r\n")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    yield tmp_path


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(tftp_handler(arguments, _context()))


def _sandbox_for(payload: dict) -> SandboxResult:
    return SandboxResult(0, json.dumps(payload) + "\n", "")


# ------------------------------------------------------- real wire-level server
class _UdpTftpServer:
    """One-shot UDP TFTP server: records an upload or serves a download."""

    def __init__(self, serve_data: bytes | None = None, error_code: int | None = None):
        self.serve_data = serve_data
        self.error_code = error_code
        self.received = bytearray()
        self.wrq_packet: bytes | None = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(20)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        try:
            pkt, peer = self.sock.recvfrom(2048)
        except OSError:
            return
        op = struct.unpack_from("!H", pkt, 0)[0]
        if self.error_code is not None:
            self.sock.sendto(
                struct.pack("!HH", OP_ERROR, self.error_code) + b"denied\x00", peer
            )
            return
        if op == OP_WRQ:
            self.wrq_packet = pkt
            self.sock.sendto(struct.pack("!HH", OP_ACK, 0), peer)
            expected = 1
            while True:
                data, peer = self.sock.recvfrom(2048)
                d_op = struct.unpack_from("!H", data, 0)[0]
                if d_op == OP_ERROR:
                    return
                block = struct.unpack_from("!H", data, 2)[0]
                if block != expected:
                    continue
                self.received.extend(data[4:])
                self.sock.sendto(struct.pack("!HH", OP_ACK, block), peer)
                expected = (expected + 1) & 0xFFFF
                if len(data[4:]) < 512:
                    return
        elif op == OP_RRQ:
            payload = self.serve_data or b""
            block = 1
            offset = 0
            while True:
                chunk = payload[offset:offset + 512]
                self.sock.sendto(struct.pack("!HH", OP_DATA, block) + chunk, peer)
                try:
                    self.sock.recvfrom(2048)
                except OSError:
                    return
                offset += 512
                block = (block + 1) & 0xFFFF
                if len(chunk) < 512:
                    return

    def close(self) -> None:
        self.sock.close()


def _run_client(port: int, *, action: str = "put", remote: str = "rev.txt",
                data: bytes = b"", timeout: str = "10") -> dict:
    argv = [
        sys.executable, "-c", TFTP_SCRIPT, action, "127.0.0.1", str(port),
        remote, "octet", base64.b64encode(data).decode(), timeout,
    ]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    payloads = [line for line in proc.stdout.splitlines() if line.startswith("{")]
    assert payloads, proc.stdout + proc.stderr
    return json.loads(payloads[-1])


def test_shipped_client_uploads_with_octet_blocks_and_reports_the_acks():
    body = b"DELAY 500\nGUI r\n" + b"A" * 600  # >1 block, so framing matters
    server = _UdpTftpServer()
    try:
        payload = _run_client(server.port, action="put", data=body)
    finally:
        server.close()
    assert payload["ok"] is True
    assert payload["bytes"] == len(body)
    assert payload["sha256"] == hashlib.sha256(body).hexdigest()
    assert server.wrq_packet is not None
    assert struct.unpack_from("!H", server.wrq_packet, 0)[0] == OP_WRQ
    assert server.wrq_packet[2:].split(b"\x00", 1)[0] == b"rev.txt"
    assert bytes(server.received) == body


def test_shipped_client_downloads_a_file_it_reassembles_correctly():
    server = _UdpTftpServer(serve_data=b"hello-tftp-" * 100)
    try:
        payload = _run_client(server.port, action="get", remote="readme")
    finally:
        server.close()
    assert payload["ok"] is True
    assert payload["bytes"] == 1100
    assert payload["sha256"] == hashlib.sha256(b"hello-tftp-" * 100).hexdigest()
    assert base64.b64decode(payload["content_b64"]) == b"hello-tftp-" * 100


def test_shipped_client_surfaces_a_server_error():
    server = _UdpTftpServer(error_code=2)
    try:
        payload = _run_client(server.port, action="put", data=b"x")
    finally:
        server.close()
    assert payload["ok"] is False
    assert payload["server_error"]["code"] == 2
    assert payload["stage"] == "wrq"


# ------------------------------------------------------------------ definition
def test_definition_is_scoped_and_declares_the_payload_effect():
    definition = tftp_definition()
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True
    assert definition.sandbox_required is True
    assert definition.effect == "exploit"
    assert definition.risk.value == "high"
    assert definition.idempotent is False
    assert definition.input_schema["properties"]["action"]["enum"] == ["put", "get"]


# --------------------------------------------------------------------- handler
def test_handler_runs_the_client_in_the_sandbox(workspace):
    payload = {"ok": True, "action": "put", "bytes": 3, "blocks": 1, "sha256": "aa"}
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run({"target": "10.66.173.92", "remote_file": "rev.txt",
                       "local_file": "payload.txt"})
    argv = sandbox.calls[0][0]
    assert argv[0] == "python3" and argv[1] == "-c"
    assert argv[3] == "put" and argv[4] == "10.66.173.92" and argv[5] == "69"
    assert argv[6] == "rev.txt" and argv[7] == "octet"
    assert result.verified is True
    assert result.verification_method == "tftp_upload_completed"
    assert result.evidence["bytes"] == 3


def test_handler_never_spawns_subprocess_directly(workspace):
    payload = {"ok": True, "action": "put", "bytes": 10, "blocks": 1}
    with _fake_sandbox(_sandbox_for(payload)):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"target": "10.66.173.92", "remote_file": "rev.txt",
                  "local_file": "payload.txt"})


def test_missing_local_file_is_refused():
    with pytest.raises(ValueError):
        _run({"target": "10.66.173.92", "remote_file": "rev.txt", "action": "put"})


def test_server_error_is_a_declared_negative(workspace):
    payload = {"ok": False, "stage": "wrq", "server_error": {"code": 6, "message": "exists"}}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"target": "10.66.173.92", "remote_file": "rev.txt",
                       "local_file": "payload.txt"})
    assert result.verified is False
    assert result.verification_method == "tftp_server_error"
    assert result.evidence["server_error_code"] == 6


def test_timeout_is_not_verified(workspace):
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"target": "10.66.173.92", "remote_file": "rev.txt",
                       "local_file": "payload.txt"})
    assert result.verified is False
    assert result.verification_method == "tftp_timeout"


def test_client_error_is_not_verified(workspace):
    with _fake_sandbox(_sandbox_for({"ok": False, "stage": "wrq", "error": "OSError: bad"})):
        result = _run({"target": "10.66.173.92", "remote_file": "rev.txt",
                       "local_file": "payload.txt"})
    assert result.verified is False
    assert result.verification_method == "tftp_failed"


def test_get_writes_the_download_into_the_workspace(workspace):
    body = b"readme-bytes"
    payload = {
        "ok": True, "action": "get", "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "content_b64": base64.b64encode(body).decode(),
    }
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"target": "10.66.173.92", "remote_file": "readme.txt",
                       "action": "get"})
    assert result.verified is True
    assert result.verification_method == "tftp_download_completed"
    artifact = result.evidence["artifact"]
    assert artifact and artifact.endswith("_readme.txt")
    from pathlib import Path

    assert Path(artifact).read_bytes() == body


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize("bad", ["../evil", "a/b", "a\\b", ".hidden", "", "x\x00y"])
def test_remote_names_that_are_paths_or_dotfiles_are_refused(bad):
    with pytest.raises(ValueError):
        validate_remote_name(bad)


def test_valid_remote_name_is_returned():
    assert validate_remote_name(" rev.txt ") == "rev.txt"


def test_unsupported_action_and_mode_are_refused():
    with pytest.raises(ValueError):
        _run({"target": "10.66.173.92", "remote_file": "rev.txt", "action": "flatten"})
    with pytest.raises(ValueError):
        _run({"target": "10.66.173.92", "remote_file": "rev.txt", "mode": "base64"})
