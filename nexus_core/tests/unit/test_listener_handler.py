"""Unit tests for the governed reverse-shell listener (sandbox mocked)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import subprocess
import sys
import time
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import listener as listener_module
from nexus_core.tools.handlers.listener import (
    LISTENER_CLIENT_SCRIPT,
    listener_definition,
    listener_handler,
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
        listener_module, "sandbox_for_environment", lambda *a, **k: sandbox
    ), mock.patch.object(listener_module, "validate_session_scope", lambda ctx: None), \
       mock.patch.object(listener_module, "_peer_in_scope", lambda ctx, peer: peer_in_scope):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict, *, peer_in_scope: bool = True) -> object:
    return asyncio.run(
        listener_handler.__wrapped__(arguments, _context())
        if hasattr(listener_handler, "__wrapped__")
        else listener_handler(arguments, _context())
    )


def _sandbox_for(payload: dict, exit_code: int = 0) -> SandboxResult:
    return SandboxResult(exit_code, json.dumps(payload) + "\n", "")


def _catch_payload(peer: str = "203.0.113.10", **overrides) -> dict:
    payload = {
        "ok": True,
        "bound": True,
        "peer": peer,
        "peer_allowed": True,
        "port": 9001,
        "commands_sent": ["id"],
        "status": "closed",
        "bytes": 42,
        "sha256": "a" * 64,
        "transcript": "uid=33(www-data) gid=33(www-data)\n",
        "truncated": False,
        "elapsed_ms": 1200,
    }
    payload.update(overrides)
    return payload


# ------------------------------------------------------------------ definition
def test_definition_is_high_risk_post_exploitation_and_engagement_scoped():
    definition = listener_definition()
    assert definition.risk.value == "high"
    assert definition.effect == "post_exploitation"
    assert definition.scope_required is True
    assert definition.scope_target_field is None


# --------------------------------------------------------------------- handler
def test_handler_runs_python_client_in_sandbox(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_catch_payload())) as sandbox:
        result = _run({"port": 9001, "commands": ["id"]})
    argv = sandbox.calls[0][0]
    assert argv[0] == "python3" and argv[1] == "-c"
    assert argv[3] == "0.0.0.0" and argv[4] == "9001"
    assert json.loads(argv[8]) == ["id"]
    assert result.verified is True
    assert result.verification_method == "listener_session_captured"
    assert result.output["peer"] == "203.0.113.10"
    assert "uid=33" in result.output["transcript"]


def test_handler_writes_workspace_artifact(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_catch_payload())):
        result = _run({"port": 9001})
    artifact = result.evidence["artifact"]
    assert artifact and artifact.endswith(".txt")
    assert open(artifact, encoding="utf-8").read().startswith("uid=33")


def test_handler_never_spawns_subprocess_directly(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_catch_payload())):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"port": 9001})


def test_no_connection_is_reported_distinctly(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    payload = {"ok": False, "bound": True, "port": 9001, "error": "no connection within timeout"}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"port": 9001})
    assert result.verified is False
    assert result.verification_method == "listener_no_connection"


def test_bind_failure_is_reported_distinctly(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    payload = {"ok": False, "bound": False, "port": 9001, "error": "OSError: address in use"}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"port": 9001})
    assert result.verified is False
    assert result.verification_method == "listener_bind_failed"


def test_out_of_scope_peer_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_catch_payload(peer="198.51.100.9")), peer_in_scope=False):
        result = _run({"port": 9001})
    assert result.verified is False
    assert result.verification_method == "listener_peer_out_of_scope"


def test_child_peer_rejection_is_refused_without_commands(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    payload = _catch_payload(peer_allowed=False, commands_sent=[], transcript="", bytes=0)
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"port": 9001})
    assert result.verified is False
    assert result.verification_method == "listener_peer_out_of_scope"
    assert result.evidence["commands_sent"] == 0
    assert result.output["commands_sent"] == []


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_listener_client_rejects_out_of_scope_peer_before_sending_a_byte():
    """V1-1 end-to-end: the peer connects and receives nothing at all.

    The check must happen inside the process that owns the socket. A handler-level
    check after the client returned would still have sent the commands, which is
    exactly the bug this test pins down.
    """
    port = _free_port()
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            LISTENER_CLIENT_SCRIPT,
            "127.0.0.1",
            str(port),
            "5",
            "1",
            "4096",
            json.dumps(["id"]),
            json.dumps(["10.0.0.0/8"]),
            json.dumps([]),
            str(time.time() + 60),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    client = None
    try:
        deadline = time.time() + 5
        while True:
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=0.25)
                break
            except OSError:
                if time.time() >= deadline:
                    raise AssertionError("listener client did not bind in time")
                time.sleep(0.05)
        client.settimeout(1.0)
        assert client.recv(4096) == b"", "the listener sent bytes to an out-of-scope peer"
        stdout, stderr = process.communicate(timeout=5)
    finally:
        if client is not None:
            client.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    assert process.returncode == 0, stderr
    payload = json.loads(stdout.strip().splitlines()[-1])
    assert payload["peer_allowed"] is False
    assert payload["commands_sent"] == []
    assert payload["transcript"] == ""
    assert payload["bytes"] == 0


def test_timeout_is_not_verified(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"port": 9001})
    assert result.verified is False
    assert result.verification_method == "listener_timeout"


def test_unparseable_output_is_not_verified(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "not json\n", "")):
        result = _run({"port": 9001})
    assert result.verified is False
    assert result.verification_method == "listener_parse_failed"


def test_port_out_of_range_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_catch_payload())):
        with pytest.raises(ValueError):
            _run({"port": 70000})


def test_too_many_commands_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_catch_payload())):
        with pytest.raises(ValueError):
            _run({"port": 9001, "commands": ["id"] * 100})
