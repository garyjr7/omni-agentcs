"""Unit tests for the governed reverse-shell listener (sandbox mocked)."""

from __future__ import annotations

import asyncio
import contextlib
import json
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import listener as listener_module
from nexus_core.tools.handlers.listener import listener_definition, listener_handler


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
