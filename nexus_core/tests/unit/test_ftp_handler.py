"""Unit tests for the durable FTP handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
import json
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import ftp as ftp_module
from nexus_core.tools.handlers.ftp import ftp_definition, ftp_handler


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
        ftp_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(ftp_handler(arguments, _context()))


def _sandbox_for(payload: dict, exit_code: int = 0) -> SandboxResult:
    return SandboxResult(exit_code, json.dumps(payload) + "\n", "")


# ------------------------------------------------------------------ definition
def test_definition_declares_scope_and_actions():
    definition = ftp_definition()
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True
    assert set(definition.input_schema["properties"]["action"]["enum"]) == {"list", "download"}


# --------------------------------------------------------------------- handler
def test_handler_runs_python_client_in_sandbox():
    payload = {"ok": True, "action": "list", "listing": [], "names": []}
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        _run({"target": "203.0.113.10", "action": "list"})
    argv = sandbox.calls[0][0]
    assert argv[0] == "python3" and argv[1] == "-c"
    assert argv[3:7] == ["list", "203.0.113.10", "21", "anonymous"]
    assert argv[7] == "anonymous@"


def test_handler_never_spawns_subprocess_directly():
    payload = {"ok": True, "action": "list", "listing": [], "names": []}
    with _fake_sandbox(_sandbox_for(payload)):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"target": "203.0.113.10"})


def test_list_action_is_verified_and_returns_entries():
    payload = {
        "ok": True,
        "action": "list",
        "listing": ["-rw-rw-r-- 1 ftp ftp 418 locks.txt", "-rw-rw-r-- 1 ftp ftp 68 task.txt"],
        "names": ["locks.txt", "task.txt"],
    }
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"target": "203.0.113.10", "action": "list"})
    assert result.verified is True
    assert result.verification_method == "ftp_listing_parsed"
    assert result.evidence["entries_total"] == 2


def test_download_action_reports_size_and_sha256():
    payload = {
        "ok": True,
        "action": "download",
        "file": "locks.txt",
        "path": "/tmp/x/ftp_run/locks.txt",
        "size": 418,
        "sha256": "a" * 64,
    }
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"target": "203.0.113.10", "action": "download", "remote_path": "locks.txt"})
    assert result.verified is True
    assert result.verification_method == "ftp_download_verified"
    assert result.evidence["sha256"] == "a" * 64
    assert result.evidence["size"] == 418


def test_list_evidence_records_mode_and_list_error():
    payload = {
        "ok": True,
        "action": "list",
        "mode": "active",
        "listing": ["-rw-rw-r-- 1 ftp ftp 418 locks.txt"],
        "names": ["/locks.txt"],
        "list_error": None,
    }
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"target": "203.0.113.10", "action": "list"})
    assert result.evidence["mode"] == "active"
    assert result.evidence["entries_total"] == 1


def test_client_error_payload_is_not_verified():
    payload = {"ok": False, "action": "list", "error": "error_perm: 530 Login incorrect"}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"target": "203.0.113.10", "action": "list"})
    assert result.verified is False
    assert result.verification_method == "ftp_list_failed"


def test_unparseable_output_is_not_verified():
    with _fake_sandbox(SandboxResult(0, "not json at all\n", "")):
        result = _run({"target": "203.0.113.10"})
    assert result.verified is False
    assert result.verification_method == "ftp_parse_failed"


def test_timeout_is_not_verified():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"target": "203.0.113.10"})
    assert result.verified is False
    assert result.verification_method == "ftp_timeout"


def test_unsupported_action_is_rejected():
    with pytest.raises(ValueError):
        _run({"target": "203.0.113.10", "action": "delete"})


def test_control_characters_in_remote_path_are_rejected():
    with pytest.raises(ValueError):
        _run({"target": "203.0.113.10", "remote_path": "ok\nINJECT"})
