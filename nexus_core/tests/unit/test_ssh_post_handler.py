"""Unit tests for the post-exploitation SSH handlers (sandbox mocked)."""

from __future__ import annotations

import asyncio
import contextlib
import json
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import ssh_post as module
from nexus_core.tools.handlers.ssh_post import (
    enum_system_definition,
    enum_system_handler,
    parse_sudo_rules,
    ssh_exec_definition,
    ssh_exec_handler,
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
        module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(handler, arguments: dict) -> object:
    return asyncio.run(handler(arguments, _context()))


def _sandbox_for(payload: dict, exit_code: int = 0) -> SandboxResult:
    return SandboxResult(exit_code, json.dumps(payload) + "\n", "")


# ------------------------------------------------------------------ definitions
def test_ssh_exec_is_high_risk_and_scope_gated():
    definition = ssh_exec_definition()
    assert definition.risk.value == "high"
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True


def test_enum_system_is_medium_risk():
    definition = enum_system_definition()
    assert definition.risk.value == "medium"
    assert definition.scope_required is True


# -------------------------------------------------------------------- sudo parse
def test_parse_sudo_rules_extracts_command():
    text = (
        "Matching Defaults entries for lin on ip-10-65-151-43:\n"
        "    env_reset, mail_badpass\n\n"
        "User lin may run the following commands on ip-10-65-151-43:\n"
        "    (root) /bin/tar\n"
    )
    assert parse_sudo_rules(text) == [{"who": "root", "command": "/bin/tar"}]


# --------------------------------------------------------------------- ssh_exec
def test_ssh_exec_runs_client_in_sandbox():
    payload = {
        "ok": True,
        "connected": True,
        "stdout": "lin\n",
        "stderr": "",
        "exit_status": 0,
    }
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run(
            ssh_exec_handler,
            {"target": "10.65.151.43", "username": "lin", "password": "pw", "command": "whoami"},
        )
    argv = sandbox.calls[0][0]
    assert argv[0] == "python3" and argv[1] == "-c"
    assert argv[3] == "exec" and argv[4] == "10.65.151.43"
    assert result.verified is True
    assert result.output["stdout"] == "lin\n"


def test_ssh_exec_rejects_destructive_command():
    with pytest.raises(ValueError):
        _run(
            ssh_exec_handler,
            {
                "target": "10.65.151.43",
                "username": "lin",
                "password": "pw",
                "command": "sudo reboot",
            },
        )


def test_ssh_exec_reports_paramiko_missing():
    payload = {"ok": False, "connected": False, "error": "ssh_unavailable", "detail": "no paramiko"}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run(
            ssh_exec_handler,
            {"target": "10.65.151.43", "username": "lin", "password": "pw", "command": "id"},
        )
    assert result.verified is False
    assert result.verification_method == "ssh_unavailable"


def test_ssh_exec_timeout_is_not_verified():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run(
            ssh_exec_handler,
            {"target": "10.65.151.43", "username": "lin", "password": "pw", "command": "id"},
        )
    assert result.verified is False
    assert result.verification_method == "ssh_exec_timeout"


# ------------------------------------------------------------------- enum_system
def test_enum_system_extracts_sudo_rules():
    payload = {
        "ok": True,
        "connected": True,
        "results": {
            "__SUDO__": {"stdout": "User lin may run:\n    (root) /bin/tar\n", "exit_status": 0},
            "identity": {"stdout": "uid=1001(lin)\n", "exit_status": 0},
        },
    }
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run(
            enum_system_handler,
            {"target": "10.65.151.43", "username": "lin", "password": "pw"},
        )
    argv = sandbox.calls[0][0]
    assert argv[3] == "enum"
    assert result.verified is True
    assert result.output["sudo_rules"] == [{"who": "root", "command": "/bin/tar"}]
    assert result.evidence["sudo_rules"] == ["/bin/tar"]


def test_enum_system_reports_paramiko_missing():
    payload = {"ok": False, "connected": False, "error": "ssh_unavailable", "detail": "x"}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run(
            enum_system_handler,
            {"target": "10.65.151.43", "username": "lin", "password": "pw"},
        )
    assert result.verified is False
    assert result.verification_method == "ssh_unavailable"
