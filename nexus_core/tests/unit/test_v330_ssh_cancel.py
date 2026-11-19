"""V0-28: ``ssh_exec`` reports timeouts separately and carries a cancel id."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import ssh_post as ssh_module

pytestmark = pytest.mark.unit

TARGET = "10.10.10.5"


class _Sandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.calls: list[tuple[list[str], dict]] = []

    async def run(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        return self.result


def _context() -> SimpleNamespace:
    return SimpleNamespace(
        tenant_id="system",
        engagement_id="eng-v330",
        run_id="run-v330",
        store=None,
    )


def _run(sandbox: _Sandbox, *, timeout_seconds: int = 30):
    with mock.patch.object(
        ssh_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ), mock.patch.object(ssh_module, "SSH_CONNECT_COOLDOWN_SECONDS", 0.0):
        return asyncio.run(
            ssh_module.ssh_exec_handler(
                {
                    "target": TARGET,
                    "username": "lin",
                    "password": "pw",
                    "command": "cat /var/log/syslog",
                    "timeout_seconds": timeout_seconds,
                },
                _context(),
            )
        )


def test_a_sandbox_timeout_is_not_a_denied_login() -> None:
    sandbox = _Sandbox(SandboxResult(-9, "", "", timed_out=True, orphans_detected=0))
    result = _run(sandbox, timeout_seconds=30)

    assert result.outcome == "timeout"
    assert result.verification_method == "ssh_exec_timeout"
    assert result.timed_out is True
    assert result.verified is False
    assert result.output["timeout_stage"] == "sandbox"
    assert result.output["reason"] == "ssh command exceeded its 30s budget"
    assert result.output["orphans_detected"] == 0
    assert result.output["cancel_id"].startswith("ssh_cancel_")
    assert result.evidence["cancel_id"] == result.output["cancel_id"]
    assert result.evidence["timeout_stage"] == "sandbox"
    assert result.outcome != "denied"

    payload = json.loads(sandbox.calls[0][0][-1])
    assert payload["command_timeout"] < 30
    # The handler sends the model's command unchanged; the guard lives in the
    # SSH client so its contract (and its redaction) does not change (V0-28).
    assert payload["command"] == "cat /var/log/syslog"
    assert "def timeout_wrap" in ssh_module.SSH_CLIENT_SCRIPT
    assert "timeout -k" in ssh_module.SSH_CLIENT_SCRIPT


def test_a_remote_command_timeout_is_reported_as_timeout() -> None:
    payload = {
        "ok": False,
        "connected": True,
        "timed_out": True,
        "error": "CommandTimeout: the remote command exceeded its time budget",
        "exit_status": 124,
    }
    sandbox = _Sandbox(SandboxResult(0, json.dumps(payload) + "\n", ""))
    result = _run(sandbox)

    assert result.outcome == "timeout"
    assert result.verification_method == "ssh_exec_timeout"
    assert result.output["timeout_stage"] == "remote_command"
    assert result.output["cancel_id"].startswith("ssh_cancel_")
    assert "CommandTimeout" in result.output["reason"]
    assert result.evidence["timeout_stage"] == "remote_command"


def test_a_real_denial_keeps_its_own_outcome() -> None:
    sandbox = _Sandbox(
        SandboxResult(
            0,
            json.dumps(
                {
                    "ok": False,
                    "connected": False,
                    "error": "AuthenticationException: Authentication failed.",
                }
            )
            + "\n",
            "",
        )
    )
    result = _run(sandbox)

    assert result.outcome == "denied"
    assert result.verification_method == "ssh_exec_authentication_failed"
    assert result.timed_out is False
    assert "cancel_id" not in result.output
