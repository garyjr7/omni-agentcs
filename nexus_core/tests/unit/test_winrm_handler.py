"""Unit tests for the durable WinRM handler and parser (sandbox mocked)."""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import winrm as winrm_module
from nexus_core.tools.handlers.winrm import (
    WINRM_FORBIDDEN_TOKENS,
    parse_winrm_output,
    winrm_exec_definition,
    winrm_exec_handler,
)

SAMPLE = (
    "WINRM   10.0.0.5   5985   FIRE   [*] Windows Server 2019 Build 17763 (name:FIRE)\n"
    "WINRM   10.0.0.5   5985   FIRE   [+] windcorp.thm\\buse:uzunLM+3131 (Pwn3d!)\n"
    "WINRM   10.0.0.5   5985   FIRE   [+] Executed command (shell type: powershell)\n"
    "WINRM   10.0.0.5   5985   FIRE   windcorp\\buse\n"
)


class FakeSandbox:
    def __init__(self, result: SandboxResult):
        self.result = result
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append(list(argv))
        return self.result


@contextlib.contextmanager
def _fake_sandbox(result: SandboxResult):
    sandbox = FakeSandbox(result)
    with mock.patch.object(winrm_module, "ad_sandbox", lambda *a, **k: sandbox):
        with mock.patch.object(
            winrm_module, "resolve_ad_binary", return_value="/home/u/.local/bin/nxc"
        ):
            yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("op", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(winrm_exec_handler(arguments, _context()))


def test_definition_is_high_risk_post_exploitation_and_scoped():
    definition = winrm_exec_definition()
    assert definition.tool_id == "nexus.win.winrm_exec"
    assert definition.risk is RiskLevel.HIGH
    assert definition.effect == "post_exploitation"
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True


def test_handler_emits_target_before_the_greedy_credential_options():
    with _fake_sandbox(SandboxResult(0, SAMPLE, "")) as sandbox:
        result = _run(
            {
                "target": "10.0.0.5",
                "domain": "windcorp.thm",
                "username": "buse",
                "password": "uzunLM+3131",
                "command": "whoami",
            }
        )
    argv = sandbox.calls[0]
    assert argv[1] == "winrm"
    assert argv.index("10.0.0.5") < argv.index("-u")
    assert argv.index("10.0.0.5") < argv.index("-p")
    assert argv[-2:] == ["-x", "whoami"]
    assert result.verified is True
    assert result.verification_method == "winrm_command_executed"
    assert result.output["stdout"] == "windcorp\\buse"


def test_handler_uses_powershell_switch_when_asked():
    with _fake_sandbox(SandboxResult(0, SAMPLE, "")) as sandbox:
        _run(
            {
                "target": "10.0.0.5",
                "username": "buse",
                "password": "x",
                "command": "Get-LocalUser",
                "shell": "powershell",
            }
        )
    assert sandbox.calls[0][-2:] == ["-X", "Get-LocalUser"]


def test_handler_rejects_destructive_commands():
    for command in ("shutdown /r /t 0", "net user tom /delete", "vssadmin delete shadows /all"):
        assert any(token in command.lower() for token in WINRM_FORBIDDEN_TOKENS)
        with _fake_sandbox(SandboxResult(0, SAMPLE, "")):
            with pytest.raises(ValueError):
                _run(
                    {
                        "target": "10.0.0.5",
                        "username": "buse",
                        "password": "x",
                        "command": command,
                    }
                )


def test_handler_allows_a_domain_password_change():
    """The documented escalation primitive must not be blocked."""
    with _fake_sandbox(SandboxResult(0, SAMPLE, "")) as sandbox:
        result = _run(
            {
                "target": "10.0.0.5",
                "username": "buse",
                "password": "x",
                "command": "net user brittanycr Password123! /domain",
            }
        )
    assert result.verified is True
    assert sandbox.calls[0][-1].endswith("/domain")


def test_handler_reports_authentication_failure():
    sample = "WINRM   10.0.0.5   5985   FIRE   [-] windcorp.thm\\buse:uzunLM+3131 STATUS_LOGON_FAILURE\n"
    with _fake_sandbox(SandboxResult(1, sample, "")):
        result = _run(
            {"target": "10.0.0.5", "username": "buse", "password": "bad", "command": "whoami"}
        )
    assert result.verified is False
    assert result.verification_method == "winrm_authentication_failed"
    assert result.output["error"] == "STATUS_LOGON_FAILURE"


def test_handler_requires_a_secret():
    with _fake_sandbox(SandboxResult(0, SAMPLE, "")):
        with pytest.raises(ValueError):
            _run({"target": "10.0.0.5", "username": "buse", "command": "whoami"})


def test_parser_strips_only_the_netexec_columns():
    parsed = parse_winrm_output(SAMPLE)
    assert parsed["authenticated"] is True
    assert parsed["executed"] is True
    assert parsed["output"] == "windcorp\\buse"
    assert parsed["failure"] is None
