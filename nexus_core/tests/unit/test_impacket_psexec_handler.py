"""Unit tests for the durable psexec handler and parser (sandbox mocked)."""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import impacket_psexec as psexec_module
from nexus_core.tools.handlers.impacket_psexec import (
    PSEXEC_FORBIDDEN_FLAGS,
    impacket_psexec_handler,
    psexec_definition,
    validate_psexec_command,
)
from nexus_core.tools.parsers.impacket_psexec import parse_psexec_output

OUTPUT = "Microsoft Windows [Version 10.0.17763.1]\nNT AUTHORITY\\SYSTEM\n"


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

    def factory(workspace_root, resolved=None, *extra):
        return sandbox

    with mock.patch.object(psexec_module, "ad_sandbox", factory):
        with mock.patch.object(
            psexec_module,
            "resolve_impacket_binary",
            return_value="/home/u/.local/bin/psexec.py",
        ):
            yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("op", "system", roles=("operator",)))


def _base(**overrides) -> dict:
    arguments = {
        "target": "10.0.0.5",
        "domain": "corp.local",
        "username": "svc",
        "password": "Passw0rd",
        "command": "whoami",
    }
    arguments.update(overrides)
    return arguments


def _run(arguments: dict) -> object:
    return asyncio.run(impacket_psexec_handler(arguments, _context()))


def test_definition_is_destructive_and_scoped():
    definition = psexec_definition()
    assert definition.tool_id == "nexus.attack.impacket_psexec"
    assert definition.risk is RiskLevel.DESTRUCTIVE
    assert definition.scope_required is True
    assert definition.scope_target_field == "target"
    assert "RemComSvc" in definition.description


def test_handler_builds_target_and_command():
    with _fake_sandbox(SandboxResult(0, OUTPUT, "")) as sandbox:
        result = _run(_base())
    argv = sandbox.calls[0]
    assert argv[0].endswith("psexec.py")
    assert argv[-2] == "corp.local/svc:Passw0rd@10.0.0.5"
    assert argv[-1] == "whoami"
    assert result.verified is True
    assert result.output["connected"] is True


def test_handler_uses_hash_and_no_password():
    with _fake_sandbox(SandboxResult(0, OUTPUT, "")) as sandbox:
        _run(
            _base(
                password=None,
                hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            )
        )
    argv = sandbox.calls[0]
    assert argv[argv.index("-hashes") + 1].startswith("aad3b")


def test_handler_requires_a_secret():
    with _fake_sandbox(SandboxResult(0, OUTPUT, "")):
        with pytest.raises(ValueError):
            _run(_base(password=None))


def test_handler_rejects_forbidden_flags():
    for flag in ("-path", "-file", "-c"):
        assert flag in PSEXEC_FORBIDDEN_FLAGS
        with _fake_sandbox(SandboxResult(0, OUTPUT, "")):
            with pytest.raises(ValueError):
                _run(_base(flags=[flag]))


def test_command_rejects_null_bytes():
    with pytest.raises(ValueError):
        validate_psexec_command("whoami\x00rm")


def test_handler_no_subprocess():
    with _fake_sandbox(SandboxResult(0, OUTPUT, "")):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses"),
        ):
            _run(_base())


def test_parser_captures_lines():
    parsed = parse_psexec_output(OUTPUT, "whoami")
    assert parsed.connected is True
    assert parsed.lines[-1] == "NT AUTHORITY\\SYSTEM"
    assert parsed.command == "whoami"
