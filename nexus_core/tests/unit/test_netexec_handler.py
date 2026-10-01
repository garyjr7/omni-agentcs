"""Unit tests for the durable NetExec handler and parser (sandbox mocked)."""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import netexec as netexec_module
from nexus_core.tools.handlers.netexec import (
    NETEXEC_ALLOWED_FLAGS,
    NETEXEC_FORBIDDEN_FLAGS,
    netexec_definition,
    netexec_handler,
    netexec_noise_level,
)
from nexus_core.tools.parsers.netexec import parse_netexec_output

SAMPLE = (
    "SMB         10.0.0.5       445    DC01    [*] Windows Server 2019 Build 17763\n"
    "SMB         10.0.0.5       445    DC01    [+] CORP\\svc:Passw0rd (Pwn3d!)\n"
    "SMB         10.0.0.5       445    DC01    Share           READ,WRITE      Desc\n"
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
    allowlists: list[tuple[str, ...]] = []

    def factory(workspace_root, resolved=None, *extra):
        allowlists.append(tuple(item for item in (resolved, *extra) if item))
        return sandbox

    with mock.patch.object(netexec_module, "ad_sandbox", factory):
        with mock.patch.object(
            netexec_module, "resolve_ad_binary", return_value="/home/u/.local/bin/nxc"
        ):
            yield sandbox, allowlists


def _context() -> RunContext:
    return RunContext("system", Identity("op", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(netexec_handler(arguments, _context()))


def test_definition_is_medium_scoped_recon():
    definition = netexec_definition()
    assert definition.tool_id == "nexus.recon.netexec"
    assert definition.risk is RiskLevel.MEDIUM
    assert definition.scope_required is True
    assert definition.scope_target_field == "target"


def test_noise_level_from_threads():
    assert netexec_noise_level(1) == "low"
    assert netexec_noise_level(10) == "medium"
    assert netexec_noise_level(25) == "high"


def test_handler_builds_enumeration_command():
    with _fake_sandbox(SandboxResult(0, SAMPLE, "")) as (sandbox, _):
        result = _run(
            {
                "protocol": "smb",
                "target": "10.0.0.5",
                "operation": "shares",
                "domain": "corp.local",
                "username": "svc",
                "password": "Passw0rd",
            }
        )
    argv = sandbox.calls[0]
    assert argv[0] == "/home/u/.local/bin/nxc"
    assert argv[1] == "smb"
    assert "--no-progress" in argv
    assert argv[argv.index("-d") + 1] == "corp.local"
    assert argv[argv.index("-u") + 1] == "svc"
    assert argv[argv.index("-p") + 1] == "Passw0rd"
    # The real enumeration flag, never the "-M module" form.
    assert "--shares" in argv
    assert argv[-1] == "10.0.0.5"
    assert result.output["count"] == 3
    assert result.evidence["operation"] == "shares"


def test_handler_rejects_smb_only_operation_over_ldap():
    with _fake_sandbox(SandboxResult(0, SAMPLE, "")):
        with pytest.raises(ValueError):
            _run({"protocol": "ldap", "target": "10.0.0.5", "operation": "shares"})


def test_handler_rejects_forbidden_flags():
    for flag in ("-x", "-X", "-M", "--sam", "--lsa", "--ntds", "--put-file"):
        assert flag in NETEXEC_FORBIDDEN_FLAGS
        with _fake_sandbox(SandboxResult(0, SAMPLE, "")):
            with pytest.raises(ValueError):
                _run({"protocol": "smb", "target": "10.0.0.5", "flags": [flag]})


def test_handler_accepts_allowlisted_debug_flags():
    with _fake_sandbox(SandboxResult(0, SAMPLE, "")) as (sandbox, _):
        result = _run(
            {"protocol": "smb", "target": "10.0.0.5", "flags": ["--verbose", "--debug"]}
        )
    assert "--verbose" in sandbox.calls[0]
    assert "--debug" in sandbox.calls[0]
    assert result.verified is True


def test_handler_requires_username_with_credentials():
    with _fake_sandbox(SandboxResult(0, SAMPLE, "")):
        with pytest.raises(ValueError):
            _run({"protocol": "smb", "target": "10.0.0.5", "password": "x"})


def test_handler_returns_unverified_on_timeout():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"protocol": "smb", "target": "10.0.0.5"})
    assert result.success is False
    assert result.verification_method == "netexec_timeout"


def test_handler_uses_sandbox_allowlist_and_no_subprocess():
    with _fake_sandbox(SandboxResult(0, SAMPLE, "")) as (sandbox, allowlists):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses"),
        ):
            _run({"protocol": "smb", "target": "10.0.0.5"})
    assert allowlists and "/home/u/.local/bin/nxc" in allowlists[0]
    assert sandbox.calls


def test_parser_extracts_hosts_status_and_entries():
    parsed = parse_netexec_output(SAMPLE, protocol="smb")
    assert parsed.targets == ("10.0.0.5",)
    assert parsed.entries[0].kind == "status"
    assert parsed.entries[0].mark == "*"
    assert parsed.entries[2].kind == "entry"
    assert parsed.entries[2].host == "DC01"


def test_parser_treats_empty_output_as_no_observation():
    parsed = parse_netexec_output("", protocol="smb")
    assert parsed.entries == ()
    assert parsed.targets == ()


def test_operations_map_to_the_real_netexec_flags():
    from nexus_core.tools.handlers.netexec import NETEXEC_OPERATIONS

    assert NETEXEC_OPERATIONS["shares"] == "--shares"
    assert NETEXEC_OPERATIONS["users"] == "--users"
    assert NETEXEC_OPERATIONS["groups"] == "--groups"
    assert NETEXEC_OPERATIONS["smb_sessions"] == "--smb-sessions"
    assert NETEXEC_OPERATIONS["disks"] == "--disks"
    # NetExec exposes --no-progress, not -q.
    assert "-q" not in NETEXEC_ALLOWED_FLAGS
