"""Unit tests for the durable GetUserSPNs handler and parser (sandbox mocked)."""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import impacket_getuserspns as guspns_module
from nexus_core.tools.handlers.impacket_getuserspns import (
    getuserspns_definition,
    impacket_getuserspns_handler,
)
from nexus_core.tools.parsers.impacket_getuserspns import parse_getuserspns_output

TABLE = (
    "ServicePrincipalName          Name    MemberOf    PasswordLastSet    LastLogon\n"
    "----------------------------  ------  ----------  ----------------  ---------\n"
    "HTTP/svc.corp.local           svc                2020-01-01        2021-01-01\n"
)
HASH = (
    "$krb5tgs$23$*svc$CORP.LOCAL$HTTP/svc.corp.local*$"
    "0123456789abcdef0123456789abcdef$deadbeef\n"
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

    def factory(workspace_root, resolved=None, *extra):
        return sandbox

    with mock.patch.object(guspns_module, "ad_sandbox", factory):
        with mock.patch.object(
            guspns_module,
            "resolve_impacket_binary",
            return_value="/home/u/.local/bin/GetUserSPNs.py",
        ):
            yield sandbox


def _context(run_id: str = "run_gu_test") -> RunContext:
    return RunContext(
        "system", Identity("op", "system", roles=("operator",)), run_id=run_id
    )


def _run(arguments: dict, context: RunContext | None = None) -> object:
    return asyncio.run(impacket_getuserspns_handler(arguments, context or _context()))


def _base(**overrides) -> dict:
    arguments = {
        "dc_ip": "10.0.0.10",
        "domain": "corp.local",
        "username": "svc",
        "password": "Passw0rd",
    }
    arguments.update(overrides)
    return arguments


def test_definition_is_medium_scoped_on_dc_ip():
    definition = getuserspns_definition()
    assert definition.tool_id == "nexus.attack.impacket_getuserspns"
    assert definition.risk is RiskLevel.MEDIUM
    assert definition.scope_target_field == "dc_ip"
    assert definition.scope_required is True


def test_handler_uses_domain_user_positional_not_at_host(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, TABLE, "")) as sandbox:
        result = _run(_base())
    argv = sandbox.calls[0]
    assert "-dc-ip" in argv
    assert argv[-1] == "corp.local/svc:Passw0rd"
    assert "@" not in argv[-1]
    assert result.output["spn_count"] == 1


def test_handler_requests_tickets_with_outputfile(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, TABLE + HASH, "")) as sandbox:
        result = _run(_base(request=True, request_user="svc"))
    argv = sandbox.calls[0]
    assert "-request" in argv
    assert "-outputfile" in argv
    assert argv[argv.index("-request-user") + 1] == "svc"
    assert result.output["hash_count"] == 1
    assert result.output["hashes"][0]["username"] == "svc"


def test_handler_requires_password_or_hash():
    with _fake_sandbox(SandboxResult(0, TABLE, "")):
        with pytest.raises(ValueError):
            _run({**_base(), "password": None})


def test_handler_rejects_unknown_flag():
    with _fake_sandbox(SandboxResult(0, TABLE, "")):
        with pytest.raises(ValueError):
            _run(_base(flags=["--nonsense"]))


def test_handler_no_subprocess(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, TABLE, "")):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses"),
        ):
            _run(_base())


def test_parser_extracts_spns_and_hashes():
    parsed = parse_getuserspns_output(TABLE + HASH)
    assert parsed.service_principals[0].service_principal_name == "HTTP/svc.corp.local"
    assert parsed.service_principals[0].name == "svc"
    assert parsed.hashes[0].domain == "CORP.LOCAL"
    assert parsed.hashes[0].service_principal_name == "HTTP/svc.corp.local"


def test_parser_empty_output_is_valid():
    parsed = parse_getuserspns_output("")
    assert parsed.service_principals == ()
    assert parsed.hashes == ()
