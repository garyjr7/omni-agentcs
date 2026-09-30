"""Unit tests for the durable searchsploit handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import searchsploit as searchsploit_module
from nexus_core.tools.handlers.searchsploit import (
    SEARCHSPLOIT_ALLOWED_PROGRAMS,
    searchsploit_definition,
    searchsploit_handler,
)

SAMPLE = (
    '{"SEARCH":"apache","RESULTS_EXPLOIT":['
    '{"Title":"Apache Log4j 2 - RCE","EDB-ID":"50592","Date_Published":"2021-12-14",'
    '"Author":"kozmer","Type":"remote","Platform":"java","Path":"/opt/x/50592.py"}],'
    '"RESULTS_SHELLCODE":[]}'
)
EMPTY = '{"SEARCH":"zzz","RESULTS_EXPLOIT":[],"RESULTS_SHELLCODE":[]}'


class FakeSandbox:
    def __init__(self, probe: SandboxResult, result: SandboxResult):
        self.probe = probe
        self.result = result
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append(list(argv))
        if "-h" in argv:
            return self.probe
        return self.result


@contextlib.contextmanager
def _fake_sandbox(result: SandboxResult, probe: SandboxResult | None = None):
    sandbox = FakeSandbox(probe or SandboxResult(0, "Usage: searchsploit", ""), result)
    allowlists: list[tuple[str, ...]] = []

    def factory(workspace_root, allowed_programs=None):
        allowlists.append(tuple(allowed_programs or ()))
        return sandbox

    with mock.patch.object(searchsploit_module, "sandbox_for_environment", factory):
        yield sandbox, allowlists


def _context() -> RunContext:
    return RunContext("system", Identity("op", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(searchsploit_handler(arguments, _context()))


def test_probe_uses_help_not_version():
    from nexus_core.tools.handlers.searchsploit import SEARCHSPLOIT_VERIFY_ARGV

    assert SEARCHSPLOIT_VERIFY_ARGV == ("searchsploit", "-h")


def test_handler_builds_json_command_and_parses():
    with _fake_sandbox(SandboxResult(0, SAMPLE, "")) as (sandbox, _):
        result = _run({"query": "apache"})
    argv = sandbox.calls[-1]
    assert argv == ["searchsploit", "--json", "apache"]
    assert result.verified is True
    assert result.output["total"] == 1
    assert result.output["exploits"][0]["edb_id"] == "50592"


def test_handler_uses_cve_flag():
    with _fake_sandbox(SandboxResult(0, EMPTY, "")) as (sandbox, _):
        _run({"cve": "CVE-2021-44228"})
    argv = sandbox.calls[-1]
    assert argv[0:3] == ["searchsploit", "--json", "--cve"]
    assert argv[3] == "CVE-2021-44228"


def test_handler_adds_exact_and_exclude():
    with _fake_sandbox(SandboxResult(0, EMPTY, "")) as (sandbox, _):
        _run({"query": "oracle", "exact": True, "exclude": "(PoC)|/dos/"})
    argv = sandbox.calls[-1]
    assert "--exact" in argv
    assert "--exclude=(PoC)|/dos/" in argv


def test_handler_requires_query_or_cve():
    with _fake_sandbox(SandboxResult(0, EMPTY, "")):
        with pytest.raises(ValueError):
            _run({})


def test_handler_rejects_invalid_cve():
    with _fake_sandbox(SandboxResult(0, EMPTY, "")):
        with pytest.raises(ValueError):
            _run({"cve": "not-a-cve"})


def test_handler_rejects_query_that_looks_like_a_flag():
    with _fake_sandbox(SandboxResult(0, EMPTY, "")):
        with pytest.raises(ValueError):
            _run({"query": "--mirror"})


def test_handler_fails_closed_when_probe_fails():
    with _fake_sandbox(SandboxResult(0, SAMPLE, ""), probe=SandboxResult(127, "", "not found")):
        result = _run({"query": "apache"})
    assert result.success is False
    assert result.verification_method == "searchsploit_unavailable"


def test_handler_treats_no_results_as_completed():
    with _fake_sandbox(SandboxResult(0, EMPTY, "")):
        result = _run({"query": "zzz"})
    assert result.verified is True
    assert result.output["total"] == 0


def test_handler_returns_unverified_on_timeout():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"query": "apache"})
    assert result.success is False
    assert result.verification_method == "searchsploit_timeout"


def test_handler_uses_sandbox_allowlist_and_no_subprocess():
    with _fake_sandbox(SandboxResult(0, SAMPLE, "")) as (sandbox, allowlists):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses"),
        ):
            _run({"query": "apache"})
    assert allowlists == [SEARCHSPLOIT_ALLOWED_PROGRAMS]
    assert "searchsploit" in SEARCHSPLOIT_ALLOWED_PROGRAMS
    assert sandbox.calls


def test_definition_is_read_only_and_has_no_scope():
    definition = searchsploit_definition()
    assert definition.tool_id == "nexus.exploit.searchsploit"
    assert definition.risk is RiskLevel.READ_ONLY
    assert definition.scope_target_field is None
    assert definition.scope_required is False
