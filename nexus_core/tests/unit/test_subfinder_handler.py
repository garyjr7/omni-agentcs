"""Unit tests for the durable subfinder handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import subfinder as subfinder_module
from nexus_core.tools.handlers._exec import RECON_ALLOWED_PROGRAMS
from nexus_core.tools.handlers.subfinder import subfinder_definition, subfinder_handler

FIXTURES = Path(__file__).parents[1] / "fixtures" / "subfinder"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


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
    allowlists: list[tuple[str, ...]] = []

    def factory(workspace_root, allowed_programs=None):
        allowlists.append(tuple(allowed_programs or ()))
        return sandbox

    with mock.patch.object(subfinder_module, "sandbox_for_environment", factory):
        yield sandbox, allowlists


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(subfinder_handler(arguments, _context()))


def test_handler_builds_canonical_argv():
    with _fake_sandbox(SandboxResult(0, _read("enumeration.jsonl"), "")) as (sandbox, _):
        _run({"domain": "scanme.example"})
    argv = sandbox.calls[0][0]
    assert argv[:6] == ["subfinder", "-d", "scanme.example", "-silent", "-json", "-nc"]
    assert argv[6] == "-timeout"
    assert argv[7] == "60"


def test_handler_reports_low_noise_and_counts():
    with _fake_sandbox(SandboxResult(0, _read("enumeration.jsonl"), "")):
        result = _run({"domain": "scanme.example"})
    assert result.verified is True
    assert result.verification_method == "subfinder_jsonl_parsed"
    assert result.evidence["noise_level"] == "low"
    assert result.evidence["passive"] is True
    assert result.evidence["count"] == 3
    assert len(result.evidence["domains_sample"]) == 3
    assert result.output["subdomains"] == [
        "www.scanme.example",
        "api.scanme.example",
        "mail.scanme.example",
    ]


def test_handler_uses_sandbox_with_recon_allowlist():
    with _fake_sandbox(SandboxResult(0, _read("enumeration.jsonl"), "")) as (_, allowlists):
        _run({"domain": "scanme.example"})
    assert allowlists == [RECON_ALLOWED_PROGRAMS]
    assert "subfinder" in RECON_ALLOWED_PROGRAMS


def test_handler_never_spawns_subprocess_directly():
    with _fake_sandbox(SandboxResult(0, _read("enumeration.jsonl"), "")) as (sandbox, _):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"domain": "scanme.example"})
    assert sandbox.calls


def test_handler_returns_unverified_on_timeout():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"domain": "scanme.example"})
    assert result.verified is False
    assert result.success is False
    assert result.verification_method == "subfinder_timeout"


def test_handler_returns_unverified_on_malformed_output():
    with _fake_sandbox(SandboxResult(0, "<<gateway error>>", "")):
        result = _run({"domain": "scanme.example"})
    assert result.verified is False
    assert result.verification_method == "subfinder_parse_failed"


def test_handler_accepts_empty_enumeration_gracefully():
    with _fake_sandbox(SandboxResult(1, "", "")):
        result = _run({"domain": "scanme.example"})
    assert result.verified is True
    assert result.evidence["count"] == 0
    assert result.output["subdomains"] == []


def test_subfinder_definition_declares_passive_scope_requirements():
    definition = subfinder_definition()
    assert definition.tool_id == "nexus.recon.subfinder"
    assert definition.risk is RiskLevel.READ_ONLY
    assert definition.scope_target_field == "domain"
    assert definition.scope_required is True
    assert definition.required_permissions == ["execute:tool:nexus.recon.subfinder"]
    assert definition.tenant_id == "system"


@pytest.mark.parametrize("timeout", [5, 9999])
def test_handler_bounds_the_requested_timeout(timeout):
    with _fake_sandbox(SandboxResult(0, _read("enumeration.jsonl"), "")) as (sandbox, _):
        _run({"domain": "scanme.example", "timeout_seconds": timeout})
    assert 10 <= sandbox.calls[0][1] <= 600
