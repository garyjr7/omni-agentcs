"""Unit tests for the durable httpx handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import httpx as httpx_module
from nexus_core.tools.handlers._exec import MAX_BATCH_TARGETS, RECON_ALLOWED_PROGRAMS
from nexus_core.tools.handlers.httpx import (
    httpx_definition,
    httpx_handler,
    httpx_noise_level,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "httpx"


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

    with mock.patch.object(httpx_module, "sandbox_for_environment", factory):
        yield sandbox, allowlists


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(httpx_handler(arguments, _context()))


def test_handler_builds_argv_with_repeated_u_targets():
    with _fake_sandbox(SandboxResult(0, _read("probes.jsonl"), "")) as (sandbox, _):
        _run({"targets": ["https://a.example", "https://b.example"]})
    argv = sandbox.calls[0][0]
    assert argv[:2] == ["httpx", "-json"]
    assert "-silent" in argv and "-nc" in argv
    target_pairs = [
        (argv[index], argv[index + 1])
        for index in range(len(argv) - 1)
        if argv[index] == "-u"
    ]
    assert target_pairs == [("-u", "https://a.example"), ("-u", "https://b.example")]


def test_handler_adds_td_and_probe_only_when_requested():
    with _fake_sandbox(SandboxResult(0, _read("probes.jsonl"), "")) as (sandbox, _):
        _run({"targets": ["https://a.example"]})
    assert "-td" not in sandbox.calls[0][0]
    assert "-probe" not in sandbox.calls[0][0]

    with _fake_sandbox(SandboxResult(0, _read("probes.jsonl"), "")) as (sandbox, _):
        _run({"targets": ["https://a.example"], "tech_detect": True, "probe": True})
    assert "-td" in sandbox.calls[0][0]
    assert "-probe" in sandbox.calls[0][0]


def test_noise_level_scales_with_batch_size():
    assert httpx_noise_level(1) == "low"
    assert httpx_noise_level(20) == "low"
    assert httpx_noise_level(21) == "medium"
    assert httpx_noise_level(100) == "medium"
    assert httpx_noise_level(101) == "high"


def test_handler_uses_sandbox_with_recon_allowlist():
    with _fake_sandbox(SandboxResult(0, _read("probes.jsonl"), "")) as (_, allowlists):
        _run({"targets": ["https://a.example"]})
    assert allowlists == [RECON_ALLOWED_PROGRAMS]
    assert "httpx" in RECON_ALLOWED_PROGRAMS


def test_handler_never_spawns_subprocess_directly():
    with _fake_sandbox(SandboxResult(0, _read("probes.jsonl"), "")) as (sandbox, _):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"targets": ["https://a.example"]})
    assert sandbox.calls


def test_handler_rejects_an_empty_target_batch():
    with _fake_sandbox(SandboxResult(0, "", "")):
        with pytest.raises(ValueError):
            _run({"targets": []})


def test_handler_rejects_a_batch_over_the_cap():
    with _fake_sandbox(SandboxResult(0, "", "")):
        with pytest.raises(ValueError):
            _run({"targets": [f"https://h{index}.example" for index in range(MAX_BATCH_TARGETS + 1)]})


def test_handler_reports_probe_summary_in_evidence():
    with _fake_sandbox(SandboxResult(0, _read("probes.jsonl"), "")):
        result = _run({"targets": ["https://scanme.example"], "tech_detect": True})
    assert result.verified is True
    assert result.verification_method == "httpx_jsonl_parsed"
    assert result.evidence["count"] == 3
    assert result.evidence["hosts_alive"] == 3
    assert result.evidence["status_counts"] == {"200": 1, "301": 1, "403": 1}
    assert result.evidence["tech_detect"] is True
    assert len(result.output["probes"]) == 3


def test_handler_reports_wrong_binary_on_empty_output():
    # Regression (B1): /usr/bin/httpx is the Python HTTP client. It exits 2 with
    # empty stdout; the handler must say "wrong binary", not "post-condition
    # failed with method=httpx_jsonl_parsed".
    class SequencedSandbox:
        def __init__(self, results):
            self.results = list(results)
            self.calls: list[list[str]] = []

        async def run(self, argv, *, timeout_seconds: float = 30):
            self.calls.append(list(argv))
            return self.results.pop(0)

    sandbox = SequencedSandbox(
        [
            SandboxResult(2, "", "Error: No such option: -json"),
            SandboxResult(2, "Usage: httpx [OPTIONS] URL\nError: No such option: -e", ""),
        ]
    )
    with mock.patch.object(httpx_module, "sandbox_for_environment", lambda *a, **k: sandbox):
        result = _run({"targets": ["http://x"]})
    assert result.success is False
    assert result.verification_method == "httpx_binary_mismatch"
    assert "projectdiscovery" in result.output["install"].lower()
    assert sandbox.calls[1][:2] == ["httpx", "-version"]


def test_handler_returns_unverified_on_timeout():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"targets": ["https://a.example"]})
    assert result.success is False
    assert result.verification_method == "httpx_timeout"


def test_httpx_definition_uses_a_list_scope_field():
    definition = httpx_definition()
    assert definition.tool_id == "nexus.recon.httpx"
    assert definition.risk is RiskLevel.LOW
    assert definition.scope_target_field == "targets"
    assert definition.scope_required is True
    assert definition.input_schema["properties"]["targets"]["type"] == "array"
