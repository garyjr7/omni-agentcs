"""Unit tests for the durable ffuf handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import ffuf as ffuf_module
from nexus_core.tools.handlers._exec import RECON_ALLOWED_PROGRAMS
from nexus_core.tools.handlers.ffuf import (
    FFUF_DEFAULT_RATE,
    FFUF_DEFAULT_THREADS,
    ffuf_definition,
    ffuf_handler,
    ffuf_noise_level,
    validate_and_canonicalize_ffuf_flags,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "ffuf"


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

    with mock.patch.object(ffuf_module, "sandbox_for_environment", factory):
        yield sandbox, allowlists


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(ffuf_handler(arguments, _context()))


@pytest.fixture
def wordlist(tmp_path, monkeypatch):
    path = tmp_path / "words.txt"
    path.write_text("admin\nlogin\n", encoding="utf-8")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    return path


@pytest.mark.parametrize(
    "flag",
    ["-u", "-w", "-X", "-e", "-t", "-o", "-of", "-x", "-config", "-input-cmd", "-input-shell"],
)
def test_validate_flags_rejects_forbidden_flag(flag):
    with pytest.raises(ValueError):
        validate_and_canonicalize_ffuf_flags([flag])


def test_validate_flags_rejects_unknown_flag():
    with pytest.raises(ValueError):
        validate_and_canonicalize_ffuf_flags(["--malicious"])


def test_validate_flags_accepts_and_canonicalizes():
    flags, noise, _ = validate_and_canonicalize_ffuf_flags(["-mc", "200,301", "-rate", "25"])
    assert flags == ["-mc", "200,301", "-rate", "25"]
    assert noise == "low"


def test_noise_level_from_threads():
    assert ffuf_noise_level(1) == "low"
    assert ffuf_noise_level(2) == "low"
    assert ffuf_noise_level(5) == "medium"
    assert ffuf_noise_level(6) == "high"
    assert ffuf_noise_level(FFUF_DEFAULT_THREADS) == "high"


def test_handler_always_rate_limits_and_defaults_to_high_noise(wordlist):
    with _fake_sandbox(SandboxResult(0, _read("ndjson.jsonl"), "")) as (sandbox, _):
        result = _run({"url": "https://scanme.example/FUZZ", "wordlist": str(wordlist)})
    argv = sandbox.calls[0][0]
    assert argv[:2] == ["ffuf", "-u"]
    assert argv[argv.index("-rate") + 1] == str(FFUF_DEFAULT_RATE)
    assert argv[argv.index("-t") + 1] == str(FFUF_DEFAULT_THREADS)
    assert argv[argv.index("-X") + 1] == "GET"
    assert "-json" in argv and "-s" in argv
    assert result.evidence["noise_level"] == "high"
    assert result.evidence["rate"] == FFUF_DEFAULT_RATE
    assert result.evidence["threads"] == FFUF_DEFAULT_THREADS
    assert result.evidence["count"] == 2


def test_handler_honours_threads_rate_method_and_extensions(wordlist):
    with _fake_sandbox(SandboxResult(0, _read("ndjson.jsonl"), "")) as (sandbox, _):
        result = _run(
            {
                "url": "https://scanme.example/FUZZ",
                "wordlist": str(wordlist),
                "threads": 2,
                "rate": 5,
                "method": "head",
                "extensions": [".php", ".bak"],
            }
        )
    argv = sandbox.calls[0][0]
    assert argv[argv.index("-t") + 1] == "2"
    assert argv[argv.index("-rate") + 1] == "5"
    assert argv[argv.index("-X") + 1] == "HEAD"
    assert argv[argv.index("-e") + 1] == ".php,.bak"
    assert result.evidence["noise_level"] == "low"


def test_handler_rejects_url_without_fuzz_keyword(wordlist):
    with _fake_sandbox(SandboxResult(0, _read("ndjson.jsonl"), "")):
        with pytest.raises(ValueError):
            _run({"url": "https://scanme.example/", "wordlist": str(wordlist)})


def test_handler_rejects_wordlist_outside_the_workspace(wordlist):
    with _fake_sandbox(SandboxResult(0, _read("ndjson.jsonl"), "")):
        with pytest.raises(ValueError):
            _run({"url": "https://scanme.example/FUZZ", "wordlist": "/etc/passwd"})


def test_handler_rejects_method_outside_the_allowlist(wordlist):
    with _fake_sandbox(SandboxResult(0, _read("ndjson.jsonl"), "")):
        with pytest.raises(ValueError):
            _run(
                {
                    "url": "https://scanme.example/FUZZ",
                    "wordlist": str(wordlist),
                    "method": "DELETE",
                }
            )


def test_handler_uses_sandbox_with_recon_allowlist_and_no_subprocess(wordlist):
    with _fake_sandbox(SandboxResult(0, _read("ndjson.jsonl"), "")) as (sandbox, allowlists):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"url": "https://scanme.example/FUZZ", "wordlist": str(wordlist)})
    assert allowlists == [RECON_ALLOWED_PROGRAMS]
    assert "ffuf" in RECON_ALLOWED_PROGRAMS
    assert sandbox.calls


def test_handler_treats_no_matches_as_a_completed_fuzz(wordlist):
    with _fake_sandbox(SandboxResult(0, "", "")):
        result = _run({"url": "https://scanme.example/FUZZ", "wordlist": str(wordlist)})
    assert result.verified is True
    assert result.evidence["count"] == 0
    assert result.output["matches"] == []


def test_handler_returns_unverified_on_timeout(wordlist):
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"url": "https://scanme.example/FUZZ", "wordlist": str(wordlist)})
    assert result.success is False
    assert result.verification_method == "ffuf_timeout"


def test_ffuf_definition_declares_scope_and_risk():
    definition = ffuf_definition()
    assert definition.tool_id == "nexus.web.ffuf"
    assert definition.risk is RiskLevel.MEDIUM
    assert definition.scope_target_field == "url"
    assert definition.scope_required is True
    assert definition.required_permissions == ["execute:tool:nexus.web.ffuf"]
