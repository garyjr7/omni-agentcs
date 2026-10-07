"""Unit tests for the durable whatweb handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import whatweb as whatweb_module
from nexus_core.tools.handlers.whatweb import (
    MIN_VALID_JSONL_BYTES,
    WHATWEB_ALLOWED_PROGRAMS,
    WHATWEB_AGGRESSION_LEVELS,
    whatweb_definition,
    whatweb_handler,
    whatweb_noise_level,
)

SAMPLE = (
    '[{"target":"http://x/","http_status":200,'
    '"plugins":{"Apache":{"version":["2.4.7"]},"Title":{"string":["hi"]}}}]'
)


class FakeSandbox:
    def __init__(self, result: SandboxResult, payload: str | None = None):
        self.result = result
        self.payload = payload
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append((list(argv), timeout_seconds))
        # whatweb writes its --log-json file during execution; emulate that so
        # the handler's fresh-file behavior is exercised faithfully.
        if self.payload is not None:
            path = next(t.split("=", 1)[1] for t in argv if t.startswith("--log-json="))
            with open(path, "a", encoding="utf-8") as stream:
                stream.write(self.payload)
        return self.result


@contextlib.contextmanager
def _fake_sandbox(result: SandboxResult, payload: str | None = None):
    sandbox = FakeSandbox(result, payload)
    allowlists: list[tuple[str, ...]] = []

    def factory(workspace_root, allowed_programs=None):
        allowlists.append(tuple(allowed_programs or ()))
        return sandbox

    with mock.patch.object(whatweb_module, "sandbox_for_environment", factory):
        yield sandbox, allowlists


def _context(run_id: str = "t1") -> RunContext:
    return RunContext(
        "system", Identity("op", "system", roles=("operator",)), run_id=run_id
    )


def _run(arguments: dict, run_id: str = "t1") -> object:
    return asyncio.run(whatweb_handler(arguments, _context(run_id)))


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    return tmp_path


def test_noise_level_from_aggression():
    # Regression (B2): whatweb only accepts 1, 3, 4. Level 2 does not exist.
    assert WHATWEB_AGGRESSION_LEVELS == (1, 3, 4)
    assert whatweb_noise_level(1) == "stealth"
    assert whatweb_noise_level(3) == "aggressive"
    assert whatweb_noise_level(4) == "heavy"
    with pytest.raises(ValueError):
        whatweb_noise_level(2)


def test_definition_rejects_aggression_two_before_argv():
    # Regression (B2): the schema must reject 2 instead of propagating an
    # invalid level to whatweb (which exits 0 with a 2-byte log).
    schema = whatweb_definition().input_schema
    assert schema["properties"]["aggression"]["enum"] == [1, 3, 4]


def test_handler_builds_log_json_command(workspace):
    with _fake_sandbox(SandboxResult(0, "", ""), SAMPLE) as (sandbox, _):
        result = _run({"targets": ["http://x/"]})
    argv = sandbox.calls[0][0]
    assert argv[0] == "whatweb"
    assert any(token.startswith("--log-json=") for token in argv)
    assert "--no-errors" in argv
    assert "--color=never" in argv
    assert "--max-threads=10" in argv
    assert "--aggression=1" in argv
    assert "--quiet" in argv
    assert result.output["count"] == 1


def test_handler_multiple_targets_skips_quiet(workspace):
    (workspace / "whatweb_t1.json").write_text(SAMPLE, encoding="utf-8")
    with _fake_sandbox(SandboxResult(0, "", "")) as (sandbox, _):
        _run({"targets": ["http://a/", "http://b/"]})
    argv = sandbox.calls[0][0]
    assert "--quiet" not in argv
    assert argv[-2:] == ["http://a/", "http://b/"]


def test_handler_honors_aggression_four(workspace):
    (workspace / "whatweb_t1.json").write_text(SAMPLE, encoding="utf-8")
    with _fake_sandbox(SandboxResult(0, "", "")) as (sandbox, _):
        result = _run({"targets": ["http://x/"], "aggression": 4})
    argv = sandbox.calls[0][0]
    assert "--aggression=4" in argv
    assert result.evidence["aggression"] == 4
    assert result.evidence["noise_level"] == "heavy"
    assert any("heavy" in warning for warning in result.evidence["warnings"])


def test_handler_rejects_invalid_aggression(workspace):
    # Regression (B2): a direct handler call must fail closed too, not just the
    # schema boundary.
    with _fake_sandbox(SandboxResult(0, "", "")):
        with pytest.raises(ValueError):
            _run({"targets": ["http://x/"], "aggression": 2})


def test_handler_rejects_two_byte_log(workspace):
    # Regression (B2): whatweb exits 0 with `[\n` when the command line is
    # invalid. That is a broken run, not "a successful scan with 0 targets".
    assert MIN_VALID_JSONL_BYTES >= 10
    with _fake_sandbox(SandboxResult(0, "", ""), "[\n"):
        result = _run({"targets": ["http://x/"]})
    assert result.success is False
    assert result.verification_method == "whatweb_output_too_small"


def test_handler_reads_and_parses_the_json_log(workspace):
    with _fake_sandbox(SandboxResult(0, "", ""), SAMPLE):
        result = _run({"targets": ["http://x/"]})
    assert result.verified is True
    assert result.output["fingerprints"][0]["url"] == "http://x/"
    assert result.evidence["fingerprint_count"] == 2


def test_handler_returns_unverified_when_no_log(workspace):
    with _fake_sandbox(SandboxResult(0, "", "")):
        result = _run({"targets": ["http://x/"]})
    assert result.success is False
    assert result.verification_method == "whatweb_no_log"


def test_handler_returns_unverified_on_parse_error(workspace):
    with _fake_sandbox(SandboxResult(0, "", ""), "{not valid json"):
        result = _run({"targets": ["http://x/"]})
    assert result.success is False
    assert result.verification_method == "whatweb_parse_failed"


def test_handler_starts_from_a_clean_log_between_calls(workspace):
    # Regression: whatweb appends to --log-json. Reusing the per-run path across
    # iterations used to concatenate documents and fail whatweb_parse_failed.
    target = workspace / "whatweb_t1.json"

    class AppendingSandbox:
        async def run(self, argv, *, timeout_seconds=30):
            with open(target, "a", encoding="utf-8") as stream:
                stream.write(SAMPLE + "\n")
            return SandboxResult(0, "", "")

    with mock.patch.object(
        whatweb_module, "sandbox_for_environment", lambda *a, **k: AppendingSandbox()
    ):
        first = _run({"targets": ["http://x/"]})
        second = _run({"targets": ["http://x/"]})
    assert first.verified is True
    assert second.verified is True


def test_handler_returns_unverified_on_timeout(workspace):
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"targets": ["http://x/"]})
    assert result.success is False
    assert result.verification_method == "whatweb_timeout"


def test_handler_rejects_empty_targets(workspace):
    with _fake_sandbox(SandboxResult(0, "", "")):
        with pytest.raises(ValueError):
            _run({"targets": ["  ", ""]})


def test_handler_uses_sandbox_allowlist_and_no_subprocess(workspace):
    (workspace / "whatweb_t1.json").write_text(SAMPLE, encoding="utf-8")
    with _fake_sandbox(SandboxResult(0, "", "")) as (sandbox, allowlists):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses"),
        ):
            _run({"targets": ["http://x/"]})
    assert allowlists == [WHATWEB_ALLOWED_PROGRAMS]
    assert "whatweb" in WHATWEB_ALLOWED_PROGRAMS
    assert sandbox.calls


def test_definition_declares_scope_and_risk():
    definition = whatweb_definition()
    assert definition.tool_id == "nexus.recon.whatweb"
    assert definition.risk is RiskLevel.LOW
    assert definition.scope_target_field == "targets"
    assert definition.scope_required is True
