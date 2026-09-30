"""Unit tests for the durable dalfox handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import dalfox as dalfox_module
from nexus_core.tools.handlers.dalfox import (
    DALFOX_ALLOWED_PROGRAMS,
    DALFOX_DEFAULT_WORKERS,
    dalfox_definition,
    dalfox_handler,
    validate_and_canonicalize_dalfox_flags,
    validate_dalfox_headers,
)

FINDING = (
    '[{"type":"V","inject_type":"inHTML-URL","method":"GET","data":"http://x/?q=1",'
    '"param":"q","payload":"<script>alert(1)</script>","evidence":"1 line",'
    '"cwe":"CWE-79","severity":"High","message_str":"Triggered XSS Payload"},{}]'
)
NO_FINDINGS = "[\n{}]"


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

    with mock.patch.object(dalfox_module, "sandbox_for_environment", factory):
        yield sandbox, allowlists


def _context() -> RunContext:
    return RunContext("system", Identity("op", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(dalfox_handler(arguments, _context()))


@pytest.mark.parametrize(
    "flag", ["--custom-payload", "--found-action", "--waf-evasion", "--remote-payloads", "--mass"]
)
def test_validate_rejects_forbidden_flags(flag):
    with pytest.raises(ValueError):
        validate_and_canonicalize_dalfox_flags([flag])


def test_validate_rejects_unknown_flag():
    with pytest.raises(ValueError):
        validate_and_canonicalize_dalfox_flags(["--make-me-coffee"])


def test_handler_builds_non_interactive_command():
    with _fake_sandbox(SandboxResult(0, NO_FINDINGS, "")) as (sandbox, _):
        _run({"target": "http://x/?q=1"})
    argv = sandbox.calls[0][0]
    assert argv[:3] == ["dalfox", "url", "http://x/?q=1"]
    assert argv[argv.index("--format") + 1] == "json"
    for expected in ("--no-color", "--silence", "--skip-bav", "--output"):
        assert expected in argv
    assert argv[argv.index("--worker") + 1] == str(DALFOX_DEFAULT_WORKERS)
    assert argv[argv.index("--timeout") + 1] == "10"


def test_handler_blind_true_omits_skip_bav():
    with _fake_sandbox(SandboxResult(0, NO_FINDINGS, "")) as (sandbox, _):
        _run({"target": "http://x/?q=1", "blind": True})
    argv = sandbox.calls[0][0]
    assert "--skip-bav" not in argv
    assert "--blind" not in argv


def test_handler_deep_domxss_adds_flag_and_high_noise():
    with _fake_sandbox(SandboxResult(0, NO_FINDINGS, "")) as (sandbox, _):
        result = _run({"target": "http://x/?q=1", "deep_domxss": True})
    argv = sandbox.calls[0][0]
    assert "--deep-domxss" in argv
    assert result.evidence["noise_level"] == "high"


def test_handler_post_method_and_data():
    with _fake_sandbox(SandboxResult(0, NO_FINDINGS, "")) as (sandbox, _):
        _run({"target": "http://x/", "method": "POST", "data": "a=1"})
    argv = sandbox.calls[0][0]
    assert argv[argv.index("--method") + 1] == "POST"
    assert argv[argv.index("--data") + 1] == "a=1"


def test_handler_passes_validated_headers():
    with _fake_sandbox(SandboxResult(0, NO_FINDINGS, "")) as (sandbox, _):
        _run({"target": "http://x/", "headers": {"Authorization": "Bearer t"}})
    argv = sandbox.calls[0][0]
    assert "Authorization: Bearer t" in argv


def test_headers_reject_host_and_forwarded_for():
    for name in ("Host", "X-Forwarded-For"):
        with pytest.raises(ValueError):
            validate_dalfox_headers({name: "evil"})


def test_headers_reject_too_many():
    with pytest.raises(ValueError):
        validate_dalfox_headers({f"H{i}": "v" for i in range(11)})


def test_handler_rejects_non_http_target():
    with _fake_sandbox(SandboxResult(0, NO_FINDINGS, "")):
        with pytest.raises(ValueError):
            _run({"target": "ftp://x/"})


def test_handler_reports_findings():
    with _fake_sandbox(SandboxResult(0, FINDING, "")):
        result = _run({"target": "http://x/?q=1"})
    assert result.verified is True
    assert result.output["count"] == 1
    assert result.output["findings"][0]["param"] == "q"


def test_handler_treats_zero_findings_as_completed():
    with _fake_sandbox(SandboxResult(0, NO_FINDINGS, "")):
        result = _run({"target": "http://x/?q=1"})
    assert result.verified is True
    assert result.output["count"] == 0


def test_handler_returns_unverified_on_timeout():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"target": "http://x/?q=1"})
    assert result.success is False
    assert result.verification_method == "dalfox_timeout"


def test_handler_uses_sandbox_allowlist_and_no_subprocess():
    with _fake_sandbox(SandboxResult(0, NO_FINDINGS, "")) as (sandbox, allowlists):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses"),
        ):
            _run({"target": "http://x/?q=1"})
    assert allowlists == [DALFOX_ALLOWED_PROGRAMS]
    assert "dalfox" in DALFOX_ALLOWED_PROGRAMS
    assert sandbox.calls


def test_definition_declares_scope_and_risk():
    definition = dalfox_definition()
    assert definition.tool_id == "nexus.web.dalfox"
    assert definition.risk is RiskLevel.MEDIUM
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True
