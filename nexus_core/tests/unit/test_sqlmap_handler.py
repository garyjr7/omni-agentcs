"""Unit tests for the durable sqlmap handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import sqlmap as sqlmap_module
from nexus_core.tools.handlers.sqlmap import (
    SQLMAP_ALLOWED_PROGRAMS,
    SQLMAP_DEFAULT_ANSWERS,
    SQLMAP_STOP_LIMIT,
    sqlmap_definition,
    sqlmap_handler,
    validate_and_canonicalize_sqlmap_flags,
)

NOT_INJECTABLE = (
    "[INFO] testing connection to the target URL\n"
    "[INFO] testing for SQL injection on GET parameter 'id'\n"
    "[WARNING] GET parameter 'id' does not seem to be injectable\n"
    "[ERROR] all tested parameters do not appear to be injectable.\n"
)
VULNERABLE = (
    "[INFO] the back-end DBMS is MySQL\n"
    "[INFO] GET parameter 'id' is vulnerable\n"
)


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

    with mock.patch.object(sqlmap_module, "sandbox_for_environment", factory):
        yield sandbox, allowlists


def _context() -> RunContext:
    return RunContext("system", Identity("op", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(sqlmap_handler(arguments, _context()))


@pytest.mark.parametrize(
    "flag",
    ["--os-shell", "--os-pwn", "--sql-shell", "--sql-query", "--file-read", "--file-write", "--priv-esc"],
)
def test_validate_rejects_forbidden_flags(flag):
    with pytest.raises(ValueError):
        validate_and_canonicalize_sqlmap_flags([flag])


def test_validate_rejects_unknown_flag():
    with pytest.raises(ValueError):
        validate_and_canonicalize_sqlmap_flags(["--turn-into-a-robot"])


def test_validate_rejects_dump_without_safe_mode():
    with pytest.raises(ValueError):
        validate_and_canonicalize_sqlmap_flags(["--dump"], safe_mode=True)


def test_validate_allows_dump_with_safe_mode():
    flags, _, _ = validate_and_canonicalize_sqlmap_flags(["--dump"], safe_mode=False)
    assert flags == ["--dump"]


def test_safe_mode_dump_adds_stop_limit():
    with _fake_sandbox(SandboxResult(0, NOT_INJECTABLE, "")) as (sandbox, _):
        _run({"url": "http://x/?id=1", "safe_mode": False, "flags": ["--dump"]})
    argv = sandbox.calls[0][0]
    assert argv[argv.index("--stop") + 1] == str(SQLMAP_STOP_LIMIT)


def test_handler_always_batches_and_flushes():
    with _fake_sandbox(SandboxResult(0, NOT_INJECTABLE, "")) as (sandbox, _):
        _run({"url": "http://x/?id=1"})
    argv = sandbox.calls[0][0]
    assert argv[0] == "sqlmap"
    for expected in ("--batch", "--flush-session", "--no-cast", "--no-escape"):
        assert expected in argv
    assert argv[argv.index("--threads") + 1] == "1"
    assert argv[argv.index("--answers") + 1] == SQLMAP_DEFAULT_ANSWERS
    assert any(token.startswith("--output-dir=") or token == "--output-dir" for token in argv)


def test_handler_uses_output_dir_under_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, NOT_INJECTABLE, "")) as (sandbox, _):
        _run({"url": "http://x/?id=1"})
    argv = sandbox.calls[0][0]
    index = argv.index("--output-dir")
    assert str(tmp_path) in argv[index + 1]
    assert "sqlmap_out_" in argv[index + 1]


def test_handler_rejects_non_http_url():
    with _fake_sandbox(SandboxResult(0, NOT_INJECTABLE, "")):
        with pytest.raises(ValueError):
            _run({"url": "file:///etc/passwd"})


def test_handler_rejects_bad_technique():
    with _fake_sandbox(SandboxResult(0, NOT_INJECTABLE, "")):
        with pytest.raises(ValueError):
            _run({"url": "http://x/?id=1", "technique": "XZ"})


def test_handler_rejects_metacharacters_in_dbms():
    with _fake_sandbox(SandboxResult(0, NOT_INJECTABLE, "")):
        with pytest.raises(ValueError):
            _run({"url": "http://x/?id=1", "dbms": "MySQL; DROP TABLE users"})


def test_handler_uses_sandbox_with_allowlist_and_no_subprocess():
    with _fake_sandbox(SandboxResult(0, NOT_INJECTABLE, "")) as (sandbox, allowlists):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses"),
        ):
            _run({"url": "http://x/?id=1"})
    assert allowlists == [SQLMAP_ALLOWED_PROGRAMS]
    assert "sqlmap" in SQLMAP_ALLOWED_PROGRAMS
    assert sandbox.calls


def test_handler_reports_vulnerability():
    with _fake_sandbox(SandboxResult(0, VULNERABLE, "")):
        result = _run({"url": "http://x/?id=1"})
    assert result.verified is True
    assert result.output["vulnerable"] is True
    assert result.output["findings"][0]["parameter"] == "id"


def test_handler_treats_not_injectable_as_completed():
    with _fake_sandbox(SandboxResult(0, NOT_INJECTABLE, "")):
        result = _run({"url": "http://x/?id=1"})
    assert result.verified is True
    assert result.output["vulnerable"] is False
    assert result.output["findings"] == []


def test_handler_returns_unverified_on_timeout():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"url": "http://x/?id=1"})
    assert result.success is False
    assert result.verification_method == "sqlmap_timeout"


def test_definition_declares_scope_and_risk():
    definition = sqlmap_definition()
    assert definition.tool_id == "nexus.web.sqlmap"
    assert definition.risk is RiskLevel.MEDIUM
    assert definition.scope_target_field == "url"
    assert definition.scope_required is True
    assert definition.required_permissions == ["execute:tool:nexus.web.sqlmap"]
