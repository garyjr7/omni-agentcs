"""Unit tests for the durable gobuster handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SANDBOX_HOME_DIRNAME, SandboxResult
from nexus_core.tools.handlers import gobuster as gobuster_module
from nexus_core.tools.handlers.gobuster import (
    GOBUSTER_ALLOWED_PROGRAMS,
    gobuster_definition,
    gobuster_handler,
    gobuster_noise_level,
    validate_and_canonicalize_gobuster_flags,
)

HITS = (
    "index.html           (Status: 200) [Size: 6974]\n"
    "shared               (Status: 301) [Size: 318] [--> http://x/shared/]\n"
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

    with mock.patch.object(gobuster_module, "sandbox_for_environment", factory):
        yield sandbox, allowlists


def _context() -> RunContext:
    return RunContext("system", Identity("op", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(gobuster_handler(arguments, _context()))


@pytest.fixture
def wordlist(tmp_path, monkeypatch):
    path = tmp_path / "words.txt"
    path.write_text("admin\nlogin\n", encoding="utf-8")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    return path


@pytest.mark.parametrize("flag", ["-o", "-of", "-z", "--proxy", "-p", "-c", "-m", "-H", "--header"])
def test_validate_rejects_forbidden_flags(flag):
    with pytest.raises(ValueError):
        validate_and_canonicalize_gobuster_flags([flag])


def test_validate_rejects_unknown_flag():
    with pytest.raises(ValueError):
        validate_and_canonicalize_gobuster_flags(["--nonsense"])


def test_validate_accepts_and_canonicalizes():
    flags, noise, _ = validate_and_canonicalize_gobuster_flags(["-k", "--timeout", "5"])
    assert flags == ["-k", "--timeout", "5"]
    assert noise == "low"


def test_noise_level_from_threads():
    assert gobuster_noise_level(1) == "low"
    assert gobuster_noise_level(5) == "low"
    assert gobuster_noise_level(10) == "medium"
    assert gobuster_noise_level(20) == "medium"
    assert gobuster_noise_level(21) == "high"


def test_handler_builds_dir_command(wordlist):
    with _fake_sandbox(SandboxResult(0, HITS, "")) as (sandbox, _):
        result = _run({"mode": "dir", "target": "http://x/", "wordlist": str(wordlist)})
    argv = sandbox.calls[0][0]
    assert argv[:2] == ["gobuster", "dir"]
    assert argv[argv.index("-u") + 1] == "http://x/"
    assert argv[argv.index("-w") + 1] == str(wordlist)
    assert argv[argv.index("-t") + 1] == "10"
    assert "-q" in argv and "--no-error" in argv and "-o" in argv
    assert result.output["count"] == 2
    assert result.evidence["noise_level"] == "medium"


def test_handler_dns_mode_uses_domain_flag(wordlist):
    with _fake_sandbox(SandboxResult(0, "", "")) as (sandbox, _):
        _run({"mode": "dns", "target": "example.com", "wordlist": str(wordlist)})
    argv = sandbox.calls[0][0]
    assert argv[:2] == ["gobuster", "dns"]
    assert argv[argv.index("-d") + 1] == "example.com"


def test_handler_honours_threads_and_extensions(wordlist):
    with _fake_sandbox(SandboxResult(0, HITS, "")) as (sandbox, _):
        result = _run(
            {
                "mode": "dir",
                "target": "http://x/",
                "wordlist": str(wordlist),
                "threads": 3,
                "extensions": [".php", ".bak"],
                "status_codes": "200,301",
            }
        )
    argv = sandbox.calls[0][0]
    assert argv[argv.index("-t") + 1] == "3"
    assert argv[argv.index("-x") + 1] == ".php,.bak"
    assert argv[argv.index("-s") + 1] == "200,301"
    assert result.evidence["noise_level"] == "low"


def test_handler_rejects_wordlist_outside_workspace(wordlist):
    with _fake_sandbox(SandboxResult(0, HITS, "")):
        with pytest.raises(ValueError):
            _run({"mode": "dir", "target": "http://x/", "wordlist": "/etc/passwd"})


def test_handler_rejects_wordlist_inside_sandbox_home(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    config_dir = tmp_path / SANDBOX_HOME_DIRNAME / ".config"
    config_dir.mkdir(parents=True)
    wordlist = config_dir / "config.yaml"
    wordlist.write_text("secret\n", encoding="utf-8")
    with _fake_sandbox(SandboxResult(0, HITS, "")):
        with pytest.raises(ValueError):
            _run({"mode": "dir", "target": "http://x/", "wordlist": str(wordlist)})


def test_handler_rejects_unknown_mode(wordlist):
    with _fake_sandbox(SandboxResult(0, HITS, "")):
        with pytest.raises(ValueError):
            _run({"mode": "fuzz", "target": "http://x/", "wordlist": str(wordlist)})


def test_handler_uses_sandbox_allowlist_and_no_subprocess(wordlist):
    with _fake_sandbox(SandboxResult(0, HITS, "")) as (sandbox, allowlists):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses"),
        ):
            _run({"mode": "dir", "target": "http://x/", "wordlist": str(wordlist)})
    assert allowlists == [GOBUSTER_ALLOWED_PROGRAMS]
    assert "gobuster" in GOBUSTER_ALLOWED_PROGRAMS
    assert sandbox.calls


def test_handler_treats_no_hits_as_completed(wordlist):
    with _fake_sandbox(SandboxResult(0, "", "")):
        result = _run({"mode": "dir", "target": "http://x/", "wordlist": str(wordlist)})
    assert result.verified is True
    assert result.evidence["count"] == 0


def test_handler_returns_unverified_on_timeout(wordlist):
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"mode": "dir", "target": "http://x/", "wordlist": str(wordlist)})
    assert result.success is False
    assert result.verification_method == "gobuster_timeout"


def test_definition_declares_scope_and_risk():
    definition = gobuster_definition()
    assert definition.tool_id == "nexus.recon.gobuster"
    assert definition.risk is RiskLevel.MEDIUM
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True
    assert "dir" in definition.input_schema["properties"]["mode"]["enum"]
