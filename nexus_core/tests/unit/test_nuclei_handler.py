"""Unit tests for the durable nuclei handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import nuclei as nuclei_module
from nexus_core.tools.handlers._exec import RECON_ALLOWED_PROGRAMS
from nexus_core.tools.handlers.nuclei import (
    NUCLEI_DEFAULT_EXCLUDE_TAGS,
    nuclei_definition,
    nuclei_handler,
    nuclei_noise_level,
    validate_and_canonicalize_nuclei_flags,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "nuclei"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def hermetic_templates(tmp_path, monkeypatch):
    """Point the handler at a real, temporary templates directory.

    The handler fails closed when no templates directory exists, so the suite
    must not depend on ``/opt/nuclei-templates`` being installed on the host.
    """
    root = tmp_path / "nuclei-templates"
    (root / "http" / "technologies").mkdir(parents=True)
    (root / "http" / "technologies" / "tech-detect.yaml").write_text(
        "id: tech-detect\ninfo:\n  name: Tech Detect\n  severity: info\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("NEXUS_NUCLEI_TEMPLATES", raising=False)
    monkeypatch.setattr(nuclei_module, "DEFAULT_NUCLEI_TEMPLATES", str(root))
    return root


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

    with mock.patch.object(nuclei_module, "sandbox_for_environment", factory):
        yield sandbox, allowlists


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(nuclei_handler(arguments, _context()))


@pytest.mark.parametrize(
    "flag",
    [
        "-iserver=https://oast.example",
        "-interactsh-token=secret",
        "-dast",
        "-headless",
        "-code",
        "-u",
        "-l",
        "-o",
        "-config",
        "-H",
    ],
)
def test_validate_flags_rejects_forbidden_flag(flag):
    with pytest.raises(ValueError):
        validate_and_canonicalize_nuclei_flags([flag])


def test_validate_flags_rejects_unknown_flag():
    with pytest.raises(ValueError):
        validate_and_canonicalize_nuclei_flags(["--malicious"])


def test_validate_flags_rejects_missing_value():
    with pytest.raises(ValueError):
        validate_and_canonicalize_nuclei_flags(["-tags"])


def test_validate_flags_accepts_and_canonicalizes():
    flags, noise, warnings = validate_and_canonicalize_nuclei_flags(["-tags", "cve", "-rl", "20"])
    assert flags == ["-tags", "cve", "-rl", "20"]
    assert noise == "medium"
    assert warnings == set()


def test_validate_flags_derives_noise_from_severity():
    _, noise, warnings = validate_and_canonicalize_nuclei_flags(["-severity", "high,critical"])
    assert noise == "high"
    assert warnings


def test_noise_level_from_severity_values():
    assert nuclei_noise_level(["info", "low"]) == "low"
    assert nuclei_noise_level(["medium"]) == "medium"
    assert nuclei_noise_level(["high", "critical"]) == "high"
    assert nuclei_noise_level([]) == "medium"


def test_handler_defaults_are_non_intrusive():
    with _fake_sandbox(SandboxResult(0, _read("findings.jsonl"), "")) as (sandbox, _):
        result = _run({"targets": ["https://scanme.example"]})
    argv = sandbox.calls[0][0]
    assert argv[:5] == ["nuclei", "-jsonl", "-silent", "-nc", "-no-interactsh"]
    assert "-severity" in argv and "low,medium" in argv
    assert "-exclude-tags" in argv and NUCLEI_DEFAULT_EXCLUDE_TAGS in argv
    assert "-u" in argv and "https://scanme.example" in argv
    assert result.evidence["interactsh"] is False
    assert result.evidence["noise_level"] == "medium"
    assert result.evidence["count"] == 3
    assert result.evidence["severity_counts"] == {"high": 1, "info": 2}


def test_handler_honours_explicit_severity_and_managed_flag_dedup():
    with _fake_sandbox(SandboxResult(0, _read("findings.jsonl"), "")) as (sandbox, _):
        result = _run(
            {"targets": ["https://scanme.example"], "flags": ["-severity", "high", "-silent"]}
        )
    argv = sandbox.calls[0][0]
    assert argv.count("-silent") == 1
    assert argv[argv.index("-severity") + 1] == "high"
    assert result.evidence["noise_level"] == "high"


def test_handler_uses_sandbox_with_recon_allowlist_and_no_subprocess():
    with _fake_sandbox(SandboxResult(0, _read("findings.jsonl"), "")) as (sandbox, allowlists):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"targets": ["https://scanme.example"]})
    assert allowlists == [RECON_ALLOWED_PROGRAMS]
    assert "nuclei" in RECON_ALLOWED_PROGRAMS
    assert sandbox.calls


def test_handler_treats_no_findings_as_a_completed_scan():
    with _fake_sandbox(SandboxResult(0, "", "")):
        result = _run({"targets": ["https://scanme.example"]})
    assert result.verified is True
    assert result.evidence["count"] == 0
    assert result.output["findings"] == []


def test_nuclei_definition_declares_scope_and_risk():
    definition = nuclei_definition()
    assert definition.tool_id == "nexus.web.nuclei"
    assert definition.risk is RiskLevel.MEDIUM
    assert definition.scope_target_field == "targets"
    assert definition.scope_required is True
    assert definition.required_permissions == ["execute:tool:nexus.web.nuclei"]
