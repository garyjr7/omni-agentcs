"""Unit tests for the durable nmap handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import nmap as nmap_module
from nexus_core.tools.handlers.nmap import (
    nmap_definition,
    nmap_handler,
    validate_and_canonicalize_flags,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "nmap"


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
    with mock.patch.object(
        nmap_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(nmap_handler(arguments, _context()))


# --------------------------------------------------------------- flag allowlist
def test_validate_flags_rejects_forbidden_flag():
    with pytest.raises(ValueError):
        validate_and_canonicalize_flags(["--script=vuln"])
    with pytest.raises(ValueError):
        validate_and_canonicalize_flags(["-A"])


def test_validate_flags_rejects_unknown_flag():
    with pytest.raises(ValueError):
        validate_and_canonicalize_flags(["--malicious"])


def test_validate_flags_accepts_allowed_and_canonicalizes():
    flags, noise, _ = validate_and_canonicalize_flags(["-sV", "-p", "22,80"])
    assert flags == ["-sV", "-p", "22,80"]
    assert noise == "medium"


def test_validate_flags_calculates_high_noise():
    _, noise, _ = validate_and_canonicalize_flags(["-T4"])
    assert noise == "high"


def test_validate_flags_calculates_low_noise():
    _, noise, _ = validate_and_canonicalize_flags(["-Pn", "-n"])
    assert noise == "low"


# --------------------------------------------------------------------- handler
def test_handler_always_appends_oX_dash():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        _run({"target": "203.0.113.10", "flags": ["-Pn", "-p", "22,80"]})
    argv = sandbox.calls[0][0]
    assert argv[:4] == ["nmap", "-Pn", "-p", "22,80"]
    assert "-oX" in argv and "-" in argv
    assert argv[-1] == "203.0.113.10"


def test_handler_uses_sandbox_not_subprocess():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"target": "203.0.113.10"})
    assert sandbox.calls


def test_handler_returns_verified_true_on_exit_zero():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")):
        result = _run({"target": "203.0.113.10", "flags": ["-sV"]})
    assert result.verified is True
    assert result.success is True
    assert result.verification_method == "nmap_xml_parsed"


def test_handler_returns_verified_false_on_timeout():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"target": "203.0.113.10"})
    assert result.verified is False
    assert result.verification_method == "nmap_timeout"


def test_handler_returns_verified_false_on_malformed_xml():
    with _fake_sandbox(SandboxResult(0, _read("scan_malformed.xml"), "")):
        result = _run({"target": "203.0.113.10"})
    assert result.verified is False
    assert result.verification_method == "nmap_xml_parse_failed"


def test_handler_includes_noise_level_in_evidence():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")):
        result = _run({"target": "203.0.113.10", "flags": ["-sV"]})
    assert result.evidence["noise_level"] == "medium"


def test_handler_includes_raw_xml_sha256_in_evidence():
    xml_text = _read("scan_single_host.xml")
    with _fake_sandbox(SandboxResult(0, xml_text, "")):
        result = _run({"target": "203.0.113.10"})
    assert result.evidence["raw_xml_sha256"] == hashlib.sha256(
        xml_text.encode("utf-8")
    ).hexdigest()
    assert result.evidence["hosts_up"] == 1
    assert result.evidence["ports_open_total"] == 2


def test_nmap_definition_declares_scope_requirements():
    definition = nmap_definition()
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True
    assert definition.tenant_id == "system"
