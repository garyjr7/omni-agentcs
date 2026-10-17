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


# ------------------------------------------------------------------- H1 stdout
def _inflate(xml_text: str, target_bytes: int = 30_000) -> str:
    """Grow the fixture with an XML comment so the raw scan exceeds 30 KB."""
    padding = "<!--" + ("A" * target_bytes) + "-->"
    head, separator, tail = xml_text.partition("?>")
    if not separator:  # no XML declaration: just lead with the comment
        return padding + xml_text
    return head + separator + padding + tail


def test_handler_truncates_raw_xml_stdout_when_scan_is_parsed():
    xml_text = _inflate(_read("scan_single_host.xml"))
    assert len(xml_text.encode("utf-8")) > 30_000
    with _fake_sandbox(SandboxResult(0, xml_text, "")):
        result = _run({"target": "203.0.113.10", "profile": "service"})
    assert result.verified is True
    assert len(result.stdout.encode("utf-8")) <= 500
    assert result.output["stdout_truncated"] is True
    assert result.evidence["stdout_truncated"] is True
    # The parsed scan is untouched, and the digest still covers the full XML.
    assert result.output["scan"]["hosts"]
    assert result.evidence["raw_xml_sha256"] == hashlib.sha256(
        xml_text.encode("utf-8")
    ).hexdigest()


SMALL_XML = (
    '<?xml version="1.0"?>'
    '<nmaprun scanner="nmap" args="nmap">'
    '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="80"><state state="open"/>'
    '<service name="http"/></port></ports></host>'
    '<runstats><hosts up="1" down="0"/></runstats></nmaprun>'
)


def test_handler_keeps_small_stdout_intact():
    assert len(SMALL_XML.encode("utf-8")) <= 500
    with _fake_sandbox(SandboxResult(0, SMALL_XML, "")):
        result = _run({"target": "10.0.0.1"})
    assert result.stdout == SMALL_XML
    assert "stdout_truncated" not in result.output
    assert result.evidence["stdout_truncated"] is False


def test_truncate_stdout_is_byte_safe():
    from nexus_core.tools.handlers.nmap import truncate_stdout

    text, truncated = truncate_stdout("á" * 400, limit=500)
    assert truncated is True
    assert len(text.encode("utf-8")) <= 500
    same, untouched = truncate_stdout("short", limit=500)
    assert same == "short" and untouched is False


def test_nmap_definition_declares_scope_requirements():
    definition = nmap_definition()
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True
    assert definition.tenant_id == "system"


def test_nmap_definition_exposes_profile_enum():
    definition = nmap_definition()
    profile = definition.input_schema["properties"]["profile"]
    assert "full_tcp" in profile["enum"]
    assert "service" in profile["enum"]


# ---------------------------------------------------------------------- profiles
def test_full_tcp_profile_scans_all_ports_with_its_own_timeout():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        result = _run({"target": "203.0.113.10", "profile": "full_tcp"})
    argv, timeout = sandbox.calls[0]
    assert "-p-" in argv
    assert timeout == 600
    assert result.output["profile"] == "full_tcp"
    assert result.evidence["profile"] == "full_tcp"


def test_explicit_timeout_overrides_profile_timeout():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        _run({"target": "203.0.113.10", "profile": "full_tcp", "timeout_seconds": 90})
    assert sandbox.calls[0][1] == 90


def test_profile_description_warns_against_passing_ports():
    definition = nmap_definition()
    properties = definition.input_schema["properties"]
    assert "NO pases" in properties["profile"]["description"]
    assert "'-p'" in properties["flags"]["description"]


def test_profile_flags_combine_with_explicit_flags():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        _run({"target": "203.0.113.10", "profile": "full_tcp", "flags": ["-sV"]})
    argv = sandbox.calls[0][0]
    assert "-p-" in argv and "-sV" in argv


def test_profiles_disable_reverse_dns():
    # ``-n`` is a pure speed win on IP targets (no reverse DNS) and was missing
    # from every profile; the RootMe scan measured 43.8 s without it.
    for profile in ("quick", "full_tcp", "service"):
        with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
            _run({"target": "203.0.113.10", "profile": profile})
        assert "-n" in sandbox.calls[0][0]


def test_min_rate_flag_is_allowed():
    flags, noise, _ = validate_and_canonicalize_flags(["--min-rate", "5000"])
    assert flags == ["--min-rate", "5000"]
    assert noise == "medium"


def test_min_rate_requires_a_value():
    with pytest.raises(ValueError):
        validate_and_canonicalize_flags(["--min-rate"])


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError):
        _run({"target": "203.0.113.10", "profile": "does-not-exist"})


def test_profile_all_ports_ignores_an_explicit_port_list():
    # Simple CTF: the model sent profile="service" + flags=["-p", "-p", ...];
    # raising here cost the run an iteration and the scan never happened. The
    # profile already means -p-, so the port selection is dropped, not fatal.
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        result = _run(
            {"target": "203.0.113.10", "profile": "full_tcp", "flags": ["-p", "22,80"]}
        )
    argv = sandbox.calls[0][0]
    assert "-p-" in argv
    assert "22,80" not in argv and "-p" not in argv
    assert result.output["ignored_flags"] == ["-p", "22,80"]
    assert any("ignored redundant port flags" in warning for warning in result.evidence["warnings"])


def test_service_profile_ignores_inline_port_selection():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        result = _run(
            {"target": "203.0.113.10", "profile": "service", "flags": ["-p=21,80", "-sV"]}
        )
    argv = sandbox.calls[0][0]
    assert "-p=21,80" not in argv and "-sV" in argv
    assert result.output["ignored_flags"] == ["-p=21,80"]


def test_profiles_leave_the_port_selection_alone_without_all_ports():
    with _fake_sandbox(SandboxResult(0, _read("scan_single_host.xml"), "")) as sandbox:
        result = _run({"target": "203.0.113.10", "profile": "quick", "flags": ["-p", "21,80"]})
    argv = sandbox.calls[0][0]
    assert "-p" in argv and "21,80" in argv
    assert "ignored_flags" not in result.output


def test_explicit_all_ports_with_port_list_is_still_a_conflict():
    # Without a profile there is no server-side expansion to fall back on: the
    # two port selectors are genuinely ambiguous, so the guard stays.
    with pytest.raises(ValueError):
        _run({"target": "203.0.113.10", "flags": ["-p-", "-p", "22,80"]})
