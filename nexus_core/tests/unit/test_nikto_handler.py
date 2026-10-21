"""Unit tests for ``nexus.recon.nikto`` (sandbox mocked) and its parser.

The handler is the room's *evasion* primitive (RUN_sala12): the tests pin the two
properties that make it governed rather than a flag dump — the evasion knobs are
validated against nikto's own tables, and the reported ``connected`` boolean is
derived from the report header instead of from the exit code.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
from unittest import mock

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import nikto as module
from nexus_core.tools.handlers.nikto import nikto_definition, nikto_handler
from nexus_core.tools.parsers.nikto import parse_nikto_report

HEADER = (
    "- Nikto v2.1.6\n"
    "---------------------------------------------------------------------------\n"
    "+ Target IP:          10.64.182.188\n"
    "+ Target Hostname:    10.64.182.188\n"
    "+ Target Port:        80\n"
    "+ Start Time:         2026-10-12 01:50:00 (GMT0)\n"
    "---------------------------------------------------------------------------\n"
)
FINDINGS = (
    "+ Server: Apache/2.4.41 (Ubuntu)\n"
    "+ /login: This might be interesting.\n"
    "+ OSVDB-3092: /login/: This might be interesting...\n"
    "+ The anti-clickjacking X-Frame-Options header is not present.\n"
)
FOOTER = (
    "+ 7918 requests: 0 error(s) and 20 item(s) reported on remote host\n"
    "+ End Time:           2026-10-12 01:52:00 (GMT0) (120 seconds)\n"
    "---------------------------------------------------------------------------\n"
    "+ 1 host(s) tested\n"
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
    with mock.patch.object(
        module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(nikto_handler(arguments, _context()))


# ------------------------------------------------------------------ definitions
def test_nikto_is_medium_risk_and_scope_gated():
    definition = nikto_definition()
    assert definition.risk.value == "medium"
    assert definition.scope_required is True
    assert definition.scope_target_field == "target"


def test_handler_never_spawns_a_process():
    # Same invariant as the rest of the durable handlers: the sandbox is the only
    # execution path.
    source = inspect.getsource(module)
    assert "create_subprocess" not in source
    assert "asyncio.subprocess" not in source


# ---------------------------------------------------------------------- parser
def test_parser_extracts_header_findings_and_totals():
    report = parse_nikto_report(HEADER + FINDINGS + FOOTER)
    assert report.connected is True
    assert report.target_ip == "10.64.182.188"
    assert report.ports == ("80",)
    assert report.server == "Apache/2.4.41 (Ubuntu)"
    assert report.requests == 7918
    assert report.items == 20
    assert [finding.path for finding in report.findings] == ["/login", "/login/", ""]
    assert report.findings[1].identifier == "OSVDB-3092"
    assert report.findings[1].message == "This might be interesting..."
    # ``Server``/``Start Time``/``End Time``/``N host(s) tested`` are header, not
    # findings: 3 findings, not 7.
    assert len(report.findings) == 3


def test_parser_extracts_the_bracketed_test_id_of_nikto_2_6():
    # The binary that ships with Kali prints ``+ [001736] /login/: message`` instead
    # of the OSVDB id (measured in RUN_sala12).
    report = parse_nikto_report(
        HEADER + "+ [001736] /login/: This might be interesting.\n" + FOOTER
    )
    finding = report.findings[0]
    assert finding.identifier == "001736"
    assert finding.path == "/login/"
    assert finding.message == "This might be interesting."


def test_parser_accepts_a_maxtime_truncated_scan():
    text = HEADER + "+ Scan terminated: 0 errors and 6 items reported on the remote host\n"
    report = parse_nikto_report(text)
    assert report.connected is True
    assert report.requests is None
    assert report.items == 6


def test_parser_reports_no_connection_without_a_header():
    report = parse_nikto_report("- Nikto v2.1.6\n+ No web server found on 10.0.0.1\n")
    assert report.connected is False
    assert report.findings[0].message == "No web server found on 10.0.0.1"


def test_parser_tolerates_empty_output():
    report = parse_nikto_report("")
    assert report.connected is False
    assert report.findings == ()


# --------------------------------------------------------------------- handler
def test_handler_builds_the_evasion_argv_and_reports_high_noise():
    payload = HEADER + FINDINGS + FOOTER
    with _fake_sandbox(SandboxResult(0, payload, "")) as sandbox:
        result = _run(
            {
                "target": "10.64.182.188",
                "ports": "80,3000",
                "evasion": "6AB",
                "tuning": "123b",
                "pause": 2,
                "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
                "maxtime_seconds": 120,
            }
        )
    argv = sandbox.calls[0][0]
    assert argv[0] == "nikto"
    # Managed opsec flags are always present and cannot be overridden.
    assert "-nolookup" in argv and "-nocheck" in argv and "-nointeractive" in argv
    assert argv[argv.index("-port") + 1] == "80,3000"
    assert argv[argv.index("-evasion") + 1] == "6AB"
    assert argv[argv.index("-Tuning") + 1] == "123b"
    assert argv[argv.index("-Pause") + 1] == "2"
    assert argv[argv.index("-maxtime") + 1] == "120s"
    assert argv[argv.index("-useragent") + 1] == "Mozilla/5.0 (X11; Linux x86_64)"
    assert result.verified is True
    assert result.verification_method == "nikto_text_parsed"
    assert result.output["count"] == 3
    # The level is honest: evasion does not lower the request volume.
    assert result.output["noise_level"] == "high"
    assert result.evidence["evasion"] == "6AB"


def test_handler_reports_a_negative_when_nikto_never_connected():
    with _fake_sandbox(SandboxResult(0, "- Nikto v2.1.6\n+ 0 host(s) tested\n", "")):
        result = _run({"target": "10.0.0.1"})
    assert result.verified is False
    assert result.verification_method == "nikto_no_target"


def test_handler_rejects_an_unknown_evasion_character():
    with _fake_sandbox(SandboxResult(0, HEADER + FOOTER, "")):
        try:
            _run({"target": "10.0.0.1", "evasion": "6Z"})
        except ValueError as exc:
            assert "invalid evasion characters" in str(exc)
        else:  # pragma: no cover - the call must raise
            raise AssertionError("invalid evasion character was accepted")


def test_handler_rejects_a_target_with_shell_metacharacters():
    with _fake_sandbox(SandboxResult(0, HEADER + FOOTER, "")):
        try:
            _run({"target": "10.0.0.1; id"})
        except ValueError as exc:
            assert "unsupported characters" in str(exc)
        else:  # pragma: no cover - the call must raise
            raise AssertionError("metacharacter target was accepted")


def test_handler_reports_a_timeout():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"target": "10.0.0.1"})
    assert result.verified is False
    assert result.verification_method == "nikto_timeout"


def test_definition_is_registered_in_the_catalog():
    from nexus_core.tools.registry import durable_tool_definitions

    catalog = durable_tool_definitions("system")
    definition, handler = catalog["nexus.recon.nikto"]
    assert definition.tool_id == "nexus.recon.nikto"
    from inspect import unwrap

    assert unwrap(handler) is nikto_handler
    assert json.dumps(definition.input_schema)[:1] == "{"


def test_an_http_url_is_reduced_to_its_host_and_port():
    """run V10: ``target="http://10.65.170.171"`` cost a turn in iteration 9."""
    with _fake_sandbox(SandboxResult(0, HEADER + FINDINGS + FOOTER, "")) as sandbox:
        result = _run({"target": "http://10.65.170.171"})
    argv = sandbox.calls[0][0]
    assert argv[argv.index("-host") + 1] == "10.65.170.171"
    assert argv[argv.index("-port") + 1] == "80"
    assert "-ssl" not in argv
    assert result.verified is True


def test_an_https_url_sets_ssl_and_its_port():
    with _fake_sandbox(SandboxResult(0, HEADER + FINDINGS + FOOTER, "")) as sandbox:
        _run({"target": "https://10.65.170.171:8443/blog/"})
    argv = sandbox.calls[0][0]
    assert argv[argv.index("-host") + 1] == "10.65.170.171"
    assert argv[argv.index("-port") + 1] == "8443"
    assert "-ssl" in argv


def test_an_explicit_port_still_wins_over_the_url_port():
    with _fake_sandbox(SandboxResult(0, HEADER + FINDINGS + FOOTER, "")) as sandbox:
        _run({"target": "http://10.65.170.171:8080/", "ports": "80"})
    argv = sandbox.calls[0][0]
    assert argv[argv.index("-port") + 1] == "80"
