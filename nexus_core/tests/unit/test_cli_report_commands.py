"""Report meta commands: ``/findings``, ``/report`` and ``/timeline``.

The REPL is never started. Report generation is exercised through
``OmniSession.invoke_tool``, which is patched so the command layer is tested
without shelling out to the toolkit; findings and timeline read the durable
store the seed actually wrote.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.cli import commands as commands_module
from nexus_core.cli.session import OmniSession
from nexus_core.tests import report_support as support

TOOL = "nexus.report.generate"


def _session(store, engagement, **kwargs) -> OmniSession:
    return OmniSession(
        store=store,
        tenant_id=support.TENANT,
        engagement=engagement,
        operator_id="operator:tester",
        **kwargs,
    )


@pytest.fixture()
def seeded(tmp_path):
    """A session bound to a full engagement: 8 findings and 2 failed attempts."""
    store, engagement, run_id = support.seed_full_engagement(tmp_path)
    return _session(store, engagement), engagement, run_id


def _invoke_result(directory: Path) -> dict:
    """``invoke_tool``'s shape: the ToolResult nested under ``output``."""
    return {"tool_id": TOOL, "output": _report_result(directory)}


def _report_result(directory: Path) -> dict:
    """The ``ToolResult`` dict the handler returns on success."""
    directory.mkdir(parents=True, exist_ok=True)
    for name in ("report.md", "report.html", "report.json"):
        (directory / name).write_text(f"<{name}>", encoding="utf-8")
    sha = "a" * 64
    return {
        "success": True,
        "verified": True,
        "verification_method": "report_generated_from_audit",
        "output": {
            "engagement_id": "eng-lab",
            "directory": str(directory),
            "report_path_md": str(directory / "report.md"),
            "report_path_html": str(directory / "report.html"),
            "report_path_json": str(directory / "report.json"),
            "findings_count": 8,
            "severity_breakdown": {
                "critical": 2,
                "high": 1,
                "medium": 0,
                "low": 1,
                "info": 4,
            },
            "failed_attempts": 2,
            "sessions_opened": 1,
            "tools_used": ["nexus.recon.nmap", "nexus.web.nuclei"],
            "report_sha256": sha,
            "markdown_size_bytes": 4096,
            "html_size_bytes": 8192,
            "json_size_bytes": 2048,
        },
        "evidence": {
            "engagement_id": "eng-lab",
            "audit_events_used": 32,
            "audit_chain_valid": True,
            "findings": 8,
            "sessions": 1,
            "report_sha256": sha,
            "artifacts": ["artifact-1", "artifact-2", "artifact-3"],
            "artifact_sha256": {
                "report.md": sha,
                "report.html": "b" * 64,
                "report.json": "c" * 64,
            },
            "files": {},
            "llm_cvss": False,
        },
    }


# ------------------------------------------------------------------ /findings
def test_cmd_findings_with_data(seeded, capsys):
    session, _engagement, _run_id = seeded
    commands_module.cmd_findings(session, [])
    out = capsys.readouterr().out
    assert "Hallazgos del engagement eng-lab:" in out
    assert "SEVERITY" in out and "TITLE" in out and "TOOL" in out
    assert "CRITICAL" in out
    assert "Total: " in out and "findings" in out
    # Failed attempts are documented but never counted as findings.
    assert "Intentos sin hallazgo: 2" in out


def test_cmd_findings_empty(tmp_path, capsys):
    store = support.make_store(tmp_path)
    engagement = support.seed_engagement(store)
    session = _session(store, engagement)
    commands_module.cmd_findings(session, [])
    assert "(sin hallazgos verificados en eng-lab)" in capsys.readouterr().out


def test_cmd_findings_without_engagement(tmp_path, capsys):
    store = support.make_store(tmp_path)
    commands_module.cmd_findings(_session(store, None), [])
    assert "no hay engagement activo" in capsys.readouterr().out


# -------------------------------------------------------------------- /report
def test_cmd_report_basic(seeded, tmp_path, capsys):
    session, _engagement, _run_id = seeded
    directory = tmp_path / "report-out"
    with mock.patch.object(
        OmniSession, "invoke_tool", return_value=_invoke_result(directory)
    ) as invoke:
        commands_module.cmd_report(session, [])
    out = capsys.readouterr().out
    assert "Generating report for engagement lab-engagement..." in out
    assert "8 findings de 32 eventos" in out
    assert "cadena de auditoría: válida" in out
    assert "Report SHA256" in out
    invoke.assert_called_once()
    tool_id, arguments = invoke.call_args.args
    assert tool_id == TOOL
    assert arguments == {"engagement_id": "eng-lab", "format": "both"}
    assert session.last_report_directory == str(directory)
    assert session.last_report_sha256 == "a" * 64


def test_cmd_report_llm_cvss_flag(seeded, tmp_path):
    session, _engagement, _run_id = seeded
    with mock.patch.object(
        OmniSession, "invoke_tool", return_value=_invoke_result(tmp_path / "r")
    ) as invoke:
        commands_module.cmd_report(session, ["--llm-cvss"])
    _tool_id, arguments = invoke.call_args.args
    assert arguments["llm_cvss"] is True


def test_cmd_report_without_engagement(tmp_path, capsys):
    store = support.make_store(tmp_path)
    commands_module.cmd_report(_session(store, None), [])
    assert "no hay engagement activo" in capsys.readouterr().out


def test_cmd_report_export_creates_dir(seeded, tmp_path, capsys):
    session, _engagement, _run_id = seeded
    target = tmp_path / "client-deliverable"
    with mock.patch.object(
        OmniSession, "invoke_tool", return_value=_invoke_result(target)
    ) as invoke:
        commands_module.cmd_report(session, ["export", str(target)])
    out = capsys.readouterr().out
    assert "Exporting lab-engagement report" in out
    assert "Done." in out
    assert (target / "report.sha256").is_file()
    assert (target / "manifest.json").is_file()
    manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["report_sha256"] == "a" * 64
    assert manifest["findings"] == 8
    assert manifest["artifacts"]["report.md"] == "a" * 64
    assert (target / "report.sha256").read_text().startswith("a" * 64)
    _tool_id, arguments = invoke.call_args.args
    assert arguments["output_dir"] == str(target)
    assert session.last_report_directory == str(target)


def test_cmd_report_export_fails_without_dir(seeded, capsys):
    session, _engagement, _run_id = seeded
    commands_module.cmd_report(session, ["export"])
    out = capsys.readouterr().out
    assert "uso: /report export <directorio>" in out
    assert session.last_report_directory is None


def test_cmd_report_unknown_subcommand(seeded, capsys):
    session, _engagement, _run_id = seeded
    commands_module.cmd_report(session, ["frobnicate"])
    assert "subcomando desconocido" in capsys.readouterr().out


# ------------------------------------------------------------------ /timeline
def test_cmd_timeline_renders(seeded, capsys):
    session, _engagement, _run_id = seeded
    commands_module.cmd_timeline(session, [])
    out = capsys.readouterr().out
    assert "recon.nmap" in out
    assert "web.nuclei" in out
    assert "evento(s)." in out


def test_cmd_timeline_respects_run_filter(seeded, capsys):
    session, _engagement, run_id = seeded
    commands_module.cmd_timeline(session, ["no-such-run"])
    assert "(sin eventos de auditoría para este engagement)" in capsys.readouterr().out
    # The real run id does produce entries.
    commands_module.cmd_timeline(session, [run_id])
    assert "recon.nmap" in capsys.readouterr().out


def test_cmd_timeline_without_engagement(tmp_path, capsys):
    store = support.make_store(tmp_path)
    commands_module.cmd_timeline(_session(store, None), [])
    assert "no hay engagement activo" in capsys.readouterr().out


# -------------------------------------------------------------------- prompt
def test_repl_prompt_shows_report_path_after_generation(seeded):
    session, _engagement, _run_id = seeded
    assert "[report" not in session.prompt
    session.last_report_directory = "/tmp/deliverables/lab-20260929-143012"
    assert "[report lab-20260929-143012]" in session.prompt


def test_report_commands_registered():
    for name in ("/findings", "/report", "/timeline"):
        assert name in commands_module.COMMANDS
