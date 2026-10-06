"""``omni report`` and ``omni cve update`` subcommand shims in ``cli.main``."""

from __future__ import annotations

from types import SimpleNamespace

from nexus_core.cli import commands as commands_module
from nexus_core.cli.main import _run_cve_command, _run_report_command
from nexus_core.report import cve_enrichment as cve_module
from nexus_core.tests import report_support as support


def _args(**over) -> SimpleNamespace:
    base = {"tenant": support.TENANT, "no_color": True, "command": ["report"]}
    base.update(over)
    return SimpleNamespace(**base)


# --------------------------------------------------------------------- report
def test_report_command_requires_engagement(tmp_path):
    store = support.make_store(tmp_path)
    code = _run_report_command(
        store, _args(), None, output_format="both", output_dir=None
    )
    assert code == 2


def test_report_command_generates_and_passes_format(tmp_path, monkeypatch):
    store, engagement, _run_id = support.seed_full_engagement(tmp_path)
    seen: dict = {}

    def fake_cmd_report(session, cargs):
        seen["args"] = cargs
        session.last_report_sha256 = "a" * 64

    monkeypatch.setattr(commands_module, "cmd_report", fake_cmd_report)
    code = _run_report_command(
        store, _args(), engagement, output_format="sarif", output_dir=None
    )
    assert code == 0
    assert seen["args"] == ["--format", "sarif"]


def test_report_command_export(tmp_path, monkeypatch):
    store, engagement, _run_id = support.seed_full_engagement(tmp_path)
    seen: dict = {}

    def fake_cmd_report(session, cargs):
        seen["args"] = cargs
        session.last_report_directory = cargs[1]

    monkeypatch.setattr(commands_module, "cmd_report", fake_cmd_report)
    target = str(tmp_path / "out")
    code = _run_report_command(
        store, _args(), engagement, output_format="both", output_dir=target
    )
    assert code == 0
    assert seen["args"] == ["export", target, "--format", "both"]


def test_report_command_failure_exit_code(tmp_path, monkeypatch):
    store, engagement, _run_id = support.seed_full_engagement(tmp_path)
    monkeypatch.setattr(commands_module, "cmd_report", lambda session, cargs: None)
    code = _run_report_command(
        store, _args(), engagement, output_format="both", output_dir=None
    )
    assert code == 2


# ------------------------------------------------------------------------ cve
def test_cve_command_requires_update_verb(tmp_path):
    store = support.make_store(tmp_path)
    args = SimpleNamespace(command=["cve"])
    assert _run_cve_command(args, store, support.TENANT, None) == 2


def test_cve_command_rejects_invalid_id(tmp_path):
    store = support.make_store(tmp_path)
    args = SimpleNamespace(command=["cve", "update", "nope"])
    assert _run_cve_command(args, store, support.TENANT, None) == 2


def test_cve_command_updates_explicit_ids(tmp_path, monkeypatch):
    store = support.make_store(tmp_path)
    captured: dict = {}

    def fake_update(cves, **kwargs):
        captured["cves"] = list(cves)
        return {
            "requested": len(list(cves)), "nvd_updated": 1,
            "epss_updated": 1, "kev_updated": True, "errors": [],
        }

    monkeypatch.setattr(cve_module, "update_cves", fake_update)
    args = SimpleNamespace(command=["cve", "update", "cve-2021-41773"])
    assert _run_cve_command(args, store, support.TENANT, None) == 0
    assert captured["cves"] == ["CVE-2021-41773"]


def test_cve_command_reports_source_errors(tmp_path, monkeypatch):
    store = support.make_store(tmp_path)
    monkeypatch.setattr(
        cve_module,
        "update_cves",
        lambda cves, **kwargs: {
            "requested": 1, "nvd_updated": 0, "epss_updated": 0,
            "kev_updated": False, "errors": ["nvd:CVE-2021-41773:Timeout"],
        },
    )
    args = SimpleNamespace(command=["cve", "update", "CVE-2021-41773"])
    assert _run_cve_command(args, store, support.TENANT, None) == 1


def test_cve_command_without_ids_or_engagement(tmp_path):
    store = support.make_store(tmp_path)
    args = SimpleNamespace(command=["cve", "update"])
    assert _run_cve_command(args, store, support.TENANT, None) == 2


def test_cve_command_collects_from_engagement(tmp_path, monkeypatch):
    store, engagement, _run_id = support.seed_full_engagement(tmp_path)
    captured: dict = {}

    def fake_update(cves, **kwargs):
        captured["cves"] = list(cves)
        return {
            "requested": len(list(cves)), "nvd_updated": 1,
            "epss_updated": 1, "kev_updated": True, "errors": [],
        }

    monkeypatch.setattr(cve_module, "update_cves", fake_update)
    args = SimpleNamespace(command=["cve", "update"])
    assert _run_cve_command(args, store, support.TENANT, engagement) == 0
    assert "CVE-2021-41773" in captured["cves"]
