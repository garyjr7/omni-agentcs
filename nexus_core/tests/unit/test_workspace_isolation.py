"""F3: a workspace that already holds the walkthrough cannot certify discovery.

Measured in DeadDrop (2026-10-23): ``docs/missions/diag/deaddrop_campaign_….md``
-held the flag, the NT hash and the recipe, and was written nine hours before
the run- sat inside the tree ``nexus.shell.exec`` greps by design. The check is
operator-facing on purpose: naming the files to the model would be an
invitation.
"""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.cli.doctor import _workspace_isolation
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.workspace_hygiene import scan_spoilers, spoiler_report
from nexus_core.tools.handlers.system import system_status_handler

pytestmark = pytest.mark.unit

FLAG = "flag{fake_flag}"


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    (root / "docs" / "missions" / "diag").mkdir(parents=True)
    (root / "loot").mkdir()
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(root))
    return root


def test_a_campaign_document_is_reported_with_its_relative_path(workspace):
    (workspace / "docs" / "missions" / "diag" / "deaddrop.md").write_text(
        f"# Campaña\n\n206 Crack john → password\n234 {FLAG}\n", encoding="utf-8"
    )
    scan = scan_spoilers()
    assert scan.contaminated is True
    assert scan.files == ("docs/missions/diag/deaddrop.md",)
    assert scan.total == 1


def test_a_flag_shaped_token_is_enough_without_prose(workspace):
    (workspace / "loot" / "captured.txt").write_text(f"{FLAG}\n", encoding="utf-8")
    assert scan_spoilers().files == ("loot/captured.txt",)


def test_a_clean_workspace_reports_nothing(workspace):
    (workspace / "loot" / "scan.xml").write_text("<nmaprun/>", encoding="utf-8")
    (workspace / "docs" / "missions" / "diag" / "notes.md").write_text(
        "3 servicios abiertos en el host\n", encoding="utf-8"
    )
    assert scan_spoilers().contaminated is False
    # No keys at all when clean: a caller never pays for "nothing to see".
    assert spoiler_report() == {}


def test_the_scan_ignores_files_outside_the_named_directories(workspace):
    (workspace / "BACKLOG.md").write_text("flag: the answer\n", encoding="utf-8")
    (workspace / "loot" / "hashes.bin").write_text(FLAG, encoding="utf-8")
    assert scan_spoilers().contaminated is False


def test_system_status_answers_the_isolation_question(workspace, tmp_path):
    (workspace / "docs" / "missions" / "diag" / "deaddrop.md").write_text(
        f"{FLAG}\n", encoding="utf-8"
    )
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    context = RunContext(
        "system",
        Identity("op", "system", roles=("operator",)),
        store=store,
        project_root=str(workspace),
        run_id="run-f3",
    )
    result = asyncio.run(system_status_handler({}, context))
    assert result.output["status"] == "healthy"
    assert result.output["workspace_spoiler_count"] == 1
    assert result.output["workspace_spoilers"] == ["docs/missions/diag/deaddrop.md"]
    assert result.output["workspace"] == str(workspace.resolve())


def test_system_status_stays_lean_on_a_clean_workspace(workspace, tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    context = RunContext(
        "system",
        Identity("op", "system", roles=("operator",)),
        store=store,
        project_root=str(workspace),
        run_id="run-f3",
    )
    result = asyncio.run(system_status_handler({}, context))
    assert "workspace_spoilers" not in result.output


def test_the_doctor_warns_before_the_run(workspace):
    (workspace / "docs" / "missions" / "diag" / "deaddrop.md").write_text(
        f"{FLAG}\n", encoding="utf-8"
    )
    warnings = _workspace_isolation()
    assert len(warnings) == 1
    warning = warnings[0]
    assert warning["service"] == "workspace"
    assert warning["severity"] == "warning"
    assert warning["files"] == ["docs/missions/diag/deaddrop.md"]
    assert "fuera de" in warning["action"]


def test_the_doctor_says_nothing_about_a_clean_workspace(workspace):
    assert _workspace_isolation() == []
