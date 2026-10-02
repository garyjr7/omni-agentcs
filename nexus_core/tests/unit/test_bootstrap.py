"""Unit tests for the approved-installation bootstrap orchestrator."""

from __future__ import annotations

from nexus_core.provisioner import bootstrap
from nexus_core.provisioner.installer import InstallPlan, InstallResult
from nexus_core.provisioner.readiness import assess_environment

ALL_BINARIES = {
    "nmap", "hydra", "gobuster", "whatweb", "ffuf", "nuclei", "httpx",
    "subfinder", "searchsploit", "msfconsole", "nxc", "bloodhound-python",
    "impacket-smbclient", "dalfox", "sliver-server",
}


def _which_missing_hydra(name):
    return None if name == "hydra" else f"/usr/bin/{name}"


def _report():
    return assess_environment(
        which=_which_missing_hydra,
        port_open=lambda *a: True,
        env={"MSF_RPC_PASSWORD": "x", "NEXUS_SCOPE_SIGNING_SECRET": "s"},
        path_exists=lambda p: True,
    )


def _fake_plan(tool, manager=None):
    if tool == "sliver-server":
        raise ValueError("no supported package manager")
    return InstallPlan(tool, "apt", ("apt", "install", "-y", tool), True, (tool,), None, "")


def test_plan_only_includes_missing_binaries_with_recipe(monkeypatch):
    monkeypatch.setattr(
        "nexus_core.provisioner.installer.plan_install", _fake_plan
    )
    plans = bootstrap.plan_binary_installs(_report())
    assert [tool for tool, _ in plans] == ["hydra"]


def test_run_bootstrap_without_yes_only_prints(monkeypatch):
    monkeypatch.setattr("nexus_core.provisioner.installer.plan_install", _fake_plan)
    called = {"exec": False}

    def _exec(*a, **k):  # pragma: no cover - must not run
        called["exec"] = True
        return InstallResult("hydra", True, 0, "", "", 0, True)

    monkeypatch.setattr("nexus_core.provisioner.installer.execute_install", _exec)
    actions = bootstrap.run_bootstrap(_report(), assume_yes=False, echo=lambda *a: None)
    assert called["exec"] is False
    assert any(a.component_id == "hydra" and not a.executed for a in actions)


def test_run_bootstrap_with_yes_executes(monkeypatch):
    monkeypatch.setattr("nexus_core.provisioner.installer.plan_install", _fake_plan)
    monkeypatch.setattr(
        "nexus_core.provisioner.installer.execute_install",
        lambda plan, **k: InstallResult(plan.tool_name, True, 0, "", "", 0.1, True),
    )
    actions = bootstrap.run_bootstrap(_report(), assume_yes=True, echo=lambda *a: None)
    hydra = next(a for a in actions if a.component_id == "hydra")
    assert hydra.executed is True and hydra.success is True


def test_run_bootstrap_reports_sliver_as_manual_when_absent(monkeypatch):
    monkeypatch.setattr("nexus_core.provisioner.installer.plan_install", _fake_plan)
    monkeypatch.setattr("nexus_core.provisioner.bootstrap.shutil.which", lambda n: None)
    actions = bootstrap.run_bootstrap(_report(), assume_yes=True, echo=lambda *a: None)
    sliver = next(a for a in actions if a.component_id == "sliver_operator_config")
    assert sliver.kind == "manual"
    assert "sliver-server operator" in sliver.command
