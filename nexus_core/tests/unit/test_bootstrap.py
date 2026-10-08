"""Unit tests for the approved-installation bootstrap orchestrator."""

from __future__ import annotations

from nexus_core.provisioner import bootstrap, sliver
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
    monkeypatch.setattr("nexus_core.provisioner.bootstrap.shutil.which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr("nexus_core.provisioner.installer.plan_install", _fake_plan)
    monkeypatch.setattr(
        "nexus_core.provisioner.installer.execute_install",
        lambda plan, **k: InstallResult(plan.tool_name, True, 0, "", "", 0.1, True),
    )
    actions = bootstrap.run_bootstrap(_report(), assume_yes=True, echo=lambda *a: None)
    hydra = next(a for a in actions if a.component_id == "hydra")
    assert hydra.executed is True and hydra.success is True


def _fake_install(ok, path=""):
    return lambda **k: sliver.SliverInstall(ok, "installed" if ok else "minisign_missing", "d", path)


def test_run_bootstrap_prints_sliver_install_plan_without_yes(monkeypatch):
    monkeypatch.setattr("nexus_core.provisioner.installer.plan_install", _fake_plan)
    monkeypatch.setattr("nexus_core.provisioner.bootstrap.shutil.which", lambda n: None)
    actions = bootstrap.run_bootstrap(_report(), assume_yes=False, echo=lambda *a: None)
    install = next(a for a in actions if a.component_id == "sliver-server")
    assert install.kind == "sliver-install" and install.executed is False
    assert "minisign" in install.command


def test_run_bootstrap_installs_sliver_verified_when_absent(monkeypatch):
    monkeypatch.setattr("nexus_core.provisioner.installer.plan_install", _fake_plan)
    monkeypatch.setattr(
        "nexus_core.provisioner.installer.execute_install",
        lambda plan, **k: InstallResult(plan.tool_name, True, 0, "", "", 0.1, True),
    )
    monkeypatch.setattr("nexus_core.provisioner.bootstrap.shutil.which", lambda n: None)
    called = {}

    def _install(**kwargs):
        called.update(kwargs)
        return sliver.SliverInstall(False, sliver.STATUS_NO_MINISIGN, "falta minisign")

    monkeypatch.setattr("nexus_core.provisioner.sliver.install_sliver_verified", _install)
    actions = bootstrap.run_bootstrap(_report(), assume_yes=True, echo=lambda *a: None)
    install = next(a for a in actions if a.component_id == "sliver-server")
    assert install.executed is True and install.success is False
    assert "minisign" in install.detail
    assert called  # verified installer was invoked
    # Without a binary the operator config stays manual.
    operator = next(a for a in actions if a.component_id == "sliver_operator_config")
    assert operator.kind == "manual" and "sliver-server operator" in operator.command


def test_run_bootstrap_generates_operator_config_after_install(monkeypatch):
    monkeypatch.setattr("nexus_core.provisioner.installer.plan_install", _fake_plan)
    monkeypatch.setattr(
        "nexus_core.provisioner.installer.execute_install",
        lambda plan, **k: InstallResult(plan.tool_name, True, 0, "", "", 0.1, True),
    )
    monkeypatch.setattr("nexus_core.provisioner.bootstrap.shutil.which", lambda n: None)
    monkeypatch.setattr(
        "nexus_core.provisioner.sliver.install_sliver_verified",
        _fake_install(True, "/home/operator/.local/bin/sliver-server"),
    )
    monkeypatch.setattr("nexus_core.provisioner.sliver.start_team_server", lambda **k: True)
    monkeypatch.setattr("nexus_core.provisioner.sliver.ensure_operator_config", lambda **k: True)
    actions = bootstrap.run_bootstrap(_report(), assume_yes=True, echo=lambda *a: None)
    operator = next(a for a in actions if a.component_id == "sliver_operator_config")
    assert operator.executed is True and operator.success is True


def test_run_bootstrap_msfrpcd_prints_plan_without_yes(monkeypatch):
    report = assess_environment(
        which=_which_missing_hydra, port_open=lambda *a: False,
        env={"MSF_RPC_PASSWORD": "x", "NEXUS_SCOPE_SIGNING_SECRET": "s"},
        path_exists=lambda p: True,
    )
    monkeypatch.setattr("nexus_core.provisioner.installer.plan_install", _fake_plan)
    monkeypatch.setattr("nexus_core.provisioner.bootstrap.shutil.which", lambda n: None)
    actions = bootstrap.run_bootstrap(report, assume_yes=False, echo=lambda *a: None)
    msf = next(a for a in actions if a.component_id == "msfrpcd")
    assert msf.kind == "service-install" and msf.executed is False
    assert "install_msfrpcd_service.sh" in msf.command


def test_bootstrap_msfrpcd_runs_script_with_temp_password_file(monkeypatch):
    from types import SimpleNamespace

    from pathlib import Path

    seen = {}

    def _run(argv, timeout=None):
        seen["argv"] = argv
        path = Path(argv[argv.index("--password-file") + 1])
        seen["password_file"] = path
        seen["content"] = path.read_text()  # still present during the run
        seen["mode"] = path.stat().st_mode & 0o777
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    component = SimpleNamespace(component_id="msfrpcd", setup="s")
    action = bootstrap._bootstrap_msfrpcd(
        component, assume_yes=True, echo=lambda *a: None, run=_run,
        env={"MSF_RPC_PASSWORD": "s3cr3t"},
    )
    assert action.executed is True and action.success is True
    assert seen["argv"][:2] == ["sudo", "-n"]
    # The secret never reaches argv; it travels in a 0600 temp file.
    assert "s3cr3t" not in " ".join(seen["argv"])
    assert seen["content"].strip() == "MSFRPC_PASSWORD=s3cr3t"
    assert seen["mode"] == 0o600
    assert not seen["password_file"].exists()  # cleaned up afterwards


def test_bootstrap_msfrpcd_without_password_is_manual():
    from types import SimpleNamespace

    component = SimpleNamespace(component_id="msfrpcd", setup="s")
    action = bootstrap._bootstrap_msfrpcd(
        component, assume_yes=True, echo=lambda *a: None,
        run=lambda *a, **k: None, env={},
    )
    assert action.executed is False
    assert "MSF_RPC_PASSWORD" in action.detail
