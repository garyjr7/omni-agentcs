"""Unit tests for the operational-environment readiness assessment."""

from __future__ import annotations

from nexus_core.provisioner.readiness import (
    BINARY_COMPONENTS,
    assess_environment,
    render_report,
    sliver_operator_plan,
)

ALL_BINARIES = {binary for _, binary, _, _ in BINARY_COMPONENTS}


def _which_all(name):
    return f"/usr/bin/{name}" if name in ALL_BINARIES else None


def _ready_env():
    return {
        "MSF_RPC_PASSWORD": "x",
        "SLIVER_OPERATOR_CONFIG": "/home/operator/.config/omni/sliver/operator.cfg",
        "NEXUS_NUCLEI_TEMPLATES": "/home/operator/nuclei-templates",
        "NEXUS_SCOPE_SIGNING_SECRET": "s3cr3t",
        "NEXUS_WORDLISTS": "/usr/share/wordlists",
    }


def test_all_ready_has_no_missing_required():
    report = assess_environment(
        which=_which_all, port_open=lambda *a: True, env=_ready_env(),
        path_exists=lambda p: True,
    )
    assert report.missing_required == []
    assert "Requeridos: OK" in render_report(report)


def test_missing_required_binaries_are_reported():
    def which(name):
        return None if name in {"nmap", "hydra"} else f"/usr/bin/{name}"

    report = assess_environment(
        which=which, port_open=lambda *a: True, env=_ready_env(),
        path_exists=lambda p: True,
    )
    missing = {c.component_id for c in report.missing_required}
    assert {"nmap", "hydra"} <= missing
    assert "Faltan componentes requeridos" in render_report(report)


def test_msfrpcd_requires_listener_and_credential():
    report = assess_environment(
        which=_which_all, port_open=lambda *a: False, env=_ready_env(),
        path_exists=lambda p: True,
    )
    msf = next(c for c in report.components if c.component_id == "msfrpcd")
    assert msf.ready is False
    assert "install_msfrpcd_service.sh" in msf.setup


def test_sliver_config_ready_only_when_file_exists():
    report = assess_environment(
        which=_which_all, port_open=lambda *a: True,
        env=_ready_env(),
        path_exists=lambda p: p.endswith("operator.cfg"),
    )
    sliver = next(c for c in report.components if c.component_id == "sliver_operator_config")
    assert sliver.ready is True


def test_sliver_config_setup_mentions_operator_command():
    report = assess_environment(
        which=_which_all, port_open=lambda *a: True,
        env={**_ready_env(), "SLIVER_OPERATOR_CONFIG": ""},
        path_exists=lambda p: True,
    )
    sliver = next(c for c in report.components if c.component_id == "sliver_operator_config")
    assert "sliver-server operator" in sliver.setup


def test_scope_signing_secret_is_required():
    env = _ready_env()
    env.pop("NEXUS_SCOPE_SIGNING_SECRET")
    report = assess_environment(
        which=_which_all, port_open=lambda *a: True, env=env, path_exists=lambda p: True,
    )
    assert "scope_signing_secret" in {c.component_id for c in report.missing_required}


def test_report_to_dict_shape():
    report = assess_environment(
        which=_which_all, port_open=lambda *a: True, env=_ready_env(),
        path_exists=lambda p: True,
    )
    data = report.to_dict()
    assert data["ready"] + data["missing"] == len(data["components"])
    assert data["missing_required"] == []


def test_sliver_operator_plan_contains_flags():
    plan = sliver_operator_plan(lhost="10.10.14.2")
    assert plan.startswith("sliver-server operator")
    assert "--lhost 10.10.14.2" in plan
    assert "--save" in plan
