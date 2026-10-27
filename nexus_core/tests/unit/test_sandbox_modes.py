"""Explicit sandbox modes and their guarantees (audit finding #3)."""

from __future__ import annotations

import pytest

from nexus_core.kernel import sandbox_modes as modes

pytestmark = pytest.mark.unit


def test_local_mode_guarantees():
    g = modes.GUARANTEES[modes.SandboxMode.LOCAL]
    assert g.filesystem_isolation is False
    assert g.process_isolation is False
    assert g.supports_network_tools is True


def test_local_strict_process_group_is_not_isolation():
    strict = modes.GUARANTEES[modes.SandboxMode.LOCAL_STRICT]
    local = modes.GUARANTEES[modes.SandboxMode.LOCAL]
    assert strict.process_isolation is False
    assert local.process_isolation is False
    assert strict.supports_network_tools is True


def test_oci_mode_no_network():
    g = modes.GUARANTEES[modes.SandboxMode.OCI]
    assert g.network_isolation is True
    assert g.supports_network_tools is False
    assert g.filesystem_isolation and g.user_isolation and g.resource_limits


def test_oci_network_documented_but_filters_network():
    g = modes.GUARANTEES[modes.SandboxMode.OCI_NETWORK]
    assert g.network_isolation is False
    assert g.supports_network_tools is True


def test_guarantees_dict_complete():
    for mode in modes.SandboxMode:
        assert mode in modes.GUARANTEES
        g = modes.GUARANTEES[mode]
        assert set(g.to_dict()) == {
            "filesystem_isolation",
            "network_isolation",
            "process_isolation",
            "resource_limits",
            "user_isolation",
            "persistent_across_calls",
            "supports_network_tools",
        }


def test_oci_network_not_implemented_raises(tmp_path):
    with pytest.raises(NotImplementedError):
        modes.sandbox_for_mode(modes.SandboxMode.OCI_NETWORK, tmp_path)


def test_mode_selected_from_env(monkeypatch):
    monkeypatch.setenv(modes.MODE_ENV, "oci")
    assert modes.active_mode() is modes.SandboxMode.OCI
    monkeypatch.setenv(modes.MODE_ENV, "local")
    assert modes.active_mode() is modes.SandboxMode.LOCAL
    monkeypatch.delenv(modes.MODE_ENV, raising=False)
    monkeypatch.setenv("NEXUS_ENV", "production")
    assert modes.active_mode() is modes.SandboxMode.OCI
    monkeypatch.setenv("NEXUS_ENV", "development")
    assert modes.active_mode() is modes.SandboxMode.LOCAL_STRICT


def test_production_refuses_local_modes(tmp_path):
    """SEC-03: production + local mode is "no isolation" announced as production."""
    for mode in ("local", "local_strict"):
        with pytest.raises(modes.SandboxModeForbidden) as excinfo:
            modes.SandboxPolicy.resolve(
                {"NEXUS_ENV": "production", modes.MODE_ENV: mode},
                workspace_root=tmp_path,
            )
        assert mode in str(excinfo.value)
        assert "NEXUS_ENV=production" in str(excinfo.value)
    # Development keeps both local modes: the guard is about production only.
    for mode in ("local", "local_strict"):
        resolved, _, _ = modes.SandboxPolicy.resolve(
            {"NEXUS_ENV": "development", modes.MODE_ENV: mode},
            workspace_root=tmp_path,
        )
        assert resolved.value == mode


def test_production_still_resolves_oci(tmp_path):
    """The fail-closed guard must not retire the one mode production has."""
    resolved, executor, guarantees = modes.SandboxPolicy.resolve(
        {"NEXUS_ENV": "production", modes.MODE_ENV: "oci"},
        workspace_root=tmp_path,
    )
    assert resolved is modes.SandboxMode.OCI
    assert guarantees["network_isolation"] is True


def test_parse_mode_rejects_unknown():
    assert modes.parse_mode("nope") is None
    assert modes.parse_mode("") is None
    assert modes.parse_mode(None) is None
    assert modes.parse_mode(" OCI ") is modes.SandboxMode.OCI


def test_build_local_sandbox_for_mode(tmp_path):
    sandbox = modes.sandbox_for_mode(modes.SandboxMode.LOCAL_STRICT, tmp_path, ("python3",))
    from nexus_core.kernel.sandbox import LocalSandbox

    assert isinstance(sandbox, LocalSandbox)
