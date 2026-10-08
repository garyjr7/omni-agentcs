"""P0-1: the advertised mode must select the actual executor."""
import pytest
from nexus_core.kernel import sandbox_modes as modes
from nexus_core.kernel.sandbox import LocalSandbox, OCISandbox, sandbox_for_environment


def test_sandbox_policy_resolve_matches_actual_executor(monkeypatch, tmp_path):
    monkeypatch.setenv('NEXUS_ENV', 'development')
    monkeypatch.setenv('NEXUS_SANDBOX_MODE', 'oci')
    assert isinstance(sandbox_for_environment(tmp_path), OCISandbox)


def test_sandbox_mode_oci_requires_oci_executor(monkeypatch, tmp_path):
    monkeypatch.setattr(modes, '_build_executor', lambda *a, **k: LocalSandbox(tmp_path))
    with pytest.raises(modes.SandboxModeMismatch):
        modes.SandboxPolicy.resolve({'NEXUS_SANDBOX_MODE': 'oci'}, workspace_root=tmp_path)


def test_unknown_sandbox_mode_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setenv('NEXUS_SANDBOX_MODE', 'typo')
    with pytest.raises(ValueError):
        sandbox_for_environment(tmp_path)


def test_sandbox_guarantees_match_executor(tmp_path):
    mode, executor, guarantees = modes.SandboxPolicy.resolve(
        {'NEXUS_SANDBOX_MODE': 'local_strict'}, workspace_root=tmp_path)
    assert isinstance(executor, LocalSandbox)
    assert not guarantees['filesystem_isolation']
    assert not guarantees['process_isolation']
    assert not guarantees['network_isolation']


def test_oci_network_fails_explicitly(tmp_path):
    with pytest.raises(modes.SandboxModeNotImplemented):
        modes.SandboxPolicy.resolve({'NEXUS_SANDBOX_MODE': 'oci_network'}, workspace_root=tmp_path)
