import pytest
from nexus_core.config.xdg import resolve_xdg_paths

pytestmark = pytest.mark.usefixtures("onboarding_env")


def test_default_paths_without_env(onboarding_env, monkeypatch):
    for name in ("CONFIG", "DATA", "STATE", "CACHE"):
        monkeypatch.delenv("XDG_" + name + "_HOME")
    paths = resolve_xdg_paths()
    assert paths.config_dir == onboarding_env.home / ".config/omni"
    assert paths.db_file == onboarding_env.home / ".local/share/omni/control.db"
    assert paths.state_dir == onboarding_env.home / ".local/state/omni"
    assert paths.cache_dir == onboarding_env.home / ".cache/omni"


@pytest.mark.parametrize("name", ["config", "data", "state", "cache"])
def test_respects_xdg_home(name, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_" + name.upper() + "_HOME", str(tmp_path / "custom"))
    assert getattr(resolve_xdg_paths(), name + "_home") == tmp_path / "custom"


def test_ensure_dirs_creates_with_mode_700(onboarding_env):
    paths = onboarding_env.paths
    paths.ensure_dirs()
    for path in (paths.config_dir, paths.data_dir, paths.state_dir, paths.cache_dir):
        assert path.is_dir() and path.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("value", ["", "relative"])
def test_invalid_xdg_ignored(onboarding_env, monkeypatch, value):
    monkeypatch.setenv("XDG_CONFIG_HOME", value)
    assert resolve_xdg_paths().config_home == onboarding_env.home / ".config"
