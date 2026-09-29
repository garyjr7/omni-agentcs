"""Isolated onboarding fixtures: subprocess and PATH lookup always mocked."""

from pathlib import Path
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nexus_core.config.xdg import resolve_xdg_paths


@pytest.fixture
def onboarding_env(tmp_path, monkeypatch):
    original_env = os.environ.copy()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    original_expand = os.path.expanduser
    monkeypatch.setattr(
        os.path,
        "expanduser",
        lambda p: str(home) + p[1:] if p == "~" or p.startswith("~/") else original_expand(p),
    )
    for name in ("CONFIG", "DATA", "STATE", "CACHE"):
        monkeypatch.setenv("XDG_" + name + "_HOME", str(tmp_path / name.lower()))
    for key in (
        "NEXUS_DB_PATH",
        "DATABASE_URL",
        "NEXUS_LLM_DEFAULT_PROVIDER",
        "LLM_PROVIDER",
        "NEXUS_ENV",
        "CI",
        "PYTEST_CURRENT_TEST",
    ):
        monkeypatch.delenv(key, raising=False)
    run = MagicMock(return_value=SimpleNamespace(returncode=0, stdout="tool 1.2.3\n", stderr=""))
    which = MagicMock(return_value=None)
    monkeypatch.setattr("subprocess.run", run)
    monkeypatch.setattr("shutil.which", which)
    try:
        yield SimpleNamespace(paths=resolve_xdg_paths(), home=home, run=run, which=which)
    finally:
        os.environ.clear()
        os.environ.update(original_env)
