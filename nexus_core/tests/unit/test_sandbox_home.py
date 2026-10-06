"""Unit tests for the ephemeral sandbox HOME (LocalSandbox env + isolation)."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.sandbox import (
    SANDBOX_BASE_ENV,
    SANDBOX_HOME_DIRNAME,
    LocalSandbox,
    OCISandbox,
    sandbox_path,
    tool_bin_dir,
)

SKIP_WITHOUT_PYTHON3 = pytest.mark.skipif(
    shutil.which("python3") is None, reason="python3 is not installed"
)

#: Prints the four HOME/XDG variables the sandbox is expected to set.
_ENV_PROBE = (
    "import json, os; print(json.dumps({k: os.environ.get(k) for k in "
    "['HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME']}))"
)


def _child_env(tmp_path: Path, **run_kwargs) -> dict[str, str]:
    """Run a probe inside the sandbox and return the env the child observed."""
    sandbox = LocalSandbox(tmp_path, allowed_programs=("python3",))
    result = asyncio.run(
        sandbox.run(["python3", "-c", _ENV_PROBE], timeout_seconds=30, **run_kwargs)
    )
    assert result.exit_code == 0, result.stderr
    return json.loads(result.stdout.strip())


def test_local_sandbox_sets_home_to_ephemeral_dir(tmp_path):
    env = _child_env(tmp_path)
    assert env["HOME"] == str(tmp_path / SANDBOX_HOME_DIRNAME)
    assert Path(env["HOME"]).is_dir()


def test_local_sandbox_respects_home_dir_override(tmp_path):
    override = tmp_path / "custom-home"
    env = _child_env(tmp_path, home_dir=override)
    assert env["HOME"] == str(override)
    assert override.is_dir()


def test_local_sandbox_creates_xdg_dirs(tmp_path):
    env = _child_env(tmp_path)
    home = Path(env["HOME"])
    assert env["XDG_CONFIG_HOME"] == str(home / ".config")
    assert env["XDG_CACHE_HOME"] == str(home / ".cache")
    assert env["XDG_DATA_HOME"] == str(home / ".local" / "share")
    for path in (home, Path(env["XDG_CONFIG_HOME"]), Path(env["XDG_CACHE_HOME"])):
        assert path.is_dir()


def test_local_sandbox_env_does_not_leak_real_home(tmp_path, monkeypatch):
    real_home = os.environ.get("HOME") or "/root"
    monkeypatch.setenv("HOME", real_home)
    env = _child_env(tmp_path)
    assert env["HOME"] != real_home
    assert real_home not in env["HOME"]
    assert env["HOME"].startswith(str(tmp_path))


def test_sandbox_env_keeps_the_minimal_base_variables(tmp_path, monkeypatch):
    monkeypatch.delenv("NEXUS_TOOL_BIN_DIR", raising=False)
    env = LocalSandbox(tmp_path)._sandbox_env(None)
    # PATH keeps the minimal base and adds the user tool dir (audit H3).
    assert env["PATH"].endswith(SANDBOX_BASE_ENV["PATH"])
    assert env["NEXUS_SANDBOX"] == "1"
    assert env["TZ"] == "UTC"
    assert "PYTHONPATH" not in env and "LD_PRELOAD" not in env


def test_sandbox_path_prepends_the_user_bin_dir(monkeypatch):
    monkeypatch.setenv("NEXUS_TOOL_BIN_DIR", "/opt/tools/bin")
    assert sandbox_path() == "/opt/tools/bin:" + SANDBOX_BASE_ENV["PATH"]


def test_sandbox_path_is_idempotent_when_already_present(monkeypatch):
    monkeypatch.setenv("NEXUS_TOOL_BIN_DIR", "/usr/bin")
    assert sandbox_path() == SANDBOX_BASE_ENV["PATH"]


def test_sandbox_path_defaults_to_local_bin(monkeypatch):
    monkeypatch.delenv("NEXUS_TOOL_BIN_DIR", raising=False)
    assert tool_bin_dir() == Path.home() / ".local" / "bin"
    assert sandbox_path().startswith(str(Path.home() / ".local" / "bin") + ":")


def test_resolve_workspace_blocks_sandbox_home_traversal(tmp_path):
    sandbox = LocalSandbox(tmp_path)
    with pytest.raises(PermissionError):
        sandbox.resolve_workspace(SANDBOX_HOME_DIRNAME)
    with pytest.raises(PermissionError):
        sandbox.resolve_workspace(f"{SANDBOX_HOME_DIRNAME}/.config")
    # A symlink into the ephemeral HOME is blocked too (it resolves first).
    (tmp_path / "link").symlink_to(tmp_path / SANDBOX_HOME_DIRNAME, target_is_directory=True)
    with pytest.raises(PermissionError):
        sandbox.resolve_workspace("link")


def test_resolve_workspace_still_allows_normal_paths(tmp_path):
    sandbox = LocalSandbox(tmp_path)
    assert sandbox.resolve_workspace(".") == tmp_path.resolve()
    assert sandbox.resolve_workspace("nested/dir") == (tmp_path / "nested" / "dir").resolve()
    with pytest.raises(PermissionError):
        sandbox.resolve_workspace("../outside")


def test_run_refuses_to_use_the_sandbox_home_as_cwd(tmp_path):
    sandbox = LocalSandbox(tmp_path, allowed_programs=("python3",))
    with pytest.raises(PermissionError):
        asyncio.run(
            sandbox.run(
                ["python3", "-c", "pass"],
                cwd=SANDBOX_HOME_DIRNAME,
                timeout_seconds=10,
            )
        )


def test_run_passes_the_ephemeral_env_to_the_child_process(tmp_path):
    """Hermetic check of the env handed to ``create_subprocess_exec``."""
    captured: dict[str, object] = {}

    async def fake_exec(*argv, **kwargs):
        captured.update(kwargs)
        raise RuntimeError("stop before spawning anything")

    sandbox = LocalSandbox(tmp_path, allowed_programs=("python3",))
    with mock.patch("asyncio.create_subprocess_exec", fake_exec):
        with pytest.raises(RuntimeError):
            asyncio.run(sandbox.run(["python3", "-c", "pass"]))

    env = captured["env"]
    assert env["HOME"] == str(tmp_path / SANDBOX_HOME_DIRNAME)
    assert env["XDG_CONFIG_HOME"] == str(tmp_path / SANDBOX_HOME_DIRNAME / ".config")


@SKIP_WITHOUT_PYTHON3
def test_tools_write_config_inside_the_ephemeral_home_not_the_workspace(tmp_path):
    """A tool that resolves its config dir from HOME must not touch the workspace."""
    script = (
        "import os, pathlib;"
        "pathlib.Path(os.path.expanduser('~'), 'tool-config.yaml').write_text('x')"
    )
    sandbox = LocalSandbox(tmp_path, allowed_programs=("python3",))
    result = asyncio.run(sandbox.run(["python3", "-c", script], timeout_seconds=30))
    assert result.exit_code == 0, result.stderr
    assert (tmp_path / SANDBOX_HOME_DIRNAME / "tool-config.yaml").is_file()
    assert not (tmp_path / "tool-config.yaml").exists()


def test_oci_sandbox_mounts_an_ephemeral_home(tmp_path):
    sandbox = OCISandbox(tmp_path, ["python:test"])
    argv = sandbox.build_argv("python:test", ["python", "-V"])
    joined = " ".join(argv)
    assert "/home/sandbox:rw,nosuid,nodev,mode=1777,size=32m" in joined
    assert "--env HOME=/home/sandbox" in joined
    assert "--env XDG_CONFIG_HOME=/home/sandbox/.config" in joined
    assert "--env XDG_CACHE_HOME=/home/sandbox/.cache" in joined
    assert "--env XDG_DATA_HOME=/home/sandbox/.local/share" in joined
    # Isolation must stay exactly as strict as before.
    assert "--network none" in joined
    assert "--read-only" in argv
    assert "--cap-drop ALL" in joined
    assert "--user 65532:65532" in joined
