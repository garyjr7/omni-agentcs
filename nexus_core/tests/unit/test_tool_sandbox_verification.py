"""A present tool is not necessarily runnable in the sandbox (finding #3)."""

from __future__ import annotations

import asyncio
import os
from unittest import mock

import pytest

from nexus_core.provisioner import detector as detector_module
from nexus_core.provisioner.detector import (
    SandboxToolState,
    ToolStatus,
    verify_tool_in_sandbox,
)

pytestmark = pytest.mark.unit


def _script(tmp_path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _status(path: str, present: bool = True) -> ToolStatus:
    return ToolStatus("demo", present, path, "1.0", ("apt",),
                      state="detected" if present else "absent", verify_argv=(path,))


def _verify(tmp_path, status, **kwargs):
    with (
        mock.patch.object(detector_module, "check_tool", return_value=status),
        mock.patch("nexus_core.provisioner.recipes.find_tool_recipe", return_value={
            "verify": [status.path], "recipes": {},
        }),
    ):
        return asyncio.run(
            verify_tool_in_sandbox("demo", workspace_root=tmp_path, **kwargs)
        )


def test_verify_tool_runnable_in_sandbox(tmp_path):
    script = _script(tmp_path, "ok.sh", "#!/bin/sh\necho demo-1.0\nexit 0\n")
    result = _verify(tmp_path, _status(script))
    assert result.state == SandboxToolState.RUNNABLE.value
    assert result.exit_code == 0
    assert result.runnable is True
    assert result.output == "verified"


def test_verify_tool_fails_when_deps_missing(tmp_path):
    script = _script(tmp_path, "broken.sh", "#!/bin/sh\necho missing lib >&2\nexit 2\n")
    result = _verify(tmp_path, _status(script))
    assert result.state == SandboxToolState.FAILED.value
    assert result.exit_code == 2
    assert result.output == "probe failed"


def test_verify_tool_absent(tmp_path):
    result = _verify(tmp_path, _status("/nowhere/demo", present=False))
    assert result.state == SandboxToolState.ABSENT.value
    assert result.exit_code is None


def test_verify_tool_present_but_unexecutable_is_failed(tmp_path):
    result = _verify(tmp_path, _status(str(tmp_path / "does-not-exist")))
    assert result.state == SandboxToolState.FAILED.value


def test_verify_tool_reports_sandbox_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_SANDBOX_MODE", "local_strict")
    script = _script(tmp_path, "ok.sh", "#!/bin/sh\nexit 0\n")
    result = _verify(tmp_path, _status(script))
    assert result.sandbox_mode == "local_strict"


def test_check_env_reports_both_states(tmp_path):
    """``check_env`` exposes DETECTED by default and RUNNABLE when asked."""
    import asyncio as _asyncio
    from dataclasses import asdict

    from nexus_core.tools.handlers import system_env as module
    from nexus_core.tests.msf_support import context

    status = ToolStatus("nmap", True, "/bin/nmap", "7.94", ("apt",))
    verification = mock.Mock(state="runnable", exit_code=0, sandbox_mode="local_strict")
    with (
        mock.patch.object(module, "check_tool", return_value=status),
        mock.patch.object(module, "verify_tool_in_sandbox", return_value=verification),
    ):
        default = _asyncio.run(module.check_env_handler({"tools": ["nmap"]}, context()))
        verified = _asyncio.run(
            module.check_env_handler({"tools": ["nmap"], "verify_sandbox": True}, context())
        )
    assert default.output["tools"]["nmap"]["sandbox_state"] == "detected"
    assert verified.output["tools"]["nmap"]["sandbox_state"] == "runnable"
    assert asdict(status)["present"] is True
    assert os.path.sep in "/bin/nmap"
