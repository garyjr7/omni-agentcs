"""FIX 2.2: ``nexus.system.install_tool`` explica *por qué* no instaló.

Medido en el sprint de Hijack: el run recibió ``{"success": false,
"path_updated": false, "post_install_notes": "", "tool_name": "nfs-common"}`` y
no supo si faltaba sudo, si el paquete no existía o si el gestor había fallado.
El handler solo devolvía el booleano; estos tests fijan un enum de razones con su
hint accionable.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.provisioner.installer import InstallPlan, InstallResult
from nexus_core.tools.handlers import system_install as module

PLAN = InstallPlan(
    tool_name="nfs-common",
    manager="apt",
    command=("sudo", "-n", "apt-get", "install", "-y", "nfs-common"),
    requires_sudo=True,
    verify_command=("showmount", "--version"),
    installs_to=None,
    post_install_notes="",
)


def _context(plan: InstallPlan = PLAN) -> RunContext:
    return RunContext(
        "system",
        Identity("operator-1", "system", roles=("operator",)),
        approved_install_plan=plan,
    )


def _run(result: InstallResult, *, binary: str | None = None):
    with patch.object(module, "execute_install", return_value=result), patch.object(
        module, "update_shell_path", return_value=False
    ), patch.object(module.shutil, "which", return_value=binary):
        return asyncio.run(
            module.install_tool_handler({"tool_name": PLAN.tool_name}, _context())
        )


def _failed(stderr: str, exit_code: int = 1) -> InstallResult:
    return InstallResult(PLAN.tool_name, False, exit_code, "", stderr, 0.1, False)


def test_sudo_missing_returns_sudo_required_reason():
    result = _run(_failed("sudo: a password is required"))

    assert result.success is False
    assert result.output["reason"] == "sudo_required"
    assert "passwordless" in result.output["hint"] or "sudo -n" in result.output["hint"]


def test_already_present_returns_reason_and_does_not_install():
    ok = InstallResult(PLAN.tool_name, True, 0, "", "", 0.1, True)
    with patch.object(module, "execute_install") as install, patch.object(
        module.shutil, "which", return_value="/usr/bin/showmount"
    ):
        result = asyncio.run(
            module.install_tool_handler({"tool_name": PLAN.tool_name}, _context())
        )

    install.assert_not_called()
    assert result.success is True
    assert result.output["reason"] == "already_installed"
    assert "PATH" in result.output["hint"]
    assert ok.success


def test_unknown_package_returns_reason():
    result = _run(_failed("E: Unable to locate package nfs-common", exit_code=100))

    assert result.output["reason"] == "package_not_found"
    assert "check_env" in result.output["hint"]


def test_post_install_path_missing_returns_reason():
    result = _run(InstallResult(PLAN.tool_name, False, 0, "", "", 0.1, False))

    assert result.output["reason"] == "post_install_path_missing"
    assert "PATH" in result.output["hint"]


def test_success_returns_reason_none():
    result = _run(InstallResult(PLAN.tool_name, True, 0, "installed", "", 0.1, True))

    assert result.success is True
    assert result.output["reason"] is None
    assert "hint" not in result.output


pytestmark = pytest.mark.unit
