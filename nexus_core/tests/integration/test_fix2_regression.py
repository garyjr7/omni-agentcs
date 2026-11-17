"""FIX 2.5: regresión sobre el NDJSON real de Hijack v3 (anonimizado).

El fixture es un *slice* del run ``run_3a188d2c…`` (598 eventos, desde
``sequence`` 4561). No guarda las salidas de las tools, así que no se puede
"reproducir" el run evento a evento: lo que sí se puede es tomar de él la
invocación exacta que falló y el veredicto que el motor registró, y comprobar que
el contrato nuevo ya no produce ese veredicto.

Medido en el fixture:

* ``nexus.recon.nfs`` ``action=list`` contestó ``partial`` (``nfs-ls`` no estaba
  instalado) y el journal la sirvió tres veces más como ``success=True``.
* La prueba de credenciales contra ssh duró 1 785 174 ms y terminó ``unavailable``.
* No hay ninguna llamada a ``nexus.system.install_tool``: el ``sequence`` 9304 que
  citaba el sprint pertenece a otro run.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.provisioner.installer import InstallPlan, InstallResult
from nexus_core.tools.handlers import cred_bruteforce as cred_module
from nexus_core.tools.handlers import system_install as install_module
from nexus_core.tools.handlers.cred_bruteforce import cred_bruteforce_handler
from nexus_core.tools.handlers.system_install import install_tool_handler

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "react" / "hijack_v3.ndjson"
TARGET = "192.0.2.10"
INSTALL_REASONS = {
    "already_installed",
    "sudo_required",
    "package_not_found",
    "post_install_path_missing",
    "network_error",
    "install_failed",
}


def _rows() -> list[dict]:
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _recorded_nfs_list_arguments() -> dict:
    rows = _rows()
    arguments = {
        row["payload"]["invocation_id"]: row["payload"]["arguments"]
        for row in rows
        if row.get("type") == "tool.invoke" and row["payload"]["arguments"].get("action") == "list"
    }
    for row in rows:
        payload = row.get("payload", {})
        if (
            row.get("type") == "tool.complete"
            and payload.get("outcome") == "partial"
            and payload.get("invocation_id") in arguments
        ):
            return arguments[payload["invocation_id"]]
    raise AssertionError("el fixture no conserva la invocación NFS action=list parcial")


def test_the_fixture_is_anonymized() -> None:
    text = FIXTURE.read_text(encoding="utf-8")
    for needle in ("10.0.0.5", "run_3a188d2c", "eng-6174", "conversation_1ecf"):
        assert needle not in text


def test_nfs_partial_does_not_lie_about_success(tmp_path: Path) -> None:
    """La invocación real, repetida, sigue siendo ``partial`` (no ``success``)."""
    arguments = _recorded_nfs_list_arguments()
    assert arguments == {"action": "list", "path": "/mnt/share", "target": TARGET}

    store = ControlStore(tmp_path / "gateway.db")
    store.initialize()
    calls: list[dict] = []

    def handler(received, context):
        calls.append(received)
        return ToolResult(
            output={
                "target": TARGET,
                "action": "list",
                "path": "/mnt/share",
                "partial": True,
                "error": "userland_client_missing",
                "hint": "Instala libnfs-utils con nexus.system.install_tool.",
            },
            verified=False,
            outcome="partial",
            verification_method="nfs_nfs_ls_missing",
            exit_code=1,
        )

    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store), ApprovalService(store))
    gateway.register(
        ToolDefinition(
            "nfs",
            "system",
            {"type": "object", "properties": {"target": {"type": "string"}}},
            tool_id="nexus.recon.nfs",
            effect="read_only",
            risk=RiskLevel.READ_ONLY,
        ),
        handler,
    )
    context = RunContext("system", Identity("operator-1", "system", roles=("operator",)))

    first = asyncio.run(gateway.invoke("nexus.recon.nfs", arguments, context))
    second = asyncio.run(gateway.invoke("nexus.recon.nfs", arguments, context))

    assert len(calls) == 1
    assert first["outcome"] == "partial"
    assert second["output"]["deduplicated"] is True
    assert second["success"] is False
    assert second["verified"] is False
    assert second["outcome"] == "partial"
    assert second["output"]["error"] == "userland_client_missing"


def test_the_measured_sweep_is_now_a_timeout(tmp_path: Path, monkeypatch) -> None:
    """1 785 174 ms y ``unavailable`` en el fixture; ahora ``timeout``."""
    measured = [
        row["payload"]
        for row in _rows()
        if row.get("type") == "tool.complete"
        and row["payload"].get("duration_ms", 0) > 1_700_000
    ]
    assert measured, "el fixture debe conservar el barrido de ~30 min"
    assert measured[0]["outcome"] == "unavailable"

    (tmp_path / "locks.txt").write_text("pw0\npw1\n", encoding="utf-8")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    result = SandboxResult(127, "", "hydra: not found", timed_out=True)
    with mock.patch.object(
        cred_module, "sandbox_for_environment", lambda *args, **kwargs: _Sandbox(result)
    ):
        output = asyncio.run(
            cred_bruteforce_handler(
                {
                    "target": TARGET,
                    "service": "ssh",
                    "username": "admin",
                    "password_file": "locks.txt",
                },
                RunContext("system", Identity("operator-1", "system", roles=("operator",))),
            )
        )

    assert output.outcome == "timeout"
    assert output.verification_method == "cred_bruteforce_timeout"


class _Sandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30, **kwargs):
        self.calls.append((list(argv), timeout_seconds))
        return self.result


def test_install_tool_failure_has_reason() -> None:
    """El fallo sin razón que registró el sprint ya no existe."""
    plan = InstallPlan(
        tool_name="nfs-common",
        manager="apt",
        command=("sudo", "-n", "apt-get", "install", "-y", "nfs-common"),
        requires_sudo=True,
        verify_command=("showmount", "--version"),
        installs_to=None,
        post_install_notes="",
    )
    failed = InstallResult(
        "nfs-common", False, 100, "", "E: Unable to locate package nfs-common", 0.1, False
    )
    context = RunContext(
        "system",
        Identity("operator-1", "system", roles=("operator",)),
        approved_install_plan=plan,
    )
    patched = (
        mock.patch.object(install_module, "execute_install", return_value=failed),
        mock.patch.object(install_module, "update_shell_path", return_value=False),
        mock.patch.object(install_module.shutil, "which", return_value=None),
    )
    with patched[0], patched[1], patched[2]:
        result = asyncio.run(install_tool_handler({"tool_name": "nfs-common"}, context))

    assert result.output["reason"] in INSTALL_REASONS
    assert result.output["reason"] == "package_not_found"
    assert result.output["hint"]


pytestmark = pytest.mark.integration
