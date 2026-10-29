"""FIX 2.1a: el dedup del journal no puede convertir un fallo en un éxito.

Medido en ``run_3a188d2c2bd440f8bca8d88ad922a024`` (Hijack v3, 2026-10-29): la
iteración 15 ejecutó ``nexus.recon.nfs action=list`` y el handler contestó
``partial`` (``nfs-ls`` no estaba instalado, comprobado contra ``dpkg.log``). El
modelo repitió la misma llamada en las iteraciones 47, 55 y 91; el journal la
reutilizó (``_already_invoked``) y la respuesta llevaba ``success=True`` y
``verified=True`` con ``previous_outcome="succeeded"``, así que el loop la contó
como un éxito de NFS, reseteó su contador de vector y el modelo nunca cambió de
estrategia. El partial (incluidos ``unavailable`` y ``negative``) es una
conclusión determinada, no un éxito: el dedup debe conservarlo tal cual.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.tool_gateway import ToolGateway

TENANT = "system"
TOOL = "nexus.recon.nfs"
TARGET = "10.0.0.5"


def _gateway(tmp_path: Path, result: ToolResult) -> tuple[ToolGateway, RunContext, list[int]]:
    store = ControlStore(tmp_path / "gateway.db")
    store.initialize()
    calls: list[int] = []

    def handler(arguments, context):
        calls.append(1)
        return result

    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store), ApprovalService(store))
    gateway.register(
        ToolDefinition(
            "nfs",
            TENANT,
            {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
            },
            tool_id=TOOL,
            effect="read_only",
            risk=RiskLevel.READ_ONLY,
        ),
        handler,
    )
    identity = Identity("operator-1", TENANT, roles=("operator",))
    context = RunContext(TENANT, identity, run_id="run-1")
    return gateway, context, calls


def _invoke(gateway: ToolGateway, context: RunContext) -> dict:
    return asyncio.run(gateway.invoke(TOOL, {"target": TARGET}, context))


def _partial() -> ToolResult:
    return ToolResult(
        output={
            "target": TARGET,
            "action": "list",
            "partial": True,
            "error": "userland_client_missing",
        },
        verified=False,
        outcome="partial",
        verification_method="nfs_nfs_ls_missing",
        exit_code=1,
    )


def test_a_reused_partial_is_not_answered_as_a_success(tmp_path: Path) -> None:
    gateway, context, calls = _gateway(tmp_path, _partial())

    first = _invoke(gateway, context)
    second = _invoke(gateway, context)

    # The effect really ran once; the second answer is the reuse branch.
    assert len(calls) == 1
    assert second["output"]["deduplicated"] is True
    assert second["evidence"]["previous_invocation_id"] == first["invocation_id"]

    # The truth of the previous answer survives the dedup.
    assert second["success"] is False
    assert second["verified"] is False
    assert second["outcome"] == "partial"
    assert second["evidence"]["previous_outcome"] == "partial"
    assert "con éxito" not in second["output"]["message"]


def test_a_reused_unavailable_is_not_answered_as_a_success(tmp_path: Path) -> None:
    unavailable = ToolResult(
        output={"target": TARGET, "error": "showmount is not available in the sandbox"},
        verified=False,
        outcome="unavailable",
        verification_method="nfs_showmount_unavailable",
    )
    gateway, context, _calls = _gateway(tmp_path, unavailable)

    _invoke(gateway, context)
    second = _invoke(gateway, context)

    assert second["success"] is False
    assert second["verified"] is False
    assert second["outcome"] == "unavailable"
    assert second["evidence"]["previous_outcome"] == "unavailable"


def test_a_reused_success_still_says_it_succeeded(tmp_path: Path) -> None:
    ok = ToolResult(
        output={"target": TARGET, "entries": ["a.txt"]},
        verified=True,
        verification_method="nfs_listing_parsed",
        exit_code=0,
    )
    gateway, context, _calls = _gateway(tmp_path, ok)

    _invoke(gateway, context)
    second = _invoke(gateway, context)

    assert second["success"] is True
    assert second["verified"] is True
    assert second["verification_method"] == "tool_already_invoked"
    assert second["evidence"]["previous_outcome"] == "succeeded"
    assert "con éxito" in second["output"]["message"]


pytestmark = pytest.mark.unit
