"""A durable human approval authorizes exactly one tool invocation.

Hermetic: no model, no network. A HIGH-risk tool is approved once and invoked
twice through the real :class:`ToolGateway`.
"""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import (
    Identity,
    RiskLevel,
    RunContext,
    ToolDefinition,
    ToolResult,
)
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.tool_gateway import ToolGateway

pytestmark = pytest.mark.integration

TENANT = "system"


def test_e2e_approval_cannot_be_replayed(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    approvals = ApprovalService(store)
    gateway = ToolGateway(PolicyEngine(), AuditWriter(store), approvals)
    tool = ToolDefinition("deploy", TENANT, {}, risk=RiskLevel.HIGH)
    gateway.register(
        tool,
        lambda arguments, context: ToolResult(
            output={"ok": True}, verified=True, verification_method="test-observation"
        ),
    )
    context = RunContext(TENANT, Identity("operator-1", TENANT, roles=("operator",)))
    action = f"execute:tool:{tool.tool_id}"
    approval = approvals.request(context, action)
    approvals.decide(approval["id"], TENANT, "admin-2", True, "ok")

    first = asyncio.run(gateway.invoke(tool.tool_id, {}, context, approval_id=approval["id"]))
    assert first["verified"] is True

    with pytest.raises(PermissionError, match="already used"):
        asyncio.run(gateway.invoke(tool.tool_id, {}, context, approval_id=approval["id"]))

    assert AuditWriter(store).verify_chain() == (True, None)
