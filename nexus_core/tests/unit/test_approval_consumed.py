"""Single-use approvals: :meth:`ApprovalService.consume` and the gateway gate."""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.tool_gateway import ToolGateway

pytestmark = pytest.mark.unit

TENANT = "system"


def _context(store: ControlStore) -> RunContext:
    return RunContext(TENANT, Identity("operator-1", TENANT, roles=("operator",)))


@pytest.fixture()
def store(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    return store


def _approved(store: ControlStore, context: RunContext, action: str) -> str:
    service = ApprovalService(store)
    approval = service.request(context, action)
    service.decide(approval["id"], TENANT, "admin-2", True, "ok")
    return approval["id"]


def test_approval_can_only_be_used_once(store):
    context = _context(store)
    approval_id = _approved(store, context, "execute:tool:test")
    service = ApprovalService(store)
    assert service.consume(approval_id, context, "execute:tool:test") is True
    assert service.consume(approval_id, context, "execute:tool:test") is False
    assert service.verify(approval_id, context, "execute:tool:test") is False


def test_consume_is_atomic_across_connections(store):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    context = _context(store)
    approval_id = _approved(store, context, "execute:tool:test")
    barrier = Barrier(4)

    def consume(_):
        barrier.wait(timeout=5)
        return ApprovalService(store).consume(approval_id, context, "execute:tool:test")

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(consume, range(4)))
    assert results.count(True) == 1


def test_additive_migration_preserves_existing_approvals(tmp_path):
    from nexus_core.kernel.control_store import SCHEMA

    old = ControlStore(tmp_path / "old.db")
    with old.connect() as conn:
        conn.executescript(SCHEMA)
    context = _context(old)
    approval_id = _approved(old, context, "execute:tool:test")
    old.initialize()
    old.initialize()
    assert ApprovalService(old).consume(approval_id, context, "execute:tool:test")


def test_consume_unknown_returns_false(store):
    assert not ApprovalService(store).consume("missing", _context(store), "execute:tool:test")


def test_consume_rejects_wrong_action(store):
    context = _context(store)
    approval_id = _approved(store, context, "execute:tool:test")
    assert ApprovalService(store).consume(approval_id, context, "execute:tool:other") is False


def test_consume_rejects_other_run(store):
    context = _context(store)
    approval_id = _approved(store, context, "execute:tool:test")
    other = RunContext(TENANT, Identity("operator-1", TENANT, roles=("operator",)))
    assert ApprovalService(store).consume(approval_id, other, "execute:tool:test") is False


def test_consume_rejects_pending_approval(store):
    context = _context(store)
    approval = ApprovalService(store).request(context, "execute:tool:test")
    assert ApprovalService(store).consume(approval["id"], context, "execute:tool:test") is False


def test_trust_mode_approval_also_consumed(store):
    """Trust-mode rows are durable approvals and must be single-use too."""
    context = _context(store)
    service = ApprovalService(store)
    approval = service.request(context, "execute:tool:nexus.attack.impacket_psexec")
    service.decide(approval["id"], TENANT, "admin-2", True, "trust_mode")
    assert service.consume(
        approval["id"], context, "execute:tool:nexus.attack.impacket_psexec"
    ) is True
    assert service.consume(
        approval["id"], context, "execute:tool:nexus.attack.impacket_psexec"
    ) is False


def test_consumed_at_column_is_present(store):
    with store.connect() as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(kernel_approvals)")}
    assert "consumed_at" in columns


def test_gateway_rejects_reused_approval(store):
    context = _context(store)
    approvals = ApprovalService(store)
    gateway = ToolGateway(PolicyEngine(), AuditWriter(store), approvals)
    tool = ToolDefinition("deploy", TENANT, {}, risk=RiskLevel.HIGH)
    gateway.register(tool, lambda arguments, context: ToolResult(
        output={"ok": True}, verified=True, verification_method="test-observation",
    ))
    approval_id = _approved(store, context, f"execute:tool:{tool.tool_id}")

    first = asyncio.run(gateway.invoke(tool.tool_id, {}, context, approval_id=approval_id))
    assert first["output"] == {"ok": True}
    with pytest.raises(PermissionError, match="already used"):
        asyncio.run(gateway.invoke(tool.tool_id, {}, context, approval_id=approval_id))
