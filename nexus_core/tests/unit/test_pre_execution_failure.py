"""A tool that refuses its arguments did not have an effect (FIX 4).

Measured in Brute It v6 (2026-10-20, iterations 11-17): ``_resolve_wordlist``
raised before hydra was spawned, the gateway journaled the invocation
``unknown``, and the model's retry of the same step met ``unknown invocation
requires human approval`` -the run closed ``blocked`` (exit 2) over a call that
never touched the target.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from nexus_core.agent.react_types import ReActConfig
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.errors import ToolInputError
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.kernel.models import Identity, RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.tools.handlers.cred_bruteforce import CRED_TOOL_TIMEOUT_SECONDS

pytestmark = pytest.mark.unit

TENANT = "system"


@pytest.fixture()
def store(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    return store


def _context() -> RunContext:
    return RunContext(TENANT, Identity("operator-1", TENANT, roles=("operator",)))


def _gateway(store: ControlStore, handler) -> ToolGateway:
    gateway = ToolGateway(PolicyEngine(), AuditWriter(store))
    tool = ToolDefinition(
        "rejecting", TENANT, {}, tool_id="rejecting", risk=RiskLevel.LOW
    )
    gateway.register(tool, handler)
    return gateway


def _state(store: ControlStore, run_id: str) -> list[str]:
    with store.connect() as conn:
        rows = conn.execute(
            "SELECT state FROM kernel_invocations WHERE run_id=? ORDER BY created_at",
            (run_id,),
        ).fetchall()
    return [row["state"] for row in rows]


def test_a_tool_input_error_settles_as_failed_and_the_retry_needs_no_approval(store):
    attempts = {"count": 0}

    def handler(arguments, context):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise ToolInputError("forbidden path: /etc/shadow")
        return ToolResult(
            output={"ok": True}, verified=True, verification_method="test-observation",
        )

    gateway = _gateway(store, handler)
    context = _context()
    with pytest.raises(ToolInputError):
        asyncio.run(gateway.invoke("rejecting", {}, context))
    assert _state(store, context.run_id) == ["failed"]
    # The same arguments are the same step: the corrected retry must just run.
    result = asyncio.run(gateway.invoke("rejecting", {}, context))
    assert result["output"] == {"ok": True}
    assert _state(store, context.run_id) == ["failed", "succeeded"]


def test_a_plain_value_error_stays_unknown_and_the_retry_asks_a_human(store):
    """Anything raised after the effect may have started keeps the fail-closed reading."""

    def handler(arguments, context):
        raise ValueError("hydra printed something we could not parse")

    gateway = _gateway(store, handler)
    context = _context()
    with pytest.raises(ValueError):
        asyncio.run(gateway.invoke("rejecting", {}, context))
    assert _state(store, context.run_id) == ["unknown"]
    with pytest.raises(PermissionError, match="requires human approval"):
        asyncio.run(gateway.invoke("rejecting", {}, context))


def test_the_loop_ceiling_leaves_room_for_the_tool_to_answer_timeout():
    """The handler must always answer first, or its ``attempts`` is lost.

    ``cred.bruteforce`` publishes 900 s and stops its sweep 15 s earlier; the loop
    ceiling is enforced by cancelling, so it has to be strictly larger than the
    contract plus the handler's reporting grace.
    """
    config = ReActConfig()
    assert config.timeout_per_tool_seconds > CRED_TOOL_TIMEOUT_SECONDS
    assert config.timeout_per_tool_seconds >= 900


def test_the_journal_marks_failed_only_while_running(store):
    journal = InvocationJournal(store)
    context = replace(_context(), invocation_id="inv-1")
    journal.prepare(context, "rejecting", {}, "")
    journal.start(context.invocation_id, TENANT)
    assert journal.fail_before_effect(context.invocation_id, TENANT, reason="x") is True
    # A second reconciliation lost the race: it must not overwrite the verdict.
    assert journal.fail_before_effect(context.invocation_id, TENANT, reason="y") is False
    assert _state(store, context.run_id) == ["failed"]
