"""P2-C closure: durable, tree-scoped token reservations.

The per-run usage ledger records spend *after* the fact; only a reservation made
*before* the provider call can stop a fan-out of children from oversubscribing
the shared root budget. These tests pin the pre-flight guardrail and its
settle/release lifecycle.
"""
from __future__ import annotations

import asyncio

import pytest

from nexus_core.agent.react import STATUS_BUDGET_EXCEEDED, ReActConfig, run_react_loop
from nexus_core.hooks import HookRunner  # noqa: F401 - ensures the hooks package imports
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.budget_ledger import BudgetLedger
from nexus_core.kernel.errors import BudgetExceeded, ProviderFailure
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.tests.unit.test_hooks_lifecycle import context
from nexus_core.tests.unit.test_react_loop import ScriptedLLM, task_complete


def loop_context(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    run = ctx.store.create_run("system", {})
    payload = {"objective": "recon", "identity": {"subject_id": "op", "roles": ["operator"]}}
    task = {"id": "t", "tenant_id": "system", "run_id": run["id"],
            "task_type": "react.run", "payload": payload}
    return ctx.store, ExecutionContext(ctx.store, task, "worker-test")


# --------------------------------------------------------------- C1: the ledger


def test_global_budget_shared_across_tree(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    ledger = BudgetLedger(ctx.store)
    ledger.reserve("system", root_id="root", run_id="child-a", parent_id="p",
                   tokens=40, global_budget=100)
    ledger.reserve("system", root_id="root", run_id="child-b", parent_id="p",
                   tokens=40, global_budget=100)
    assert ledger.committed("system", "root") == 80


def test_child_cannot_exceed_root_budget(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    ledger = BudgetLedger(ctx.store)
    settled = ledger.reserve("system", root_id="root", run_id="child-a", parent_id="p",
                             tokens=50, global_budget=100)
    ledger.settle(settled, 50)
    # 50 already committed leaves room for the sibling's 40, but not for a repeat.
    ledger.reserve("system", root_id="root", run_id="child-b", parent_id="p",
                   tokens=40, global_budget=100)
    with pytest.raises(BudgetExceeded):
        ledger.reserve("system", root_id="root", run_id="child-b", parent_id="p",
                       tokens=20, global_budget=100)


def test_reservation_released_on_error(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    ledger = BudgetLedger(ctx.store)
    reservation = ledger.reserve("system", root_id="root", run_id="r", parent_id="p",
                                 tokens=30, global_budget=100)
    assert ledger.get(reservation, "system")["state"] == "reserved"
    ledger.release(reservation)
    assert ledger.get(reservation, "system")["state"] == "released"
    assert ledger.committed("system", "root") == 0


def test_reservation_settles_with_real_usage(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    ledger = BudgetLedger(ctx.store)
    reservation = ledger.reserve("system", root_id="root", run_id="r", parent_id="p",
                                 tokens=30, global_budget=100)
    ledger.settle(reservation, 7)
    record = ledger.get(reservation, "system")
    assert record["state"] == "settled" and record["tokens_used"] == 7
    assert ledger.committed("system", "root") == 7
    with pytest.raises(PermissionError):
        ledger.release(reservation)


# --------------------------------------------------- C2: the reservation callback


def test_reservation_before_provider_call(tmp_path, monkeypatch):
    store, exec_ctx = loop_context(tmp_path, monkeypatch)
    order = []

    class Ordered(ScriptedLLM):
        async def complete(self, messages, **kwargs):
            order.append("provider")
            return await super().complete(messages, **kwargs)

    def before(tokens):
        order.append("reserve")
        return "handle"

    def after(handle, actual):
        order.append("settle")

    result = asyncio.run(run_react_loop(
        context=exec_ctx, objective="recon", engagement_id=None,
        llm_client=Ordered([task_complete("done")]),
        config=ReActConfig(enforce_completion_gates=False,
                           before_provider_call=before, after_provider_call=after)))
    assert result.status == "completed"
    assert order[0] == "reserve" and "provider" in order
    assert order.index("reserve") < order.index("provider")


def test_before_provider_call_reserves_tokens(tmp_path, monkeypatch):
    store, exec_ctx = loop_context(tmp_path, monkeypatch)
    estimates = []
    asyncio.run(run_react_loop(
        context=exec_ctx, objective="recon", engagement_id=None,
        llm_client=ScriptedLLM([task_complete("done")]),
        config=ReActConfig(enforce_completion_gates=False,
                           before_provider_call=lambda tokens: estimates.append(tokens))))
    assert estimates and all(tokens > 0 for tokens in estimates)


def test_budget_exceeded_before_provider_call(tmp_path, monkeypatch):
    store, exec_ctx = loop_context(tmp_path, monkeypatch)

    def before(tokens):
        raise BudgetExceeded("tree is full")

    llm = ScriptedLLM([task_complete("must not run")])
    result = asyncio.run(run_react_loop(
        context=exec_ctx, objective="recon", engagement_id=None, llm_client=llm,
        config=ReActConfig(enforce_completion_gates=False, before_provider_call=before)))
    assert result.status == STATUS_BUDGET_EXCEEDED
    assert llm.calls == []  # the provider was never contacted


def test_budget_exceeded_aborts_turn_cleanly(tmp_path, monkeypatch):
    store, exec_ctx = loop_context(tmp_path, monkeypatch)

    def before(tokens):
        raise BudgetExceeded("tree is full")

    result = asyncio.run(run_react_loop(
        context=exec_ctx, objective="recon", engagement_id=None,
        llm_client=ScriptedLLM([task_complete("must not run")]),
        config=ReActConfig(enforce_completion_gates=False, before_provider_call=before)))
    assert result.status == STATUS_BUDGET_EXCEEDED
    events = AuditWriter(store).export("system")
    assert any(
        e["action"] == "react.step" and e["payload"].get("action") == "budget_exceeded"
        for e in events
    )


def test_loop_releases_reservation_on_provider_error(tmp_path, monkeypatch):
    store, exec_ctx = loop_context(tmp_path, monkeypatch)
    ledger = BudgetLedger(store)
    reservations = []

    def before(tokens):
        reservation = ledger.reserve(
            "system", root_id="root", run_id=exec_ctx.run_id, parent_id="p",
            tokens=max(1, tokens), global_budget=1_000_000)
        reservations.append(reservation)
        return reservation

    def after(handle, actual):
        if actual > 0:
            ledger.settle(handle, actual)
        else:
            ledger.release(handle)

    class Boom(ScriptedLLM):
        async def complete(self, messages, **kwargs):
            raise RuntimeError("provider down")

    config = ReActConfig(max_iterations=1, enforce_completion_gates=False,
                         before_provider_call=before, after_provider_call=after)
    # A provider failure surfaces as ProviderFailure; the invariant is that the
    # reservation never stays open.
    with pytest.raises(ProviderFailure):
        asyncio.run(run_react_loop(
            context=exec_ctx, objective="recon", engagement_id=None,
            llm_client=Boom([]), config=config))
    assert reservations
    assert all(
        ledger.get(reservation, "system")["state"] in {"released", "settled"}
        for reservation in reservations
    )
    assert ledger.committed("system", "root") == 0
