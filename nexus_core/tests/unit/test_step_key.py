"""P2-D1 closure: a durable step key distinguishes intent, not just arguments.

The key is derived by the gateway from engine-supplied context (tool + canonical
arguments + kill-chain phase + objective prefix). A new intent that happens to
reuse arguments must not be mistaken for a replay, and the model can never
supply the key itself.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace

from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.tests.unit.test_hooks_lifecycle import context
from nexus_core.tests.unit.test_invocation_journal import gateway


def test_step_key_distinguishes_new_intent_from_replay():
    key = InvocationJournal.step_key
    assert key("probe", {"target": "10.0.0.5"}, phase="recon") != key(
        "probe", {"target": "10.0.0.5"}, phase="exploitation")
    assert key("probe", {"target": "10.0.0.5"}, objective="scan 10.0.0.5") != key(
        "probe", {"target": "10.0.0.5"}, objective="dump the database")


def test_same_step_key_reuses_succeeded(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    calls = []

    def handler(arguments, context_):
        calls.append(1)
        return _result(len(calls))

    governed = gateway(ctx, handler)
    first = asyncio.run(governed.invoke("probe", {}, ctx))
    second = asyncio.run(governed.invoke("probe", {}, ctx))
    assert first["invocation_id"] == second["invocation_id"]
    assert len(calls) == 1  # the effect happened exactly once


def test_different_phase_same_args_creates_new_step(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    calls = []

    def handler(arguments, context_):
        calls.append(context_.phase)
        return _result(len(calls))

    governed = gateway(ctx, handler)
    asyncio.run(governed.invoke("probe", {}, replace(ctx, phase="recon")))
    asyncio.run(governed.invoke("probe", {}, replace(ctx, phase="exploitation")))
    assert calls == ["recon", "exploitation"]  # same args, two distinct intents


def test_step_key_generated_by_gateway_not_model(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    journal = InvocationJournal(ctx.store)
    arguments = {"target": "10.0.0.5", "step_key": "forged-by-the-model"}
    expected = journal.step_key("probe", arguments, phase=ctx.phase, objective=ctx.objective)
    assert expected != "forged-by-the-model"

    def handler(arguments, context_):
        return _result(1)

    asyncio.run(gateway(ctx, handler).invoke("probe", arguments, ctx))
    stored = journal.matching(ctx, "probe", arguments, step_key=expected)
    assert stored is not None
    assert stored["step_key"] == expected


def _result(count):
    from nexus_core.kernel.models import ToolResult

    return ToolResult({"effect_count": count}, True, "probe")
