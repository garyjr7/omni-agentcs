"""Per-run token budget for the ReAct loop (``NEXUS_RUN_BUDGET_TOKENS``)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent.react import (
    ReActConfig,
    BUDGET_EVENT_TYPE,
    STATUS_BUDGET_EXCEEDED,
    STATUS_COMPLETED,
    _budget_tokens,
    run_react_loop,
)
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore

pytestmark = pytest.mark.unit

TENANT = "system"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-budget",
        tenant_id=TENANT,
        name="budget",
        client="acme",
        owner_id="owner-1",
        valid_from=_iso(-timedelta(days=1)),
        valid_until=_iso(timedelta(days=1)),
        cidrs=("10.0.0.0/24",),
        domains=(),
        urls=(),
        exclusions=(),
        created_at=_iso(timedelta(0)),
    )


class _LLM:
    def __init__(self, tokens_input: int = 0, tokens_output: int = 0) -> None:
        self.tokens_input = tokens_input
        self.tokens_output = tokens_output

    async def complete(self, messages, **kwargs):
        return LLMResponse(
            content=json.dumps(
                {
                    "thought": "fin",
                    "action": "task_complete",
                    "summary": "hecho",
                    "findings": [],
                }
            ),
            model="fake",
            provider=LLMProvider.FAKE,
            tokens_input=self.tokens_input,
            tokens_output=self.tokens_output,
        )


@pytest.fixture()
def harness(tmp_path):
    store = ControlStore(tmp_path / "budget.db")
    store.initialize()
    EngagementStore(store).create(_scope())
    run = store.create_run(TENANT, {})
    task = {
        "id": f"task-{run['id']}",
        "tenant_id": TENANT,
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {"objective": "objetivo", "engagement_id": "eng-budget"},
    }
    return store, ExecutionContext(store, task, "worker")


# ------------------------------------------------------------- resolution rules


def test_budget_default_unlimited(monkeypatch):
    monkeypatch.delenv("NEXUS_RUN_BUDGET_TOKENS", raising=False)
    assert _budget_tokens({}, None) == 0


def test_budget_reads_environment(monkeypatch):
    monkeypatch.setenv("NEXUS_RUN_BUDGET_TOKENS", "500")
    assert _budget_tokens({}, None) == 500


def test_explicit_budget_overrides_environment(monkeypatch):
    monkeypatch.setenv("NEXUS_RUN_BUDGET_TOKENS", "500")
    assert _budget_tokens({}, 100) == 100


def test_payload_budget_overrides_environment(monkeypatch):
    monkeypatch.setenv("NEXUS_RUN_BUDGET_TOKENS", "500")
    assert _budget_tokens({"budget_tokens": 300}, None) == 300


# ----------------------------------------------------------------- loop behaviour


async def test_run_budget_zero_never_aborts(harness):
    store, context = harness
    store.record_usage(
        TENANT, context.run_id, "model_route", "react", "tokens", 10_000
    )
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        result = await run_react_loop(
                config=_loop_config(),
            context=context,
            objective="objetivo",
            engagement_id="eng-budget",
            llm_client=_LLM(),
            budget_tokens=0,
        )
    assert result.status == STATUS_COMPLETED


async def test_run_aborts_when_budget_already_exceeded(harness):
    store, context = harness
    store.record_usage(TENANT, context.run_id, "model_route", "react", "tokens", 100)
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        result = await run_react_loop(
                config=_loop_config(),
            context=context,
            objective="objetivo",
            engagement_id="eng-budget",
            llm_client=_LLM(),
            budget_tokens=100,
        )
    assert result.status == STATUS_BUDGET_EXCEEDED
    events = [
        event
        for event in store.list_run_events(TENANT, context.run_id)
        if event.get("event_type") == BUDGET_EVENT_TYPE
    ]
    assert events and events[0]["payload"]["used"] >= 100


async def test_run_budget_records_usage(harness):
    store, context = harness
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        await run_react_loop(
                config=_loop_config(),
            context=context,
            objective="objetivo",
            engagement_id="eng-budget",
            llm_client=_LLM(tokens_input=30, tokens_output=12),
            budget_tokens=1000,
        )
    used = store.usage_total(TENANT, context.run_id, "model_route", "react", "tokens")
    assert used == 42


async def test_budget_counts_accumulate_across_iterations(harness):
    store, context = harness
    # Two iterations: first a tool call, then task_complete.
    calls = {"n": 0}

    class _TwoStep:
        async def complete(self, messages, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return LLMResponse(
                    content=json.dumps(
                        {
                            "thought": "tool",
                            "action": "tool_call",
                            "tool_id": "nexus.recon.nmap",
                            "arguments": {"target": "10.0.0.5"},
                        }
                    ),
                    model="fake",
                    provider=LLMProvider.FAKE,
                    tokens_input=20,
                    tokens_output=5,
                )
            return LLMResponse(
                content=json.dumps(
                    {"thought": "fin", "action": "task_complete", "summary": "ok", "findings": []}
                ),
                model="fake",
                provider=LLMProvider.FAKE,
                tokens_input=10,
                tokens_output=5,
            )

    ok = {"success": True, "output": {"stdout": "22/tcp open"}}
    with mock.patch.object(
        runtime_module, "execute_tool", mock.AsyncMock(return_value=ok)
    ):
        result = await run_react_loop(
                config=_loop_config(),
            context=context,
            objective="objetivo",
            engagement_id="eng-budget",
            llm_client=_TwoStep(),
            budget_tokens=1000,
        )
    assert result.status == STATUS_COMPLETED
    used = store.usage_total(TENANT, context.run_id, "model_route", "react", "tokens")
    assert used == 20 + 5 + 10 + 5


async def test_budget_aborts_mid_run_when_exhausted(harness):
    store, context = harness
    # Budget of 25: the first iteration spends 25, so the second aborts.
    calls = {"n": 0}

    class _LoopForever:
        async def complete(self, messages, **kwargs):
            calls["n"] += 1
            return LLMResponse(
                content=json.dumps(
                    {
                        "thought": "tool",
                        "action": "tool_call",
                        "tool_id": "nexus.recon.nmap",
                        "arguments": {"target": "10.0.0.5"},
                    }
                ),
                model="fake",
                provider=LLMProvider.FAKE,
                tokens_input=20,
                tokens_output=5,
            )

    ok = {"success": True, "output": {"stdout": "22/tcp open"}}
    with mock.patch.object(
        runtime_module, "execute_tool", mock.AsyncMock(return_value=ok)
    ):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-budget",
            llm_client=_LoopForever(),
            budget_tokens=25,
            config=_loop_config(max_iterations=10),
        )
    assert result.status == STATUS_BUDGET_EXCEEDED
    assert calls["n"] == 1


def _loop_config(**kwargs):
    """Loop config for tests that exercise mechanics, not the completion gates.

    ``require_plan_completion=False`` disables the B8.2.2/B8.2.3 gate on purpose:
    these tests script a ``task_complete`` (or need the loop to keep proposing
    recon tools) while the blackboard is empty, which production must refuse. The
    gate itself is covered by ``test_react_frame.py``. The host-binary preflight
    (B6) is disabled too so the tool catalog never depends on the CI machine.
    """
    kwargs.setdefault("enforce_completion_gates", False)
    return ReActConfig(**kwargs)


# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))
