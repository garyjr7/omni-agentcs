"""Cancellation of the durable ReAct loop (audit finding #2, loop side)."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent.react import STATUS_CANCELLED, run_react_loop
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
        engagement_id="eng-cancel",
        tenant_id=TENANT,
        name="cancel",
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


def _tool_call() -> str:
    return json.dumps(
        {
            "thought": "lanzo la tool",
            "action": "tool_call",
            "tool_id": "nexus.recon.nmap",
            "arguments": {"target": "10.0.0.5"},
        }
    )


def _complete() -> str:
    return json.dumps(
        {"thought": "fin", "action": "task_complete", "summary": "hecho", "findings": []}
    )


class _LLM:
    def __init__(self, *responses: str) -> None:
        self._responses = list(responses) or [_complete()]
        self.calls = 0

    async def complete(self, messages, **kwargs):
        index = min(self.calls, len(self._responses) - 1)
        self.calls += 1
        return LLMResponse(
            content=self._responses[index], model="fake", provider=LLMProvider.FAKE
        )


@pytest.fixture()
def harness(tmp_path):
    store = ControlStore(tmp_path / "cancel.db")
    store.initialize()
    EngagementStore(store).create(_scope())
    run = store.create_run(TENANT, {})
    task = {
        "id": f"task-{run['id']}",
        "tenant_id": TENANT,
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {"objective": "objetivo", "engagement_id": "eng-cancel"},
    }
    return store, ExecutionContext(store, task, "worker")


async def test_cancel_event_aborts_loop_before_first_iteration(harness):
    store, context = harness
    event = asyncio.Event()
    event.set()
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-cancel",
            llm_client=_LLM(),
            cancel_event=event,
        )
    assert result.status == STATUS_CANCELLED
    events = [
        item
        for item in store.list_run_events(TENANT, context.run_id)
        if item.get("event_type") == "react.cancelled"
    ]
    assert events and events[-1]["payload"]["phase"] == "between_iterations"


async def test_cancel_between_iterations_stops_cleanly(harness):
    store, context = harness
    event = asyncio.Event()

    async def tool_that_requests_cancel(payload, ctx):
        event.set()
        return {"success": True, "output": {"stdout": "22/tcp open"}}

    with mock.patch.object(
        runtime_module, "execute_tool", mock.AsyncMock(side_effect=tool_that_requests_cancel)
    ):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-cancel",
            llm_client=_LLM(_tool_call(), _complete()),
            cancel_event=event,
        )
    assert result.status == STATUS_CANCELLED
    # The tool actually ran once before the loop noticed the request.
    assert result.iterations == 1
    events = [
        item
        for item in store.list_run_events(TENANT, context.run_id)
        if item.get("event_type") == "react.cancelled"
    ]
    assert events[-1]["payload"]["phase"] == "between_iterations"


async def test_cancel_during_tool_call_propagates(harness):
    store, context = harness
    event = asyncio.Event()
    tool_started = asyncio.Event()
    tool_cancelled = {"value": False}

    async def hanging_tool(payload, ctx):
        tool_started.set()
        try:
            await asyncio.sleep(30)
        finally:
            tool_cancelled["value"] = True
        return {"success": True, "output": {}}

    async def cancel_soon():
        await asyncio.sleep(0.2)
        event.set()

    with mock.patch.object(runtime_module, "execute_tool", hanging_tool):
        canceller = asyncio.ensure_future(cancel_soon())
        try:
            result = await run_react_loop(
                context=context,
                objective="objetivo",
                engagement_id="eng-cancel",
                llm_client=_LLM(_tool_call(), _complete()),
                cancel_event=event,
            )
        finally:
            canceller.cancel()

    assert tool_started.is_set()
    assert result.status == STATUS_CANCELLED
    assert tool_cancelled["value"] is True
    events = [
        item
        for item in store.list_run_events(TENANT, context.run_id)
        if item.get("event_type") == "react.cancelled"
    ]
    assert events[-1]["payload"]["phase"] == "tool"


async def test_context_cancel_event_is_used_when_argument_omitted(harness):
    store, context = harness
    event = asyncio.Event()
    event.set()
    context = ExecutionContext(store, context.task, "worker", cancel_event=event)
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-cancel",
            llm_client=_LLM(),
        )
    assert result.status == STATUS_CANCELLED


# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))
