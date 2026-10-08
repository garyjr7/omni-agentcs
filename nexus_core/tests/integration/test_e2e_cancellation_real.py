"""E2E: cancelling a long sandbox run leaves no orphan process behind (#2).

Deterministic and offline: a dummy tool runs ``sleep 300`` in the sandbox,
gets cancelled, and the whole process group must be gone.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.sandbox import LocalSandbox

pytestmark = pytest.mark.integration


def _sleep300_pids() -> list[int]:
    pids: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            parts = (entry / "cmdline").read_bytes().split(b"\x00")
        except OSError:
            continue
        args = [part.decode("utf-8", "replace") for part in parts if part]
        if args[:2] == ["sleep", "300"]:
            pids.append(int(entry.name))
    return pids


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def test_cancellation_kills_sleep_and_leaves_no_orphans():
    async def scenario():
        sandbox = LocalSandbox("/tmp", allowed_programs=("sleep",))
        event = asyncio.Event()
        canceller = asyncio.ensure_future(_cancel_soon(event, 2.0))
        try:
            return await sandbox.run(
                ["sleep", "300"],
                timeout_seconds=600,
                cancel_event=event,
                grace_seconds=2.0,
            )
        finally:
            canceller.cancel()

    result = asyncio.run(scenario())
    assert result.cancelled is True
    assert result.timed_out is False
    assert result.orphans_detected == 0
    time.sleep(1.0)
    assert _sleep300_pids() == []


def test_loop_cancellation_kills_the_tool_sandbox(tmp_path):
    """The ReAct loop cancels an in-flight tool; its sandbox tree dies too."""
    from nexus_core.agent.react import STATUS_CANCELLED, run_react_loop
    from nexus_core.kernel import runtime as runtime_module
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.kernel.runtime import ExecutionContext
    from nexus_core.llm.abstraction import LLMProvider, LLMResponse
    from nexus_core.scope import EngagementScope, EngagementStore

    store = ControlStore(tmp_path / "e2e.db")
    store.initialize()
    store_scope = EngagementStore(store).create(
        EngagementScope(
            engagement_id="eng-cancel",
            tenant_id="system",
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
    )
    assert store_scope is not None
    run = store.create_run("system", {})
    context = ExecutionContext(
        store,
        {
            "id": f"task-{run['id']}",
            "tenant_id": "system",
            "run_id": run["id"],
            "task_type": "react.run",
            "payload": {"objective": "dummy", "engagement_id": "eng-cancel"},
        },
        "worker",
    )
    event = asyncio.Event()

    class _LLM:
        async def complete(self, messages, **kwargs):
            return LLMResponse(
                content=json.dumps(
                    {
                        "thought": "lanzo el dummy",
                        "action": "tool_call",
                        "tool_id": "nexus.recon.nmap",
                        "arguments": {"target": "10.0.0.5"},
                    }
                ),
                model="fake",
                provider=LLMProvider.FAKE,
            )

    async def dummy_tool(payload, ctx):
        sandbox = LocalSandbox("/tmp", allowed_programs=("sleep",))
        outcome = await sandbox.run(
            ["sleep", "300"], timeout_seconds=600, cancel_event=event, grace_seconds=2.0
        )
        return {"success": True, "output": {"cancelled": outcome.cancelled}}

    async def scenario():
        canceller = asyncio.ensure_future(_cancel_soon(event, 1.5))
        try:
            with mock.patch.object(runtime_module, "execute_tool", dummy_tool):
                return await run_react_loop(
                    context=context,
                    objective="dummy",
                    engagement_id="eng-cancel",
                    llm_client=_LLM(),
                    cancel_event=event,
                )
        finally:
            canceller.cancel()

    result = asyncio.run(scenario())
    assert result.status == STATUS_CANCELLED
    time.sleep(0.5)
    assert _sleep300_pids() == []


async def _cancel_soon(event: asyncio.Event, delay: float) -> None:
    await asyncio.sleep(delay)
    event.set()


# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))
