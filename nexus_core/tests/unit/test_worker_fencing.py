"""A lost lease is an ordinary worker outcome, never authority to retry work."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

import nexus_worker
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.errors import LeaseLost
from nexus_core.kernel.runtime import ExecutionContext, ExecutorRegistry


@pytest.mark.parametrize("renewal_error", [False, OSError("database unavailable")])
def test_heartbeat_cancels_even_without_cooperative_polling(renewal_error: bool | Exception) -> None:
    async def scenario() -> None:
        store = Mock(spec=ControlStore)
        if isinstance(renewal_error, Exception):
            store.renew_task_lease.side_effect = renewal_error
        else:
            store.renew_task_lease.return_value = False
        registry = ExecutorRegistry()
        task = {"id": "task", "lease_generation": 7, "task_type": "noop", "payload": {},
                "tenant_id": "system", "run_id": "run"}
        context = ExecutionContext(store, task, "worker", asyncio.Event())
        cleaned = asyncio.Event()

        async def executor(payload: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
            try:
                await asyncio.Event().wait()  # deliberately does not poll ctx.cancel_event
                return {}
            finally:
                cleaned.set()

        registry.register("noop", executor)
        with pytest.raises(LeaseLost):
            await nexus_worker._execute_with_heartbeat(
                store, task, "worker", registry, context, 2, renew_interval=0.01,
            )
        assert cleaned.is_set()
        assert context.cancel_event.is_set()
        store.renew_task_lease.assert_called_with(
            "task", "worker", lease_generation=7, lease_seconds=nexus_worker.LEASE_SECONDS,
        )

    asyncio.run(scenario())


@pytest.mark.parametrize("executor_fails", [False, True])
def test_worker_survives_takeover_before_completion_or_failure(
    tmp_path: Path, executor_fails: bool,
) -> None:
    store = ControlStore(tmp_path / "worker.db")
    store.initialize()
    run = store.create_run("system", {})
    store.enqueue_task(tenant_id="system", run_id=run["id"], task_type="noop", payload={})
    old = store.claim_task("worker")
    assert old is not None
    replacements: list[dict[str, Any]] = []
    registry = ExecutorRegistry()

    async def replaced_executor(payload: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
        with store.connect() as conn:
            conn.execute("UPDATE kernel_tasks SET lease_until=? WHERE id=?",
                         ("2000-01-01T00:00:00+00:00", old["id"]))
        new = store.claim_task("worker")
        assert new is not None
        replacements.append(new)
        if executor_fails:
            raise RuntimeError("old execution failed after takeover")
        return {"stale": True}

    registry.register("noop", replaced_executor)
    assert nexus_worker._process_task(store, old, "worker", registry) is False
    assert [t["to_status"] for t in store.list_task_transitions(old["id"])] == [
        "queued", "running", "running",
    ]
    assert not any(e["event_type"] == "task.failed" for e in store.list_run_events("system", run["id"]))
    # The next loop iteration can complete using the new claim.
    current_registry = ExecutorRegistry()

    async def current_executor(payload: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
        return {"current": True}

    current_registry.register("noop", current_executor)
    assert nexus_worker._process_task(store, replacements[0], "worker", current_registry) is True
    current_run = store.get_run(run["id"], "system")
    assert current_run is not None and current_run["result"] == {"current": True}
