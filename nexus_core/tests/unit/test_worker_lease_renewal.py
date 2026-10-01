"""Renewable worker lease keeps long tasks from being double-claimed (#9)."""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.kernel.control_store import ControlStore
import nexus_worker

pytestmark = pytest.mark.unit

TENANT = "system"


@pytest.fixture()
def store(tmp_path) -> ControlStore:
    value = ControlStore(tmp_path / "lease.db")
    value.initialize()
    return value


def _enqueue(store: ControlStore, *, timeout_seconds: int = 300) -> dict:
    run = store.create_run(TENANT, {})
    return store.enqueue_task(
        tenant_id=TENANT,
        run_id=run["id"],
        task_type="noop",
        payload={},
        timeout_seconds=timeout_seconds,
    )


def test_renew_task_lease_extends_until(store):
    task = _enqueue(store)
    claimed = store.claim_task("worker-1", lease_seconds=1)
    original = claimed["lease_until"]
    time.sleep(0.05)
    assert store.renew_task_lease(claimed["id"], "worker-1", lease_seconds=120) is True
    with store.connect() as conn:
        row = conn.execute(
            "SELECT lease_until, lease_owner FROM kernel_tasks WHERE id=?", (task["id"],)
        ).fetchone()
    assert row["lease_until"] > original
    assert row["lease_owner"] == "worker-1"


def test_renew_task_lease_fails_for_other_worker(store):
    _enqueue(store)
    claimed = store.claim_task("worker-1", lease_seconds=60)
    assert store.renew_task_lease(claimed["id"], "worker-2", lease_seconds=60) is False


def test_renew_task_lease_fails_for_completed_task(store):
    _enqueue(store)
    claimed = store.claim_task("worker-1", lease_seconds=60)
    store.complete_task(claimed["id"], "worker-1", result={"ok": True})
    assert store.renew_task_lease(claimed["id"], "worker-1", lease_seconds=60) is False


def test_second_worker_cannot_claim_renewed_task(store):
    _enqueue(store)
    claimed = store.claim_task("worker-1", lease_seconds=1)
    # Keep renewing well past the original expiry.
    for _ in range(5):
        assert store.renew_task_lease(claimed["id"], "worker-1", lease_seconds=5)
        time.sleep(0.05)
    assert store.claim_task("worker-2", lease_seconds=60) is None


def test_second_worker_can_claim_after_lease_expires(store):
    _enqueue(store)
    claimed = store.claim_task("worker-1", lease_seconds=1)
    time.sleep(1.2)
    reclaimed = store.claim_task("worker-2", lease_seconds=60)
    assert reclaimed is not None
    assert reclaimed["id"] == claimed["id"]
    assert reclaimed["lease_owner"] == "worker-2"


class _Registry:
    def __init__(self, delay: float = 0.0, on_run=None) -> None:
        self.delay = delay
        self.on_run = on_run

    async def execute(self, task, context):
        if self.on_run is not None:
            return await self.on_run(context)
        if self.delay:
            await asyncio.sleep(self.delay)
        return {"ok": True}


def _context(cancel_event):
    return SimpleNamespace(cancel_event=cancel_event)


def test_heartbeat_renews_on_interval():
    async def scenario():
        renew = mock.MagicMock(return_value=True)
        fake_store = SimpleNamespace(renew_task_lease=renew)
        result = await nexus_worker._execute_with_heartbeat(
            fake_store,
            {"id": "task-1"},
            "worker-1",
            _Registry(delay=0.2),
            _context(asyncio.Event()),
            timeout_seconds=5,
            renew_interval=0.05,
            lease_seconds=120,
        )
        return result, renew

    result, renew = asyncio.run(scenario())
    assert result == {"ok": True}
    assert renew.call_count >= 2


def test_heartbeat_stops_on_completion():
    async def scenario():
        renew = mock.MagicMock(return_value=True)
        fake_store = SimpleNamespace(renew_task_lease=renew)
        await nexus_worker._execute_with_heartbeat(
            fake_store,
            {"id": "task-1"},
            "worker-1",
            _Registry(delay=0.0),
            _context(asyncio.Event()),
            timeout_seconds=5,
            renew_interval=30.0,
        )
        # Let any spawned renewal settle; none should be pending afterwards.
        await asyncio.sleep(0)
        return renew

    renew = asyncio.run(scenario())
    assert renew.call_count == 0


def test_heartbeat_cancels_executor_when_lost():
    async def scenario():
        renew = mock.MagicMock(return_value=False)
        fake_store = SimpleNamespace(renew_task_lease=renew)
        cancel_event = asyncio.Event()

        async def executor(context):
            await asyncio.wait_for(context.cancel_event.wait(), timeout=2)
            return {"stopped": True}

        result = await nexus_worker._execute_with_heartbeat(
            fake_store,
            {"id": "task-1"},
            "worker-1",
            _Registry(on_run=executor),
            _context(cancel_event),
            timeout_seconds=5,
            renew_interval=0.05,
        )
        return result, cancel_event

    result, cancel_event = asyncio.run(scenario())
    assert cancel_event.is_set()
    assert result == {"stopped": True}


def test_heartbeat_propagates_executor_result():
    async def scenario():
        renew = mock.MagicMock(return_value=True)
        fake_store = SimpleNamespace(renew_task_lease=renew)
        return await nexus_worker._execute_with_heartbeat(
            fake_store,
            {"id": "task-1"},
            "worker-1",
            _Registry(delay=0.0),
            _context(asyncio.Event()),
            timeout_seconds=5,
            renew_interval=0.05,
        )

    assert asyncio.run(scenario()) == {"ok": True}
