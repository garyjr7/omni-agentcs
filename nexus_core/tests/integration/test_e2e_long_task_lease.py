"""E2E: a running task renews its lease, so a second worker cannot claim it (#9).

Deterministic and offline: a fake registry keeps the executor busy while the
heartbeat renews the lease past its original expiry.
"""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
import nexus_worker

pytestmark = pytest.mark.integration

TENANT = "system"


class _Registry:
    def __init__(self, delay: float) -> None:
        self.delay = delay

    async def execute(self, task, context):
        await asyncio.sleep(self.delay)
        return {"ok": True}


def _task_state(store: ControlStore, task_id: str) -> dict:
    with store.connect() as conn:
        return dict(
            conn.execute(
                "SELECT status, lease_owner, lease_until FROM kernel_tasks WHERE id=?",
                (task_id,),
            ).fetchone()
        )


def test_renewed_lease_blocks_second_worker(tmp_path):
    store = ControlStore(tmp_path / "lease-e2e.db")
    store.initialize()
    run = store.create_run(TENANT, {})
    enqueued = store.enqueue_task(
        tenant_id=TENANT, run_id=run["id"], task_type="noop", payload={}, timeout_seconds=30
    )
    # Worker 1 claims a short lease that it must renew to keep the task.
    claimed = store.claim_task("worker-1", lease_seconds=1)
    assert claimed is not None and claimed["lease_owner"] == "worker-1"

    async def scenario():
        context = ExecutionContext(
            store=store, task=claimed, worker_id="worker-1", cancel_event=asyncio.Event()
        )
        heartbeat = asyncio.ensure_future(
            nexus_worker._execute_with_heartbeat(
                store,
                claimed,
                "worker-1",
                _Registry(delay=1.6),
                context,
                timeout_seconds=10,
                renew_interval=0.3,
                lease_seconds=1,
            )
        )
        # The original 1s lease would already be expired here without renewal.
        await asyncio.sleep(0.8)
        second_claim = store.claim_task("worker-2", lease_seconds=60)
        result = await heartbeat
        return result, second_claim

    result, second_claim = asyncio.run(scenario())
    assert result == {"ok": True}
    # Worker 2 could not steal a task whose lease worker 1 kept renewing.
    assert second_claim is None

    store.complete_task(claimed["id"], "worker-1", result=result)
    state = _task_state(store, enqueued["id"])
    assert state["status"] == "completed"
    assert state["lease_owner"] is None
    assert state["lease_until"] is None


def test_expired_lease_is_reclaimable(tmp_path):
    """Without renewal the lease expires and a second worker may take over."""
    store = ControlStore(tmp_path / "lease-expire.db")
    store.initialize()
    run = store.create_run(TENANT, {})
    store.enqueue_task(
        tenant_id=TENANT, run_id=run["id"], task_type="noop", payload={}, timeout_seconds=30
    )
    claimed = store.claim_task("worker-1", lease_seconds=1)
    assert claimed is not None
    import time

    time.sleep(1.2)
    reclaimed = store.claim_task("worker-2", lease_seconds=60)
    assert reclaimed is not None
    assert reclaimed["lease_owner"] == "worker-2"
