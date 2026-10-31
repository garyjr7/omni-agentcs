"""Background task scheduler: spawn, caps, cancellation, delivery, wake-up."""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.agent import task_manager as tm

pytestmark = pytest.mark.unit


def _result(tool_id: str = "local.one", *, success: bool = True) -> dict:
    return {
        "success": success,
        "outcome": "success" if success else "negative",
        "verification_method": "unit",
        "invocation_id": f"inv-{tool_id}",
        "evidence": {"ports": [22, 80]},
        "assertions": [{"target": "10.0.0.5", "fact_type": "service"}],
        "output": {"ports": [22, 80]},
    }


async def test_spawn_returns_before_the_tool_finishes():
    """The whole point: the caller is not waiting for the scan."""
    release = asyncio.Event()

    async def runner(payload, cancel_event):
        await release.wait()
        return _result(payload["tool_id"])

    manager = tm.TaskManager(runner)
    record = await manager.spawn_task(
        tool_id="nexus.recon.nmap", arguments={"target": "10.0.0.5"}, label="nmap -p-"
    )

    assert record.status == tm.RUNNING
    assert manager.running_count() == 1
    assert manager.get_status(record.task_id)["status"] == tm.RUNNING
    assert manager.pending_results() == []

    release.set()
    finished = await manager.wait_for_result(timeout=2)
    assert [item.task_id for item in finished] == [record.task_id]
    assert record.status == tm.SUCCEEDED
    assert record.observation()["background"] is True
    assert record.observation()["success"] is True
    assert record.observation()["evidence"] == {"ports": [22, 80]}
    await manager.cancel_all()


async def test_a_finished_task_is_delivered_exactly_once():
    manager = tm.TaskManager(lambda payload, cancel: _as_async(_result()))
    await manager.spawn_task(tool_id="local.one", arguments={})

    first = await manager.wait_for_result(timeout=2)
    second = manager.pending_results()

    assert len(first) == 1 and second == []
    assert first[0].delivered is True


async def _as_async(value):
    return value


async def test_the_completion_hook_runs_before_delivery():
    seen: list[tuple[str, str]] = []

    async def hook(record):
        seen.append((record.task_id, record.status))
        await asyncio.sleep(0)

    manager = tm.TaskManager(lambda payload, cancel: _as_async(_result()), on_complete=hook)
    record = await manager.spawn_task(tool_id="local.one", arguments={})
    pending = await manager.wait_for_result(timeout=2)

    assert seen == [(record.task_id, tm.SUCCEEDED)]
    assert len(pending) == 1


async def test_a_broken_hook_does_not_lose_the_result():
    def hook(record):
        raise RuntimeError("blackboard down")

    manager = tm.TaskManager(lambda payload, cancel: _as_async(_result()), on_complete=hook)
    record = await manager.spawn_task(tool_id="local.one", arguments={})
    pending = await manager.wait_for_result(timeout=2)

    assert len(pending) == 1
    assert record.status == tm.SUCCEEDED
    assert "hook" in record.error


async def test_failure_and_timeout_are_local_outcomes():
    async def failing(payload, cancel_event):
        raise RuntimeError("team server down")

    manager = tm.TaskManager(failing)
    failed = await manager.spawn_task(tool_id="local.one", arguments={})
    await manager.wait_for_result(timeout=2)
    assert failed.status == tm.FAILED
    assert "RuntimeError" in failed.error
    assert failed.observation()["success"] is False
    await manager.cancel_all()


async def test_a_timeout_marks_the_task_and_keeps_the_loop_alive():
    async def slow(payload, cancel_event):
        await asyncio.sleep(5)
        return _result()

    manager = tm.TaskManager(slow)
    record = await manager.spawn_task(tool_id="local.one", arguments={}, timeout_seconds=0.05)
    await manager.wait_for_result(timeout=2)

    assert record.status == tm.TIMEOUT
    assert record.observation()["status"] == tm.TIMEOUT
    assert record.observation()["guidance"]
    await manager.cancel_all()


async def test_cancel_task_stops_only_that_task():
    async def runner(payload, cancel_event):
        await cancel_event.wait()
        return _result()

    manager = tm.TaskManager(runner)
    first = await manager.spawn_task(tool_id="local.one", arguments={})
    second = await manager.spawn_task(tool_id="local.two", arguments={})

    assert manager.cancel_task(first.task_id) is True
    assert manager.cancel_task(first.task_id) is False  # already cancelled
    pending = await manager.wait_for_result(timeout=2)

    assert first.status == tm.CANCELLED
    assert second.status == tm.RUNNING
    assert [item.task_id for item in pending] == [first.task_id]

    manager.cancel_task(second.task_id)
    await manager.wait_for_result(timeout=2)
    assert second.status == tm.CANCELLED
    await manager.cancel_all()


async def test_cancel_all_settles_every_task():
    async def runner(payload, cancel_event):
        await asyncio.sleep(30)
        return _result()

    manager = tm.TaskManager(runner)
    records = [await manager.spawn_task(tool_id=f"local.{index}", arguments={}) for index in range(2)]
    await asyncio.sleep(0)

    await manager.cancel_all()

    assert all(record.status == tm.CANCELLED for record in records)
    assert manager.running_count() == 0


async def test_concurrency_cap_refuses_instead_of_stackng_tasks():
    async def runner(payload, cancel_event):
        await asyncio.sleep(30)
        return _result()

    manager = tm.TaskManager(runner, max_concurrent=2)
    await manager.spawn_task(tool_id="local.one", arguments={})
    await manager.spawn_task(tool_id="local.two", arguments={})
    with pytest.raises(tm.TaskManagerError):
        await manager.spawn_task(tool_id="local.three", arguments={})
    await manager.cancel_all()


async def test_total_cap_refuses_an_unbounded_spawner():
    manager = tm.TaskManager(lambda payload, cancel: _as_async(_result()), max_total=2)
    await manager.spawn_task(tool_id="local.one", arguments={})
    await manager.wait_for_result(timeout=2)
    await manager.spawn_task(tool_id="local.two", arguments={})
    await manager.wait_for_result(timeout=2)

    with pytest.raises(tm.TaskManagerError):
        await manager.spawn_task(tool_id="local.three", arguments={})


async def test_a_manager_without_a_runner_refuses_to_spawn():
    with pytest.raises(tm.TaskManagerError):
        await tm.TaskManager().spawn_task(tool_id="local.one", arguments={})


async def test_labels_are_single_line_and_bounded():
    manager = tm.TaskManager(lambda payload, cancel: _as_async(_result()))
    record = await manager.spawn_task(
        tool_id="local.one", arguments={}, label="nmap\n-p-  " + "x" * 300
    )

    assert "\n" not in record.label
    assert len(record.label) <= tm.MAX_LABEL_CHARS
    await manager.wait_for_result(timeout=2)


async def test_wait_for_result_reports_a_timeout_instead_of_blocking():
    async def runner(payload, cancel_event):
        await asyncio.sleep(5)
        return _result()

    manager = tm.TaskManager(runner)
    await manager.spawn_task(tool_id="local.one", arguments={})

    assert await manager.wait_for_result(timeout=0.01) == []
    await manager.cancel_all()


async def test_retention_keeps_the_records_bounded():
    manager = tm.TaskManager(
        lambda payload, cancel: _as_async(_result()), max_total=50, retention=3
    )
    for _ in range(6):
        await manager.spawn_task(tool_id="local.one", arguments={})
        await manager.wait_for_result(timeout=2)

    assert len(manager.list_tasks()) <= 4
    assert manager.count() == 6


async def test_concurrent_tasks_write_to_the_store_without_corrupting_it(tmp_path):
    """B4: background writes share the store; WAL + busy timeout keep it sane.

    Each task opens its own connection (``ControlStore.connect``) and appends run
    events while the others do the same, which is the shape that used to raise
    ``database is locked`` when SQLite ran in rollback mode.
    """
    from nexus_core.kernel.control_store import ControlStore

    store = ControlStore(tmp_path / "bg.db")
    store.initialize()
    run = store.create_run("system", {})
    written: list[int] = []

    async def runner(payload, cancel_event):
        for index in range(20):
            store.append_run_event("system", run["id"], "bg.tick", {"i": index})
            await asyncio.sleep(0)
        written.append(1)
        return _result()

    manager = tm.TaskManager(runner)
    records = [
        await manager.spawn_task(tool_id=f"local.{index}", arguments={}) for index in range(3)
    ]
    finished = await manager.wait_for_result(timeout=5)

    assert written == [1, 1, 1]
    assert all(record.status == tm.SUCCEEDED for record in records)
    assert len(finished) == 3


def test_concurrency_can_be_configured_by_the_operator():
    assert tm.max_concurrent_from_env({tm.MAX_CONCURRENT_ENV: "2"}) == 2
    assert tm.max_concurrent_from_env({tm.MAX_CONCURRENT_ENV: "0"}) == 1
    assert tm.max_concurrent_from_env({tm.MAX_CONCURRENT_ENV: "999"}) == 8
    assert tm.max_concurrent_from_env({tm.MAX_CONCURRENT_ENV: "nope"}) == tm.DEFAULT_MAX_CONCURRENT
    assert tm.max_concurrent_from_env({}) == tm.DEFAULT_MAX_CONCURRENT
