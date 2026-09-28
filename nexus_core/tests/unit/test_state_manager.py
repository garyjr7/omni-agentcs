import json
from pathlib import Path

import pytest

from nexus_core.state.manager import StateManager, TaskState, TaskStatus


def task(task_id: str, priority: int = 5) -> TaskState:
    return TaskState(task_id, "test", TaskStatus.PENDING, "agent-1", {"id": task_id}, priority=priority)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_initialize_creates_valid_state(tmp_state_file: Path):
    manager = StateManager(tmp_state_file)
    await manager.initialize()
    content = json.loads(tmp_state_file.read_text())
    assert content["tasks"] == {}
    assert content["state_checksum"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_task_persists_across_instances(state_manager: StateManager, tmp_state_file: Path):
    await state_manager.create_task(task("task-1"))
    restored = StateManager(tmp_state_file)
    await restored.initialize()
    assert (await restored.get_task("task-1")).payload == {"id": "task-1"}
    assert not tmp_state_file.with_suffix(".json.tmp").exists()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_update_checkpoint_and_priority_order(state_manager: StateManager):
    await state_manager.create_task(task("low", 1))
    await state_manager.create_task(task("high", 10))
    updated = await state_manager.update_task("low", status=TaskStatus.COMPLETED)
    assert updated.status is TaskStatus.COMPLETED
    await state_manager.checkpoint("high", {"step": 2})
    assert await state_manager.restore_from_checkpoint("high") == {"step": 2}
    assert [item.task_id for item in await state_manager.get_pending_tasks()] == ["high"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_checksum_corruption_is_detected(state_manager: StateManager, tmp_state_file: Path):
    await state_manager.create_task(task("task-1"))
    content = json.loads(tmp_state_file.read_text())
    content["tasks"]["task-1"]["payload"] = {"tampered": True}
    tmp_state_file.write_text(json.dumps(content))
    with pytest.raises(RuntimeError, match="corrupted"):
        await StateManager(tmp_state_file).load()
