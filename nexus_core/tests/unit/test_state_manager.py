import json
import hashlib
from pathlib import Path

import pytest

# Assume these models and components exist
try:
    from nexus_core.state_manager import StateManager
    from nexus_core.models.task import TaskState, TaskStatus, TaskPriority
except ImportError:
    # Dummy classes for validation
    from enum import Enum
    from dataclasses import dataclass
    from typing import List, Dict, Any
    import time

    class TaskStatus(str, Enum):
        PENDING = "PENDING"
        COMPLETED = "COMPLETED"
        FAILED = "FAILED"

    class TaskPriority(int, Enum):
        LOW = 1
        MEDIUM = 2
        HIGH = 3

    @dataclass
    class TaskState:
        task_id: str
        status: TaskStatus = TaskStatus.PENDING
        priority: TaskPriority = TaskPriority.MEDIUM
        payload: Dict[str, Any] = None
        created_at: float = time.time()
        updated_at: float = time.time()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_initialize_creates_file(tmp_state_file: Path):
    """
    Tests that StateManager.initialize() creates the state file if it doesn't exist.
    """
    if tmp_state_file.exists():
        tmp_state_file.unlink()
    assert not tmp_state_file.exists()

    sm = StateManager(db_path=tmp_state_file)
    await sm.initialize()

    assert tmp_state_file.exists()
    # Check if it's a valid, empty JSON state
    content = json.loads(tmp_state_file.read_text())
    assert "tasks" in content
    assert "agents" in content
    assert "checksum" in content


@pytest.mark.integration
@pytest.mark.asyncio
async def test_atomic_write_no_tmp_residue(state_manager: StateManager, tmp_state_file: Path):
    """
    Tests that after saving state, the temporary file (.tmp) is removed.
    """
    tmp_file = tmp_state_file.with_suffix(".json.tmp")
    assert not tmp_file.exists()

    await state_manager.create_task(payload={"data": "test"}, priority=TaskPriority.LOW)
    # The save is triggered inside create_task

    assert tmp_state_file.exists()
    assert not tmp_file.exists(), "Temporary file was not removed after save"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_create_and_get_task(state_manager: StateManager):
    """
    Tests creating a task and then retrieving it to verify its contents.
    """
    payload = {"query": "SELECT 1"}
    priority = TaskPriority.HIGH
    task = await state_manager.create_task(payload=payload, priority=priority)

    assert task is not None
    assert task.payload == payload
    assert task.priority == priority
    assert task.status == TaskStatus.PENDING

    retrieved_task = await state_manager.get_task(task.task_id)
    assert retrieved_task is not None
    assert retrieved_task.task_id == task.task_id
    assert retrieved_task.payload == payload


@pytest.mark.integration
@pytest.mark.asyncio
async def test_update_task_status(state_manager: StateManager):
    """
    Tests updating the status of an existing task.
    """
    task = await state_manager.create_task(payload={}, priority=TaskPriority.MEDIUM)
    assert task.status == TaskStatus.PENDING

    updated_task = await state_manager.update_task_status(task.task_id, TaskStatus.COMPLETED)
    assert updated_task.status == TaskStatus.COMPLETED

    retrieved_task = await state_manager.get_task(task.task_id)
    assert retrieved_task.status == TaskStatus.COMPLETED


@pytest.mark.integration
@pytest.mark.asyncio
async def test_checkpoint_and_restore(state_manager: StateManager):
    """
    Tests saving a checkpoint and restoring from it.
    """
    checkpoint_data = {"key": "value", "progress": 0.75}
    task = await state_manager.create_task(payload={}, priority=TaskPriority.MEDIUM)

    await state_manager.save_checkpoint(task.task_id, "analysis_step", checkpoint_data)
    
    restored_data = await state_manager.restore_from_checkpoint(task.task_id, "analysis_step")
    
    assert restored_data == checkpoint_data


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_pending_tasks_sorted_by_priority(state_manager: StateManager):
    """
    Tests that get_pending_tasks returns tasks sorted by priority (descending).
    """
    await state_manager.create_task(payload={"id": 1}, priority=TaskPriority.MEDIUM)
    await state_manager.create_task(payload={"id": 2}, priority=TaskPriority.HIGH)
    await state_manager.create_task(payload={"id": 3}, priority=TaskPriority.LOW)

    pending_tasks = await state_manager.get_pending_tasks()
    
    assert len(pending_tasks) == 3
    assert pending_tasks[0].priority == TaskPriority.HIGH
    assert pending_tasks[1].priority == TaskPriority.MEDIUM
    assert pending_tasks[2].priority == TaskPriority.LOW


@pytest.mark.integration
@pytest.mark.asyncio
async def test_state_checksum_corruption_detected(tmp_state_file: Path):
    """
    Tests that loading a manually corrupted state file raises a RuntimeError.
    """
    sm = StateManager(db_path=tmp_state_file)
    await sm.initialize()
    await sm.create_task(payload={"data": "initial"}, priority=TaskPriority.LOW)

    # Manually corrupt the file
    with open(tmp_state_file, "r+") as f:
        state = json.load(f)
        state["tasks"][0]["payload"]["data"] = "corrupted" # Change data
        # But do NOT update the checksum
        f.seek(0)
        json.dump(state, f)
        f.truncate()

    # A new instance should fail to load the corrupted state
    new_sm = StateManager(db_path=tmp_state_file)
    with pytest.raises(RuntimeError, match="State checksum mismatch. Data may be corrupted."):
        await new_sm.load_state()
