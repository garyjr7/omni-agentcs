import asyncio
import json
import os
import pathlib
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, List
import uuid
import hashlib
import copy
import dataclasses
import logging

class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRY = "retry"
    CANCELLED = "cancelled"

@dataclass
class TaskState:
    task_id: str
    name: str
    status: TaskStatus
    agent_id: str
    payload: dict
    result: Optional[dict] = None
    error: Optional[str] = None
    retries: int = 0
    max_retries: int = 3
    priority: int = 5
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    checkpoint_data: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "name": self.name,
            "status": self.status,
            "agent_id": self.agent_id,
            "payload": self.payload,
            "result": self.result,
            "error": self.error,
            "retries": self.retries,
            "max_retries": self.max_retries,
            "priority": self.priority,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "checkpoint_data": self.checkpoint_data
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TaskState":
        return cls(
            task_id=data["task_id"],
            name=data["name"],
            status=TaskStatus(data["status"]),
            agent_id=data["agent_id"],
            payload=data["payload"],
            result=data.get("result"),
            error=data.get("error"),
            retries=data.get("retries", 0),
            max_retries=data.get("max_retries", 3),
            priority=data.get("priority", 5),
            created_at=datetime.fromisoformat(data["created_at"]),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            checkpoint_data=data.get("checkpoint_data")
        )

@dataclass
class SystemState:
    run_id: str
    version: str = "1.0.0-alpha"
    phase: int = 0
    tasks: Dict[str, dict] = field(default_factory=dict)
    agents_registered: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    state_checksum: Optional[str] = None

class StateManager:
    def __init__(self, state_file: pathlib.Path = pathlib.Path("nexus_state.json")):
        self._file: pathlib.Path = state_file
        self._tmp: pathlib.Path = state_file.with_suffix(".json.tmp")
        self._state: SystemState = SystemState(run_id=str(uuid.uuid4()))
        self._lock: asyncio.Lock = asyncio.Lock()
        self._logger: logging.Logger = logging.getLogger("StateManager")

    async def initialize(self) -> None:
        if self._file.exists():
            try:
                await self.load()
            except Exception as e:
                self._logger.warning(f"State file inválido, recreando: {e}")
                self._file.unlink(missing_ok=True)
                self._state = SystemState(run_id=str(uuid.uuid4()))
                await self.save()
        else:
            await self.save()

    async def save(self) -> None:
        async with self._lock:
            self._state.updated_at = datetime.utcnow()
            state_dict = dataclasses.asdict(self._state)
            def _json_serial(obj):
                if hasattr(obj, 'isoformat'):
                    return obj.isoformat()
                raise TypeError(f'Type {type(obj)} not serializable')
            state_json = json.dumps(state_dict, indent=2, default=_json_serial)
            checksum = hashlib.sha256(state_json.encode()).hexdigest()
            self._state.state_checksum = checksum
            with open(self._tmp, "w") as f:
                f.write(state_json)
            os.replace(self._tmp, self._file)

    async def load(self) -> SystemState:
        async with self._lock:
            with open(self._file, "r") as f:
                state_dict = json.load(f)
            checksum = hashlib.sha256(json.dumps(state_dict, indent=2).encode()).hexdigest()
            if checksum != state_dict.get("state_checksum"):
                raise RuntimeError("State file corrupted")
            self._state = SystemState(**state_dict)
            return self._state

    async def create_task(self, task: TaskState) -> None:
        async with self._lock:
            self._state.tasks[task.task_id] = task.to_dict()
            await self.save()

    async def update_task(self, task_id: str, **kwargs) -> TaskState:
        async with self._lock:
            task_data = self._state.tasks.get(task_id)
            if not task_data:
                raise ValueError(f"Task {task_id} not found")
            task = TaskState.from_dict(task_data)
            for key, value in kwargs.items():
                setattr(task, key, value)
            task.updated_at = datetime.utcnow()
            self._state.tasks[task_id] = task.to_dict()
            await self.save()
            return task

    async def get_task(self, task_id: str) -> Optional[TaskState]:
        async with self._lock:
            task_data = self._state.tasks.get(task_id)
            return TaskState.from_dict(task_data) if task_data else None

    async def get_tasks_by_status(self, status: TaskStatus) -> List[TaskState]:
        async with self._lock:
            return [TaskState.from_dict(task) for task in self._state.tasks.values() if task["status"] == status]

    async def get_pending_tasks(self) -> List[TaskState]:
        async with self._lock:
            tasks = [TaskState.from_dict(task) for task in self._state.tasks.values() if task["status"] == TaskStatus.PENDING]
            return sorted(tasks, key=lambda t: t.priority)

    async def get_failed_tasks(self) -> List[TaskState]:
        async with self._lock:
            return [TaskState.from_dict(task) for task in self._state.tasks.values() if task["status"] == TaskStatus.FAILED]

    async def checkpoint(self, task_id: str, data: dict) -> None:
        async with self._lock:
            task_data = self._state.tasks.get(task_id)
            if not task_data:
                raise ValueError(f"Task {task_id} not found")
            task = TaskState.from_dict(task_data)
            task.checkpoint_data = data
            self._state.tasks[task_id] = task.to_dict()
            await self.save()

    async def restore_from_checkpoint(self, task_id: str) -> Optional[dict]:
        async with self._lock:
            task_data = self._state.tasks.get(task_id)
            if not task_data:
                return None
            task = TaskState.from_dict(task_data)
            return task.checkpoint_data

    async def advance_phase(self, new_phase: int) -> None:
        async with self._lock:
            self._state.phase = new_phase
            await self.save()

    async def register_agent(self, agent_id: str) -> None:
        async with self._lock:
            if agent_id not in self._state.agents_registered:
                self._state.agents_registered.append(agent_id)
                await self.save()

    def get_stats(self) -> dict:
        return {
            "total_tasks": len(self._state.tasks),
            "tasks_by_status": {status: sum(1 for task in self._state.tasks.values() if task["status"] == status) for status in TaskStatus},
            "agents_registered": len(self._state.agents_registered),
            "current_phase": self._state.phase
        }
