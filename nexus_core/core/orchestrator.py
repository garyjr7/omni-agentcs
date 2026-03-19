import asyncio
import dataclasses
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional
import uuid
import datetime
import time
import logging
import pathlib
import random

from nexus_core.state.manager import TaskState, StateManager, TaskStatus
from nexus_core.core.event_bus import EventBus, EventType, Event
from nexus_core.agents.registry import AgentRegistry
from nexus_core.agents.base import AgentCapability

@dataclass
class OrchestratorConfig:
    max_concurrent_tasks: int = 5
    task_timeout_seconds: int = 300
    max_retries: int = 3
    retry_base_delay: float = 2.0
    retry_max_delay: float = 60.0
    checkpoint_interval: int = 10
    health_check_interval: int = 30
    queue_max_size: int = 500

class OrchestratorStatus(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"

class NexusOrchestrator:
    def __init__(self, config: OrchestratorConfig, state_manager: StateManager, agent_registry: AgentRegistry, event_bus: EventBus, logger: Optional[logging.Logger] = None):
        self._config = config
        self._state = state_manager
        self._registry = agent_registry
        self._bus = event_bus
        self._logger = logger or logging.getLogger("NexusOrchestrator")
        self._queue = asyncio.PriorityQueue(maxsize=config.queue_max_size)
        self._semaphore = asyncio.Semaphore(config.max_concurrent_tasks)
        self._status = OrchestratorStatus.STOPPED
        self._active_tasks: Dict[str, asyncio.Task] = {}
        self._completed_count = 0
        self._background_tasks: List[asyncio.Task] = []

    async def start(self) -> None:
        self._status = OrchestratorStatus.STARTING
        await self.restore_and_resume()
        self._background_tasks = [
            asyncio.create_task(self._dispatch_loop()),
            asyncio.create_task(self._health_check_loop()),
            asyncio.create_task(self._checkpoint_loop())
        ]
        self._status = OrchestratorStatus.RUNNING
        await self._bus.publish(Event(type=EventType.SYSTEM_STARTED, payload={}, source="NexusOrchestrator"))

    async def stop(self) -> None:
        self._status = OrchestratorStatus.STOPPING
        await asyncio.wait_for(asyncio.gather(*self._active_tasks.values()), timeout=30)
        for task in self._background_tasks:
            task.cancel()
        await self._bus.publish(Event(type=EventType.SYSTEM_SHUTDOWN, payload={}, source="NexusOrchestrator"))
        self._status = OrchestratorStatus.STOPPED

    async def dispatch(self, task_name: str, payload: dict, required_capability: str, priority: int = 5) -> str:
        task_id = str(uuid.uuid4())

        payload["required_capability"] = required_capability

        task_state = TaskState(
            task_id=task_id,
            name=task_name,
            status=TaskStatus.PENDING,
            agent_id="",
            payload=payload,
            priority=priority
        )
        await self._state.create_task(task_state)
        await self._bus.publish(Event(type=EventType.TASK_DISPATCHED, payload={"task_id": task_id}, source="NexusOrchestrator"))
        await self._queue.put((priority, task_id))
        return task_id

    async def _dispatch_loop(self) -> None:
        while self._status == OrchestratorStatus.RUNNING:
            priority, task_id = await self._queue.get()
            task_state = await self._state.get_task(task_id)
            if not task_state:
                continue
            cap = AgentCapability(task_state.payload.get("required_capability"))
            agent = await self._registry.get_best_agent(cap)
            if not agent:
                await asyncio.sleep(5)
                await self._queue.put((priority, task_id))
                continue
            async with self._semaphore:
                task = asyncio.create_task(self._execute_task(task_id, agent))
                self._active_tasks[task_id] = task

    async def _execute_task(self, task_id: str, agent) -> None:
        task_state = await self._state.get_task(task_id)
        if not task_state:
            return
        await self._state.update_task(task_id, status=TaskStatus.RUNNING)
        try:
            result = await asyncio.wait_for(agent.run(task_id, task_state.payload), timeout=self._config.task_timeout_seconds)
            if result["success"]:
                await self._state.update_task(task_id, status=TaskStatus.COMPLETED, result=result["result"], completed_at=datetime.datetime.utcnow())
                self._completed_count += 1
                await self._bus.publish(Event(
                    type=EventType.TASK_COMPLETED,
                    payload={"task_id": task_id, "result": result["result"]},
                    source="NexusOrchestrator"
                ))
            else:
                await self._retry_or_fail(task_id, result["error"])
        except asyncio.TimeoutError:
            await self._retry_or_fail(task_id, "Task timeout")
        except Exception as e:
            await self._retry_or_fail(task_id, str(e))
        finally:
            self._active_tasks.pop(task_id, None)

    async def _retry_or_fail(self, task_id: str, error: str) -> None:
        task_state = await self._state.get_task(task_id)
        if not task_state:
            return
        if task_state.retries < self._config.max_retries:
            task_state.retries += 1
            await self._state.update_task(task_id, status=TaskStatus.RETRY, retries=task_state.retries)
            await self._bus.publish(Event(type=EventType.TASK_RETRY, payload={"task_id": task_id, "error": error}, source="NexusOrchestrator"))
            delay = min(self._config.retry_base_delay * (2 ** task_state.retries), self._config.retry_max_delay) + random.uniform(0, 1)
            await asyncio.sleep(delay)
            await self._queue.put((task_state.priority, task_id))
        else:
            await self._state.update_task(task_id, status=TaskStatus.FAILED, error=error)
            await self._bus.publish(Event(type=EventType.TASK_FAILED, payload={"task_id": task_id, "error": error}, source="NexusOrchestrator"))

    async def _health_check_loop(self) -> None:
        while self._status == OrchestratorStatus.RUNNING:
            health_status = await self._registry.health_check()
            self._logger.info(f"Health check results: {health_status}")
            await self._bus.publish(Event(type=EventType.HEALTH_CHECK, payload=health_status, source="NexusOrchestrator"))
            await asyncio.sleep(self._config.health_check_interval)

    async def _checkpoint_loop(self) -> None:
        while self._status == OrchestratorStatus.RUNNING:
            if self._completed_count > 0 and self._completed_count % self._config.checkpoint_interval == 0:
                await self._state.save()
                self._logger.info("Checkpoint saved")
            await asyncio.sleep(1)

    async def restore_and_resume(self) -> None:
        running_tasks = await self._state.get_tasks_by_status(TaskStatus.RUNNING)
        retry_tasks = await self._state.get_tasks_by_status(TaskStatus.RETRY)
        for task in running_tasks + retry_tasks:
            await self._state.update_task(task.task_id, status=TaskStatus.RETRY)
            await self._queue.put((task.priority, task.task_id))
        self._logger.info(f"Restored and resumed {len(running_tasks) + len(retry_tasks)} tasks.")

    async def wait_for_task(self, task_id: str, timeout: float = 60.0) -> dict:
        start_time = time.time()
        while time.time() - start_time < timeout:
            task_state = await self._state.get_task(task_id)
            if task_state and task_state.status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}:
                return task_state.to_dict()
            await asyncio.sleep(0.5)
        raise asyncio.TimeoutError(f"Timeout waiting for task {task_id}")

    def get_status(self) -> dict:
        return {
            "status": self._status,
            "queue_size": self._queue.qsize(),
            "active_tasks": len(self._active_tasks),
            "completed_count": self._completed_count,
            "config": dataclasses.asdict(self._config)
        }
