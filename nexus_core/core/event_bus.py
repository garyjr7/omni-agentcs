import asyncio
import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Awaitable, Optional, Dict, List
import uuid
import datetime
import logging

class EventType(str, Enum):
    TASK_DISPATCHED = "task.dispatched"
    TASK_STARTED = "task.started"
    TASK_COMPLETED = "task.completed"
    TASK_FAILED = "task.failed"
    TASK_RETRY = "task.retry"
    TASK_CANCELLED = "task.cancelled"
    AGENT_REGISTERED = "agent.registered"
    AGENT_UNREGISTERED = "agent.unregistered"
    CHECKPOINT_SAVED = "checkpoint.saved"
    CHECKPOINT_RESTORED = "checkpoint.restored"
    SYSTEM_STARTED = "system.started"
    SYSTEM_SHUTDOWN = "system.shutdown"
    HEALTH_CHECK = "system.health_check"

@dataclass
class Event:
    type: EventType
    payload: dict
    source: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)
    correlation_id: Optional[str] = None

class EventBus:
    def __init__(self):
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=1000)
        self._subscribers: Dict[EventType, List[Callable[[Event], Awaitable[None]]]] = {}
        self._running: bool = False
        self._dispatch_task: Optional[asyncio.Task] = None
        self._stats: Dict[str, int] = {event_type: 0 for event_type in EventType}
        self._logger: logging.Logger = logging.getLogger("EventBus")

    async def subscribe(self, event_type: EventType, handler: Callable[[Event], Awaitable[None]]) -> None:
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)

    async def unsubscribe(self, event_type: EventType, handler: Callable) -> None:
        if event_type in self._subscribers:
            self._subscribers[event_type].remove(handler)

    async def publish(self, event: Event) -> None:
        await self._queue.put(event)
        self._stats[event.type] += 1
        if event.correlation_id:
            self._logger.info(f"Published event {event.type} with correlation ID {event.correlation_id}")

    async def _dispatch_loop(self) -> None:
        while self._running:
            event = await self._queue.get()
            handlers = self._subscribers.get(event.type, [])
            for handler in handlers:
                asyncio.create_task(self._handle_event(handler, event))

    async def _handle_event(self, handler: Callable[[Event], Awaitable[None]], event: Event) -> None:
        try:
            await handler(event)
        except Exception as e:
            self._logger.error(f"Error handling event {event.type}: {e}", exc_info=True)

    async def start(self) -> None:
        self._running = True
        self._dispatch_task = asyncio.create_task(self._dispatch_loop())
        await self.publish(Event(type=EventType.SYSTEM_STARTED, payload={}, source="EventBus"))

    async def stop(self) -> None:
        await asyncio.wait_for(self._queue.join(), timeout=5)
        self._running = False
        if self._dispatch_task:
            self._dispatch_task.cancel()
        await self.publish(Event(type=EventType.SYSTEM_SHUTDOWN, payload={}, source="EventBus"))

    def get_stats(self) -> dict:
        return self._stats.copy()

    def subscriber_count(self, event_type: EventType) -> int:
        return len(self._subscribers.get(event_type, []))

_BUS_INSTANCE: Optional[EventBus] = None

def get_event_bus() -> EventBus:
    global _BUS_INSTANCE
    if _BUS_INSTANCE is None:
        _BUS_INSTANCE = EventBus()
    return _BUS_INSTANCE

def reset_event_bus() -> None:
    global _BUS_INSTANCE
    _BUS_INSTANCE = None
