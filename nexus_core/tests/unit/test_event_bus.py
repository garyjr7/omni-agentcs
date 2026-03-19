import asyncio
from collections import defaultdict
from typing import Any, Dict, List
from unittest.mock import Mock

import pytest

# Assume these models and components exist
try:
    from nexus_core.event_bus import Event, EventBus, EventType
except ImportError:
    # Dummy classes for validation
    from enum import Enum
    from uuid import uuid4
    from dataclasses import dataclass, field
    import time

    class EventType(str, Enum):
        TASK_RECEIVED = "task.received"
        TASK_DISPATCHED = "task.dispatched"
        TASK_COMPLETED = "task.completed"
        AGENT_REGISTERED = "agent.registered"

    @dataclass
    class Event:
        event_id: str = field(default_factory=lambda: str(uuid4()))
        event_type: EventType = EventType.TASK_RECEIVED
        data: Dict[str, Any] = field(default_factory=dict)
        timestamp: float = field(default_factory=time.time)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_publish_and_subscribe(event_bus: EventBus):
    """
    Tests that a handler subscribed to an event type is correctly called
    when an event of that type is published.
    """
    queue = asyncio.Queue()

    async def handler(event: Event):
        await queue.put(event)

    event_type = EventType.TASK_RECEIVED
    await event_bus.subscribe(event_type, handler)

    test_data = {"task_id": "123", "payload": "test"}
    await event_bus.publish(event_type, test_data)

    try:
        received_event = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert received_event is not None
        assert received_event.event_type == event_type
        assert received_event.data == test_data
    except asyncio.TimeoutError:
        pytest.fail("Handler was not called within the timeout period.")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_event_stats_increment(event_bus: EventBus):
    """
    Tests that publishing events correctly increments the statistics counter.
    """
    event_type = EventType.TASK_DISPATCHED
    num_events = 3

    for i in range(num_events):
        await event_bus.publish(event_type, {"task_id": f"task_{i}"})

    stats = event_bus.get_stats()
    assert stats[event_type] == num_events


@pytest.mark.unit
@pytest.mark.asyncio
async def test_multiple_event_types(event_bus: EventBus):
    """
    Tests that handlers are only called for their subscribed event types.
    """
    received_events: Dict[str, List[Event]] = defaultdict(list)

    async def handler_received(event: Event):
        received_events[EventType.TASK_RECEIVED].append(event)

    async def handler_completed(event: Event):
        received_events[EventType.TASK_COMPLETED].append(event)

    await event_bus.subscribe(EventType.TASK_RECEIVED, handler_received)
    await event_bus.subscribe(EventType.TASK_COMPLETED, handler_completed)

    await event_bus.publish(EventType.TASK_RECEIVED, {"task_id": "A"})
    await event_bus.publish(EventType.TASK_COMPLETED, {"task_id": "B"})
    await event_bus.publish(EventType.TASK_RECEIVED, {"task_id": "C"})

    # Allow some time for events to be processed
    await asyncio.sleep(0.01)

    assert len(received_events[EventType.TASK_RECEIVED]) == 2
    assert len(received_events[EventType.TASK_COMPLETED]) == 1
    assert received_events[EventType.TASK_RECEIVED][0].data["task_id"] == "A"
    assert received_events[EventType.TASK_COMPLETED][0].data["task_id"] == "B"


@pytest.mark.unit
def test_bus_start_stop(event_bus: EventBus):
    """
    Tests the start and stop methods of the EventBus, verifying its running state.
    """
    assert not event_bus.running, "EventBus should not be running initially"
    event_bus.start()
    assert event_bus.running, "EventBus should be running after start()"
    event_bus.stop()
    assert not event_bus.running, "EventBus should not be running after stop()"


@pytest.mark.unit
def test_event_has_unique_id():
    """
    Tests that multiple Event instances have unique IDs.
    """
    num_events = 100
    event_ids = {Event().event_id for _ in range(num_events)}
    assert len(event_ids) == num_events, "Event IDs are not unique"
