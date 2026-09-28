import asyncio

import pytest

from nexus_core.core.event_bus import Event, EventBus, EventType


@pytest.mark.unit
@pytest.mark.asyncio
async def test_publish_dispatch_and_stats(event_bus: EventBus):
    received = asyncio.Queue()

    async def handler(event: Event):
        await received.put(event)

    await event_bus.subscribe(EventType.TASK_RECEIVED, handler)
    await event_bus.publish(EventType.TASK_RECEIVED, {"task_id": "123"}, source="test")
    event = await asyncio.wait_for(received.get(), timeout=1)

    assert event.type is EventType.TASK_RECEIVED
    assert event.payload == {"task_id": "123"}
    assert event.source == "test"
    assert event_bus.get_stats()[EventType.TASK_RECEIVED] == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_handlers_are_isolated_by_event_type(event_bus: EventBus):
    received = []

    async def handler(event: Event):
        received.append(event)

    await event_bus.subscribe(EventType.TASK_COMPLETED, handler)
    await event_bus.publish(EventType.TASK_RECEIVED, {})
    await event_bus.publish(EventType.TASK_COMPLETED, {"task_id": "done"})
    await asyncio.wait_for(event_bus._queue.join(), timeout=1)

    assert [event.payload for event in received] == [{"task_id": "done"}]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_start_and_stop_are_idempotent():
    bus = EventBus()
    assert not bus.running
    await bus.start()
    await bus.start()
    assert bus.running
    await bus.stop()
    await bus.stop()
    assert not bus.running


def test_event_ids_are_unique():
    events = [Event(EventType.HEALTH_CHECK, {}, "test") for _ in range(100)]
    assert len({event.id for event in events}) == 100
