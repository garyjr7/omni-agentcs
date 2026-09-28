from pathlib import Path

import pytest
import pytest_asyncio

from nexus_core.core.event_bus import EventBus
from nexus_core.state.manager import StateManager


@pytest.fixture
def tmp_state_file(tmp_path: Path) -> Path:
    return tmp_path / "nexus-state.json"


@pytest_asyncio.fixture
async def state_manager(tmp_state_file: Path) -> StateManager:
    manager = StateManager(tmp_state_file)
    await manager.initialize()
    return manager


@pytest_asyncio.fixture
async def event_bus():
    bus = EventBus()
    await bus.start()
    yield bus
    await bus.stop()
