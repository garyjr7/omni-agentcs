import asyncio
import tempfile
from pathlib import Path
from typing import AsyncGenerator, Any, Dict, Generator
from uuid import uuid4

import pytest
import pytest_asyncio

# Assume these models and components exist in the nexus_core library
# In a real scenario, these would be direct imports
try:
    from nexus_core.event_bus import EventBus, reset_event_bus
    from nexus_core.state_manager import StateManager
    from nexus_core.models.agent import Agent, AgentMetadata, Capability
    from nexus_core.models.task import Task, TaskPriority, TaskStatus
except ImportError:
    # Create dummy classes if the real ones are not available for syntax validation
    # This allows writing tests before the main code is complete.
    print("Warning: nexus_core components not found. Using dummy classes for tests.")
    from enum import Enum
    from dataclasses import dataclass, field
    import time

    class Capability(Enum):
        DATA_ANALYSIS = "data_analysis"
        CODE_EXECUTION = "code_execution"

    @dataclass
    class AgentMetadata:
        agent_id: str
        name: str
        version: str
        description: str
        capabilities: list[Capability] = field(default_factory=list)

    class Agent:
        def __init__(self, metadata: AgentMetadata):
            self.metadata = metadata
        async def execute_task(self, task: 'Task') -> Any:
            return {"status": "completed", "result": f"Mock result for task {task.task_id}"}

    class EventBus:
        def __init__(self):
            self.running = False
            self._stats = {"task.dispatched": 0}
        def start(self): self.running = True
        def stop(self): self.running = False
        async def publish(self, event_type: str, data: Any):
            if event_type == "task.dispatched": self._stats["task.dispatched"] += 1
        async def subscribe(self, event_type: str, handler): pass
        def get_stats(self): return self._stats

    def reset_event_bus(): return EventBus()

    class StateManager:
        def __init__(self, db_path: Path): self._db_path = db_path
        async def initialize(self):
            if not self._db_path.exists(): self._db_path.touch()
        async def save_state(self, state: Dict): pass
        async def load_state(self) -> Dict: return {}
        async def create_task(self, *args, **kwargs): return None
        async def get_task(self, task_id: str): return None
    
    class TaskPriority(Enum):
        HIGH = 3

# A mock agent for testing purposes
class MockDataAnalystAgent(Agent):
    """A mock agent for testing that simulates data analysis."""
    def __init__(self):
        super().__init__(
            metadata=AgentMetadata(
                agent_id="mock-data-analyst-001",
                name="MockDataAnalystAgent",
                version="1.0.0",
                description="A mock agent for running data analysis tasks in tests.",
                capabilities=[Capability.DATA_ANALYSIS],
            )
        )

    async def execute_task(self, task: 'Task') -> Dict[str, Any]:
        """Simulates executing a data analysis task."""
        print(f"Mock agent executing task: {task.task_id}")
        await asyncio.sleep(0.01)  # Simulate async work
        return {
            "status": "completed",
            "result": {"processed_rows": 1000, "insights": "Mock insight"},
        }


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """
    Creates an instance of the default event loop for the whole test session.
    """
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def tmp_state_file() -> Path:
    """
    Provides a temporary file path for the state manager database.
    The file is automatically cleaned up after the test.

    Returns:
        Path: The path to the temporary state file.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as fp:
        path = Path(fp.name)
    yield path
    if path.exists():
        path.unlink()


@pytest_asyncio.fixture
async def state_manager(tmp_state_file: Path) -> StateManager:
    """
    Provides an initialized StateManager instance using a temporary file.

    Args:
        tmp_state_file: The fixture for the temporary state file path.

    Returns:
        StateManager: An initialized instance of the StateManager.
    """
    sm = StateManager(db_path=tmp_state_file)
    await sm.initialize()
    return sm


@pytest.fixture
def event_bus() -> EventBus:
    """
    Provides a clean instance of the EventBus for each test.
    This ensures that tests are isolated and do not share event state.

    Returns:
        EventBus: A new, clean instance of the EventBus.
    """
    return reset_event_bus()


@pytest.fixture
def sample_task_payload() -> Dict[str, Any]:
    """
    Provides a sample dictionary representing a task payload.

    Returns:
        Dict[str, Any]: A dictionary with sample task data.
    """
    return {
        "type": "DATA_ANALYSIS",
        "payload": {
            "query": "SELECT * FROM sales WHERE region='North'",
            "data_source": "s3://bucket/data.csv",
        },
        "priority": TaskPriority.HIGH.value,
    }


@pytest.fixture
def sample_agent_metadata() -> AgentMetadata:
    """
    Provides a sample AgentMetadata instance for a data analysis agent.

    Returns:
        AgentMetadata: An instance of AgentMetadata.
    """
    return AgentMetadata(
        agent_id=f"agent-{uuid4()}",
        name="Test Data Analyst",
        version="0.1.0-test",
        description="A test agent for data analysis.",
        capabilities=[Capability.DATA_ANALYSIS],
    )


@pytest.fixture
def mock_agent() -> MockDataAnalystAgent:
    """
    Provides a mock agent instance for testing agent interactions.

    Returns:
        MockDataAnalystAgent: An instance of the mock agent.
    """
    return MockDataAnalystAgent()
