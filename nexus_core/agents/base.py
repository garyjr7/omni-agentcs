# nexus_core/agents/base.py

"""
Defines the foundational abstract base class for all agents in the NEXUS system.

This module provides the core components for agent creation, including:
- AgentCapability: An enumeration of skills an agent can possess.
- AgentMetadata: A dataclass for an agent's static configuration.
- AgentStats: A class for tracking an agent's performance metrics.
- BaseAgent: An abstract class that all concrete agents must inherit from,
  defining the common interface and execution lifecycle.
"""

import abc
import asyncio
import logging
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

# Assuming a logger utility exists. If not, a standard logger is used.
try:
    from nexus_core.utils.logger import get_logger
except ImportError:
    # Fallback to standard logging if the custom logger is not available
    def get_logger(name: str) -> logging.Logger:
        """Provides a basic logger instance."""
        logger = logging.getLogger(name)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger


class AgentCapability(str, Enum):
    """Enumerates the potential capabilities of an agent."""
    CODE_GENERATION = "code_generation"
    DATA_ANALYSIS = "data_analysis"
    WEB_SEARCH = "web_search"
    FILE_OPERATIONS = "file_operations"
    API_CALLS = "api_calls"
    DATABASE_QUERIES = "database_queries"
    SECURITY_AUDIT = "security_audit"
    REPORT_GENERATION = "report_generation"
    ORCHESTRATION = "orchestration"
    LLM_INTERACTION = "llm_interaction"


@dataclass
class AgentMetadata:
    """
    Holds the static configuration and metadata for an agent.

    Attributes:
        agent_id: A unique identifier for the agent instance.
        name: The human-readable name of the agent.
        version: The version of the agent's implementation.
        capabilities: A list of skills the agent possesses.
        model: The underlying model used by the agent (e.g., an LLM).
        max_concurrent: The maximum number of tasks the agent can run in parallel.
        timeout_seconds: The default timeout for a single task.
        tags: A list of arbitrary tags for grouping or filtering agents.
        created_at: The timestamp when the agent instance was created.
    """
    name: str
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: str = "1.0.0"
    capabilities: List[AgentCapability] = field(default_factory=list)
    model: str = "openai/gpt-4o-mini"
    max_concurrent: int = 3
    timeout_seconds: int = 120
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def has_capability(self, cap: AgentCapability) -> bool:
        """
        Checks if the agent possesses a specific capability.

        Args:
            cap: The capability to check for.

        Returns:
            True if the agent has the capability, False otherwise.
        """
        return cap in self.capabilities

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes the metadata to a dictionary.

        Returns:
            A dictionary representation of the agent's metadata.
        """
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "version": self.version,
            "capabilities": [c.value for c in self.capabilities],
            "model": self.model,
            "max_concurrent": self.max_concurrent,
            "timeout_seconds": self.timeout_seconds,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
        }


class AgentStats:
    """
    Tracks runtime statistics for an agent's performance.
    """
    def __init__(self) -> None:
        self.total_tasks: int = 0
        self.completed_tasks: int = 0
        self.failed_tasks: int = 0
        self.total_retries: int = 0
        self.avg_duration_ms: float = 0.0
        self.last_active: Optional[datetime] = None

    def update(self, success: bool, duration_ms: float) -> None:
        """
        Updates the statistics after a task is completed.

        Args:
            success: Whether the task succeeded or failed.
            duration_ms: The duration of the task in milliseconds.
        """
        self.total_tasks += 1
        if success:
            self.completed_tasks += 1
        else:
            self.failed_tasks += 1

        # Update average duration using a weighted average
        if self.completed_tasks == 1 and success:
             self.avg_duration_ms = duration_ms
        elif success:
            total_duration = self.avg_duration_ms * (self.completed_tasks - 1)
            self.avg_duration_ms = (total_duration + duration_ms) / self.completed_tasks

        self.last_active = datetime.utcnow()

    def success_rate(self) -> float:
        """
        Calculates the success rate of the agent.

        Returns:
            The success rate as a float between 0.0 and 1.0. Returns 0.0 if
            no tasks have been processed.
        """
        if self.total_tasks == 0:
            return 0.0
        return self.completed_tasks / self.total_tasks


class BaseAgent(abc.ABC):
    """
    Abstract base class for all agents in the NEXUS system.

    This class defines the common interface and lifecycle for agent operations,
    including task execution, state management, and statistics tracking.
    """

    def __init__(self, metadata: AgentMetadata, event_bus: Any = None, logger: Optional[logging.Logger] = None):
        """
        Initializes the BaseAgent.

        Args:
            metadata: The static configuration for the agent.
            event_bus: An optional event bus for emitting system-wide events.
            logger: An optional logger instance. If not provided, a default
                    logger will be created.
        """
        self.metadata = metadata
        self._event_bus = event_bus
        self._logger = logger or get_logger(f"Agent.{self.metadata.name}")
        self._stats = AgentStats()
        self._current_tasks: int = 0
        self._lock = asyncio.Lock()

    @abc.abstractmethod
    async def execute(self, task_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        The core logic of the agent's task execution.

        This method must be implemented by all concrete agent subclasses. It
        contains the specific logic for handling a given task.

        Args:
            task_id: A unique identifier for the task.
            payload: A dictionary containing the data required to execute the task.

        Returns:
            A dictionary containing the result of the task execution.
        """
        raise NotImplementedError

    async def run(self, task_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orchestrates the full lifecycle of a task execution.

        This method wraps the `execute` call with pre-execution setup,
        post-execution cleanup, error handling, and timeout management.

        Args:
            task_id: A unique identifier for the task.
            payload: The data for the task.

        Returns:
            A dictionary containing the outcome of the task, including success
            status, result, error message, and duration.
        """
        start_time = time.perf_counter()
        try:
            await self._pre_execute(task_id, payload)
            
            result = await asyncio.wait_for(
                self.execute(task_id, payload),
                timeout=self.metadata.timeout_seconds
            )
            
            duration_ms = (time.perf_counter() - start_time) * 1000
            await self._post_execute(task_id, result, duration_ms)
            
            return {
                "success": True,
                "result": result,
                "error": None,
                "duration_ms": duration_ms
            }
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            await self._handle_failure(task_id, e, duration_ms)
            return {
                "success": False,
                "result": {},
                "error": f"{type(e).__name__}: {e}",
                "duration_ms": duration_ms
            }

    async def _pre_execute(self, task_id: str, payload: Dict[str, Any]) -> None:
        """
        Handles pre-task execution logic.
        """
        async with self._lock:
            self._current_tasks += 1
        self._logger.info(f"Starting task {task_id} on agent {self.name}.")
        if self._event_bus:
            await self._event_bus.publish(
                "agent.task.started",
                {"agent_id": self.agent_id, "task_id": task_id, "payload": payload}
            )

    async def _post_execute(self, task_id: str, result: Dict[str, Any], duration_ms: float) -> None:
        """
        Handles successful post-task execution logic.
        """
        async with self._lock:
            self._current_tasks -= 1
            self._stats.update(success=True, duration_ms=duration_ms)
        self._logger.info(f"Task {task_id} completed successfully in {duration_ms:.2f}ms.")
        if self._event_bus:
            await self._event_bus.publish(
                "agent.task.completed",
                {"agent_id": self.agent_id, "task_id": task_id, "result": result, "duration_ms": duration_ms}
            )

    async def _handle_failure(self, task_id: str, error: Exception, duration_ms: float) -> None:
        """
        Handles task execution failures.
        """
        async with self._lock:
            self._current_tasks -= 1
            self._stats.update(success=False, duration_ms=duration_ms)
        
        error_type = type(error).__name__
        self._logger.error(
            f"Task {task_id} failed on agent {self.name} after {duration_ms:.2f}ms. "
            f"Error: {error_type}: {error}",
            exc_info=True
        )
        
        if self._event_bus:
            await self._event_bus.publish(
                "agent.task.failed",
                {
                    "agent_id": self.agent_id,
                    "task_id": task_id,
                    "error": f"{error_type}: {error}",
                    "traceback": traceback.format_exc(),
                    "duration_ms": duration_ms
                }
            )

    @property
    def is_available(self) -> bool:
        """
        Checks if the agent can accept new tasks.

        Returns:
            True if the number of current tasks is less than the maximum
            concurrent limit, False otherwise.
        """
        return self._current_tasks < self.metadata.max_concurrent

    @property
    def agent_id(self) -> str:
        """Returns the agent's unique ID."""
        return self.metadata.agent_id

    @property
    def name(self) -> str:
        """Returns the agent's name."""
        return self.metadata.name

    def get_stats(self) -> Dict[str, Any]:
        """
        Retrieves the current statistics and basic metadata of the agent.

        Returns:
            A dictionary containing performance metrics and identifying info.
        """
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "is_available": self.is_available,
            "current_tasks": self._current_tasks,
            "max_concurrent": self.metadata.max_concurrent,
            "stats": {
                "total_tasks": self._stats.total_tasks,
                "completed_tasks": self._stats.completed_tasks,
                "failed_tasks": self._stats.failed_tasks,
                "success_rate": self._stats.success_rate(),
                "avg_duration_ms": self._stats.avg_duration_ms,
                "last_active": self._stats.last_active.isoformat() if self._stats.last_active else None,
            }
        }
