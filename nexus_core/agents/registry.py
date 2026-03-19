# nexus_core/agents/registry.py

"""
Provides a central registry for managing the lifecycle and discovery of agents.

The AgentRegistry is responsible for:
- Registering and unregistering agents in the system.
- Discovering agents based on their capabilities.
- Selecting the most suitable agent for a task based on load.
- Providing health checks and aggregated statistics for all registered agents.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from nexus_core.agents.base import AgentCapability, BaseAgent

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


class AgentRegistry:
    """
    Manages the collection of active agents in the NEXUS system.

    This class acts as a service locator for agents, allowing other parts of
    the system to find and interact with agents based on their capabilities
    and current workload.
    """

    def __init__(self, event_bus: Any = None, state_manager: Any = None, logger: Optional[logging.Logger] = None):
        """
        Initializes the AgentRegistry.

        Args:
            event_bus: An optional event bus for emitting system-wide events.
            state_manager: An optional state manager for persisting registry state.
            logger: An optional logger instance.
        """
        self._agents: Dict[str, BaseAgent] = {}
        self._lock = asyncio.Lock()
        self._event_bus = event_bus
        self._state_manager = state_manager
        self._logger = logger or get_logger("AgentRegistry")

    async def register(self, agent: BaseAgent) -> None:
        """
        Registers a new agent with the registry.

        If an agent with the same ID already exists, it will be overwritten.

        Args:
            agent: The agent instance to register.
        """
        async with self._lock:
            if agent.agent_id in self._agents:
                self._logger.warning(f"Overwriting existing agent registration for ID: {agent.agent_id}")
            self._agents[agent.agent_id] = agent
            self._logger.info(f"Agent '{agent.name}' (ID: {agent.agent_id}) registered.")

        # state_manager sync omitido — update_agent_state no implementado aún

        if self._event_bus:
            try:
                from nexus_core.core.event_bus import Event, EventType
                await self._event_bus.publish(Event(
                    type=EventType.AGENT_REGISTERED,
                    payload={"agent_id": agent.agent_id, "metadata": agent.metadata.to_dict()},
                    source="AgentRegistry"
                ))
            except Exception:
                pass

    async def unregister(self, agent_id: str) -> None:
        """
        Removes an agent from the registry.

        Args:
            agent_id: The ID of the agent to unregister.
        """
        async with self._lock:
            agent = self._agents.pop(agent_id, None)

        if agent:
            self._logger.info(f"Agent '{agent.name}' (ID: {agent_id}) unregistered.")
            if self._event_bus:
                await self._event_bus.publish("agent.unregistered", {"agent_id": agent_id})
        else:
            self._logger.warning(f"Attempted to unregister non-existent agent with ID: {agent_id}")

    async def discover(self, capability: AgentCapability) -> List[BaseAgent]:
        """
        Finds all agents that possess a specific capability.

        The returned list is sorted by the current load, with the least
        busy agents appearing first.

        Args:
            capability: The capability to search for.

        Returns:
            A list of agent instances that have the specified capability.
        """
        async with self._lock:
            # Create a snapshot to work with
            agents_snapshot = list(self._agents.values())

        capable_agents = [
            agent for agent in agents_snapshot
            if agent.metadata.has_capability(capability)
        ]

        # Sort by current load (_current_tasks) ascending
        capable_agents.sort(key=lambda a: a._current_tasks)
        return capable_agents

    async def get_best_agent(self, capability: AgentCapability) -> Optional[BaseAgent]:
        """
        Finds the most suitable agent for a task requiring a specific capability.

        The "best" agent is defined as the one that is currently available and
        has the lowest load ratio (current tasks / max concurrent tasks).

        Args:
            capability: The required capability.

        Returns:
            The best available agent instance, or None if no suitable agent is found.
        """
        async with self._lock:
            agents_snapshot = list(self._agents.values())

        available_agents = [
            agent for agent in agents_snapshot
            if agent.is_available and agent.metadata.has_capability(capability)
        ]

        if not available_agents:
            return None

        # Calculate load ratio and find the agent with the minimum
        best_agent = min(
            available_agents,
            key=lambda a: a._current_tasks / a.metadata.max_concurrent
        )
        return best_agent

    def get(self, agent_id: str) -> Optional[BaseAgent]:
        """
        Retrieves a specific agent by its ID.

        Args:
            agent_id: The ID of the agent to retrieve.

        Returns:
            The agent instance, or None if not found.
        """
        return self._agents.get(agent_id)

    async def get_all(self) -> Dict[str, BaseAgent]:
        """
        Retrieves all registered agents.

        Returns:
            A dictionary mapping agent IDs to agent instances.
        """
        async with self._lock:
            return dict(self._agents)

    async def health_check(self) -> Dict[str, bool]:
        """
        Performs a simple health check on all registered agents.

        The current implementation checks the `is_available` property.

        Returns:
            A dictionary mapping agent IDs to their availability status (bool).
        """
        async with self._lock:
            return {
                agent_id: agent.is_available
                for agent_id, agent in self._agents.items()
            }

    def get_agents_by_capability(self, capability):
        """
        Devuelve los agentes que soportan una capacidad específica
        """

        result = []

        for agent in self._agents.values():

            for cap in agent.metadata.capabilities:
                if cap.value == capability:
                    result.append(agent)

        return result

    def get_stats(self) -> Dict[str, Any]:
        """
        Provides aggregated statistics about the agents in the registry.

        Returns:
            A dictionary with statistics, including total agents, agents by
            capability, and currently available agents.
        """
        total_agents = len(self._agents)
        available_now = sum(1 for agent in self._agents.values() if agent.is_available)

        agents_by_capability: Dict[str, int] = {}
        for capability in AgentCapability:
            count = sum(
                1 for agent in self._agents.values()
                if agent.metadata.has_capability(capability)
            )
            if count > 0:
                agents_by_capability[capability.value] = count

        return {
            "total_agents": total_agents,
            "available_agents": available_now,
            "agents_by_capability": agents_by_capability,
        }
