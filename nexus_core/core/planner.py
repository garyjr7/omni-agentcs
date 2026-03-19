"""
NEXUS Planner Engine
Goal → Tasks decomposition
"""

from nexus_core.agents.base import AgentCapability


class NexusPlanner:

    def __init__(self, agent_registry, agent_factory, logger):
        self.registry = agent_registry
        self.factory = agent_factory
        self.logger = logger

    async def plan(self, goal: str):
        """
        Convierte un objetivo en tareas ejecutables
        """

        goal = goal.lower()

        tasks = []

        if "analysis" in goal or "analyze" in goal:
            tasks.append({
                "task": "data_analysis",
                "capability": AgentCapability.DATA_ANALYSIS,
                "payload": {"dataset": "data.csv"}
            })

        if "report" in goal:
            tasks.append({
                "task": "generate_report",
                "capability": AgentCapability.REPORT_GENERATION,
                "payload": {"source": "analysis"}
            })

        if "security" in goal or "audit" in goal:
            tasks.append({
                "task": "security_audit",
                "capability": AgentCapability.SECURITY_AUDIT,
                "payload": {"target": "system"}
            })

        return tasks

    async def ensure_agents(self, tasks):
        """
        Verifica si existen agentes para cada capacidad
        y los crea si no existen
        """

        for task in tasks:

            capability = task["capability"]

            agents = self.registry.get_agents_by_capability(
                capability.value
            )

            if not agents:
                self.logger.info(
                    f"No agent found for {capability}. Creating one..."
                )

                await self.factory.create_agent(
                    capability.name.title(),
                    capability
                )
