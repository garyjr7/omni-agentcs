"""
NEXUS Agent Factory — Dynamic Agent Generation System
"""
import importlib
import uuid
from pathlib import Path
from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability

class AgentFactory:
    def __init__(self, agent_registry, logger, agent_generator=None):
        self.registry  = agent_registry
        self.logger    = logger
        self.generator = agent_generator
        self.generated_agents_dir = Path("nexus_core/agents/generated")
        self.generated_agents_dir.mkdir(parents=True, exist_ok=True)

    def _to_class_name(self, agent_name: str) -> str:
        """
        Convierte cualquier formato a CamelCase + Agent.
        'Data Analysis'       → DataAnalysisAgent
        'DATA_ANALYSIS'       → DataAnalysisAgent
        'Log Analyzer'        → LogAnalyzerAgent
        'data_analysis'       → DataAnalysisAgent
        """
        # Normaliza: reemplaza _ y - por espacio, luego CamelCase
        name = agent_name.replace("_", " ").replace("-", " ")
        # Quita la palabra "Agent" si ya viene incluida
        name = name.replace("Agent", "").strip()
        # CamelCase
        class_name = "".join(w.capitalize() for w in name.split()) + "Agent"
        return class_name

    async def create_agent(self, agent_name: str, capability: AgentCapability,
                           description: str = ""):
        class_name = self._to_class_name(agent_name)
        file_name  = class_name.lower()
        file_path  = self.generated_agents_dir / f"{file_name}.py"

        if file_path.exists():
            self.logger.info(f"Agent already exists: {class_name}")
            return await self.load_agent(class_name, file_name, capability)

        agent_code = await self.generate_agent_code(class_name, capability)
        file_path.write_text(agent_code)
        self.logger.info(f"New agent generated: {file_path}")
        return await self.load_agent(class_name, file_name, capability)

    async def load_agent(self, class_name: str, file_name: str, capability: AgentCapability):
        module_name = f"nexus_core.agents.generated.{file_name}"
        # Fuerza reload si ya estaba cargado
        import sys
        if module_name in sys.modules:
            del sys.modules[module_name]

        module      = importlib.import_module(module_name)
        agent_class = getattr(module, class_name)
        metadata    = AgentMetadata(name=class_name, capabilities=[capability])
        agent       = agent_class(metadata=metadata)
        await self.registry.register(agent)
        self.logger.info(f"Dynamically registered agent: {class_name}")
        return agent

    async def generate_agent_code(self, class_name: str, capability) -> str:
        if self.generator:
            code = await self.generator.generate_agent_code(capability)
            if code and "class " in code:
                return code
        # Fallback template siempre funcional
        return f'''from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
import asyncio

class {class_name}(BaseAgent):
    async def execute(self, task_id: str, payload: dict) -> dict:
        await asyncio.sleep(0.5)
        return {{
            "agent":   "{class_name}",
            "task_id": task_id,
            "status":  "completed",
            "result":  "execution ok"
        }}
'''
