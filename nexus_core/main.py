"""
NEXUS CORE ALPHA v1.0.0
BajioWare AI Orchestration Engine

Este script es un demo funcional de NEXUS, mostrando cómo integrar y ejecutar agentes
en un entorno orquestado. Para ejecutar este demo, simplemente ejecute este archivo
usando Python 3.11+.

Uso:
    python -m nexus_core.main
"""

import os
import asyncio
from dotenv import load_dotenv

from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
from nexus_core.core.event_bus import EventBus
from nexus_core.core.orchestrator import NexusOrchestrator, OrchestratorConfig
from nexus_core.state.manager import StateManager
from nexus_core.agents.registry import AgentRegistry
from nexus_core.utils.logger import NexusLogger
from nexus_core.core.agent_factory import AgentFactory
from nexus_core.core.planner import NexusPlanner
from nexus_core.llm.gemini_provider import GeminiProvider
from nexus_core.core.agent_generator import AgentGenerator

# 👇 imports de skills
from nexus_core.skills.registry import SkillRegistry
from nexus_core.skills.file_reader import FileReaderSkill
from nexus_core.skills.http_client import HttpClientSkill
from nexus_core.skills.nmap_scan import NmapScanSkill
from nexus_core.skills.nuclei_scan import NucleiScanSkill

# 👇 import de memoria
from nexus_core.memory.manager import MemoryManager
from nexus_core.vector.memory import VectorMemory

load_dotenv()

gemini_api_key = os.getenv("GEMINI_API_KEY")
openai_api_key = os.getenv("OPENAI_API_KEY")


class DataAnalystAgent(BaseAgent):
    async def execute(self, task_id, payload) -> dict:
        await asyncio.sleep(1.0)
        return {"analysis": "completed", "records": 1500, "anomalies": 3}


class ReportGeneratorAgent(BaseAgent):
    async def execute(self, task_id, payload) -> dict:
        await asyncio.sleep(0.5)
        return {"report_url": "/output/report.pdf", "pages": 12}


class SecurityAuditAgent(BaseAgent):
    _fail_count: int = 0

    async def execute(self, task_id, payload) -> dict:
        if self._fail_count == 0:
            self._fail_count += 1
            raise RuntimeError("Conexión rechazada — simulando fallo")
        return {"vulnerabilities": 0, "score": 98}


async def main():
    logger = NexusLogger("NEXUS")
    logger.info("EventBus started")
    event_bus = EventBus()
    state_manager = StateManager()
    logger.info("StateManager initialized (phase: 1)")
    agent_registry = AgentRegistry()

    # 👇 inicializamos memoria
    memory_manager = MemoryManager()
    logger.info("Memory system initialized")

    vector_memory = VectorMemory()
    logger.info("Vector memory initialized")

    # 👇 probamos memoria
    memory_manager.remember_task(
        "demo-task",
        {
            "goal": "scan example.com",
            "result": "ports 80,443"
        }
    )
    memory = memory_manager.recall_task("demo-task")
    print("Memory recall:", memory)

    vector_memory.add_memory(
        "scan example.com found ports 80 and 443",
        {"target": "example.com"}
    )

    vector_memory.add_memory(
        "scan internal server found port 22 open",
        {"target": "internal"}
    )

    results = vector_memory.search_memory(
        "ports discovered on example"
    )

    print("Vector search:", results)

    # 👇 inicializamos LLM provider y AgentGenerator
    llm_provider = GeminiProvider(api_key=gemini_api_key)
    agent_generator = AgentGenerator(llm_provider, logger)

    agent_factory = AgentFactory(agent_registry, logger, agent_generator)
    planner = NexusPlanner(agent_registry, agent_factory, logger)

    orchestrator_config = OrchestratorConfig()
    orchestrator = NexusOrchestrator(
        config=orchestrator_config,
        state_manager=state_manager,
        agent_registry=agent_registry,
        event_bus=event_bus,
        logger=logger
    )

    # 👇 inicializamos SkillRegistry y registramos skills
    skill_registry = SkillRegistry()
    skill_registry.register(FileReaderSkill())
    skill_registry.register(HttpClientSkill())
    skill_registry.register(NmapScanSkill())
    skill_registry.register(NucleiScanSkill())
    logger.info(f"Skills loaded: {skill_registry.list_skills()}")

    # 👇 probamos la skill Nmap
    nmap_skill = skill_registry.get("nmap_scan")
    result = await nmap_skill.execute("scanme.nmap.org")

    print("Nmap result:", result["scan_result"][:500])

    # 👇 guardamos el resultado en memoria vectorial
    vector_memory.add_memory(
        result["scan_result"],
        {"target": "scanme.nmap.org", "type": "port_scan"}
    )

    # 👇 probamos una skill
    file_skill = skill_registry.get("file_reader")
    result = await file_skill.execute(path="nexus_core/README.md")
    print("Skill result:", result)

    # Registro de agentes estáticos
    metadata = AgentMetadata(name="Data Analyst", capabilities=[AgentCapability.DATA_ANALYSIS])
    await agent_registry.register(DataAnalystAgent(metadata=metadata))
    logger.info("Agent registered: DataAnalystAgent")

    metadata = AgentMetadata(name="Report Generator", capabilities=[AgentCapability.REPORT_GENERATION])
    await agent_registry.register(ReportGeneratorAgent(metadata=metadata))
    logger.info("Agent registered: ReportGeneratorAgent")

    metadata = AgentMetadata(name="Security Audit", capabilities=[AgentCapability.SECURITY_AUDIT])
    await agent_registry.register(SecurityAuditAgent(metadata=metadata))
    logger.info("Agent registered: SecurityAuditAgent")

    # Agente dinámico
    dynamic_agent = await agent_factory.create_agent(
        "Log Analyzer",
        AgentCapability.DATA_ANALYSIS
    )
    logger.info("Dynamic agent created: Log Analyzer")

    await orchestrator.start()
    logger.info("Planner demo: ejecutando Goal...")

    goal = "analyze sales data and generate report"
    tasks = await planner.plan(goal)
    await planner.ensure_agents(tasks)

    task_ids = []
    for t in tasks:
        task_id = await orchestrator.dispatch(
            t["task"],
            t["payload"],
            t["capability"].value,
            priority=3
        )
        task_ids.append(task_id)

    for task_id in task_ids:
        await orchestrator.wait_for_task(task_id)

    logger.info("All tasks completed.")

    status = orchestrator.get_status()
    print("════════════════════════════════════════")
    print(f"status:           {status['status']}")
    print(f"queue_size:       {status['queue_size']}")
    print(f"active_tasks:     {status['active_tasks']}")
    print(f"completed_tasks:  {status['completed_count']}")
    print("════════════════════════════════════════")

    await orchestrator.stop()


if __name__ == "__main__":
    asyncio.run(main())
