import sys, logging, asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("nexus_service")

class NexusService:
    def __init__(self, settings):
        self.settings     = settings
        self._orch        = None
        self._planner     = None
        self._registry    = None
        self._factory     = None
        self._event_bus   = None
        self._state_mgr   = None
        self._initialized = False
        self._mode        = "offline"

    async def initialize(self) -> None:
        # Añadir BW-AI root y nexus_core al path
        nexus_root = Path(__file__).parent.parent.parent / "nexus_core"
        bw_root    = nexus_root.parent
        for p in [str(bw_root), str(nexus_root)]:
            if p not in sys.path:
                sys.path.insert(0, p)
        try:
            # ── Imports exactos del main.py de NEXUS ──
            from nexus_core.core.event_bus       import EventBus
            from nexus_core.core.orchestrator    import NexusOrchestrator, OrchestratorConfig
            from nexus_core.state.manager        import StateManager
            from nexus_core.agents.registry      import AgentRegistry
            from nexus_core.utils.logger         import NexusLogger
            from nexus_core.core.agent_factory   import AgentFactory
            from nexus_core.core.planner         import NexusPlanner
            from nexus_core.core.agent_generator import AgentGenerator
            from nexus_core.llm.gemini_provider  import GeminiProvider
            import os

            nexus_logger   = NexusLogger("NEXUS-API")
            event_bus      = EventBus()
            state_manager  = StateManager()
            agent_registry = AgentRegistry()

            # LLM provider — usa Gemini si está disponible, sino sin generator
            gemini_key = os.getenv("GEMINI_API_KEY", "")
            if gemini_key:
                llm_provider    = GeminiProvider(api_key=gemini_key)
                agent_generator = AgentGenerator(llm_provider, nexus_logger)
            else:
                agent_generator = None

            agent_factory = AgentFactory(agent_registry, nexus_logger, agent_generator)
            planner       = NexusPlanner(agent_registry, agent_factory, nexus_logger)

            orchestrator = NexusOrchestrator(
                config         = OrchestratorConfig(),
                state_manager  = state_manager,
                agent_registry = agent_registry,
                event_bus      = event_bus,
                logger         = nexus_logger,
            )

            await orchestrator.start()

            # Guardar referencias
            self._event_bus  = event_bus
            self._state_mgr  = state_manager
            self._registry   = agent_registry
            self._factory    = agent_factory
            self._planner    = planner
            self._orch       = orchestrator
            self._initialized = True
            self._mode        = "online"
            logger.info("✅ NEXUS initialized — ONLINE mode")

        except Exception as e:
            logger.warning(f"NEXUS offline: {e}")
            self._mode = "offline"

    async def get_status(self) -> Dict[str, Any]:
        if self._mode == "offline":
            return {"status": "offline", "mode": "demo",
                    "message": "NEXUS running in demo mode",
                    "agents": 0, "tasks_active": 0,
                    "tasks_completed": 0, "uptime_seconds": 0}
        try:
            s = self._orch.get_status()
            agents = await self.get_agents()
            return {
                "status":           "online",
                "mode":             "live",
                "message":          "NEXUS operational",
                "agents":           len(agents),
                "tasks_active":     s.get("active_tasks", 0),
                "tasks_completed":  s.get("completed_count", 0),
                "queue_size":       s.get("queue_size", 0),
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def submit_goal(self, goal: str, context: Dict = {}) -> Dict:
        if self._mode == "offline":
            return {"goal": goal, "status": "queued_offline",
                    "message": "Demo mode — NEXUS not connected",
                    "tasks": [], "task_ids": []}
        try:
            tasks = await self._planner.plan(goal)
            await self._planner.ensure_agents(tasks)
            task_ids = []
            for t in tasks:
                # create_task evita bloquear el event loop de FastAPI
                tid = f"task_{len(task_ids)}_{t['task']}"
                asyncio.create_task(
                    self._orch.dispatch(
                        t["task"], t["payload"],
                        t["capability"].value, priority=3
                    )
                )
                task_ids.append(tid)
            return {"goal": goal, "status": "dispatched",
                    "tasks": [t["task"] for t in tasks],
                    "task_ids": task_ids}
        except Exception as e:
            logger.error(f"submit_goal error: {e}")
            raise

    async def get_agents(self) -> List[Dict]:
        if self._mode == "offline":
            return [
                {"id":"demo-arch",  "name":"ArchitectAgent", "status":"offline","capabilities":["architecture","planning"]},
                {"id":"demo-build", "name":"BuilderAgent",   "status":"offline","capabilities":["code_generation"]},
                {"id":"demo-sec",   "name":"SecurityAgent",  "status":"offline","capabilities":["nmap_scan","nuclei_scan"]},
                {"id":"demo-test",  "name":"TesterAgent",    "status":"offline","capabilities":["testing"]},
                {"id":"demo-fix",   "name":"FixerAgent",     "status":"offline","capabilities":["bug_fix"]},
            ]
        try:
            agents = list((await self._registry.get_all()).values())
            return [{"id":   getattr(a, "id",   getattr(getattr(a,"metadata",a),"id",   str(i))),
                     "name": getattr(a, "name", getattr(getattr(a,"metadata",a),"name", "Agent")),
                     "status": "online",
                     "capabilities": [str(c) for c in getattr(
                         getattr(a,"metadata",a),"capabilities",[])]}
                    for i, a in enumerate(agents)]
        except Exception as e:
            logger.error(f"get_agents: {e}"); return []

    async def get_tasks(self, status: Optional[str] = None) -> List[Dict]:
        if self._mode == "offline": return []
        try:
            s     = self._orch.get_status()
            tasks = s.get("tasks", [])
            if status:
                tasks = [t for t in tasks if t.get("status") == status]
            return tasks
        except Exception as e:
            logger.error(f"get_tasks: {e}"); return []

    async def shutdown(self) -> None:
        try:
            if self._orch:
                await self._orch.stop()
            logger.info("NEXUS shutdown OK")
        except Exception as e:
            logger.error(f"shutdown: {e}")
