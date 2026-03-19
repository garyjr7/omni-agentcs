"""
nexus_core/junior_bridge.py — NEXUS PRO v2.0
El conector central: une nexus_api ↔ Orchestrator ↔ Registry ↔ LLM ↔ Memory

Flujo:
  Dashboard → nexus_api → junior_bridge → NexusOrchestrator → Agentes
                                    ↕
                              Registry + LLM + Memory + EventBus
"""
import asyncio
import logging
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))
try:
    from nexus_api.services.memory_service import save_message as _mem_save, get_context as _mem_ctx, init_memory_table as _mem_init
    _mem_init()
    _MEMORY_ENABLED = True
except Exception:
    _MEMORY_ENABLED = False

import os
from typing import Optional

logger = logging.getLogger("nexus.junior_bridge")

# ── Singletons ────────────────────────────────────────────────
_bridge: Optional["JuniorBridge"] = None


class JuniorBridge:
    """
    Punto de entrada unificado para interactuar con el núcleo de NEXUS.
    Expone una API simple para despachar tareas, consultar estado y
    comunicarse con el LLM desde cualquier ruta de nexus_api.
    """

    def __init__(self):
        self.orchestrator   = None
        self.registry       = None
        self.llm            = None
        self.memory         = None
        self.event_bus      = None
        self.state_manager  = None
        self.workflow_manager = None
        self._ready         = False
        logger.info("[JuniorBridge] Instancia creada")

    async def initialize(self) -> bool:
        """Conecta todos los módulos del core."""
        errors = []

        try:
            from nexus_core.core.event_bus import EventBus
            self.event_bus = EventBus()
            logger.info("[JuniorBridge] ✓ EventBus")
        except Exception as e:
            errors.append(f"EventBus: {e}")

        try:
            from nexus_core.state.manager import StateManager
            self.state_manager = StateManager()
            logger.info("[JuniorBridge] ✓ StateManager")
        except Exception as e:
            errors.append(f"StateManager: {e}")

        try:
            from nexus_core.agents.registry import AgentRegistry
            self.registry = AgentRegistry(event_bus=self.event_bus)
            logger.info("[JuniorBridge] ✓ AgentRegistry")
        except Exception as e:
            errors.append(f"AgentRegistry: {e}")

        try:
            from nexus_core.core.orchestrator import NexusOrchestrator, OrchestratorConfig
            if self.state_manager and self.registry and self.event_bus:
                self.orchestrator = NexusOrchestrator(
                    config=OrchestratorConfig(),
                    state_manager=self.state_manager,
                    agent_registry=self.registry,
                    event_bus=self.event_bus,
                )
                asyncio.ensure_future(self.orchestrator.start())
                logger.info("[JuniorBridge] ✓ NexusOrchestrator")
        except Exception as e:
            errors.append(f"Orchestrator: {e}")

        try:
            from nexus_core.llm.abstraction import LLMFactory, NexusLLM
            clients = LLMFactory.create_from_env()
            if clients:
                keys = list(clients.keys())
                self.llm = NexusLLM(
                    primary=clients[keys[0]],
                    fallback=clients[keys[1]] if len(keys) > 1 else None,
                )
                logger.info(f"[JuniorBridge] ✓ LLM ({', '.join(keys)})")
            else:
                logger.warning("[JuniorBridge] ⚠ LLM sin API keys")
        except Exception as e:
            errors.append(f"LLM: {e}")

        try:
            from nexus_core.memory.manager import MemoryManager
            self.memory = MemoryManager()
            logger.info("[JuniorBridge] ✓ MemoryManager")
        except Exception as e:
            errors.append(f"Memory: {e}")

        try:
            from nexus_core.workflow_manager import WorkflowManager
            if self.event_bus:
                self.workflow_manager = WorkflowManager(
                    event_bus=self.event_bus,
                    orchestrator=self.orchestrator,
                )
                logger.info("[JuniorBridge] ✓ WorkflowManager")
        except Exception as e:
            errors.append(f"WorkflowManager: {e}")

        # Registrar agentes disponibles
        await self._register_agents()

        self._ready = len(errors) == 0
        if errors:
            logger.warning(f"[JuniorBridge] Inicializado con {len(errors)} advertencias: {errors}")
        else:
            logger.info("[JuniorBridge] ✓ Todo listo — NEXUS operativo")

        return True  # siempre True — degraded es aceptable

    async def _register_agents(self):
        """Registra todos los agentes disponibles en el Registry."""
        if not self.registry:
            return

        import importlib
        from nexus_core.agents.base import AgentMetadata, AgentCapability

        # Agentes que necesitan metadata explícita
        _agents_with_meta = [
            ("nexus_core.agents.generated.bashagent", "BashAgent",
             AgentMetadata(name="BashAgent", capabilities=[AgentCapability.FILE_OPERATIONS])),
            ("nexus_core.agents.generated.codeagent", "CodeAgent",
             AgentMetadata(name="CodeAgent", capabilities=[AgentCapability.CODE_GENERATION])),
            ("nexus_core.agents.generated.fileagent", "FileAgent",
             AgentMetadata(name="FileAgent", capabilities=[AgentCapability.FILE_OPERATIONS])),
        ]

        registered = []
        for mod_path, cls_name, meta in _agents_with_meta:
            try:
                mod = importlib.import_module(mod_path)
                AgentClass = getattr(mod, cls_name)
                agent = AgentClass(metadata=meta)
                await self.registry.register(agent)
                registered.append(cls_name)
            except Exception as e:
                logger.warning(f"[JuniorBridge] ⚠ {cls_name}: {e}")

        if registered:
            logger.info(f"[JuniorBridge] ✓ Agentes: {', '.join(registered)}")

    # ── API pública ──────────────────────────────────────────

    async def dispatch(
        self,
        task_name: str,
        payload: dict,
        capability: str = "code_generation",
        priority: int = 5,
    ) -> str:
        """Despacha una tarea al Orchestrator. Retorna task_id."""
        if self.orchestrator:
            return await self.orchestrator.dispatch(
                task_name=task_name,
                payload=payload,
                required_capability=capability,
                priority=priority,
            )
        raise RuntimeError("Orchestrator no disponible")

    async def ask_llm(self, system: str, user: str) -> str:
        """Consulta rápida al LLM con fallback automático."""
        if self.llm:
            return await self.llm.ask(system, user)
        raise RuntimeError("LLM no disponible — agrega API keys al .env")

    async def remember(self, key: str, value: str, collection: str = "nexus"):
        """Guarda en memoria vectorial."""
        if self.memory:
            await self.memory.store(key=key, value=value, collection=collection)

    async def recall(self, query: str, collection: str = "nexus", top_k: int = 5):
        """Busca en memoria vectorial."""
        if self.memory:
            return await self.memory.search(query=query, collection=collection, top_k=top_k)
        return []

    def status(self) -> dict:
        """Estado completo del bridge."""
        return {
            "ready": self._ready,
            "orchestrator": self.orchestrator is not None,
            "registry": self.registry is not None,
            "llm": self.llm is not None,
            "memory": self.memory is not None,
            "event_bus": self.event_bus is not None,
            "workflow_manager": self.workflow_manager is not None,
        }


# ── Singleton helpers ─────────────────────────────────────────

async def initialize_bridge() -> bool:
    global _bridge
    if _bridge is None:
        _bridge = JuniorBridge()
    return await _bridge.initialize()


def get_junior_bridge() -> Optional[JuniorBridge]:
    return _bridge
