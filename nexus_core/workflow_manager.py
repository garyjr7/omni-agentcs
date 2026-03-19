"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  BAJIOWARE NEXUS — WORKFLOW MANAGER                                          ║
║  Conecta WorkflowDAG con NexusOrchestrator via EventBus                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Este es el componente que hace a Nexus superior a LangGraph:               ║
║  - Workflows definidos en JSON/dict                                          ║
║  - Ejecución paralela de nodos sin dependencias                              ║
║  - Inyección automática de resultados entre nodos                            ║
║  - Tolerancia a fallos heredada del Orchestrator                             ║
║  - EventBus para comunicación asíncrona                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from nexus_core.core.event_bus import EventBus, EventType, Event

logger = logging.getLogger("nexus.workflow_manager")


class WorkflowStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


class NodeStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    SKIPPED   = "skipped"


@dataclass
class WorkflowNode:
    """Un nodo en el grafo del workflow."""
    node_id: str
    task_name: str
    capability: str
    payload: Dict[str, Any]
    dependencies: List[str] = field(default_factory=list)
    status: NodeStatus = NodeStatus.PENDING
    task_id: Optional[str] = None        # task_id del Orchestrator
    result: Optional[Dict] = None
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


@dataclass
class WorkflowInstance:
    """Una instancia de ejecución de un workflow."""
    workflow_id: str
    name: str
    nodes: Dict[str, WorkflowNode]
    status: WorkflowStatus = WorkflowStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)  # datos compartidos entre nodos

    def to_dict(self) -> Dict:
        return {
            "workflow_id": self.workflow_id,
            "name": self.name,
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "nodes": {
                nid: {
                    "node_id": n.node_id,
                    "task_name": n.task_name,
                    "capability": n.capability,
                    "status": n.status,
                    "dependencies": n.dependencies,
                    "result": n.result,
                    "error": n.error,
                    "started_at": n.started_at,
                    "completed_at": n.completed_at,
                }
                for nid, n in self.nodes.items()
            },
            "context_keys": list(self.context.keys()),
        }


class WorkflowManager:
    """
    Gestor de workflows que conecta WorkflowDAG con NexusOrchestrator.

    Flujo de ejecución:
    1. create_workflow() — define el grafo
    2. run_workflow()    — despacha nodos sin dependencias al Orchestrator
    3. EventBus         — escucha TASK_COMPLETED/FAILED
    4. _on_task_done()  — evalúa qué nodos pueden ejecutarse ahora
    5. Repite hasta completar o fallar
    """

    def __init__(self, event_bus: EventBus, orchestrator=None):
        self._bus = event_bus
        self._orchestrator = orchestrator
        self._workflows: Dict[str, WorkflowInstance] = {}
        self._task_to_node: Dict[str, tuple] = {}  # task_id → (workflow_id, node_id)
        self._completion_events: Dict[str, asyncio.Event] = {}
        self._subscribed = False
        logger.info("WorkflowManager iniciado")

    async def _ensure_subscribed(self):
        """Suscribirse al EventBus una sola vez."""
        if not self._subscribed:
            await self._bus.subscribe(EventType.TASK_COMPLETED, self._on_task_completed)
            await self._bus.subscribe(EventType.TASK_FAILED, self._on_task_failed)
            self._subscribed = True
            logger.info("WorkflowManager suscrito al EventBus")

    def create_workflow(self, name: str, definition: Dict[str, Any]) -> WorkflowInstance:
        """
        Crea un workflow desde una definición dict.

        Ejemplo de definición:
        {
            "fetch_data": {
                "task_name": "FetchData",
                "capability": "code_generation",
                "payload": {"type": "bash", "command": "curl ..."},
                "dependencies": []
            },
            "process": {
                "task_name": "Process",
                "capability": "code_generation",
                "payload": {"type": "analyze", "filepath": "data.json"},
                "dependencies": ["fetch_data"]
            }
        }
        """
        workflow_id = f"wf_{uuid.uuid4().hex[:8]}"
        nodes = {}

        for node_id, node_def in definition.items():
            nodes[node_id] = WorkflowNode(
                node_id=node_id,
                task_name=node_def.get("task_name", node_id),
                capability=node_def.get("capability", "code_generation"),
                payload=node_def.get("payload", {}),
                dependencies=node_def.get("dependencies", []),
            )

        workflow = WorkflowInstance(
            workflow_id=workflow_id,
            name=name,
            nodes=nodes,
        )
        self._workflows[workflow_id] = workflow
        logger.info(f"Workflow creado: {name} | ID: {workflow_id} | Nodos: {len(nodes)}")
        return workflow

    async def run_workflow(
        self,
        workflow_id: str,
        wait: bool = True,
        timeout: float = 300.0,
    ) -> WorkflowInstance:
        """
        Ejecuta un workflow completo.
        Si wait=True, espera hasta que complete o falle.
        """
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow {workflow_id} no encontrado")

        await self._ensure_subscribed()

        workflow.status = WorkflowStatus.RUNNING
        self._completion_events[workflow_id] = asyncio.Event()

        # Despachar nodos sin dependencias (nodos raíz)
        ready = self._get_ready_nodes(workflow)
        if not ready:
            logger.error(f"Workflow {workflow_id}: no hay nodos listos para ejecutar")
            workflow.status = WorkflowStatus.FAILED
            return workflow

        logger.info(f"Workflow {workflow_id}: iniciando con {len(ready)} nodos raíz")
        await self._dispatch_nodes(workflow, ready)

        if wait:
            try:
                await asyncio.wait_for(
                    self._completion_events[workflow_id].wait(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                workflow.status = WorkflowStatus.FAILED
                logger.error(f"Workflow {workflow_id}: timeout después de {timeout}s")

        return workflow

    def _get_ready_nodes(self, workflow: WorkflowInstance) -> List[WorkflowNode]:
        """Retorna nodos cuyas dependencias están completadas."""
        ready = []
        for node in workflow.nodes.values():
            if node.status != NodeStatus.PENDING:
                continue
            deps_ok = all(
                workflow.nodes[dep].status == NodeStatus.COMPLETED
                for dep in node.dependencies
                if dep in workflow.nodes
            )
            if deps_ok:
                ready.append(node)
        return ready

    async def _dispatch_nodes(self, workflow: WorkflowInstance, nodes: List[WorkflowNode]):
        """Despacha múltiples nodos en paralelo al Orchestrator."""
        for node in nodes:
            node.status = NodeStatus.RUNNING
            node.started_at = datetime.now().isoformat()

            # Inyectar contexto del workflow en el payload
            enriched_payload = {**node.payload, "_workflow_context": workflow.context}

            if self._orchestrator:
                # Despachar via Orchestrator real
                task_id = await self._orchestrator.dispatch(
                    task_name=node.task_name,
                    payload=enriched_payload,
                    required_capability=node.capability,
                    priority=5,
                )
            else:
                # Fallback: ejecutar directamente con JuniorAgent
                task_id = await self._execute_with_junior(node, enriched_payload, workflow)

            node.task_id = task_id
            self._task_to_node[task_id] = (workflow.workflow_id, node.node_id)
            logger.info(f"Nodo despachado: {node.node_id} → task_id: {task_id}")

    async def _execute_with_junior(
        self,
        node: WorkflowNode,
        payload: Dict,
        workflow: WorkflowInstance,
    ) -> str:
        """Ejecuta un nodo directamente con JuniorAgent (sin Orchestrator)."""
        task_id = f"task_{uuid.uuid4().hex[:8]}"

        async def _run():
            try:
                from nexus_core.agents.junior_agent import JuniorAgent
                agent = JuniorAgent()
                result = await agent.run(task_id, payload)

                node.status = NodeStatus.COMPLETED if result["success"] else NodeStatus.FAILED
                node.result = result.get("result", {})
                node.error = result.get("error")
                node.completed_at = datetime.now().isoformat()

                # Guardar resultado en contexto compartido
                workflow.context[node.node_id] = node.result

                # Publicar evento para que el WorkflowManager procese
                await self._bus.publish(Event(
                    type=EventType.TASK_COMPLETED if result["success"] else EventType.TASK_FAILED,
                    payload={"task_id": task_id, "result": node.result, "error": node.error},
                    source="WorkflowManager"
                ))
            except Exception as e:
                node.status = NodeStatus.FAILED
                node.error = str(e)
                node.completed_at = datetime.now().isoformat()
                await self._bus.publish(Event(
                    type=EventType.TASK_FAILED,
                    payload={"task_id": task_id, "error": str(e)},
                    source="WorkflowManager"
                ))

        asyncio.ensure_future(_run())
        return task_id

    async def _on_task_completed(self, event: Event):
        """Handler: tarea completada — evaluar qué nodos pueden ejecutarse."""
        task_id = event.payload.get("task_id")
        result = event.payload.get("result", {})

        mapping = self._task_to_node.get(task_id)
        if not mapping:
            return

        workflow_id, node_id = mapping
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return

        node = workflow.nodes.get(node_id)
        if node and node.status == NodeStatus.RUNNING:
            node.status = NodeStatus.COMPLETED
            node.result = result
            node.completed_at = datetime.now().isoformat()
            workflow.context[node_id] = result
            logger.info(f"Nodo completado: {node_id} en workflow {workflow_id}")

        # Verificar si el workflow terminó
        all_done = all(
            n.status in {NodeStatus.COMPLETED, NodeStatus.SKIPPED}
            for n in workflow.nodes.values()
        )
        if all_done:
            workflow.status = WorkflowStatus.COMPLETED
            workflow.completed_at = datetime.now().isoformat()
            logger.info(f"✅ Workflow completado: {workflow.name} ({workflow_id})")
            if workflow_id in self._completion_events:
                self._completion_events[workflow_id].set()
            return

        # Despachar nodos que ahora están listos
        ready = self._get_ready_nodes(workflow)
        if ready:
            logger.info(f"Workflow {workflow_id}: {len(ready)} nodos listos para ejecutar")
            await self._dispatch_nodes(workflow, ready)

    async def _on_task_failed(self, event: Event):
        """Handler: tarea fallida — marcar workflow como fallido."""
        task_id = event.payload.get("task_id")
        error = event.payload.get("error", "unknown")

        mapping = self._task_to_node.get(task_id)
        if not mapping:
            return

        workflow_id, node_id = mapping
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return

        node = workflow.nodes.get(node_id)
        if node:
            node.status = NodeStatus.FAILED
            node.error = error
            node.completed_at = datetime.now().isoformat()

        workflow.status = WorkflowStatus.FAILED
        workflow.completed_at = datetime.now().isoformat()
        logger.error(f"❌ Workflow fallido: {workflow.name} | Nodo: {node_id} | Error: {error}")

        if workflow_id in self._completion_events:
            self._completion_events[workflow_id].set()

    def get_workflow(self, workflow_id: str) -> Optional[WorkflowInstance]:
        return self._workflows.get(workflow_id)

    def get_all_workflows(self) -> List[Dict]:
        return [wf.to_dict() for wf in self._workflows.values()]


# ── Singleton ─────────────────────────────────────────────────────────────────

_manager: Optional[WorkflowManager] = None


def get_workflow_manager(event_bus: EventBus = None, orchestrator=None) -> WorkflowManager:
    global _manager
    if _manager is None:
        if event_bus is None:
            from nexus_core.core.event_bus import get_event_bus
            event_bus = get_event_bus()
        _manager = WorkflowManager(event_bus=event_bus, orchestrator=orchestrator)
    return _manager
