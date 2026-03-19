"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  BAJIOWARE NEXUS — AGENT TEAM MANAGER                                        ║
║  Orquesta equipos dinámicos de agentes para proyectos reales                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Supera a CrewAI: equipos dinámicos con roles configurables en runtime       ║
║  Supera a AutoGen: workflows condicionales con lógica if/else real           ║
║  Supera a LangGraph: integración nativa con herramientas del sistema         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable

logger = logging.getLogger("nexus.agent_team_manager")


# ── Tipos de roles disponibles ────────────────────────────────────────────────

class AgentRole(str, Enum):
    PLANNER    = "planner"      # Diseña la arquitectura y divide tareas
    CODER      = "coder"        # Escribe código
    TESTER     = "tester"       # Ejecuta pruebas
    REVIEWER   = "reviewer"     # Revisa calidad y seguridad
    DEPLOYER   = "deployer"     # Despliega y ejecuta scripts
    RESEARCHER = "researcher"   # Investiga y analiza
    SECURITY   = "security"     # Audita seguridad
    DOCUMENTER = "documenter"   # Genera documentación


# ── Resultado de una tarea de agente ─────────────────────────────────────────

@dataclass
class AgentTaskResult:
    task_id: str
    role: AgentRole
    success: bool
    output: Any
    error: Optional[str] = None
    duration_ms: float = 0.0
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "task_id": self.task_id,
            "role": self.role,
            "success": self.success,
            "output": str(self.output)[:2000] if self.output else None,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


# ── Definición de un miembro del equipo ──────────────────────────────────────

@dataclass
class TeamMember:
    role: AgentRole
    name: str
    capability: str           # capability para el dispatcher
    system_prompt: str        # instrucciones específicas del rol
    tools: List[str] = field(default_factory=list)
    max_retries: int = 2


# ── Estado del equipo ─────────────────────────────────────────────────────────

class TeamStatus(str, Enum):
    IDLE      = "idle"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    WAITING   = "waiting_approval"  # punto de revisión humana


@dataclass
class TeamExecution:
    execution_id: str
    project_name: str
    objective: str
    status: TeamStatus
    members: List[TeamMember]
    results: Dict[str, AgentTaskResult] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    human_approval_required: bool = False
    human_approval_message: str = ""

    def to_dict(self) -> Dict:
        return {
            "execution_id": self.execution_id,
            "project_name": self.project_name,
            "objective": self.objective,
            "status": self.status,
            "members": [{"role": m.role, "name": m.name} for m in self.members],
            "results": {k: v.to_dict() for k, v in self.results.items()},
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "human_approval_required": self.human_approval_required,
            "human_approval_message": self.human_approval_message,
        }


# ── Agent Team Manager ────────────────────────────────────────────────────────

class AgentTeamManager:
    """
    Orquesta equipos dinámicos de agentes para ejecutar proyectos completos.
    
    Capacidades:
    - Crear equipos con roles dinámicos según el objetivo
    - Ejecutar tareas en paralelo o secuencial según dependencias
    - Lógica condicional: si test falla → volver a coder con el error
    - Puntos de aprobación humana (el 20%)
    - Memoria compartida entre miembros del equipo
    """

    # ── Templates de equipos predefinidos ────────────────────────────────────

    TEAM_TEMPLATES = {
        "software_development": [
            TeamMember(
                role=AgentRole.PLANNER,
                name="PlannerAgent",
                capability="code_generation",
                system_prompt="Eres un arquitecto de software. Analiza el objetivo y crea un plan técnico detallado con los archivos a crear y su estructura.",
                tools=["file_read", "file_search"],
            ),
            TeamMember(
                role=AgentRole.CODER,
                name="CoderAgent",
                capability="code_generation",
                system_prompt="Eres un desarrollador senior. Implementa el código siguiendo el plan del arquitecto. Escribe código limpio, documentado y con manejo de errores.",
                tools=["file_write", "file_read", "bash_exec"],
            ),
            TeamMember(
                role=AgentRole.TESTER,
                name="TesterAgent",
                capability="code_generation",
                system_prompt="Eres un QA engineer. Ejecuta las pruebas del código y reporta si pasan o fallan con detalles específicos.",
                tools=["bash_exec", "file_read"],
            ),
            TeamMember(
                role=AgentRole.REVIEWER,
                name="ReviewerAgent",
                capability="code_generation",
                system_prompt="Eres un senior reviewer. Revisa el código en busca de bugs, problemas de seguridad y mejoras de calidad.",
                tools=["file_read", "file_search"],
            ),
        ],
        "security_audit": [
            TeamMember(
                role=AgentRole.RESEARCHER,
                name="ReconAgent",
                capability="code_generation",
                system_prompt="Eres un investigador de seguridad. Mapea la superficie de ataque del sistema objetivo.",
                tools=["bash_exec", "file_read"],
            ),
            TeamMember(
                role=AgentRole.SECURITY,
                name="SecurityAgent",
                capability="code_generation",
                system_prompt="Eres un auditor de seguridad. Identifica vulnerabilidades críticas y propone mitigaciones con código.",
                tools=["bash_exec", "file_read", "file_search"],
            ),
            TeamMember(
                role=AgentRole.DOCUMENTER,
                name="ReportAgent",
                capability="code_generation",
                system_prompt="Eres un redactor técnico. Genera reportes de seguridad claros y accionables basados en los hallazgos.",
                tools=["file_write", "file_read"],
            ),
        ],
        "feature_sprint": [
            TeamMember(
                role=AgentRole.PLANNER,
                name="SprintPlanner",
                capability="code_generation",
                system_prompt="Eres un Scrum Master técnico. Divide el feature en tareas específicas y define el orden de implementación.",
                tools=["file_read"],
            ),
            TeamMember(
                role=AgentRole.CODER,
                name="BackendDev",
                capability="code_generation",
                system_prompt="Eres un desarrollador backend. Implementa los endpoints, modelos y lógica de negocio.",
                tools=["file_write", "file_read", "bash_exec"],
            ),
            TeamMember(
                role=AgentRole.TESTER,
                name="QAAgent",
                capability="code_generation",
                system_prompt="Ejecuta pytest y reporta resultados con detalles de fallos.",
                tools=["bash_exec"],
            ),
        ],
    }

    def __init__(self):
        self._executions: Dict[str, TeamExecution] = {}
        self._approval_events: Dict[str, asyncio.Event] = {}
        self._approval_decisions: Dict[str, bool] = {}
        logger.info("AgentTeamManager iniciado")

    def create_team(
        self,
        project_name: str,
        objective: str,
        template: str = "software_development",
        custom_members: Optional[List[TeamMember]] = None,
    ) -> TeamExecution:
        """
        Crea un equipo de agentes para un proyecto.
        
        Args:
            project_name: nombre del proyecto (ej: "ecommerce_zapateria")
            objective: qué debe lograr el equipo
            template: "software_development" | "security_audit" | "feature_sprint"
            custom_members: lista custom de miembros (override del template)
        """
        members = custom_members or self.TEAM_TEMPLATES.get(template, self.TEAM_TEMPLATES["software_development"])
        
        execution = TeamExecution(
            execution_id=f"team_{uuid.uuid4().hex[:8]}",
            project_name=project_name,
            objective=objective,
            status=TeamStatus.IDLE,
            members=members,
        )
        self._executions[execution.execution_id] = execution
        logger.info(f"Equipo creado: {project_name} | {len(members)} miembros | Template: {template}")
        return execution

    async def run_team(
        self,
        execution_id: str,
        require_human_approval: bool = True,
        timeout: float = 300.0,
    ) -> TeamExecution:
        """
        Ejecuta el equipo completo con lógica condicional.
        
        Flujo:
        1. Planner → crea el plan
        2. Coder → implementa (en paralelo si hay varios)
        3. Tester → ejecuta pruebas
           → SI falla: vuelve a Coder con el error (max 2 reintentos)
           → SI pasa: continúa
        4. Reviewer → revisa calidad
        5. [Aprobación humana si require_human_approval=True]
        6. Deployer/Documenter → entrega final
        """
        execution = self._executions.get(execution_id)
        if not execution:
            raise ValueError(f"Execution {execution_id} no encontrada")

        execution.status = TeamStatus.RUNNING
        logger.info(f"Iniciando equipo {execution_id} para: {execution.objective[:50]}")

        try:
            # Fase 1: Planner
            planner = self._get_member(execution, AgentRole.PLANNER)
            if planner:
                logger.info(f"[{execution_id}] Fase 1: Planning...")
                plan_result = await self._execute_member_task(
                    execution, planner,
                    f"OBJETIVO: {execution.objective}\n\nCrea un plan técnico detallado.",
                )
                execution.context["plan"] = plan_result.output
                if not plan_result.success:
                    logger.warning(f"[{execution_id}] Planner falló, continuando sin plan...")

            # Fase 2: Coder (con reintentos si tester falla)
            coder = self._get_member(execution, AgentRole.CODER)
            tester = self._get_member(execution, AgentRole.TESTER)
            
            if coder:
                for attempt in range(3):  # max 3 intentos
                    logger.info(f"[{execution_id}] Fase 2: Coding (intento {attempt+1})...")
                    
                    plan_context = execution.context.get("plan", "")
                    test_error = execution.context.get("last_test_error", "")
                    
                    prompt = f"OBJETIVO: {execution.objective}\n\n"
                    if plan_context:
                        prompt += f"PLAN:\n{str(plan_context)[:1000]}\n\n"
                    if test_error:
                        prompt += f"⚠️ CORRECCIÓN REQUERIDA — El tester reportó este error:\n{test_error}\n\nCorrige el problema específico.\n\n"
                    prompt += "Implementa el código ahora."
                    
                    code_result = await self._execute_member_task(execution, coder, prompt)
                    execution.context["code"] = code_result.output

                    # Materializar archivos en disco
                    if code_result.success and code_result.output:
                        pdir = f"/home/operator/BW-AI/projects/{execution.project_name}/backend"
                        mat = await self._materialize_code(execution, code_result.output, pdir)
                        logger.info(f"[{execution.execution_id}] Materializados: {mat['files_written']} archivos")

                    
                    # Fase 3: Tester — lógica condicional
                    if tester and code_result.success:
                        logger.info(f"[{execution_id}] Fase 3: Testing...")
                        test_result = await self._execute_member_task(
                            execution, tester,
                            f"Ejecuta las pruebas para el código implementado.\n\nContexto: {execution.objective}",
                        )
                        
                        if test_result.success:
                            logger.info(f"[{execution_id}] ✅ Tests pasaron en intento {attempt+1}")
                            execution.context.pop("last_test_error", None)
                            break  # Tests OK — salir del loop
                        else:
                            # Tests fallaron — guardar error y reintentar con Coder
                            execution.context["last_test_error"] = test_result.error or str(test_result.output)[:500]
                            logger.warning(f"[{execution_id}] ❌ Tests fallaron, reintentando con Coder...")
                            if attempt == 2:
                                logger.error(f"[{execution_id}] Máximo reintentos alcanzado")
                    else:
                        break  # Sin tester, continuar

            # Fase 4: Reviewer
            reviewer = self._get_member(execution, AgentRole.REVIEWER)
            if reviewer:
                logger.info(f"[{execution_id}] Fase 4: Code Review...")
                review_result = await self._execute_member_task(
                    execution, reviewer,
                    f"Revisa el código implementado para: {execution.objective}\n\nBusca bugs, vulnerabilidades y mejoras.",
                )
                execution.context["review"] = review_result.output

            # Fase 5: Aprobación humana
            if require_human_approval:
                logger.info(f"[{execution_id}] ⏸ Esperando aprobación humana...")
                execution.status = TeamStatus.WAITING
                execution.human_approval_required = True
                
                summary = self._generate_summary(execution)
                execution.human_approval_message = summary
                
                # Esperar aprobación con timeout
                event = asyncio.Event()
                self._approval_events[execution_id] = event
                
                try:
                    await asyncio.wait_for(event.wait(), timeout=timeout)
                    approved = self._approval_decisions.get(execution_id, False)
                    
                    if not approved:
                        execution.status = TeamStatus.FAILED
                        logger.info(f"[{execution_id}] ❌ Rechazado por humano")
                        return execution
                    
                    logger.info(f"[{execution_id}] ✅ Aprobado por humano")
                except asyncio.TimeoutError:
                    logger.warning(f"[{execution_id}] Timeout esperando aprobación")

            # Fase 6: Deployer/Documenter en paralelo
            deployer   = self._get_member(execution, AgentRole.DEPLOYER)
            documenter = self._get_member(execution, AgentRole.DOCUMENTER)
            
            final_tasks = []
            if deployer:
                final_tasks.append(self._execute_member_task(
                    execution, deployer,
                    f"Despliega o finaliza: {execution.objective}"
                ))
            if documenter:
                final_tasks.append(self._execute_member_task(
                    execution, documenter,
                    f"Documenta el trabajo realizado para: {execution.objective}"
                ))
            
            if final_tasks:
                logger.info(f"[{execution_id}] Fase 6: Deploy/Docs en paralelo...")
                await asyncio.gather(*final_tasks)

            execution.status = TeamStatus.COMPLETED
            execution.completed_at = datetime.now().isoformat()
            logger.info(f"[{execution_id}] ✅ Equipo completado exitosamente")

            # Guardar automáticamente en Memory Bank
            try:
                from nexus_core.memory.manager import MemoryManager
                mm = MemoryManager()
                mm.remember_task(execution_id, {
                    "project": execution.project_name,
                    "objective": execution.objective[:300],
                    "status": "completed",
                    "members": [m.name for m in execution.members],
                    "timestamp": execution.completed_at,
                })
                # Guardar resultados de cada agente como knowledge
                for role, result in execution.results.items():
                    if result.success and result.output:
                        mm.remember_knowledge(
                            f"team_{execution_id}_{role}",
                            {
                                "project": execution.project_name,
                                "role": str(role),
                                "output": str(result.output)[:500],
                                "timestamp": execution.completed_at,
                            }
                        )
                logger.info(f"[{execution_id}] 🧠 Resultados guardados en Memory Bank")
            except Exception as e:
                logger.warning(f"[{execution_id}] No se pudo guardar en memoria: {e}")

        except Exception as e:
            execution.status = TeamStatus.FAILED
            logger.error(f"[{execution_id}] Error en equipo: {e}", exc_info=True)

        return execution

    async def approve(self, execution_id: str, approved: bool = True) -> bool:
        """Aprobación/rechazo humano de una ejecución en espera."""
        self._approval_decisions[execution_id] = approved
        event = self._approval_events.get(execution_id)
        if event:
            event.set()
            return True
        return False

    def get_execution(self, execution_id: str) -> Optional[TeamExecution]:
        return self._executions.get(execution_id)

    def get_all_executions(self) -> List[Dict]:
        return [e.to_dict() for e in self._executions.values()]

    def get_pending_approvals(self) -> List[Dict]:
        return [
            e.to_dict() for e in self._executions.values()
            if e.status == TeamStatus.WAITING
        ]

    # ── Métodos internos ──────────────────────────────────────────────────────

    def _get_member(self, execution: TeamExecution, role: AgentRole) -> Optional[TeamMember]:
        return next((m for m in execution.members if m.role == role), None)



    async def _materialize_code(self, execution, code_output, project_dir):
        import re
        from pathlib import Path
        if not code_output:
            return {"files_written": 0}
        base = Path(project_dir)
        base.mkdir(parents=True, exist_ok=True)
        files_written = []
        pat = re.compile(
            r'[`*]{1,3}([\w/\-.]+\.\w+)[`*]{0,3}\s*\n```\w*\n(.*?)```',
            re.DOTALL
        )
        for m in pat.finditer(code_output):
            rel = m.group(1).strip()
            code = m.group(2)
            if rel.startswith("/") or ".." in rel:
                continue
            target = base / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                target.write_text(code, encoding="utf-8")
                files_written.append(rel)
                logger.info(f"Materializado: {rel}")
            except Exception as e:
                logger.warning(f"Error {rel}: {e}")
        if not files_written:
            exts = {
                "python": "main.py", "py": "main.py",
                "javascript": "app.js", "js": "app.js",
                "typescript": "app.ts", "ts": "app.ts",
                "bash": "script.sh", "sql": "schema.sql",
                "json": "data.json", "html": "index.html",
            }
            pat2 = re.compile(r"```(\w+)\n(.*?)```", re.DOTALL)
            for i, m in enumerate(pat2.finditer(code_output)):
                lang = m.group(1).lower()
                code = m.group(2)
                fname = exts.get(lang, f"file_{i}.txt")
                if i > 0:
                    fname = f"file_{i}_{fname}"
                target = base / fname
                try:
                    target.write_text(code, encoding="utf-8")
                    files_written.append(fname)
                    logger.info(f"Bloque: {fname}")
                except Exception as e:
                    logger.warning(f"Error bloque {i}: {e}")
        execution.context["materialized_files"] = files_written
        execution.context["project_dir"] = str(base)
        logger.info(f"[{execution.execution_id}] {len(files_written)} archivos en {base}")
        return {"files_written": len(files_written), "files": files_written}


    async def _execute_member_task(
        self,
        execution: TeamExecution,
        member: TeamMember,
        prompt: str,
    ) -> AgentTaskResult:
        """Ejecuta la tarea de un miembro del equipo via JuniorAgent."""
        import time
        task_id = f"{execution.execution_id}_{member.role}_{uuid.uuid4().hex[:4]}"
        t0 = time.time()
        
        try:
            from nexus_core.agents.junior_agent import JuniorAgent
            agent = JuniorAgent()
            
            # Construir payload con contexto del equipo
            full_prompt = f"""ROL: {member.system_prompt}

PROYECTO: {execution.project_name}
CONTEXTO DEL EQUIPO: {str(execution.context)[:800]}

TAREA:
{prompt}"""
            
            result = await agent.run(task_id, {
                "type": "llm_query",
                "system_prompt": member.system_prompt,
                "prompt": full_prompt,
            })
            
            duration_ms = (time.time() - t0) * 1000
            response = result.get("result", {}).get("response", "") or result.get("result", {}).get("output", "")
            
            task_result = AgentTaskResult(
                task_id=task_id,
                role=member.role,
                success=result.get("success", False),
                output=response,
                duration_ms=duration_ms,
            )
            
            execution.results[member.role] = task_result
            logger.info(f"[{execution.execution_id}] {member.role}: {'✅' if task_result.success else '❌'} ({duration_ms:.0f}ms)")
            return task_result
            
        except Exception as e:
            duration_ms = (time.time() - t0) * 1000
            task_result = AgentTaskResult(
                task_id=task_id,
                role=member.role,
                success=False,
                output=None,
                error=str(e),
                duration_ms=duration_ms,
            )
            execution.results[member.role] = task_result
            logger.error(f"[{execution.execution_id}] {member.role} ERROR: {e}")
            return task_result

    def _generate_summary(self, execution: TeamExecution) -> str:
        """Genera resumen para aprobación humana."""
        lines = [
            f"📋 RESUMEN: {execution.project_name}",
            f"🎯 Objetivo: {execution.objective[:200]}",
            f"👥 Equipo: {', '.join(m.name for m in execution.members)}",
            "",
            "RESULTADOS:",
        ]
        for role, result in execution.results.items():
            status = "✅" if result.success else "❌"
            lines.append(f"  {status} {role}: {str(result.output)[:200] if result.output else result.error or 'sin output'}")
        return "\n".join(lines)


# ── Endpoints FastAPI ─────────────────────────────────────────────────────────

def create_team_router():
    from fastapi import APIRouter
    router = APIRouter(prefix="/teams", tags=["AgentTeams"])
    
    _manager = AgentTeamManager()

    @router.post("/create")
    async def create_team(req: dict):
        """Crea un equipo de agentes para un proyecto."""
        execution = _manager.create_team(
            project_name=req.get("project_name", "proyecto"),
            objective=req.get("objective", ""),
            template=req.get("template", "software_development"),
        )
        return execution.to_dict()

    @router.post("/{execution_id}/run")
    async def run_team(execution_id: str, req: dict = {}):
        """Inicia la ejecución del equipo."""
        require_approval = req.get("require_human_approval", True)
        asyncio.ensure_future(
            _manager.run_team(execution_id, require_human_approval=require_approval)
        )
        return {"started": True, "execution_id": execution_id}

    @router.get("/{execution_id}/status")
    async def team_status(execution_id: str):
        execution = _manager.get_execution(execution_id)
        if not execution:
            from fastapi import HTTPException
            raise HTTPException(404, "Execution no encontrada")
        return execution.to_dict()

    @router.post("/{execution_id}/approve")
    async def approve_team(execution_id: str, req: dict = {}):
        """Aprobación/rechazo humano."""
        approved = req.get("approved", True)
        ok = await _manager.approve(execution_id, approved)
        return {"approved": approved, "ok": ok}

    @router.get("/")
    async def list_teams():
        return {"executions": _manager.get_all_executions()}

    @router.get("/pending-approvals")
    async def pending_approvals():
        return {"pending": _manager.get_pending_approvals()}

    return router


# ── Singleton ─────────────────────────────────────────────────────────────────

_team_manager: Optional[AgentTeamManager] = None

def get_team_manager() -> AgentTeamManager:
    global _team_manager
    if _team_manager is None:
        _team_manager = AgentTeamManager()
    return _team_manager
