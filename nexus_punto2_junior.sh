#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Punto 2: Junior Agente Autónomo               ║
# ║  Encadena tools · Planifica · Ejecuta · Entrega resultado  ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

CORE="/home/operator/NEXUS-PRO/nexus_core"
API="/home/operator/NEXUS-PRO/nexus_api"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

mkdir -p "$CORE/agents" "$API/routes"
mkdir -p "/home/operator/NEXUS-PRO/data/reports"
mkdir -p "/home/operator/NEXUS-PRO/data/junior_workspace"

# ══════════════════════════════════════════════════════════════
head "1/4 · nexus_core/agents/junior_agent.py — El agente estrella"
# ══════════════════════════════════════════════════════════════
cat > "$CORE/agents/junior_agent.py" << 'EOF'
"""
NEXUS PRO — Junior Agent v1.0
El agente autónomo estrella de NEXUS.

Junior es diferente a todos los demás agentes:
- Recibe un OBJETIVO en lenguaje natural
- GPT-4o genera un PLAN de N pasos
- Ejecuta cada paso encadenando resultados
- Cada paso puede usar cualquier tool
- El resultado de un paso alimenta el siguiente
- Genera un reporte final completo

Ejemplos de lo que Junior puede hacer solo:
  "Construye una API REST para una zapatería"
  "Audita la seguridad del proyecto NEXUS"
  "Analiza el código y genera documentación"
  "Crea un pipeline CI/CD seguro"
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
from nexus_core.agents.dynamic_agent import ToolExecutor

logger = logging.getLogger("nexus.junior")

WORKSPACE = Path("/home/operator/NEXUS-PRO/data/junior_workspace")
WORKSPACE.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════
# JUNIOR PLANNER — GPT-4o genera plan de N pasos
# ══════════════════════════════════════════════════════════════
class JuniorPlanner:

    SYSTEM = """Eres el planificador de JUNIOR, el agente autónomo de NEXUS PRO.

Tu trabajo: dado un objetivo, genera un plan de pasos concretos y ejecutables.

Herramientas disponibles:
- bash_exec:    {command, cwd, timeout}
- file_read:    {path}
- file_write:   {path, content}
- file_list:    {path}
- http_request: {url, method, headers, body}
- code_exec:    {code, timeout}
- nmap_scan:    {target, flags}
- sast_scan:    {filepath}
- stride_model: {target, context}
- report_gen:   {title, content}
- llm_call:     {system, prompt}

REGLAS CRÍTICAS:
1. Máximo 8 pasos por plan
2. Cada paso debe ser atómico y verificable
3. Usa {prev_result} en params para referenciar el resultado anterior
4. El último paso SIEMPRE debe ser report_gen con el resumen completo
5. Sé específico con los parámetros — nada genérico

RESPONDE ÚNICAMENTE con JSON válido:
{
  "objective": "descripción del objetivo",
  "estimated_duration": "X minutos",
  "steps": [
    {
      "step": 1,
      "name": "nombre descriptivo",
      "tool": "nombre_tool",
      "params": { ... },
      "description": "qué hace este paso",
      "depends_on_prev": false
    }
  ]
}"""

    @classmethod
    async def create_plan(cls, llm, objective: str, context: dict = None) -> dict:
        """GPT-4o genera el plan completo de ejecución."""
        ctx = ""
        if context:
            ctx = f"\nContexto adicional: {json.dumps(context, ensure_ascii=False)[:500]}"

        user_msg = f"""Objetivo: {objective}{ctx}

Workspace de Junior: /home/operator/NEXUS-PRO/data/junior_workspace/
Proyecto NEXUS en: /home/operator/NEXUS-PRO/

Genera el plan de pasos para completar este objetivo."""

        try:
            response = await llm.ask(cls.SYSTEM, user_msg)
            # Limpiar respuesta
            response = response.strip()
            if "```" in response:
                parts = response.split("```")
                for part in parts:
                    if "{" in part:
                        response = part.replace("json", "").strip()
                        break
            plan = json.loads(response)
            logger.info(f"[Junior Planner] Plan generado: {len(plan.get('steps',[]))} pasos")
            return plan
        except json.JSONDecodeError as e:
            logger.error(f"[Junior Planner] JSON inválido: {e}")
            # Plan de fallback
            return {
                "objective": objective,
                "estimated_duration": "2 minutos",
                "steps": [
                    {
                        "step": 1,
                        "name": "Explorar proyecto",
                        "tool": "file_list",
                        "params": {"path": "/home/operator/NEXUS-PRO"},
                        "description": "Listar estructura del proyecto",
                        "depends_on_prev": False
                    },
                    {
                        "step": 2,
                        "name": "Análisis con LLM",
                        "tool": "llm_call",
                        "params": {
                            "system": "Eres Junior, agente de NEXUS PRO.",
                            "prompt": f"Completa este objetivo: {objective}"
                        },
                        "description": "GPT-4o analiza y responde",
                        "depends_on_prev": False
                    },
                    {
                        "step": 3,
                        "name": "Reporte final",
                        "tool": "report_gen",
                        "params": {
                            "title": f"Junior_{objective[:30].replace(' ','_')}",
                            "content": "Reporte generado por Junior Agent"
                        },
                        "description": "Generar reporte de resultados",
                        "depends_on_prev": False
                    }
                ]
            }
        except Exception as e:
            logger.error(f"[Junior Planner] Error: {e}")
            raise


# ══════════════════════════════════════════════════════════════
# JUNIOR AGENT
# ══════════════════════════════════════════════════════════════
class JuniorAgent(BaseAgent):
    """
    El agente autónomo estrella de NEXUS PRO.

    Recibe un objetivo → planifica → ejecuta N pasos → entrega resultado.
    """

    JUNIOR_SYSTEM = """Eres JUNIOR, el agente autónomo más avanzado de NEXUS PRO.

Características:
- Trabajas de forma completamente autónoma
- Encadenas múltiples herramientas para completar objetivos complejos
- Piensas antes de actuar y verificas tus resultados
- Generas reportes detallados de todo lo que haces
- Eres preciso, eficiente y seguro

Especialidades:
- Desarrollo de software (APIs, scripts, automatización)
- Ciberseguridad (análisis, pentesting, documentación)
- DevOps (CI/CD, Docker, infraestructura)
- Análisis de código y generación de documentación"""

    def __init__(self, llm=None):
        metadata = AgentMetadata(
            name="Junior",
            capabilities=list(AgentCapability),  # todas
            model="gpt-4o",
            timeout_seconds=600,  # 10 min para tareas complejas
            max_concurrent=2,
            tags=["autonomous", "junior", "star_agent"],
        )
        super().__init__(metadata=metadata)
        self._llm = llm
        self._execution_log: List[dict] = []

    def _log_step(self, step: int, name: str, status: str,
                  tool: str = None, result: Any = None, error: str = None):
        """Registra cada paso de la ejecución."""
        entry = {
            "step": step,
            "name": name,
            "status": status,
            "tool": tool,
            "timestamp": datetime.utcnow().isoformat(),
            "result_preview": str(result)[:200] if result else None,
            "error": error,
        }
        self._execution_log.append(entry)
        emoji = "✓" if status == "completed" else "✗" if status == "failed" else "→"
        logger.info(f"[Junior] {emoji} Paso {step}: {name} [{status}]")

    def _inject_context(self, params: dict, prev_result: Any,
                        step_results: dict) -> dict:
        """
        Inyecta resultados previos en los parámetros del paso actual.
        Reemplaza {prev_result} y {step_N} con valores reales.
        """
        params_str = json.dumps(params, ensure_ascii=False)

        # Inyectar resultado previo
        if prev_result and "{prev_result}" in params_str:
            prev_str = str(prev_result)[:500] if prev_result else ""
            params_str = params_str.replace("{prev_result}", prev_str)

        # Inyectar resultados de pasos específicos
        for step_num, result in step_results.items():
            placeholder = f"{{step_{step_num}}}"
            if placeholder in params_str:
                params_str = params_str.replace(
                    placeholder, str(result)[:300]
                )

        try:
            return json.loads(params_str)
        except Exception:
            return params

    async def _enrich_params_with_llm(
        self, llm, step: dict, prev_result: Any,
        step_results: dict, objective: str
    ) -> dict:
        """
        Si el paso depende del anterior y tiene placeholders,
        GPT-4o decide cómo enriquecer los parámetros.
        """
        if not step.get("depends_on_prev") or not prev_result:
            return step.get("params", {})

        params = step.get("params", {})
        params_str = json.dumps(params, ensure_ascii=False)

        if "{prev_result}" not in params_str and not step.get("depends_on_prev"):
            return params

        prompt = f"""Objetivo general: {objective}
Paso actual: {step.get('name')} usando {step.get('tool')}
Resultado del paso anterior: {json.dumps(prev_result, ensure_ascii=False, default=str)[:800]}
Parámetros base del paso: {params_str}

Actualiza los parámetros para usar la información del paso anterior.
Responde SOLO con el JSON de parámetros actualizado."""

        try:
            response = await llm.ask(
                "Eres el motor de parámetros de Junior Agent. Actualiza parámetros JSON.",
                prompt
            )
            response = response.strip()
            if "```" in response:
                for part in response.split("```"):
                    if "{" in part:
                        response = part.replace("json", "").strip()
                        break
            return json.loads(response)
        except Exception:
            return params

    async def execute(self, task_id: str, payload: dict) -> dict:
        """
        Ejecuta el objetivo autónomamente.

        Payload esperado:
        - objective: string con el objetivo en lenguaje natural
        - context: dict opcional con contexto adicional
        - max_steps: int opcional (default: 8)
        """
        objective = payload.get(
            "objective",
            payload.get("prompt",
            payload.get("_task_name", "Analizar el proyecto NEXUS"))
        )
        context = payload.get("context", {})
        max_steps = int(payload.get("max_steps", 8))

        self._execution_log = []
        session_id = f"junior_{uuid.uuid4().hex[:8]}"

        logger.info(f"[Junior] 🚀 Iniciando sesión {session_id}")
        logger.info(f"[Junior] 🎯 Objetivo: {objective}")

        if not self._llm:
            return {
                "status": "error",
                "error": "Junior requiere LLM — configura una API key en Modelos & APIs",
                "objective": objective,
            }

        # ── FASE 1: Planificación ─────────────────────────────
        logger.info(f"[Junior] 🧠 GPT-4o generando plan...")
        try:
            plan = await JuniorPlanner.create_plan(
                self._llm, objective, context
            )
        except Exception as e:
            return {"status": "error", "error": f"Error en planificación: {e}"}

        steps = plan.get("steps", [])[:max_steps]
        logger.info(
            f"[Junior] 📋 Plan: {len(steps)} pasos | "
            f"ETA: {plan.get('estimated_duration','?')}"
        )

        # ── FASE 2: Ejecución paso a paso ─────────────────────
        step_results = {}
        prev_result = None
        failed_steps = []
        final_report = None

        for i, step in enumerate(steps):
            step_num = step.get("step", i + 1)
            step_name = step.get("name", f"Paso {step_num}")
            tool_name = step.get("tool", "llm_call")

            self._log_step(step_num, step_name, "running", tool_name)

            try:
                # Enriquecer params con contexto previo
                params = step.get("params", {})
                if step.get("depends_on_prev") and prev_result:
                    params = await self._enrich_params_with_llm(
                        self._llm, step, prev_result, step_results, objective
                    )
                else:
                    params = self._inject_context(params, prev_result, step_results)

                # Ejecutar la tool
                result = await ToolExecutor.execute_tool(
                    tool_name, params, self._llm
                )

                # Guardar resultado
                step_results[step_num] = result
                prev_result = result

                status = "completed" if result.get("status") != "error" else "failed"
                self._log_step(step_num, step_name, status, tool_name, result)

                if status == "failed":
                    failed_steps.append({
                        "step": step_num,
                        "name": step_name,
                        "error": result.get("error", "Unknown error"),
                    })
                    logger.warning(
                        f"[Junior] ⚠ Paso {step_num} falló: "
                        f"{result.get('error','?')} — continuando..."
                    )

                # Si es report_gen, guardar como reporte final
                if tool_name == "report_gen" and result.get("status") == "ok":
                    final_report = result

            except Exception as e:
                error_msg = f"{type(e).__name__}: {e}"
                self._log_step(step_num, step_name, "failed", tool_name, error=error_msg)
                failed_steps.append({"step": step_num, "name": step_name, "error": error_msg})
                logger.error(f"[Junior] ✗ Paso {step_num} excepción: {error_msg}")
                prev_result = {"status": "error", "error": error_msg}

        # ── FASE 3: Resumen final ─────────────────────────────
        completed = len(steps) - len(failed_steps)
        success_rate = (completed / len(steps) * 100) if steps else 0

        logger.info(
            f"[Junior] ✅ Sesión completada | "
            f"{completed}/{len(steps)} pasos OK | "
            f"{success_rate:.0f}% éxito"
        )

        # Guardar log de sesión
        log_path = WORKSPACE / f"{session_id}_log.json"
        log_path.write_text(
            json.dumps({
                "session_id": session_id,
                "objective": objective,
                "plan": plan,
                "execution_log": self._execution_log,
                "step_results": {
                    k: str(v)[:500] for k, v in step_results.items()
                },
                "timestamp": datetime.utcnow().isoformat(),
            }, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8"
        )

        return {
            "agent": "Junior",
            "session_id": session_id,
            "objective": objective,
            "status": "completed" if not failed_steps else "completed_with_errors",
            "steps_total": len(steps),
            "steps_completed": completed,
            "steps_failed": len(failed_steps),
            "success_rate": round(success_rate, 1),
            "estimated_duration": plan.get("estimated_duration"),
            "execution_log": self._execution_log,
            "failed_steps": failed_steps,
            "final_report": final_report,
            "log_path": str(log_path),
            "last_result": str(prev_result)[:1000] if prev_result else None,
        }
EOF
log "junior_agent.py — El agente estrella"

# ══════════════════════════════════════════════════════════════
head "2/4 · nexus_api/routes/junior.py — endpoints de Junior"
# ══════════════════════════════════════════════════════════════
cat > "$API/routes/junior.py" << 'EOF'
"""
NEXUS PRO — Junior API
Endpoints para interactuar con Junior Agent autónomo
"""
import uuid
import asyncio
from datetime import datetime
from fastapi import APIRouter, HTTPException, Request, BackgroundTasks, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from nexus_api.db.database import db_create_task, db_update_task, db_get_task

router = APIRouter()

# ── Store de sesiones activas ─────────────────────────────────
_sessions: Dict[str, dict] = {}


class JuniorRequest(BaseModel):
    objective: str
    context: Optional[Dict[str, Any]] = {}
    max_steps: Optional[int] = 8
    agent_id: Optional[str] = None  # usar agente específico o Junior por defecto


class JuniorChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None


async def _run_junior_task(task_id: str, objective: str,
                            context: dict, max_steps: int, app):
    """Ejecuta Junior en background."""
    import datetime as dt
    db_update_task(task_id, status="running",
        started_at=dt.datetime.utcnow().isoformat(), progress=10)

    try:
        # Obtener Junior del Registry
        registry = getattr(app.state, 'registry', None)
        llm = getattr(app.state, 'llm', None)
        junior = None

        if registry:
            all_agents = await registry.get_all()
            for ag in all_agents.values():
                if ag.name == "Junior":
                    junior = ag
                    break

        # Si no está en registry, crear instancia temporal
        if not junior:
            from nexus_core.agents.junior_agent import JuniorAgent
            junior = JuniorAgent(llm=llm)

        db_update_task(task_id, progress=20)

        # Ejecutar
        payload = {
            "objective": objective,
            "context": context,
            "max_steps": max_steps,
            "_task_name": objective[:50],
        }
        result = await junior.run(task_id, payload)

        # Actualizar DB
        success = result.get("success", False)
        inner = result.get("result", {})

        db_update_task(task_id,
            status="completed" if success else "failed",
            progress=100,
            result=str(inner)[:3000],
            completed_at=dt.datetime.utcnow().isoformat()
        )

        # Guardar sesión
        if isinstance(inner, dict):
            session_id = inner.get("session_id", task_id)
            _sessions[session_id] = {
                "task_id": task_id,
                "objective": objective,
                "result": inner,
                "timestamp": dt.datetime.utcnow().isoformat(),
            }

    except Exception as e:
        import traceback
        db_update_task(task_id, status="failed",
            error=f"{type(e).__name__}: {e}", progress=0)


@router.post("/junior/run", status_code=202)
async def run_junior(body: JuniorRequest, background: BackgroundTasks, request: Request):
    """
    Ejecuta Junior con un objetivo en lenguaje natural.
    Retorna task_id inmediatamente — monitorear con GET /junior/status/{task_id}
    """
    task_id = f"junior_{uuid.uuid4().hex[:8]}"

    # Crear tarea en DB
    db_create_task({
        "id": task_id,
        "name": f"Junior: {body.objective[:50]}",
        "description": body.objective,
        "task_type": "unique",
        "priority": "alta",
        "payload": {"objective": body.objective, "context": body.context},
    })

    background.add_task(
        _run_junior_task,
        task_id, body.objective, body.context or {},
        body.max_steps or 8, request.app
    )

    return {
        "task_id": task_id,
        "objective": body.objective,
        "status": "running",
        "message": f"Junior iniciado — monitorea en GET /junior/status/{task_id}",
        "estimated_steps": body.max_steps or 8,
    }


@router.get("/junior/status/{task_id}")
def junior_status(task_id: str):
    """Estado detallado de una ejecución de Junior."""
    task = db_get_task(task_id)
    if not task:
        raise HTTPException(404, f"Tarea '{task_id}' no encontrada")
    return task


@router.get("/junior/sessions")
def list_sessions():
    """Lista todas las sesiones de Junior."""
    return {
        "sessions": list(_sessions.values()),
        "total": len(_sessions),
    }


@router.get("/junior/sessions/{session_id}")
def get_session(session_id: str):
    """Detalle de una sesión específica de Junior."""
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(404, f"Sesión '{session_id}' no encontrada")
    return session


@router.post("/junior/chat")
async def junior_chat(body: JuniorChatRequest, request: Request):
    """
    Chat rápido con Junior — responde sin ejecutar tools.
    Para objetivos complejos usar POST /junior/run
    """
    llm = getattr(request.app.state, 'llm', None)
    if not llm:
        raise HTTPException(503, "LLM no disponible")

    system = """Eres JUNIOR, el agente autónomo estrella de NEXUS PRO.
Eres experto en:
- Desarrollo de software (Python, FastAPI, React)
- Ciberseguridad (pentesting, arquitectura Zero Trust, STRIDE)
- DevOps (Docker, CI/CD, Terraform)
- Automatización con IA

Responde de forma concisa, técnica y práctica."""

    try:
        response = await llm.ask(system, body.message)
        return {
            "agent": "Junior",
            "message": body.message,
            "response": response,
            "session_id": body.session_id,
        }
    except Exception as e:
        raise HTTPException(500, f"Error: {e}")


@router.post("/junior/dispatch")
async def junior_dispatch(body: dict, request: Request):
    """
    Despacha una tarea específica a Junior (para integración interna).
    Compatible con el sistema de tareas existente.
    """
    task_name = body.get("task_name", "Tarea Junior")
    payload = body.get("payload", {})
    capability = body.get("capability", "code_generation")

    task_id = f"junior_{uuid.uuid4().hex[:8]}"
    objective = payload.get("objective", task_name)

    db_create_task({
        "id": task_id,
        "name": task_name,
        "description": objective,
        "task_type": "unique",
        "priority": "alta",
        "payload": payload,
    })

    # Ejecutar en background
    from fastapi import BackgroundTasks
    bg = BackgroundTasks()
    bg.add_task(_run_junior_task, task_id, objective, {}, 8, request.app)

    return {
        "task_id": task_id,
        "success": True,
        "message": f"Junior despachado: {task_name}",
    }
EOF
log "junior.py routes"

# ══════════════════════════════════════════════════════════════
head "3/4 · Registrar Junior en main.py + route"
# ══════════════════════════════════════════════════════════════
python3 << 'PYFIX'
path = "/home/operator/NEXUS-PRO/nexus_api/main.py"
with open(path) as f:
    content = f.read()

# 1. Registrar Junior en el Registry al startup
old_dynamic = """    # ── Cargar agentes de DB al Registry ────────────────────
    try:
        from nexus_api.db.database import db_list_agents
        from nexus_core.agents.dynamic_agent import DynamicAgent
        db_agents = db_list_agents()
        loaded = []
        llm = getattr(app.state, 'llm', None)
        registry = getattr(app.state, 'registry', None)
        if registry and db_agents:
            for agent_cfg in db_agents:
                try:
                    dyn_agent = DynamicAgent(agent_cfg, llm=llm)
                    await registry.register(dyn_agent)
                    loaded.append(agent_cfg['name'])
                except Exception as ae:
                    logger.warning(f"[DYNAMIC] ⚠ {agent_cfg['name']}: {ae}")
            if loaded:
                logger.info(f"[DYNAMIC] ✓ Agentes DB cargados: {', '.join(loaded)}")
    except Exception as e:
        logger.warning(f"[DYNAMIC] ⚠ Error cargando agentes DB: {e}")"""

new_dynamic = """    # ── Registrar Junior Agent (estrella) ───────────────────
    try:
        from nexus_core.agents.junior_agent import JuniorAgent
        llm = getattr(app.state, 'llm', None)
        registry = getattr(app.state, 'registry', None)
        if registry:
            junior = JuniorAgent(llm=llm)
            await registry.register(junior)
            app.state.junior = junior
            logger.info("[JUNIOR-AGENT] ✓ Junior Agent registrado — autónomo y listo")
    except Exception as e:
        logger.warning(f"[JUNIOR-AGENT] ⚠ {e}")
        app.state.junior = None

    # ── Cargar agentes de DB al Registry ────────────────────
    try:
        from nexus_api.db.database import db_list_agents
        from nexus_core.agents.dynamic_agent import DynamicAgent
        db_agents = db_list_agents()
        loaded = []
        llm = getattr(app.state, 'llm', None)
        registry = getattr(app.state, 'registry', None)
        if registry and db_agents:
            for agent_cfg in db_agents:
                try:
                    dyn_agent = DynamicAgent(agent_cfg, llm=llm)
                    await registry.register(dyn_agent)
                    loaded.append(agent_cfg['name'])
                except Exception as ae:
                    logger.warning(f"[DYNAMIC] ⚠ {agent_cfg['name']}: {ae}")
            if loaded:
                logger.info(f"[DYNAMIC] ✓ Agentes DB cargados: {', '.join(loaded)}")
    except Exception as e:
        logger.warning(f"[DYNAMIC] ⚠ Error cargando agentes DB: {e}")"""

# 2. Agregar route de Junior
old_routes = '''    ("nexus_api.routes.tools",           {},                              ["Tools"]),
    ("nexus_api.routes.models",          {},                              ["Models"]),
]'''

new_routes = '''    ("nexus_api.routes.tools",           {},                              ["Tools"]),
    ("nexus_api.routes.models",          {},                              ["Models"]),
    ("nexus_api.routes.junior",          {},                              ["Junior"]),
]'''

changed = False
if old_dynamic in content:
    content = content.replace(old_dynamic, new_dynamic)
    print("  ✓ Junior Agent registrado en startup")
    changed = True
else:
    print("  ⚠ Bloque dynamic no encontrado — Junior se iniciará sin registry explícito")

if old_routes in content:
    content = content.replace(old_routes, new_routes)
    print("  ✓ Route /junior/* registrado")
    changed = True
else:
    print("  ⚠ Routes no encontradas")

if changed:
    with open(path, 'w') as f:
        f.write(content)
PYFIX

# ══════════════════════════════════════════════════════════════
head "4/4 · Build frontend"
# ══════════════════════════════════════════════════════════════
cd /home/operator/NEXUS-PRO/nexus_frontend
npm run build --silent 2>&1 | tail -2

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO — Punto 2: Junior Autónomo ✓           ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Nuevos endpoints:"
echo -e "  ${CYAN}POST /junior/run${NC}              ← objetivo en lenguaje natural"
echo -e "  ${CYAN}GET  /junior/status/:id${NC}       ← monitorear ejecución"
echo -e "  ${CYAN}POST /junior/chat${NC}             ← chat rápido con Junior"
echo -e "  ${CYAN}GET  /junior/sessions${NC}         ← historial de sesiones"
echo ""
echo -e "  Reinicia uvicorn y ejecuta las pruebas:"
echo ""
echo -e "  ${CYAN}# Prueba 1 — Junior analiza el proyecto NEXUS${NC}"
echo -e "  curl -s -X POST http://localhost:8000/junior/run \\"
echo -e "    -H 'Content-Type: application/json' \\"
echo -e "    -d '{\"objective\":\"Analiza la arquitectura del proyecto NEXUS y genera un reporte ejecutivo con los componentes principales, su función y recomendaciones de mejora\",\"max_steps\":6}' | python3 -m json.tool"
echo ""
echo -e "  ${CYAN}# Prueba 2 — Junior construye una API simple${NC}"
echo -e "  curl -s -X POST http://localhost:8000/junior/run \\"
echo -e "    -H 'Content-Type: application/json' \\"
echo -e "    -d '{\"objective\":\"Crea un archivo Python con una API FastAPI simple para una lista de tareas TODO con endpoints GET POST DELETE y guárdalo en /home/operator/NEXUS-PRO/data/junior_workspace/todo_api.py\",\"max_steps\":5}' | python3 -m json.tool"
echo ""
echo -e "  Después monitorear con:"
echo -e "  ${CYAN}curl -s http://localhost:8000/junior/status/TASK_ID | python3 -m json.tool${NC}"
echo ""
