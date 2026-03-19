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
