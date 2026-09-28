"""
NEXUS PRO — Tasks API
CRUD de tareas: única, monitor 24/7, crontab, pipeline, event-driven
"""
import uuid
import asyncio
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from nexus_api.auth.deps import get_current_user
from nexus_api.db.database import (
    db_list_tasks, db_get_task, db_create_task, db_update_task
)

router = APIRouter(dependencies=[Depends(get_current_user)])

class CreateTaskRequest(BaseModel):
    name: str
    description: str = ""
    task_type: str = "unique"   # unique | monitor | cron | pipeline | event
    priority: str = "media"     # crítica | alta | media | baja
    agent_id: Optional[str] = None
    team_id: Optional[str] = None
    payload: Dict[str, Any] = {}
    cron_expr: Optional[str] = None  # "0 */6 * * *"

async def _run_task_background(task_id: str, app):
    """Ejecuta la tarea directamente via DynamicAgent."""
    import datetime
    db_update_task(task_id, status="running",
        started_at=datetime.datetime.utcnow().isoformat(), progress=10)
    try:
        task = db_get_task(task_id)
        if not task:
            return

        payload = task.get('payload', {}) or {}
        # Enriquecer payload con metadatos para que el agente razone mejor
        payload['_task_name'] = task.get('name', 'Tarea')
        payload['_task_desc'] = task.get('description', '')
        payload['_task_id']   = task_id
        payload['_priority']  = task.get('priority', 'media')

        # Buscar el agente en el Registry
        registry = getattr(app.state, 'registry', None)
        agent = None
        if registry and task.get('agent_id'):
            from nexus_api.db.database import db_get_agent
            agent_cfg = db_get_agent(task['agent_id'])
            if agent_cfg:
                # Buscar por nombre en el registry
                all_agents = await registry.get_all()
                for ag in all_agents.values():
                    if ag.name == agent_cfg['name']:
                        agent = ag
                        break

        db_update_task(task_id, progress=30)

        if agent:
            # Ejecutar directamente en el agente
            result = await agent.run(task_id, payload)
            success = result.get('success', False)
            db_update_task(task_id,
                status="completed" if success else "failed",
                progress=100,
                result=str(result.get('result', ''))[:2000] if success else None,
                error=str(result.get('error', ''))[:500] if not success else None,
                completed_at=datetime.datetime.utcnow().isoformat()
            )
        else:
            # Fallback: ejecutar bash directo si hay command
            db_update_task(task_id, progress=50)
            if 'command' in payload or payload.get('tool') == 'bash_exec':
                from nexus_core.kernel.legacy import require_legacy_execution
                require_legacy_execution()
                import asyncio as _asyncio, os as _os
                cmd = payload.get('command', 'echo NEXUS OK && date')
                proc = await _asyncio.create_subprocess_shell(
                    cmd, stdout=_asyncio.subprocess.PIPE,
                    stderr=_asyncio.subprocess.PIPE,
                    env={**_os.environ}
                )
                stdout, stderr = await _asyncio.wait_for(proc.communicate(), timeout=60)
                output = stdout.decode('utf-8', errors='replace').strip()
                db_update_task(task_id,
                    status="completed" if proc.returncode == 0 else "failed",
                    progress=100,
                    result=output[:2000],
                    completed_at=datetime.datetime.utcnow().isoformat()
                )
            else:
                await asyncio.sleep(1)
                db_update_task(task_id, status="completed", progress=100,
                    result=f"Tarea ejecutada — agente no encontrado en Registry, payload: {str(payload)[:200]}",
                    completed_at=datetime.datetime.utcnow().isoformat())
    except Exception as e:
        import traceback
        db_update_task(task_id, status="failed",
            error=f"{type(e).__name__}: {e}", progress=0)

@router.get("/tasks")
def list_tasks(status: Optional[str] = None):
    return db_list_tasks(status)

@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    task = db_get_task(task_id)
    if not task:
        raise HTTPException(404, f"Tarea '{task_id}' no encontrada")
    return task

@router.post("/tasks", status_code=201)
async def create_task(
    body: CreateTaskRequest,
    background: BackgroundTasks,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Crea y opcionalmente ejecuta una tarea."""
    task_id = f"task_{uuid.uuid4().hex[:8]}"
    data = {"id": task_id, **body.model_dump()}
    db_create_task(data)

    # Ejecutar inmediatamente si es tipo unique
    if body.task_type == "unique":
        background.add_task(_run_task_background, task_id, request.app)

    return {"id": task_id, "message": f"Tarea '{body.name}' creada", **db_get_task(task_id)}

@router.post("/tasks/{task_id}/run")
async def run_task(
    task_id: str,
    background: BackgroundTasks,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Ejecuta manualmente una tarea."""
    task = db_get_task(task_id)
    if not task:
        raise HTTPException(404)
    background.add_task(_run_task_background, task_id, request.app)
    return {"task_id": task_id, "message": "Tarea en ejecución"}

@router.post("/tasks/{task_id}/cancel")
def cancel_task(
    task_id: str,
    current_user: dict = Depends(get_current_user),
):
    db_update_task(task_id, status="cancelled")
    return {"task_id": task_id, "status": "cancelled"}

@router.delete("/tasks/{task_id}")
def delete_task(
    task_id: str,
    current_user: dict = Depends(get_current_user),
):
    task = db_get_task(task_id)
    if not task:
        raise HTTPException(404)
    if task['status'] == 'running':
        raise HTTPException(409, "No se puede eliminar una tarea en ejecución")
    db_update_task(task_id, status="deleted")
    return {"deleted": task_id}
