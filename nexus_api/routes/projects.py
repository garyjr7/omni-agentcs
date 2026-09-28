"""
nexus_api/routes/projects.py — NEXUS PRO v2.0
Gestión de proyectos — sin dependencias del proyecto viejo BAJIOWARE
"""
import uuid
import asyncio
from datetime import datetime
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, Depends
from pydantic import BaseModel, Field
from nexus_api.auth.deps import get_current_user, require_operator, authenticate_websocket

router = APIRouter()

# ── In-memory store (migrar a DB en fase siguiente) ───────────
_projects: Dict[str, dict] = {}
_subscribers: Dict[str, list] = {}


# ── Schemas ───────────────────────────────────────────────────
class CreateProjectRequest(BaseModel):
    name: str = Field(..., min_length=2, description="Nombre del proyecto")
    description: str = Field("", description="Descripción")
    tech_stack: List[str] = Field(default_factory=list)
    prompt: str = Field("", description="Instrucción para el agente generador")


class ProjectResponse(BaseModel):
    id: str
    name: str
    status: str
    description: str
    tech_stack: List[str]
    created_at: str
    progress: int
    message: str = ""


# ── Helpers ───────────────────────────────────────────────────
def _new_project(req: CreateProjectRequest) -> dict:
    return {
        "id": f"proj_{uuid.uuid4().hex[:8]}",
        "name": req.name,
        "description": req.description,
        "tech_stack": req.tech_stack,
        "prompt": req.prompt,
        "status": "pending",
        "progress": 0,
        "files": {},
        "log": [],
        "errors": [],
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }


async def _notify(project_id: str, event: str, data: dict):
    subs = _subscribers.get(project_id, [])
    dead = []
    for q in subs:
        try:
            await q.put({"event": event, "data": data})
        except Exception:
            dead.append(q)
    for q in dead:
        subs.remove(q)


async def _run_pipeline(project_id: str, prompt: str):
    """Pipeline simplificado — en futuro conecta con WorkflowManager."""
    proj = _projects.get(project_id)
    if not proj:
        return

    proj["status"] = "running"
    await _notify(project_id, "pipeline_start", {"project_id": project_id})

    steps = [
        ("Analizando requerimientos", 10),
        ("Generando arquitectura", 25),
        ("Escribiendo código", 60),
        ("Validando estructura", 80),
        ("Finalizando proyecto", 100),
    ]

    for step_name, progress in steps:
        await asyncio.sleep(1.5)
        proj["progress"] = progress
        proj["log"].append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {step_name}...")
        await _notify(project_id, "log_line", {
            "line": step_name,
            "progress": progress,
        })

    proj["status"] = "completed"
    proj["updated_at"] = datetime.utcnow().isoformat()
    await _notify(project_id, "pipeline_done", {
        "project_id": project_id,
        "status": "completed",
        "progress": 100,
        "log": proj["log"],
    })


# ── Endpoints ─────────────────────────────────────────────────
@router.post("/", response_model=ProjectResponse, status_code=202)
async def create_project(body: CreateProjectRequest, background_tasks: BackgroundTasks, _: dict = Depends(require_operator)):
    proj = _new_project(body)
    _projects[proj["id"]] = proj
    background_tasks.add_task(_run_pipeline, proj["id"], body.prompt)
    return ProjectResponse(
        id=proj["id"],
        name=proj["name"],
        status=proj["status"],
        description=proj["description"],
        tech_stack=proj["tech_stack"],
        created_at=proj["created_at"],
        progress=0,
        message=f"Pipeline iniciado — WebSocket: /projects/ws/{proj['id']}",
    )


@router.get("/", response_model=List[dict])
async def list_projects(_: dict = Depends(get_current_user)):
    return [
        {k: v for k, v in p.items() if k != "files"}
        for p in _projects.values()
    ]


@router.get("/{project_id}")
async def get_project(project_id: str, _: dict = Depends(get_current_user)):
    proj = _projects.get(project_id)
    if not proj:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    return proj


@router.delete("/{project_id}")
async def delete_project(project_id: str, _: dict = Depends(require_operator)):
    proj = _projects.pop(project_id, None)
    if not proj:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    if proj["status"] == "running":
        raise HTTPException(status_code=409, detail="No se puede eliminar un proyecto en ejecución")
    return {"deleted": project_id}


@router.websocket("/ws/{project_id}")
async def project_ws(websocket: WebSocket, project_id: str):
    if not await authenticate_websocket(websocket):
        return
    await websocket.accept()
    proj = _projects.get(project_id)
    if not proj:
        await websocket.send_json({"event": "error", "data": {"msg": "Proyecto no encontrado"}})
        await websocket.close()
        return

    # Si ya terminó, enviar snapshot
    if proj["status"] in ("completed", "failed"):
        await websocket.send_json({
            "event": "pipeline_done",
            "data": {"project_id": project_id, "status": proj["status"],
                     "log": proj["log"], "progress": proj["progress"]},
        })
        await websocket.close()
        return

    # Suscribir
    queue: asyncio.Queue = asyncio.Queue()
    _subscribers.setdefault(project_id, []).append(queue)

    # Enviar log histórico
    for line in proj.get("log", []):
        await websocket.send_json({"event": "log_line", "data": {"line": line}})

    try:
        while True:
            try:
                payload = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json(payload)
                if payload.get("event") == "pipeline_done":
                    break
            except asyncio.TimeoutError:
                await websocket.send_json({"event": "ping", "data": {}})
    except WebSocketDisconnect:
        pass
    finally:
        subs = _subscribers.get(project_id, [])
        if queue in subs:
            subs.remove(queue)
        try:
            await websocket.close()
        except Exception:
            pass
