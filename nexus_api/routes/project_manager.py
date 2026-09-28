from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
import sqlite3, sys, os
from pathlib import Path
from nexus_api.config import NEXUS_DATA_PATH
from nexus_api.auth.deps import require_operator
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
router = APIRouter(dependencies=[Depends(require_operator)])
DB = NEXUS_DATA_PATH / "database.db"

class ProjectRequest(BaseModel):
    name: str
    repo_path: Optional[str] = None

class StatusUpdate(BaseModel):
    project_id: str
    status: str

@router.post("/create")
async def create_project(req: ProjectRequest):
    from nexus_core.agents.generated.project_manager_agent import ProjectManagerAgent
    pm = ProjectManagerAgent()
    result = pm.create_project(name=req.name, repo_path=req.repo_path)
    if not result.get("success"):
        raise HTTPException(500, result.get("error", "Error"))
    return result

@router.get("/list")
async def list_projects():
    if not DB.exists():
        return {"projects": [], "total": 0}
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT project_id, name, status, repo_path, created_at FROM projects ORDER BY created_at DESC").fetchall()
    conn.close()
    return {"projects": [{"project_id": r[0], "name": r[1], "status": r[2], "repo_path": r[3], "created_at": r[4]} for r in rows], "total": len(rows)}

@router.patch("/status")
async def update_status(req: StatusUpdate):
    valid = ["PLANEACION", "DESARROLLO", "PRUEBAS", "REVISION", "DEPLOY", "COMPLETADO", "PAUSADO"]
    if req.status not in valid:
        raise HTTPException(400, f"Estado invalido. Validos: {valid}")
    conn = sqlite3.connect(DB)
    conn.execute("UPDATE projects SET status=? WHERE project_id=?", (req.status, req.project_id))
    conn.commit()
    conn.close()
    return {"project_id": req.project_id, "status": req.status, "updated": True}

@router.get("/{project_id}")
async def get_project(project_id: str):
    conn = sqlite3.connect(DB)
    row = conn.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Proyecto no encontrado")
    return {"project_id": row[0], "name": row[1], "status": row[2], "repo_path": row[3], "created_at": row[4]}
