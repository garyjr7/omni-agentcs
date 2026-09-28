"""Composite Tools API — Capacidades de alto nivel para Junior."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from nexus_api.auth.deps import require_operator

router = APIRouter(dependencies=[Depends(require_operator)])

class ExploreRequest(BaseModel):
    query: str
    base_path: Optional[str] = None
    file_type: Optional[str] = "*.py"

class AnalyzeRequest(BaseModel):
    project_path: str

class PatchRequest(BaseModel):
    filepath: str
    description: str
    old_text: str
    new_text: str
    auto_test: Optional[bool] = True

@router.post("/explore")
async def explore_filesystem(req: ExploreRequest):
    """Explorar y encontrar archivos relevantes en UNA operación."""
    from nexus_core.composite_tools import explore_filesystem
    return await explore_filesystem(req.query, req.base_path, req.file_type)

@router.post("/analyze")
async def analyze_project(req: AnalyzeRequest):
    """Análisis completo de un proyecto."""
    from nexus_core.composite_tools import analyze_project
    return await analyze_project(req.project_path)

@router.post("/patch")
async def smart_patch(req: PatchRequest):
    """Patch quirúrgico con backup + verificación + test automático."""
    from nexus_core.composite_tools import smart_patch
    return await smart_patch(req.filepath, req.description,
                              req.old_text, req.new_text, req.auto_test)

@router.get("/health")
async def system_health():
    """Check completo del sistema en UNA llamada."""
    from nexus_core.composite_tools import system_health_check
    return await system_health_check()
