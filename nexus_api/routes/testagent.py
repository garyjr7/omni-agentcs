"""TestAgent API — Filtro de calidad BajioWare."""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from nexus_api.auth.deps import require_operator

router = APIRouter(dependencies=[Depends(require_operator)])

class TestRequest(BaseModel):
    filepath: str
    project_id: Optional[str] = "general"

class SandboxRequest(BaseModel):
    project_path: str
    test_command: Optional[str] = "pytest"
    project_id: Optional[str] = "general"

@router.post("/syntax")
async def syntax_check(req: TestRequest):
    from nexus_core.agents.generated.test_agent import run_syntax_check
    return run_syntax_check(req.filepath, req.project_id)

@router.post("/lint")
async def lint_check(req: TestRequest):
    from nexus_core.agents.generated.test_agent import run_lint_check
    return run_lint_check(req.filepath, req.project_id)

@router.post("/security")
async def security_check(req: TestRequest):
    from nexus_core.agents.generated.test_agent import run_security_check
    return run_security_check(req.filepath, req.project_id)

@router.post("/full")
async def full_check(req: TestRequest):
    """Ejecuta todos los checks: sintaxis + lint + seguridad."""
    from nexus_core.agents.generated.test_agent import full_quality_check
    return full_quality_check(req.filepath, req.project_id)

@router.post("/sandbox")
async def sandbox_test(req: SandboxRequest):
    """Ejecuta pruebas en Docker sandbox aislado."""
    from nexus_core.agents.generated.test_agent import run_in_docker_sandbox
    return run_in_docker_sandbox(req.project_path, req.test_command, req.project_id)

@router.get("/history")
async def test_history(project_id: Optional[str] = None, limit: int = 20):
    from nexus_core.agents.generated.test_agent import get_test_history
    results = get_test_history(project_id=project_id, limit=limit)
    return {"results": results, "total": len(results)}
