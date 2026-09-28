"""Plans API — Junior propone, Marcos aprueba, Junior ejecuta."""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from nexus_api.auth.deps import require_operator

router = APIRouter(dependencies=[Depends(require_operator)])

class PlanStep(BaseModel):
    name: str
    capability: str
    payload: dict = {}
    description: Optional[str] = ""

class CreatePlanRequest(BaseModel):
    title: str
    objective: str
    steps: List[PlanStep]
    risk_level: Optional[str] = "low"
    affects_core: Optional[bool] = False

class ApprovalRequest(BaseModel):
    approved_by: str = "marcos"

class RejectRequest(BaseModel):
    reason: str = ""

@router.post("/create")
async def create_plan(req: CreatePlanRequest):
    """Junior crea un plan completo para revisión de Marcos."""
    from nexus_core.agents.generated.plan_agent import create_plan
    steps = [s.dict() for s in req.steps]
    return create_plan(req.title, req.objective, steps, req.risk_level, req.affects_core)

@router.get("/pending")
async def pending_plans():
    """Planes esperando aprobación de Marcos."""
    from nexus_core.agents.generated.plan_agent import get_pending_plans
    plans = get_pending_plans()
    return {"plans": plans, "total": len(plans),
            "message": f"{len(plans)} planes esperan tu aprobación" if plans else "Sin planes pendientes"}

@router.get("/list")
async def list_plans(status: Optional[str] = None):
    """Lista todos los planes."""
    from nexus_core.agents.generated.plan_agent import list_plans
    plans = list_plans(status=status)
    return {"plans": plans, "total": len(plans)}

@router.get("/{plan_id}")
async def get_plan(plan_id: str):
    """Ver detalles de un plan específico."""
    from nexus_core.agents.generated.plan_agent import get_plan
    plan = get_plan(plan_id)
    if "error" in plan:
        raise HTTPException(404, plan["error"])
    return plan

@router.post("/approve/{plan_id}")
async def approve_plan(plan_id: str, req: ApprovalRequest):
    """✅ Marcos aprueba el plan — Junior ejecutará todos los pasos."""
    from nexus_core.agents.generated.plan_agent import approve_plan
    return approve_plan(plan_id, req.approved_by)

@router.post("/reject/{plan_id}")
async def reject_plan(plan_id: str, req: RejectRequest):
    """❌ Marcos rechaza el plan."""
    from nexus_core.agents.generated.plan_agent import reject_plan
    return reject_plan(plan_id, req.reason)

@router.post("/execute/{plan_id}")
async def execute_plan(plan_id: str):
    """🚀 Ejecutar un plan aprobado — Junior ejecuta todos los pasos automáticamente."""
    from nexus_core.agents.generated.plan_agent import execute_approved_plan
    return await execute_approved_plan(plan_id)
