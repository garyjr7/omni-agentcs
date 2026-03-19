from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Dict, Any
from nexus_api.services.nexus_service import NexusService

router = APIRouter()

# ── Dependency — obtiene el servicio desde el estado de la app ──
def get_nexus_service() -> NexusService:
    # nexus_svc deprecated
    return nexus_svc

# ── Models ──
class GoalRequest(BaseModel):
    goal: str
    context: Dict[str, Any] = {}

# ── Endpoints ──
@router.get("/status")
async def get_status(svc: NexusService = Depends(get_nexus_service)):
    return await svc.get_status()

@router.post("/goal")
async def submit_goal(request: GoalRequest, svc: NexusService = Depends(get_nexus_service)):
    return await svc.submit_goal(request.goal, request.context)
