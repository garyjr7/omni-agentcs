"""Kill Switch API — Control de seguridad crítica BajioWare."""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from nexus_api.auth.deps import require_admin

router = APIRouter(dependencies=[Depends(require_admin)])

class OperationRequest(BaseModel):
    operation_type: str
    description: str
    payload: dict = {}
    risk_level: str = "high"

class ApprovalRequest(BaseModel):
    approved_by: str = "marcos"

class RejectRequest(BaseModel):
    reason: str = ""

class EmergencyRequest(BaseModel):
    reason: str
    triggered_by: str = "marcos"

@router.get("/status")
async def kill_switch_status():
    """Estado del Kill Switch."""
    from nexus_core.agents.generated.kill_switch_agent import is_active, get_pending_operations
    pending = get_pending_operations()
    return {
        "kill_switch_active": is_active(),
        "pending_operations": len(pending),
        "pending": pending[:5],
        "message": "🚨 SISTEMA DETENIDO" if is_active() else "✅ Sistema operacional",
    }

@router.get("/pending")
async def get_pending():
    """Operaciones críticas pendientes de aprobación."""
    from nexus_core.agents.generated.kill_switch_agent import get_pending_operations
    ops = get_pending_operations()
    return {"pending": ops, "total": len(ops)}

@router.post("/request")
async def request_critical_op(req: OperationRequest):
    """Registra una operación crítica para aprobación."""
    from nexus_core.agents.generated.kill_switch_agent import request_approval, is_blacklisted
    if is_blacklisted(req.description):
        raise HTTPException(403, "Operación en lista negra — bloqueada permanentemente")
    return request_approval(req.operation_type, req.description, req.payload, req.risk_level)

@router.post("/approve/{op_id}")
async def approve_op(op_id: str, req: ApprovalRequest):
    """Aprueba una operación crítica — SOLO MARCOS puede hacer esto."""
    from nexus_core.agents.generated.kill_switch_agent import approve_operation
    return approve_operation(op_id, req.approved_by)

@router.post("/reject/{op_id}")
async def reject_op(op_id: str, req: RejectRequest):
    """Rechaza una operación crítica."""
    from nexus_core.agents.generated.kill_switch_agent import reject_operation
    return reject_operation(op_id, req.reason)

@router.post("/emergency/stop")
async def emergency_stop(req: EmergencyRequest):
    """🚨 KILL SWITCH — Detiene TODAS las operaciones inmediatamente."""
    from nexus_core.agents.generated.kill_switch_agent import activate_emergency_stop
    return activate_emergency_stop(req.reason, req.triggered_by)

@router.post("/emergency/resume")
async def emergency_resume(req: ApprovalRequest):
    """Reactiva el sistema tras un Kill Switch."""
    from nexus_core.agents.generated.kill_switch_agent import deactivate_emergency_stop
    return deactivate_emergency_stop(req.approved_by)
