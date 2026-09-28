"""Durable policy approvals for the new NEXUS kernel."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from nexus_api.auth.deps import get_current_user, require_operator
from nexus_api.config import NEXUS_DB_PATH
from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.store_factory import get_control_store

router = APIRouter(prefix="/approvals", tags=["Approvals"])
service = ApprovalService(get_control_store(NEXUS_DB_PATH))


class Decision(BaseModel):
    approved: bool
    reason: str = ""


@router.get("/{approval_id}")
def get_approval(approval_id: str, user: dict = Depends(get_current_user)):
    tenant_id = user.get("tenant_id", "system")
    try:
        return service.get(approval_id, tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{approval_id}/decision")
def decide(approval_id: str, body: Decision, user: dict = Depends(require_operator)):
    tenant_id = user.get("tenant_id", "system")
    try:
        return service.decide(
            approval_id, tenant_id, str(user["id"]), body.approved, body.reason
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
