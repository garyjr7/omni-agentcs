"""Tenant-scoped ABAC/RBAC policy administration."""

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from nexus_api.auth.deps import ensure_tenant_access, require_admin
from nexus_api.config import NEXUS_DB_PATH
from nexus_core.kernel.policy import PolicyRepository
from nexus_core.kernel.store_factory import get_control_store

router = APIRouter(prefix="/policies", tags=["Policies"])
store = get_control_store(NEXUS_DB_PATH)
repository = PolicyRepository(store)


class PolicyCreate(BaseModel):
    tenant_id: str
    name: str = Field(min_length=3, max_length=120)
    effect: str
    actions: list[str]
    resource_kinds: list[str]
    conditions: dict = {}
    requires_approval: bool = False
    version: str = "1.0.0"


class PolicyBinding(BaseModel):
    tenant_id: str
    policy_id: str
    subject_type: str
    subject_id: str


@router.get("")
def list_policies(tenant_id: str, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, tenant_id)
    with store.connect() as conn:
        rows = conn.execute(
            "SELECT * FROM kernel_policies WHERE tenant_id=? ORDER BY created_at",
            (tenant_id,),
        ).fetchall()
    items = []
    for row in rows:
        value = dict(row)
        for key in ("actions", "resource_kinds", "conditions"):
            value[key] = json.loads(value[key])
        items.append(value)
    return {"items": items}


@router.post("", status_code=201)
def create_policy(body: PolicyCreate, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    try:
        return repository.create(**body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/bindings", status_code=201)
def bind_policy(body: PolicyBinding, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    try:
        binding_id = repository.bind(**body.model_dump())
        return {"id": binding_id}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
