"""Durable workflow registration, dispatch and history API."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from nexus_api.auth.deps import ensure_tenant_access, require_admin, require_operator
from nexus_api.config import NEXUS_DB_PATH
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.store_factory import get_control_store
from nexus_core.kernel.workflows import DurableWorkflowEngine

router = APIRouter(prefix="/workflows", tags=["Workflows"])
store = get_control_store(NEXUS_DB_PATH)
engine = DurableWorkflowEngine(store)
audit = AuditWriter(store)


class WorkflowCreate(BaseModel):
    tenant_id: str
    name: str = Field(min_length=2, max_length=120)
    version: str = "1.0.0"
    definition: dict


class WorkflowDispatch(BaseModel):
    tenant_id: str
    workflow_id: str | None = None
    workflow_name: str | None = None
    input_data: dict = {}
    idempotency_key: str | None = None


@router.post("", status_code=201)
async def register_workflow(body: WorkflowCreate, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    try:
        result = engine.register(
            body.tenant_id, body.name, body.version, body.definition
        )
        audit.append(
            tenant_id=body.tenant_id, trace_id=uuid.uuid4().hex,
            actor_id=str(user["id"]), action="workflow.register",
            resource_type="workflow", resource_id=result["id"],
            payload={"name": body.name, "version": body.version}, decision="allow",
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/dispatch", status_code=202)
async def dispatch_workflow(body: WorkflowDispatch,
                            user: dict = Depends(require_operator)):
    ensure_tenant_access(user, body.tenant_id)
    workflow_id = body.workflow_id
    if not workflow_id and body.workflow_name:
        with store.connect() as conn:
            row = conn.execute(
                """SELECT id FROM kernel_workflows WHERE tenant_id=? AND name=?
                AND status='active' ORDER BY version DESC LIMIT 1""",
                (body.tenant_id, body.workflow_name),
            ).fetchone()
        workflow_id = row["id"] if row else None
    if not workflow_id:
        raise HTTPException(status_code=404, detail="workflow not found; register it first")
    try:
        result = engine.start(
            body.tenant_id, workflow_id, body.input_data,
            body.idempotency_key or f"api-{uuid.uuid4().hex}",
        )
        audit.append(
            tenant_id=body.tenant_id, trace_id=uuid.uuid4().hex,
            actor_id=str(user["id"]), action="workflow.dispatch",
            resource_type="run", resource_id=result["id"],
            payload={"run_id": result["id"], "workflow_id": workflow_id},
            decision="allow",
        )
        return result
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{run_id}")
async def workflow_status(run_id: str, tenant_id: str,
                          user: dict = Depends(require_operator)):
    ensure_tenant_access(user, tenant_id)
    run = store.get_run(run_id, tenant_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return {"run": run, "steps": engine.history(run_id, tenant_id)}
