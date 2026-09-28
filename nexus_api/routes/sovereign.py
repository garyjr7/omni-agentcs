"""First-party NEXUS Sovereign conversations and durable runs API."""

from __future__ import annotations

import asyncio
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from nexus_api.auth.deps import ensure_tenant_access, get_current_user, require_operator
from nexus_api.config import NEXUS_DB_PATH
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.knowledge import KnowledgeStore
from nexus_core.kernel.store_factory import get_control_store

router = APIRouter(prefix="/sovereign", tags=["Sovereign"])
store = get_control_store(NEXUS_DB_PATH)
audit = AuditWriter(store)
knowledge = KnowledgeStore(store)


class ConversationCreate(BaseModel):
    tenant_id: str
    title: str = Field(default="Nueva conversación", max_length=120)
    agent_id: str | None = None
    classification: str = "internal"


class MessageCreate(BaseModel):
    content: str = Field(min_length=1, max_length=100_000)
    model_route: str | None = None
    idempotency_key: str | None = None


class AgentRunCreate(BaseModel):
    tenant_id: str
    objective: str = Field(min_length=1, max_length=100_000)
    agent_id: str = "nexus"
    model_route: str | None = None
    idempotency_key: str | None = None
    mode: str = "brain"
    # Declarative, persisted execution plan. Every item is still authorized
    # and post-condition-verified by the worker; this is not raw shell input.
    steps: list[dict] = Field(default_factory=list, max_length=8)
    expected_response: str | None = Field(default=None, max_length=100_000)


class KnowledgeCreate(BaseModel):
    tenant_id: str
    title: str = Field(min_length=1, max_length=200)
    source_uri: str = Field(min_length=1, max_length=2000)
    content: str = Field(min_length=1, max_length=2_000_000)
    classification: str = "internal"
    metadata: dict = {}


class ToolRunCreate(BaseModel):
    tenant_id: str
    tool_id: str
    arguments: dict = {}
    approval_id: str | None = None
    idempotency_key: str | None = None


def _identity(user: dict) -> tuple[str, str]:
    return str(user.get("tenant_id", "system")), str(user["id"])


@router.get("/capabilities")
async def capabilities(user: dict = Depends(get_current_user)):
    from nexus_core.kernel.runtime import build_default_registry
    return {"version": "3.0.0", "mode": "sovereign",
            "task_types": build_default_registry().task_types,
            "tenant_id": user.get("tenant_id", "system")}


@router.post("/knowledge", status_code=201)
async def ingest_knowledge(body: KnowledgeCreate,
                           user: dict = Depends(require_operator)):
    ensure_tenant_access(user, body.tenant_id)
    result = knowledge.ingest(tenant_id=body.tenant_id, title=body.title,
                              source_uri=body.source_uri, content=body.content,
                              classification=body.classification,
                              metadata=body.metadata, created_by=str(user["id"]))
    audit.append(tenant_id=body.tenant_id, trace_id=uuid.uuid4().hex,
                 actor_id=str(user["id"]), action="knowledge.ingest",
                 resource_type="knowledge_document", resource_id=result["id"],
                 payload={"source_uri": body.source_uri,
                          "classification": body.classification}, decision="allow")
    return result


@router.get("/knowledge/search")
async def search_knowledge(tenant_id: str, q: str = Query(min_length=1),
                           user: dict = Depends(get_current_user)):
    ensure_tenant_access(user, tenant_id)
    allowed = {"public", "internal"}
    if user.get("role") in {"admin", "operator"}:
        allowed.add("confidential")
    if user.get("role") == "admin":
        allowed.add("restricted")
    return {"results": knowledge.search(tenant_id, q,
                                         allowed_classifications=allowed)}


@router.get("/operations/summary")
async def operations_summary(tenant_id: str,
                             user: dict = Depends(get_current_user)):
    ensure_tenant_access(user, tenant_id)
    with store.connect() as conn:
        tasks = [dict(row) for row in conn.execute(
            """SELECT status,COUNT(*) AS count FROM kernel_tasks
            WHERE tenant_id=? GROUP BY status""", (tenant_id,)).fetchall()]
        usage = [dict(row) for row in conn.execute(
            """SELECT metric,SUM(amount) AS total FROM kernel_usage_ledger
            WHERE tenant_id=? GROUP BY metric""", (tenant_id,)).fetchall()]
        runs = [dict(row) for row in conn.execute(
            """SELECT status,COUNT(*) AS count FROM kernel_runs
            WHERE tenant_id=? GROUP BY status""", (tenant_id,)).fetchall()]
    return {"tenant_id": tenant_id, "tasks": tasks, "runs": runs, "usage": usage}


@router.post("/conversations", status_code=201)
async def create_conversation(body: ConversationCreate,
                              user: dict = Depends(get_current_user)):
    ensure_tenant_access(user, body.tenant_id)
    return store.create_conversation(body.tenant_id, str(user["id"]), body.title,
                                     body.agent_id, body.classification)


@router.get("/conversations")
async def list_conversations(tenant_id: str,
                             user: dict = Depends(get_current_user)):
    ensure_tenant_access(user, tenant_id)
    return {"conversations": store.list_conversations(tenant_id, str(user["id"]))}


@router.get("/conversations/{conversation_id}/messages")
async def list_messages(conversation_id: str, tenant_id: str,
                        user: dict = Depends(get_current_user)):
    ensure_tenant_access(user, tenant_id)
    if not store.get_conversation(tenant_id, conversation_id, str(user["id"])):
        raise HTTPException(404, "conversation not found")
    return {"messages": store.list_messages(tenant_id, conversation_id)}


@router.delete("/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str, tenant_id: str,
                              user: dict = Depends(get_current_user)):
    ensure_tenant_access(user, tenant_id)
    if not store.delete_conversation(tenant_id, conversation_id, str(user["id"])):
        raise HTTPException(404, "conversation not found")
    return {"status": "deleted"}


@router.post("/conversations/{conversation_id}/messages", status_code=202)
async def send_message(conversation_id: str, body: MessageCreate,
                       user: dict = Depends(require_operator)):
    tenant_id, owner_id = _identity(user)
    conversation = store.get_conversation(tenant_id, conversation_id, owner_id)
    if not conversation:
        raise HTTPException(404, "conversation not found")
    run = store.create_run(
        tenant_id, {"kind": "conversation", "conversation_id": conversation_id,
                    "actor_id": owner_id, "classification": conversation["classification"]},
        idempotency_key=body.idempotency_key,
    )
    if run["status"] != "pending":
        return run
    message = store.append_message(
        tenant_id, conversation_id, "user", body.content, run_id=run["id"],
        classification=conversation["classification"],
    )
    store.append_run_event(tenant_id, run["id"], "run.created",
                           {"kind": "conversation", "conversation_id": conversation_id})
    task = store.enqueue_task(
        tenant_id=tenant_id, run_id=run["id"], task_type="conversation.respond",
        payload={"conversation_id": conversation_id,
                 "model_route": body.model_route}, timeout_seconds=120,
    )
    audit.append(tenant_id=tenant_id, trace_id=uuid.uuid4().hex, actor_id=owner_id,
                 action="conversation.message", resource_type="conversation",
                 resource_id=conversation_id,
                 payload={"run_id": run["id"], "message_id": message["id"]},
                 decision="allow")
    return {"run": run, "task": task, "message": message}


@router.post("/runs", status_code=202)
async def create_agent_run(body: AgentRunCreate,
                           user: dict = Depends(require_operator)):
    ensure_tenant_access(user, body.tenant_id)
    run = store.create_run(body.tenant_id, {
        "kind": "agent", "agent_id": body.agent_id, "actor_id": str(user["id"])
    }, idempotency_key=body.idempotency_key)
    if run["status"] == "pending":
        store.append_run_event(body.tenant_id, run["id"], "run.created",
                               {"kind": "agent", "agent_id": body.agent_id})
        task_type = "brain.run" if body.mode == "brain" else "agent.run"
        task = store.enqueue_task(
            tenant_id=body.tenant_id, run_id=run["id"], task_type=task_type,
            payload={"agent_id": body.agent_id, "objective": body.objective,
                     "model_route": body.model_route, "steps": body.steps,
                     "expected_response": body.expected_response,
                     "identity": {"subject_id": str(user["id"]),
                                  "roles": [str(user["role"])]}}, timeout_seconds=300,
        )
        run["task"] = task
    return run


@router.post("/tools/invoke", status_code=202)
async def invoke_tool(body: ToolRunCreate,
                      user: dict = Depends(require_operator)):
    ensure_tenant_access(user, body.tenant_id)
    run = store.create_run(body.tenant_id, {
        "kind": "tool", "tool_id": body.tool_id, "actor_id": str(user["id"])
    }, idempotency_key=body.idempotency_key)
    if run["status"] == "pending":
        store.append_run_event(body.tenant_id, run["id"], "run.created",
                               {"kind": "tool", "tool_id": body.tool_id})
        run["task"] = store.enqueue_task(
            tenant_id=body.tenant_id, run_id=run["id"], task_type="tool.invoke",
            payload={"tool_id": body.tool_id, "arguments": body.arguments,
                     "approval_id": body.approval_id,
                     "identity": {"subject_id": str(user["id"]),
                                  "roles": [str(user["role"])]}},
            timeout_seconds=120,
        )
    return run


@router.get("/runs/{run_id}")
async def get_run(run_id: str, tenant_id: str,
                  user: dict = Depends(get_current_user)):
    ensure_tenant_access(user, tenant_id)
    run = store.get_run(run_id, tenant_id)
    if not run:
        raise HTTPException(404, "run not found")
    run["events"] = store.list_run_events(tenant_id, run_id)
    return run


@router.post("/runs/{run_id}/cancel", status_code=202)
async def cancel_run(run_id: str, tenant_id: str,
                     user: dict = Depends(require_operator)):
    ensure_tenant_access(user, tenant_id)
    with store.connect() as conn:
        rows = conn.execute("SELECT id FROM kernel_tasks WHERE run_id=? AND tenant_id=?",
                            (run_id, tenant_id)).fetchall()
    changed = [row["id"] for row in rows
               if store.request_task_cancel(row["id"], tenant_id, str(user["id"]))]
    store.append_run_event(tenant_id, run_id, "run.cancel_requested", {"tasks": changed})
    return {"run_id": run_id, "cancel_requested": bool(changed), "tasks": changed}


@router.get("/runs/{run_id}/events")
async def run_events(run_id: str, tenant_id: str, after: int = Query(0, ge=0),
                     user: dict = Depends(get_current_user)):
    ensure_tenant_access(user, tenant_id)
    if not store.get_run(run_id, tenant_id):
        raise HTTPException(404, "run not found")
    return {"events": store.list_run_events(tenant_id, run_id, after)}


@router.get("/runs/{run_id}/stream")
async def stream_run(run_id: str, tenant_id: str,
                     user: dict = Depends(get_current_user)):
    ensure_tenant_access(user, tenant_id)
    if not store.get_run(run_id, tenant_id):
        raise HTTPException(404, "run not found")

    async def generate():
        cursor = 0
        while True:
            events = store.list_run_events(tenant_id, run_id, cursor)
            for event in events:
                cursor = event["sequence"]
                yield f"id: {cursor}\nevent: {event['event_type']}\ndata: {json.dumps(event)}\n\n"
            run = store.get_run(run_id, tenant_id)
            if run and run["status"] in {"completed", "failed", "dead_letter", "cancelled"}:
                yield f"event: stream.closed\ndata: {json.dumps({'status': run['status']})}\n\n"
                return
            await asyncio.sleep(0.75)

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
