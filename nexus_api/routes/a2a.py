"""Minimal A2A-compatible gateway backed by durable NEXUS runs."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from nexus_api.auth.deps import get_current_user
from nexus_api.config import NEXUS_DB_PATH, settings
from nexus_core.kernel.store_factory import get_control_store

router = APIRouter(tags=["A2A"])
store = get_control_store(NEXUS_DB_PATH)


class JSONRPCRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: str | int
    method: str
    params: dict = {}


@router.get("/.well-known/agent-card.json")
def agent_card():
    return {
        "protocolVersion": "0.3.0",
        "name": "BAJIOWARE NEXUS",
        "description": "Policy-governed enterprise agent directory and execution plane",
        "url": f"{settings.NEXUS_PUBLIC_URL.rstrip('/')}/a2a",
        "preferredTransport": "JSONRPC",
        "version": "0.5.0",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": [{
            "id": "submit-goal",
            "name": "Submit governed goal",
            "description": "Creates a durable NEXUS run subject to tenant policies",
            "tags": ["orchestration", "agents", "governance"],
        }],
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "security": [{"bearer": []}],
    }


def rpc_result(request_id, result):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def rpc_error(request_id, code: int, message: str):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


@router.post("/a2a")
def a2a(request: JSONRPCRequest, user: dict = Depends(get_current_user)):
    tenant_id = user.get("tenant_id", "system")
    if request.jsonrpc != "2.0":
        return rpc_error(request.id, -32600, "Invalid JSON-RPC version")
    if request.method == "message/send":
        message = request.params.get("message", {})
        message_id = message.get("messageId")
        if not message_id:
            return rpc_error(request.id, -32602, "message.messageId is required")
        text_parts = [
            part.get("text", "") for part in message.get("parts", [])
            if part.get("kind") == "text"
        ]
        run = store.create_run(
            tenant_id,
            {"goal": "\n".join(text_parts), "source": "a2a", "message": message},
            idempotency_key=f"a2a:{message_id}",
        )
        return rpc_result(request.id, {
            "id": run["id"],
            "contextId": request.params.get("contextId", run["id"]),
            "status": {"state": "submitted"},
            "kind": "task",
        })
    if request.method == "tasks/get":
        run = store.get_run(str(request.params.get("id", "")), tenant_id)
        if not run:
            return rpc_error(request.id, -32001, "Task not found")
        state_map = {
            "pending": "submitted", "queued": "submitted", "running": "working",
            "completed": "completed", "failed": "failed", "cancelled": "canceled",
        }
        result = {
            "id": run["id"], "contextId": run["id"],
            "status": {"state": state_map.get(run["status"], "unknown")},
            "kind": "task",
        }
        if run.get("result") is not None:
            result["artifacts"] = [{
                "artifactId": f"result-{run['id']}",
                "parts": [{"kind": "data", "data": run["result"]}],
            }]
        return rpc_result(request.id, result)
    return rpc_error(request.id, -32601, "Method not found")
