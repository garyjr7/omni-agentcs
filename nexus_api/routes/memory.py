from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Optional
from nexus_api.auth.deps import get_current_user, require_operator
from nexus_api.config import NEXUS_DB_PATH
from nexus_core.kernel.memory import MemoryStore
from nexus_core.kernel.store_factory import get_control_store

router = APIRouter(prefix="/memory", tags=["memory"])
store = get_control_store(NEXUS_DB_PATH)
memory = MemoryStore(store)


def tenant_for(user: dict) -> str:
    return user.get("tenant_id", "system")

class SaveMessageRequest(BaseModel):
    agent_id:   str
    agent_name: str
    role:       str
    content:    str
    session_id: Optional[str] = None
    classification: str = "internal"
    retention_days: Optional[int] = None

class SaveSummaryRequest(BaseModel):
    agent_id:   str
    summary:    str
    session_id: Optional[str] = None
    msg_count:  int = 0

@router.get("/agents")
async def list_agents(user=Depends(get_current_user)):
    """Lista todos los agentes que tienen memoria almacenada."""
    agents = memory.agents(tenant_for(user))
    return {"agents": agents, "total": len(agents)}

@router.get("/agents/{agent_id}")
async def agent_memory(
    agent_id: str,
    session_id: Optional[str] = Query(None),
    limit: int = Query(20, le=100),
    user=Depends(get_current_user)
):
    """Obtiene el historial de memoria de un agente."""
    tenant_id = tenant_for(user)
    ctx = memory.context(tenant_id, agent_id, session_id, limit)
    stats = memory.stats(tenant_id, agent_id)
    summ = memory.summary(tenant_id, agent_id, session_id)
    return {
        "agent_id":   agent_id,
        "session_id": session_id,
        "context":    ctx,
        "summary":    summ,
        "stats":      stats
    }

@router.get("/agents/{agent_id}/stats")
async def agent_stats(agent_id: str, user=Depends(get_current_user)):
    return memory.stats(tenant_for(user), agent_id)

@router.get("/agents/{agent_id}/search")
async def search(
    agent_id: str,
    q: str = Query(..., min_length=2),
    limit: int = Query(10, le=50),
    user=Depends(get_current_user)
):
    results = memory.search(tenant_for(user), agent_id, q, limit)
    return {"results": results, "total": len(results), "query": q}

@router.post("/messages")
async def add_message(body: SaveMessageRequest, user=Depends(require_operator)):
    msg_id = memory.save_message(
        tenant_for(user), body.agent_id, body.agent_name,
        body.role, body.content, body.session_id,
        body.classification, body.retention_days,
    )
    return {"id": msg_id, "status": "saved"}

@router.post("/summaries")
async def add_summary(body: SaveSummaryRequest, user=Depends(require_operator)):
    summary_id = memory.save_summary(
        tenant_for(user), body.agent_id, body.summary, body.session_id, body.msg_count,
    )
    return {"id": summary_id, "status": "saved"}

@router.delete("/agents/{agent_id}")
async def clear_memory(
    agent_id: str,
    session_id: Optional[str] = Query(None),
    user=Depends(require_operator)
):
    deleted = memory.clear(tenant_for(user), agent_id, session_id)
    return {"deleted": deleted, "agent_id": agent_id}
