from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import Optional
from nexus_api.auth.deps import get_current_user, require_operator
from nexus_api.services.memory_service import (
    init_memory_table, list_agents_with_memory, get_context,
    get_agent_stats, clear_agent_memory, search_memory,
    save_message, save_summary, get_summary
)

router = APIRouter(prefix="/memory", tags=["memory"])
init_memory_table()

class SaveMessageRequest(BaseModel):
    agent_id:   str
    agent_name: str
    role:       str
    content:    str
    session_id: Optional[str] = None

class SaveSummaryRequest(BaseModel):
    agent_id:   str
    summary:    str
    session_id: Optional[str] = None
    msg_count:  int = 0

@router.get("/agents")
async def list_agents(user=Depends(get_current_user)):
    """Lista todos los agentes que tienen memoria almacenada."""
    agents = list_agents_with_memory()
    return {"agents": agents, "total": len(agents)}

@router.get("/agents/{agent_id}")
async def agent_memory(
    agent_id: str,
    session_id: Optional[str] = Query(None),
    limit: int = Query(20, le=100),
    user=Depends(get_current_user)
):
    """Obtiene el historial de memoria de un agente."""
    ctx   = get_context(agent_id, session_id, limit)
    stats = get_agent_stats(agent_id)
    summ  = get_summary(agent_id, session_id)
    return {
        "agent_id":   agent_id,
        "session_id": session_id,
        "context":    ctx,
        "summary":    summ,
        "stats":      stats
    }

@router.get("/agents/{agent_id}/stats")
async def agent_stats(agent_id: str, user=Depends(get_current_user)):
    return get_agent_stats(agent_id)

@router.get("/agents/{agent_id}/search")
async def search(
    agent_id: str,
    q: str = Query(..., min_length=2),
    limit: int = Query(10, le=50),
    user=Depends(get_current_user)
):
    results = search_memory(agent_id, q, limit)
    return {"results": results, "total": len(results), "query": q}

@router.post("/messages")
async def add_message(body: SaveMessageRequest, user=Depends(require_operator)):
    msg_id = save_message(
        body.agent_id, body.agent_name,
        body.role, body.content, body.session_id
    )
    return {"id": msg_id, "status": "saved"}

@router.post("/summaries")
async def add_summary(body: SaveSummaryRequest, user=Depends(require_operator)):
    save_summary(body.agent_id, body.summary, body.session_id, body.msg_count)
    return {"status": "saved"}

@router.delete("/agents/{agent_id}")
async def clear_memory(
    agent_id: str,
    session_id: Optional[str] = Query(None),
    user=Depends(require_operator)
):
    deleted = clear_agent_memory(agent_id, session_id)
    return {"deleted": deleted, "agent_id": agent_id}
