"""
NEXUS PRO — Agents API
CRUD completo de agentes: crear, configurar modelo, asignar tools
"""
import uuid
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from nexus_api.db.database import (
    db_list_agents, db_get_agent, db_create_agent,
    db_update_agent, db_delete_agent
)

router = APIRouter()

class CreateAgentRequest(BaseModel):
    name: str
    role: str = "general"
    description: str = ""
    model: str = "gpt-4o"
    provider: str = "openai"
    temperature: float = 0.7
    max_tokens: int = 4096
    system_prompt: str = ""
    tools: List[str] = []
    hitl_mode: str = "destructive"  # always | destructive | never

class UpdateAgentRequest(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    description: Optional[str] = None
    model: Optional[str] = None
    provider: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    system_prompt: Optional[str] = None
    tools: Optional[List[str]] = None
    hitl_mode: Optional[str] = None

class AssignToolsRequest(BaseModel):
    tools: List[str]

@router.get("/agents")
def list_agents(request: Request):
    """Lista todos los agentes — DB + Registry."""
    db_agents = db_list_agents()

    # Enriquecer con estado del Registry si disponible
    registry = getattr(request.app.state, 'registry', None)
    if registry and db_agents:
        # Los agentes del registry tienen stats en tiempo real
        pass

    return db_agents

@router.get("/agents/registry")
async def get_registry_agents(request: Request):
    """Agentes vivos en el Registry del Orchestrator."""
    registry = getattr(request.app.state, 'registry', None)
    if not registry:
        return []
    agents = await registry.get_all()
    return [a.get_stats() for a in agents.values()]

@router.get("/agents/{agent_id}")
def get_agent(agent_id: str):
    agent = db_get_agent(agent_id)
    if not agent:
        raise HTTPException(404, f"Agente '{agent_id}' no encontrado")
    return agent

@router.post("/agents", status_code=201)
def create_agent(body: CreateAgentRequest):
    """Crea un nuevo agente con modelo y herramientas."""
    agent_id = f"agt_{uuid.uuid4().hex[:8]}"
    data = {"id": agent_id, **body.model_dump()}
    db_create_agent(data)
    return {"id": agent_id, "message": f"Agente '{body.name}' creado", **data}

@router.put("/agents/{agent_id}")
def update_agent(agent_id: str, body: UpdateAgentRequest):
    """Actualiza configuración de un agente."""
    existing = db_get_agent(agent_id)
    if not existing:
        raise HTTPException(404, f"Agente '{agent_id}' no encontrado")
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    db_update_agent(agent_id, updates)
    return db_get_agent(agent_id)

@router.post("/agents/{agent_id}/tools")
def assign_tools(agent_id: str, body: AssignToolsRequest):
    """Asigna herramientas a un agente."""
    existing = db_get_agent(agent_id)
    if not existing:
        raise HTTPException(404, f"Agente '{agent_id}' no encontrado")
    db_update_agent(agent_id, {"tools": body.tools})
    return {"agent_id": agent_id, "tools": body.tools, "message": "Herramientas asignadas"}

@router.delete("/agents/{agent_id}")
def delete_agent(agent_id: str):
    db_delete_agent(agent_id)
    return {"deleted": agent_id}


# ── Chat directo con un agente ────────────────────────────────
from fastapi import Request as _Request

class ChatRequest(BaseModel):
    message: str
    system_override: Optional[str] = None

@router.post("/agents/{agent_id}/chat")
async def chat_with_agent(agent_id: str, body: ChatRequest, request: _Request):
    """
    Chat directo con un agente — usa su LLM y system prompt configurado.
    """
    agent_cfg = db_get_agent(agent_id)
    if not agent_cfg:
        raise HTTPException(404, f"Agente '{agent_id}' no encontrado")

    llm = getattr(request.app.state, 'llm', None)
    if not llm:
        raise HTTPException(503, "LLM no disponible — configura una API key")

    system = body.system_override or agent_cfg.get("system_prompt") or \
        f"Eres {agent_cfg['name']}, un agente de IA especializado en {agent_cfg['role']}."

    try:
        response = await llm.ask(system, body.message)
        return {
            "agent": agent_cfg["name"],
            "role": agent_cfg["role"],
            "model": agent_cfg["model"],
            "message": body.message,
            "response": response,
        }
    except Exception as e:
        raise HTTPException(500, f"Error LLM: {str(e)}")
