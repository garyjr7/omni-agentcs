"""
NEXUS PRO — Teams API v2
CRUD de equipos: crear, agregar/quitar agentes, estrategia de orquestación
"""
import uuid
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from nexus_api.db.database import (
    db_list_teams, db_get_team, db_create_team,
    db_update_team, db_delete_team, db_get_agent
)

router = APIRouter()

class CreateTeamRequest(BaseModel):
    name: str
    description: str = ""
    specialization: str = "General"
    strategy: str = "sequential"   # sequential | parallel | hierarchical | consensus
    agents: List[str] = []         # lista de agent_ids
    hitl: str = "enabled"          # enabled | critical_only | disabled

class UpdateTeamRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    specialization: Optional[str] = None
    strategy: Optional[str] = None
    hitl: Optional[str] = None

class AddAgentRequest(BaseModel):
    agent_id: str

@router.get("")
def list_teams():
    teams = db_list_teams()
    # Enriquecer con info de agentes
    for t in teams:
        agent_ids = t.get('agents', [])
        agents_info = []
        for aid in agent_ids:
            a = db_get_agent(aid)
            if a:
                agents_info.append({"id": aid, "name": a["name"], "role": a["role"]})
        t['agents_detail'] = agents_info
    return teams

@router.get("/{team_id}")
def get_team(team_id: str):
    team = db_get_team(team_id)
    if not team:
        raise HTTPException(404, f"Equipo '{team_id}' no encontrado")
    return team

@router.post("", status_code=201)
def create_team(body: CreateTeamRequest):
    """Crea un equipo con agentes asignados."""
    team_id = f"team_{uuid.uuid4().hex[:8]}"
    data = {"id": team_id, **body.model_dump()}
    db_create_team(data)
    return {"id": team_id, "message": f"Equipo '{body.name}' creado", **data}

@router.post("/{team_id}/agents")
def add_agent_to_team(team_id: str, body: AddAgentRequest):
    """Agrega un agente a un equipo."""
    team = db_get_team(team_id)
    if not team:
        raise HTTPException(404, f"Equipo '{team_id}' no encontrado")
    agent = db_get_agent(body.agent_id)
    if not agent:
        raise HTTPException(404, f"Agente '{body.agent_id}' no encontrado")
    agents = team.get('agents', [])
    if body.agent_id not in agents:
        agents.append(body.agent_id)
        db_update_team(team_id, {"agents": agents})
    return {"team_id": team_id, "agents": agents, "message": f"Agente '{agent['name']}' agregado"}

@router.delete("/{team_id}/agents/{agent_id}")
def remove_agent_from_team(team_id: str, agent_id: str):
    """Quita un agente de un equipo."""
    team = db_get_team(team_id)
    if not team:
        raise HTTPException(404)
    agents = [a for a in team.get('agents', []) if a != agent_id]
    db_update_team(team_id, {"agents": agents})
    return {"team_id": team_id, "agents": agents}

@router.put("/{team_id}")
def update_team(team_id: str, body: UpdateTeamRequest):
    team = db_get_team(team_id)
    if not team:
        raise HTTPException(404)
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    db_update_team(team_id, updates)
    return db_get_team(team_id)

@router.delete("/{team_id}")
def delete_team(team_id: str):
    db_delete_team(team_id)
    return {"deleted": team_id}
