"""
NEXUS PRO — Tools API
Catálogo de herramientas disponibles para los agentes
"""
import uuid
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
from nexus_api.db.database import db_list_tools, db_create_tool, db_delete_tool

router = APIRouter()

class CreateToolRequest(BaseModel):
    name: str
    category: str = "custom"
    description: str = ""
    config: Dict[str, Any] = {}

@router.get("/tools")
def list_tools():
    """Lista todas las herramientas disponibles."""
    tools = db_list_tools()
    # Agrupar por categoría
    by_cat = {}
    for t in tools:
        cat = t['category']
        by_cat.setdefault(cat, []).append(t)
    return {"tools": tools, "by_category": by_cat, "total": len(tools)}

@router.get("/tools/categories")
def list_categories():
    tools = db_list_tools()
    cats = {}
    for t in tools:
        cats.setdefault(t['category'], 0)
        cats[t['category']] += 1
    return cats

@router.post("/tools", status_code=201)
def create_tool(body: CreateToolRequest):
    """Crea una herramienta personalizada."""
    tool_id = f"tool_{uuid.uuid4().hex[:8]}"
    data = {"id": tool_id, **body.model_dump()}
    db_create_tool(data)
    return {"id": tool_id, "message": f"Herramienta '{body.name}' creada", **data}

@router.delete("/tools/{tool_id}")
def delete_tool(tool_id: str):
    """Elimina una herramienta personalizada (no built-in)."""
    db_delete_tool(tool_id)
    return {"deleted": tool_id}
