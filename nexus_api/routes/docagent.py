"""DocAgent API — Memoria Técnica BajioWare."""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from nexus_api.auth.deps import require_operator

router = APIRouter(dependencies=[Depends(require_operator)])

class IncidentDocRequest(BaseModel):
    incident_id: str
    title: str
    description: str
    severity: str = "medium"
    root_cause: Optional[str] = ""
    solution: Optional[str] = ""
    prevention: Optional[str] = ""

class SolutionDocRequest(BaseModel):
    title: str
    problem: str
    solution: str
    tags: Optional[List[str]] = []
    project_id: Optional[str] = "general"
    related_commit: Optional[str] = ""

class SearchRequest(BaseModel):
    query: str
    limit: Optional[int] = 5

@router.post("/incident")
async def document_incident(req: IncidentDocRequest):
    """Documenta un incidente con causa, solución y prevención."""
    from nexus_core.agents.generated.doc_agent import document_incident
    return document_incident(req.incident_id, req.title, req.description,
                             req.severity, req.root_cause, req.solution, req.prevention)

@router.post("/solution")
async def document_solution(req: SolutionDocRequest):
    """Documenta una solución para reutilización futura."""
    from nexus_core.agents.generated.doc_agent import document_solution
    return document_solution(req.title, req.problem, req.solution,
                             req.tags, req.project_id, req.related_commit)

@router.get("/analyze/incidents")
async def analyze_incidents(limit: int = 14):
    """Analiza y clasifica los incidentes recientes con recomendaciones."""
    from nexus_core.agents.generated.doc_agent import analyze_incidents_with_llm
    return analyze_incidents_with_llm(limit=limit)

@router.post("/search")
async def search_solutions(req: SearchRequest):
    """Busca soluciones similares en la memoria técnica."""
    from nexus_core.agents.generated.doc_agent import search_similar_solutions
    results = search_similar_solutions(req.query, req.limit)
    return {"query": req.query, "results": results, "total": len(results)}

@router.get("/recent")
async def recent_docs(doc_type: Optional[str] = None, limit: int = 10):
    """Documentos técnicos recientes."""
    from nexus_core.agents.generated.doc_agent import get_recent_docs
    docs = get_recent_docs(doc_type=doc_type, limit=limit)
    return {"docs": docs, "total": len(docs)}
