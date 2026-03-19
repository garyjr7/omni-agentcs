"""
Rutas REST para gestionar el scheduler de agentes.
GET  /scheduler/jobs          — listar jobs
POST /scheduler/jobs          — crear job
DELETE /scheduler/jobs/{id}   — eliminar job
"""
import asyncio
import logging
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

from ..scheduler.manager import add_interval_job, add_cron_job, remove_job, list_jobs
from ..auth.dependencies import get_current_user

logger = logging.getLogger("nexus.scheduler.routes")
router = APIRouter(prefix="/scheduler", tags=["Scheduler"])


class JobCreate(BaseModel):
    job_id: str
    name: str
    agent: str          # "monitor" | "code_review" | "sql_query" | custom
    type: str           # "interval" | "cron"
    seconds: Optional[int] = 60
    cron: Optional[str] = "*/5 * * * *"
    kwargs: Optional[dict] = {}


async def _dummy_agent_task(agent: str, kwargs: dict):
    """
    Invoca un agente real via HTTP interno.
    Mapeo: monitor -> /agents/monitor | code_review -> /agents/code-review | etc.
    """
    endpoint_map = {
        "monitor":     "http://localhost:8000/agents/monitor",
        "code_review": "http://localhost:8000/agents/code-review",
        "sql_query":   "http://localhost:8000/agents/sql-query",
    }
    url = endpoint_map.get(agent, f"http://localhost:8000/agents/{agent}")
    logger.info(f"[Scheduler] → POST {url} kwargs={kwargs}")
    try:
        import httpx
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=kwargs or {})
            logger.info(f"[Scheduler] ✔ {agent} status={resp.status_code}")
    except Exception as exc:
        logger.error(f"[Scheduler] ✖ {agent} error: {exc}")


@router.get("/jobs")
async def get_jobs(_: dict = Depends(get_current_user)):
    return {"jobs": list_jobs()}


@router.post("/jobs", status_code=201)
async def create_job(payload: JobCreate, _: dict = Depends(get_current_user)):
    async def task():
        await _dummy_agent_task(payload.agent, payload.kwargs or {})

    if payload.type == "interval":
        job = add_interval_job(payload.job_id, task, payload.seconds or 60, payload.name)
    elif payload.type == "cron":
        job = add_cron_job(payload.job_id, task, payload.cron or "*/5 * * * *", payload.name)
    else:
        raise HTTPException(400, "type debe ser 'interval' o 'cron'")

    return {"message": "Job creado", "job": job}


@router.delete("/jobs/{job_id}")
async def delete_job(job_id: str, _: dict = Depends(get_current_user)):
    removed = remove_job(job_id)
    if not removed:
        raise HTTPException(404, f"Job '{job_id}' no encontrado")
    return {"message": f"Job '{job_id}' eliminado"}
