"""
Scheduler de agentes con APScheduler.
Permite programar tareas recurrentes para los agentes Nexus.
FIX: SQLiteJobStore para persistencia entre reinicios (antes: MemoryJobStore)
"""
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Any, Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

logger = logging.getLogger("nexus.scheduler")

# ── Persistencia SQLite ────────────────────────────────────────
DB_PATH = Path(__file__).parent.parent.parent / "data" / "scheduler_jobs.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
REGISTRY_PATH = Path(__file__).parent.parent.parent / "data" / "job_registry.json"

scheduler = AsyncIOScheduler(
    jobstores={
        "default": SQLAlchemyJobStore(url=f"sqlite:///{DB_PATH}")
    },
    timezone="America/Mexico_City",
    job_defaults={
        "coalesce": True,          # Si se acumulan ejecuciones, corre solo una
        "max_instances": 1,        # Evita ejecuciones paralelas del mismo job
        "misfire_grace_time": 60,  # Segundos de gracia si el job se retrasa
    }
)

# ── Registry persistente en JSON ───────────────────────────────
def _load_registry() -> Dict[str, Dict[str, Any]]:
    if REGISTRY_PATH.exists():
        try:
            return json.loads(REGISTRY_PATH.read_text())
        except Exception:
            return {}
    return {}

def _save_registry(registry: Dict[str, Dict[str, Any]]):
    try:
        REGISTRY_PATH.write_text(json.dumps(registry, indent=2, ensure_ascii=False))
    except Exception as e:
        logger.warning(f"No se pudo guardar registry: {e}")

_job_registry: Dict[str, Dict[str, Any]] = _load_registry()


def start_scheduler():
    if not scheduler.running:
        scheduler.start()
        logger.info(f"Scheduler iniciado — DB: {DB_PATH}")
        logger.info(f"Jobs persistidos recuperados: {len(scheduler.get_jobs())}")

def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler detenido")


def add_interval_job(
    job_id: str,
    func: Callable,
    seconds: int = 60,
    name: str = "",
    kwargs: Optional[dict] = None,
) -> dict:
    """Agrega un job con intervalo en segundos. Persiste entre reinicios."""
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    scheduler.add_job(
        func,
        trigger=IntervalTrigger(seconds=seconds),
        id=job_id,
        name=name or job_id,
        kwargs=kwargs or {},
        replace_existing=True,
    )

    _job_registry[job_id] = {
        "id": job_id,
        "name": name or job_id,
        "type": "interval",
        "seconds": seconds,
        "created_at": datetime.now().isoformat(),
        "status": "running",
    }
    _save_registry(_job_registry)
    logger.info(f"Job agregado: {job_id} cada {seconds}s")
    return _job_registry[job_id]


def add_cron_job(
    job_id: str,
    func: Callable,
    cron_expr: str = "0 * * * *",
    name: str = "",
    kwargs: Optional[dict] = None,
) -> dict:
    """Agrega un job con expresión cron. Persiste entre reinicios."""
    parts = cron_expr.split()
    trigger = CronTrigger(
        minute=parts[0],
        hour=parts[1] if len(parts) > 1 else "*",
        day=parts[2] if len(parts) > 2 else "*",
        month=parts[3] if len(parts) > 3 else "*",
        day_of_week=parts[4] if len(parts) > 4 else "*",
    )

    scheduler.add_job(
        func,
        trigger=trigger,
        id=job_id,
        name=name or job_id,
        kwargs=kwargs or {},
        replace_existing=True,
    )

    _job_registry[job_id] = {
        "id": job_id,
        "name": name or job_id,
        "type": "cron",
        "cron": cron_expr,
        "created_at": datetime.now().isoformat(),
        "status": "running",
    }
    _save_registry(_job_registry)
    return _job_registry[job_id]


def remove_job(job_id: str) -> bool:
    job = scheduler.get_job(job_id)
    if job:
        scheduler.remove_job(job_id)
        if job_id in _job_registry:
            _job_registry[job_id]["status"] = "removed"
            _save_registry(_job_registry)
        return True
    return False


def list_jobs() -> list:
    jobs = []
    for job in scheduler.get_jobs():
        reg = _job_registry.get(job.id, {})
        next_run = job.next_run_time.isoformat() if job.next_run_time else None
        jobs.append({
            "id": job.id,
            "name": job.name,
            "next_run": next_run,
            **reg,
        })
    return jobs
