import os, json, sqlite3, uuid, logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from nexus_api.config import NEXUS_DATA_PATH, NEXUS_DB_PATH

logger = logging.getLogger("nexus.factory")

def _db():
    conn = sqlite3.connect(NEXUS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_factory_tables():
    with _db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS factory_projects (
                id           TEXT PRIMARY KEY,
                nombre       TEXT NOT NULL,
                cliente      TEXT NOT NULL,
                tipo         TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'draft',
                requirements TEXT,
                plan_maestro TEXT,
                approved_by  TEXT,
                approved_at  TEXT,
                created_at   TEXT DEFAULT (datetime('now')),
                updated_at   TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS factory_phases (
                id           TEXT PRIMARY KEY,
                project_id   TEXT NOT NULL,
                fase_num     INTEGER NOT NULL,
                nombre       TEXT NOT NULL,
                descripcion  TEXT,
                status       TEXT DEFAULT 'pending',
                agentes      TEXT,
                tools        TEXT,
                output_path  TEXT,
                result       TEXT,
                started_at   TEXT,
                completed_at TEXT,
                FOREIGN KEY(project_id) REFERENCES factory_projects(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pentest_engagements (
                id           TEXT PRIMARY KEY,
                nombre       TEXT NOT NULL,
                cliente      TEXT NOT NULL,
                tipo         TEXT NOT NULL,
                status       TEXT DEFAULT 'draft',
                scope        TEXT,
                plan         TEXT,
                approved_by  TEXT,
                approved_at  TEXT,
                findings     TEXT,
                created_at   TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.commit()

def parse_requirements_md(content: str) -> dict:
    """Parsea el MD de requerimientos a dict estructurado."""
    import re
    result = {}
    current_section = None
    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1]
            result[current_section] = {}
            continue
        if "=" in line and current_section:
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').split("#")[0].strip()
            if val and val != '""':
                result.setdefault(current_section, {})[key] = val
    return result

def generate_plan_maestro(requirements: dict, llm_analysis: str = None) -> dict:
    """Genera el Plan Maestro basado en requerimientos."""
    proyecto = requirements.get("proyecto", {})
    stack    = requirements.get("stack", {})
    rfs      = requirements.get("requerimientos_funcionales", {})
    restricc = requirements.get("restricciones", {})

    tipo = proyecto.get("tipo", "web")
    backend = stack.get("backend", "fastapi")
    frontend = stack.get("frontend", "react")
    db = stack.get("base_datos", "sqlite")
    auth = stack.get("auth", "jwt")
    deadline = int(restricc.get("deadline_dias", 7))

    # Determinar número de fases según complejidad
    num_rfs = len([v for v in rfs.values() if v])
    if num_rfs <= 3 or deadline <= 2:
        num_fases = 3
    elif num_rfs <= 6 or deadline <= 5:
        num_fases = 5
    else:
        num_fases = 7

    fases_base = {
        3: [
            {"num":1, "nombre":"Setup + Modelos + DB",
             "tools":["bash_exec","file_write"],
             "agentes":["CodeAgent","FileAgent"],
             "desc":f"Estructura del proyecto, modelos {db}, configuración inicial"},
            {"num":2, "nombre":"API + Auth + Endpoints",
             "tools":["file_write","bash_exec"],
             "agentes":["CodeAgent"],
             "desc":f"Implementar endpoints con {backend}, auth {auth}, lógica de negocio"},
            {"num":3, "nombre":"Tests + Docker + Docs",
             "tools":["bash_exec","file_write"],
             "agentes":["CodeAgent","FileAgent"],
             "desc":"Tests unitarios, Dockerfile, docker-compose, README, API docs"},
        ],
        5: [
            {"num":1, "nombre":"Setup + Arquitectura",
             "tools":["bash_exec","file_write"],
             "agentes":["CodeAgent","FileAgent"],
             "desc":f"Estructura, dependencias, configuración {backend}+{db}"},
            {"num":2, "nombre":"Modelos + DB + Migrations",
             "tools":["file_write","bash_exec"],
             "agentes":["CodeAgent"],
             "desc":f"Modelos Pydantic/ORM, esquema {db}, seeds de prueba"},
            {"num":3, "nombre":"Auth + Core API",
             "tools":["file_write"],
             "agentes":["CodeAgent"],
             "desc":f"Sistema {auth}, endpoints core, middleware, CORS"},
            {"num":4, "nombre":"Features + Frontend",
             "tools":["file_write","bash_exec"],
             "agentes":["CodeAgent","FileAgent"],
             "desc":f"Requerimientos funcionales, {frontend if frontend!='none' else 'API docs'}"},
            {"num":5, "nombre":"Security + Tests + Entrega",
             "tools":["bash_exec","file_write"],
             "agentes":["CodeAgent","FileAgent","BashAgent"],
             "desc":"OWASP hardening, tests, Docker, README, empaquetado"},
        ],
        7: [
            {"num":1, "nombre":"Arquitectura + Setup",      "tools":["bash_exec","file_write"],"agentes":["CodeAgent","FileAgent"],"desc":"Estructura completa del proyecto"},
            {"num":2, "nombre":"DB + Modelos + Schemas",    "tools":["file_write"],"agentes":["CodeAgent"],"desc":"Capa de datos completa"},
            {"num":3, "nombre":"Auth + Security Layer",     "tools":["file_write"],"agentes":["CodeAgent"],"desc":f"Auth {auth} + RBAC + rate limiting"},
            {"num":4, "nombre":"Core Business Logic",       "tools":["file_write"],"agentes":["CodeAgent"],"desc":"Lógica de negocio principal"},
            {"num":5, "nombre":"API Endpoints + Validation","tools":["file_write","bash_exec"],"agentes":["CodeAgent"],"desc":"Todos los endpoints con validación"},
            {"num":6, "nombre":"Frontend + Integration",    "tools":["file_write","bash_exec"],"agentes":["CodeAgent","FileAgent"],"desc":f"UI {frontend} + integración"},
            {"num":7, "nombre":"Tests + DevSecOps + Entrega","tools":["bash_exec","file_write"],"agentes":["CodeAgent","FileAgent","BashAgent"],"desc":"Tests + seguridad + Docker + docs"},
        ]
    }

    fases = fases_base.get(num_fases, fases_base[5])

    return {
        "version":    "1.0",
        "proyecto":   proyecto.get("nombre", "Proyecto"),
        "cliente":    proyecto.get("cliente", "Cliente"),
        "tipo":       tipo,
        "stack":      stack,
        "num_fases":  num_fases,
        "fases":      fases,
        "estimacion": f"{num_fases * 2}-{num_fases * 4} horas de procesamiento",
        "output_dir": str(NEXUS_DATA_PATH / "factory" / "projects" / proyecto.get("nombre", "proyecto").lower().replace(" ", "_")),
        "llm_analysis": llm_analysis or "Pendiente de análisis LLM",
        "generated_at": datetime.utcnow().isoformat(),
    }

def create_project(nombre, cliente, tipo, requirements_raw, requirements_parsed) -> str:
    pid = f"factory_{uuid.uuid4().hex[:8]}"
    with _db() as conn:
        conn.execute(
            """INSERT INTO factory_projects(id,nombre,cliente,tipo,requirements,status)
               VALUES(?,?,?,?,?,?)""",
            (pid, nombre, cliente, tipo,
             json.dumps(requirements_parsed), "analyzing")
        )
        conn.commit()
    return pid

def save_plan(project_id: str, plan: dict):
    with _db() as conn:
        conn.execute(
            "UPDATE factory_projects SET plan_maestro=?,status=?,updated_at=datetime('now') WHERE id=?",
            (json.dumps(plan), "pending_approval", project_id)
        )
        for fase in plan.get("fases", []):
            fid = f"phase_{uuid.uuid4().hex[:8]}"
            conn.execute(
                """INSERT INTO factory_phases(id,project_id,fase_num,nombre,descripcion,agentes,tools)
                   VALUES(?,?,?,?,?,?,?)""",
                (fid, project_id, fase["num"], fase["nombre"],
                 fase["desc"], json.dumps(fase["agentes"]), json.dumps(fase["tools"]))
            )
        conn.commit()

def approve_project(project_id: str, approved_by: str = "admin"):
    with _db() as conn:
        conn.execute(
            """UPDATE factory_projects
               SET status='approved', approved_by=?, approved_at=datetime('now'), updated_at=datetime('now')
               WHERE id=?""",
            (approved_by, project_id)
        )
        conn.commit()

def get_project(project_id: str) -> Optional[dict]:
    with _db() as conn:
        row = conn.execute("SELECT * FROM factory_projects WHERE id=?", (project_id,)).fetchone()
        return dict(row) if row else None

def list_projects() -> list:
    with _db() as conn:
        rows = conn.execute("SELECT * FROM factory_projects ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

def get_phases(project_id: str) -> list:
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM factory_phases WHERE project_id=? ORDER BY fase_num",
            (project_id,)
        ).fetchall()
        return [dict(r) for r in rows]

def update_phase_status(phase_id: str, status: str, result: str = None):
    with _db() as conn:
        if status == "running":
            conn.execute("UPDATE factory_phases SET status=?,started_at=datetime('now') WHERE id=?",
                        (status, phase_id))
        elif status in ("completed", "failed"):
            conn.execute("""UPDATE factory_phases
                           SET status=?,result=?,completed_at=datetime('now') WHERE id=?""",
                        (status, result, phase_id))
        conn.commit()

# Pentest engagements
def create_pentest(nombre, cliente, tipo, scope_raw) -> str:
    pid = f"engage_{uuid.uuid4().hex[:8]}"
    with _db() as conn:
        conn.execute(
            "INSERT INTO pentest_engagements(id,nombre,cliente,tipo,scope,status) VALUES(?,?,?,?,?,?)",
            (pid, nombre, cliente, tipo, scope_raw, "analyzing")
        )
        conn.commit()
    return pid

def list_pentests() -> list:
    with _db() as conn:
        rows = conn.execute("SELECT * FROM pentest_engagements ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

def get_pentest(pid: str) -> Optional[dict]:
    with _db() as conn:
        row = conn.execute("SELECT * FROM pentest_engagements WHERE id=?", (pid,)).fetchone()
        return dict(row) if row else None

def approve_pentest(pid: str, approved_by: str = "admin"):
    with _db() as conn:
        conn.execute(
            "UPDATE pentest_engagements SET status='approved',approved_by=?,approved_at=datetime('now') WHERE id=?",
            (approved_by, pid)
        )
        conn.commit()
