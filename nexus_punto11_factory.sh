#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Punto 11: Software Factory + Pentest Flow     ║
# ║  11A · MD requerimientos  11B · Plan Maestro engine        ║
# ║  11C · Factory executor   11D · Pentest scope flow         ║
# ║  11E · Frontend páginas   11F · API endpoints              ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

ROOT="/home/operator/NEXUS-PRO"
API="$ROOT/nexus_api"
FRONT="$ROOT/nexus_frontend/src"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

# ══════════════════════════════════════════════════════════════
head "1/8 · Templates MD — requerimientos + pentest scope"
# ══════════════════════════════════════════════════════════════
mkdir -p "$ROOT/data/factory/templates"
mkdir -p "$ROOT/data/factory/projects"
mkdir -p "$ROOT/data/factory/pentests"

python3 - << 'PYEOF'
# Template Software Factory
sw = """# BAJIOWARE — Software Factory
# Instrucciones: Llena cada campo. Los campos con * son obligatorios.
# Guarda este archivo y súbelo desde el dashboard Factory.

[proyecto]
nombre        = ""              # * Nombre del proyecto
cliente       = ""              # * Empresa cliente
tipo          = "web"           # * web | movil | escritorio | api | fullstack
descripcion   = ""              # * Descripción en 1-2 oraciones

[stack]
backend       = "fastapi"       # fastapi | django | express | laravel | spring
frontend      = "react"         # react | vue | angular | none
base_datos    = "sqlite"        # sqlite | postgresql | mysql | mongodb
auth          = "jwt"           # jwt | oauth2 | session | none
cache         = "none"          # redis | memcache | none
queue         = "none"          # celery | rq | none

[requerimientos_funcionales]
# Lista cada requerimiento en una línea nueva con el formato:
# RF-01 = "descripcion"
RF-01 = ""
RF-02 = ""
RF-03 = ""
RF-04 = ""
RF-05 = ""

[requerimientos_no_funcionales]
rendimiento   = "100 req/s"     # carga esperada
disponibilidad= "99.9%"         # uptime requerido
seguridad     = "owasp-top10"   # nivel de seguridad
escalabilidad = "horizontal"    # horizontal | vertical | none

[restricciones]
deadline_dias = 7               # días para entrega
presupuesto   = "medio"         # bajo | medio | alto | ilimitado
idioma_codigo = "es"            # es | en
tests         = true            # incluir tests unitarios
docker        = true            # empaquetar en Docker
documentacion = true            # generar README + API docs

[entregables]
codigo_fuente = true
docker_compose= true
readme        = true
api_docs      = true
reporte_seg   = true            # reporte de seguridad incluido
"""

# Template Pentest Scope
pt = """# BAJIOWARE — Pentest Scope
# Instrucciones: Define el alcance ANTES de ejecutar.
# Este documento requiere aprobación del cliente antes de proceder.

[proyecto]
nombre        = ""              # * Nombre del engagement
cliente       = ""              # * Empresa cliente
tipo          = "web"           # * web | api | red | movil | fullstack
clasificacion = "confidencial"  # confidencial | secreto | publico

[alcance]
# URLs/IPs autorizadas para pruebas — una por línea
targets = [
    "",
]

# Rutas/sistemas FUERA del alcance — no tocar
excluidos = [
    "",
]

[permisos]
reconocimiento  = true          # nmap, fingerprinting
fuzzing         = true          # dirbusting, param fuzzing
sqli            = true          # SQL injection testing
xss             = true          # Cross-site scripting
auth_bypass     = true          # Authentication bypass
brute_force     = false         # Fuerza bruta (requiere autorización especial)
dos             = false         # Denial of Service — NUNCA sin autorización explícita

[ventana_tiempo]
inicio          = ""            # YYYY-MM-DD HH:MM
fin             = ""            # YYYY-MM-DD HH:MM
zona_horaria    = "America/Mexico_City"

[contacto_cliente]
nombre          = ""
email           = ""
telefono        = ""
disponible_24h  = false         # contacto de emergencia disponible

[entregables]
reporte_ejecutivo = true        # para la junta directiva
reporte_tecnico   = true        # para el equipo de desarrollo
evidencias        = true        # capturas + PoC de vulnerabilidades
remediacion       = true        # guía de corrección
retesting         = false       # segunda prueba después de correcciones
"""

with open("/home/operator/NEXUS-PRO/data/factory/templates/software_requirements.md", "w") as f:
    f.write(sw)
with open("/home/operator/NEXUS-PRO/data/factory/templates/pentest_scope.md", "w") as f:
    f.write(pt)
print("Templates creados")
PYEOF
log "templates MD"

# ══════════════════════════════════════════════════════════════
head "2/8 · nexus_api/services/factory_service.py — Plan Maestro engine"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
content = '''import os, json, sqlite3, uuid, logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("nexus.factory")

def _db():
    p = os.getenv("NEXUS_DB_PATH",
        str(Path(__file__).parent.parent.parent / "data" / "nexus_pro.db"))
    conn = sqlite3.connect(p)
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
    for line in content.split("\\n"):
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
        "output_dir": f"/home/operator/NEXUS-PRO/data/factory/projects/{proyecto.get('nombre','proyecto').lower().replace(' ','_')}",
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
'''

with open("/home/operator/NEXUS-PRO/nexus_api/services/factory_service.py", "w") as f:
    f.write(content)
print("factory_service.py —", len(content), "bytes")
PYEOF
log "services/factory_service.py"

# ══════════════════════════════════════════════════════════════
head "3/8 · nexus_api/routes/factory.py — endpoints /factory"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
content = '''from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
import json, os, asyncio, logging
from nexus_api.auth.deps import get_current_user, require_operator
from nexus_api.services.factory_service import (
    init_factory_tables, parse_requirements_md, generate_plan_maestro,
    create_project, save_plan, approve_project, get_project, list_projects,
    get_phases, update_phase_status, create_pentest, list_pentests,
    get_pentest, approve_pentest
)

logger = logging.getLogger("nexus.factory")
router = APIRouter(prefix="/factory", tags=["factory"])
init_factory_tables()

class AnalyzeRequest(BaseModel):
    requirements_md: str
    use_llm: bool = True

class ApproveRequest(BaseModel):
    approved_by: str = "admin"
    notes: Optional[str] = None

class PentestAnalyzeRequest(BaseModel):
    scope_md: str
    use_llm: bool = True

# ── Software Factory ──────────────────────────────────────────

@router.get("/templates")
async def get_templates(user=Depends(get_current_user)):
    """Devuelve los templates MD para descargar."""
    templates_dir = "/home/operator/NEXUS-PRO/data/factory/templates"
    sw_path = f"{templates_dir}/software_requirements.md"
    pt_path = f"{templates_dir}/pentest_scope.md"
    result = {}
    if os.path.exists(sw_path):
        with open(sw_path) as f:
            result["software"] = f.read()
    if os.path.exists(pt_path):
        with open(pt_path) as f:
            result["pentest"] = f.read()
    return result

@router.post("/analyze")
async def analyze_requirements(
    body: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    user=Depends(require_operator)
):
    """Analiza el MD de requerimientos y genera el Plan Maestro."""
    try:
        reqs = parse_requirements_md(body.requirements_md)
        proyecto = reqs.get("proyecto", {})
        nombre = proyecto.get("nombre", "Proyecto Sin Nombre")
        cliente = proyecto.get("cliente", "Cliente")
        tipo = proyecto.get("tipo", "web")

        if not nombre or nombre == "":
            raise HTTPException(400, "El campo nombre es obligatorio en [proyecto]")

        # Análisis LLM si está habilitado
        llm_analysis = None
        if body.use_llm:
            try:
                from nexus_core.llm.abstraction import NexusLLM
                llm = NexusLLM()
                prompt = f"""Eres un arquitecto de software senior de BAJIOWARE.
Analiza estos requerimientos y en 3-4 párrafos concisos responde:
1. Complejidad técnica (baja/media/alta) y por qué
2. Riesgos principales del proyecto
3. Recomendaciones de arquitectura específicas para el stack elegido
4. Estimación realista de fases necesarias

Requerimientos:
{body.requirements_md[:2000]}

Responde en español, directo y técnico."""
                resp = await asyncio.wait_for(
                    llm.chat_async([{"role":"user","content":prompt}]),
                    timeout=30
                )
                llm_analysis = resp.content if hasattr(resp,'content') else str(resp)
            except Exception as e:
                llm_analysis = f"Análisis LLM no disponible: {e}"

        plan = generate_plan_maestro(reqs, llm_analysis)
        project_id = create_project(nombre, cliente, tipo, reqs, reqs)
        save_plan(project_id, plan)

        return {
            "project_id":   project_id,
            "nombre":        nombre,
            "cliente":       cliente,
            "status":        "pending_approval",
            "plan_maestro":  plan,
            "llm_analysis":  llm_analysis,
            "message":       f"Plan Maestro generado — {plan['num_fases']} fases. Revisa y aprueba para ejecutar."
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Error analizando requerimientos: {e}")

@router.post("/projects/{project_id}/approve")
async def approve(
    project_id: str,
    body: ApproveRequest,
    background_tasks: BackgroundTasks,
    user=Depends(require_operator)
):
    """Aprueba el Plan Maestro e inicia la ejecución."""
    project = get_project(project_id)
    if not project:
        raise HTTPException(404, "Proyecto no encontrado")
    if project["status"] not in ("pending_approval", "analyzing"):
        raise HTTPException(400, f"Proyecto en estado {project['status']} — no se puede aprobar")

    approve_project(project_id, body.approved_by or user["name"])

    # Lanzar ejecución en background
    background_tasks.add_task(_execute_factory, project_id)

    return {
        "project_id": project_id,
        "status":     "executing",
        "message":    "Plan Maestro aprobado — fábrica iniciada en background"
    }

async def _execute_factory(project_id: str):
    """Ejecuta las fases del Plan Maestro secuencialmente."""
    import httpx, asyncio
    project = get_project(project_id)
    if not project:
        return

    plan = json.loads(project.get("plan_maestro","{}"))
    phases = get_phases(project_id)
    output_dir = plan.get("output_dir", f"/home/operator/NEXUS-PRO/data/factory/projects/{project_id}")
    os.makedirs(output_dir, exist_ok=True)

    stack = plan.get("stack", {})
    proyecto_info = f"""
Proyecto: {plan.get('proyecto')}
Cliente: {plan.get('cliente')}
Stack: {json.dumps(stack)}
Output dir: {output_dir}
"""

    for phase in phases:
        phase_id = phase["id"]
        fase_num = phase["fase_num"]
        nombre   = phase["nombre"]
        desc     = phase["descripcion"]

        logger.info(f"[FACTORY] Ejecutando fase {fase_num}: {nombre}")
        update_phase_status(phase_id, "running")

        try:
            # Construir objetivo para Junior
            objective = f"""FASE {fase_num}/{len(phases)} del proyecto {plan.get('proyecto')} para {plan.get('cliente')}.
{proyecto_info}
TAREA DE ESTA FASE: {nombre} — {desc}
INSTRUCCIONES:
- Crea/modifica archivos en {output_dir}/
- Esta es la fase {fase_num} de {len(phases)} — {'primera fase: crear estructura base' if fase_num==1 else 'continuación del proyecto anterior'}
- Genera código REAL y funcional, sin TODOs ni stubs
- Si es la última fase ({fase_num}=={len(phases)}): crear Dockerfile, docker-compose.yml y README.md
- Guarda TODOS los archivos en {output_dir}/
Contexto previo del proyecto: backend={stack.get('backend','fastapi')}, db={stack.get('base_datos','sqlite')}, auth={stack.get('auth','jwt')}"""

            # Llamar a Junior via API interna
            base_url = os.getenv("NEXUS_API_URL", "http://localhost:8000")
            async with httpx.AsyncClient(timeout=300) as client:
                # Login para obtener token interno
                login_resp = await client.post(f"{base_url}/auth/login",
                    json={"email": os.getenv("NEXUS_ADMIN_EMAIL","admin@nexuspro.io"),
                          "password": os.getenv("NEXUS_ADMIN_PASSWORD","synthetic-password")})
                token = login_resp.json().get("access_token","")

                run_resp = await client.post(f"{base_url}/junior/run",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"objective": objective, "max_steps": 10})
                task_id = run_resp.json().get("task_id")

                # Poll hasta completar
                for _ in range(60):
                    await asyncio.sleep(8)
                    status_resp = await client.get(
                        f"{base_url}/junior/status/{task_id}",
                        headers={"Authorization": f"Bearer {token}"}
                    )
                    status_data = status_resp.json()
                    if status_data.get("status") in ("completed","failed"):
                        break

                result_summary = f"Fase {fase_num} completada — {status_data.get('status')} — {task_id}"
                update_phase_status(phase_id, "completed", result_summary)
                logger.info(f"[FACTORY] Fase {fase_num} completada")

        except Exception as e:
            logger.error(f"[FACTORY] Error en fase {fase_num}: {e}")
            update_phase_status(phase_id, "failed", str(e))

    # Marcar proyecto como completado
    import sqlite3
    db_path = os.getenv("NEXUS_DB_PATH",
        str(__import__('pathlib').Path(__file__).parent.parent.parent / "data" / "nexus_pro.db"))
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE factory_projects SET status='completed',updated_at=datetime('now') WHERE id=?",
            (project_id,)
        )
        conn.commit()
    logger.info(f"[FACTORY] Proyecto {project_id} completado — archivos en {output_dir}")

@router.get("/projects")
async def list_all_projects(user=Depends(get_current_user)):
    projects = list_projects()
    return {"projects": projects, "total": len(projects)}

@router.get("/projects/{project_id}")
async def get_project_detail(project_id: str, user=Depends(get_current_user)):
    project = get_project(project_id)
    if not project:
        raise HTTPException(404, "Proyecto no encontrado")
    phases = get_phases(project_id)
    plan = {}
    try:
        plan = json.loads(project.get("plan_maestro") or "{}")
    except: pass
    return {**project, "phases": phases, "plan_maestro_parsed": plan}

# ── Pentest Engagements ───────────────────────────────────────

@router.post("/pentest/analyze")
async def analyze_pentest_scope(
    body: PentestAnalyzeRequest,
    user=Depends(require_operator)
):
    """Analiza el MD de scope y genera el plan de pentest."""
    try:
        from nexus_api.services.factory_service import parse_requirements_md
        scope = parse_requirements_md(body.scope_md)
        proyecto = scope.get("proyecto", {})
        nombre = proyecto.get("nombre", "Pentest Sin Nombre")
        cliente = proyecto.get("cliente", "Cliente")
        tipo = proyecto.get("tipo", "web")

        llm_plan = None
        if body.use_llm:
            try:
                from nexus_core.llm.abstraction import NexusLLM
                llm = NexusLLM()
                prompt = f"""Eres un pentester senior de BAJIOWARE (empresa de ciberseguridad).
Analiza este scope de pentest y genera:
1. Resumen del engagement (2 párrafos)
2. Metodología recomendada (OWASP/PTES/NIST)
3. Top 5 vectores de ataque más probables para este tipo de target
4. Herramientas específicas a usar
5. Estimación de tiempo por fase
6. Riesgos legales/éticos a considerar
7. Criterios de éxito del engagement

Scope:
{body.scope_md[:2000]}

Responde en español, profesional y técnico."""
                resp = await asyncio.wait_for(
                    llm.chat_async([{"role":"user","content":prompt}]),
                    timeout=30
                )
                llm_plan = resp.content if hasattr(resp,'content') else str(resp)
            except Exception as e:
                llm_plan = f"Análisis LLM no disponible: {e}"

        engage_id = create_pentest(nombre, cliente, tipo, body.scope_md)

        # Guardar plan LLM
        import sqlite3
        db_path = os.getenv("NEXUS_DB_PATH",
            str(__import__('pathlib').Path(__file__).parent.parent.parent / "data" / "nexus_pro.db"))
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE pentest_engagements SET plan=?,status='pending_approval' WHERE id=?",
                (llm_plan or "Sin análisis", engage_id)
            )
            conn.commit()

        return {
            "engagement_id": engage_id,
            "nombre":        nombre,
            "cliente":       cliente,
            "status":        "pending_approval",
            "llm_plan":      llm_plan,
            "scope_parsed":  scope,
            "message":       "Scope analizado — revisa el plan y aprueba para ejecutar"
        }
    except Exception as e:
        raise HTTPException(500, f"Error: {e}")

@router.post("/pentest/{engage_id}/approve")
async def approve_pentest_engagement(
    engage_id: str,
    body: ApproveRequest,
    background_tasks: BackgroundTasks,
    user=Depends(require_operator)
):
    """Aprueba el scope y ejecuta el pentest."""
    engage = get_pentest(engage_id)
    if not engage:
        raise HTTPException(404, "Engagement no encontrado")
    if engage["status"] not in ("pending_approval","analyzing"):
        raise HTTPException(400, f"Estado inválido: {engage['status']}")

    approve_pentest(engage_id, body.approved_by or user["name"])
    background_tasks.add_task(_execute_pentest, engage_id)

    return {
        "engagement_id": engage_id,
        "status":        "executing",
        "message":       "Pentest aprobado — ejecutando en background"
    }

async def _execute_pentest(engage_id: str):
    """Ejecuta el pentest completo después de aprobación."""
    import httpx
    engage = get_pentest(engage_id)
    if not engage:
        return

    scope = parse_requirements_md(engage.get("scope",""))
    targets = scope.get("alcance", {})
    proyecto = scope.get("proyecto", {})
    nombre = proyecto.get("nombre", engage_id)

    try:
        base_url = os.getenv("NEXUS_API_URL", "http://localhost:8000")
        async with httpx.AsyncClient(timeout=300) as client:
            login_resp = await client.post(f"{base_url}/auth/login",
                json={"email": os.getenv("NEXUS_ADMIN_EMAIL","admin@nexuspro.io"),
                      "password": os.getenv("NEXUS_ADMIN_PASSWORD","synthetic-password")})
            token = login_resp.json().get("access_token","")

            run_resp = await client.post(f"{base_url}/pentest/run",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "target": "localhost:8000",
                    "target_path": "/home/operator/NEXUS-PRO",
                    "target_name": nombre,
                    "scope": "full"
                })
            task_id = run_resp.json().get("task_id")

            for _ in range(60):
                await asyncio.sleep(10)
                status_resp = await client.get(
                    f"{base_url}/pentest/status/{task_id}",
                    headers={"Authorization": f"Bearer {token}"}
                )
                if status_resp.json().get("status") in ("completed","failed"):
                    break

        import sqlite3
        db_path = os.getenv("NEXUS_DB_PATH",
            str(__import__('pathlib').Path(__file__).parent.parent.parent / "data" / "nexus_pro.db"))
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE pentest_engagements SET status='completed',findings=? WHERE id=?",
                (task_id, engage_id)
            )
            conn.commit()
        logger.info(f"[FACTORY] Pentest {engage_id} completado")
    except Exception as e:
        logger.error(f"[FACTORY] Error pentest {engage_id}: {e}")

@router.get("/pentest")
async def list_pentests_endpoint(user=Depends(get_current_user)):
    engagements = list_pentests()
    return {"engagements": engagements, "total": len(engagements)}

@router.get("/pentest/{engage_id}")
async def get_pentest_detail(engage_id: str, user=Depends(get_current_user)):
    engage = get_pentest(engage_id)
    if not engage:
        raise HTTPException(404, "Engagement no encontrado")
    return engage
'''

with open("/home/operator/NEXUS-PRO/nexus_api/routes/factory.py", "w") as f:
    f.write(content)
print("routes/factory.py —", len(content), "bytes")
PYEOF
log "routes/factory.py"

# ══════════════════════════════════════════════════════════════
head "4/8 · Registrar factory router en main.py"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
path = "/home/operator/NEXUS-PRO/nexus_api/main.py"
with open(path) as f:
    content = f.read()

if "routes.factory" not in content:
    content = content.replace(
        "from nexus_api.routes.memory import router as memory_router",
        "from nexus_api.routes.memory  import router as memory_router\nfrom nexus_api.routes.factory import router as factory_router"
    )
    content = content.replace(
        "app.include_router(memory_router)",
        "app.include_router(memory_router)\napp.include_router(factory_router)"
    )
    with open(path, "w") as f:
        f.write(content)
    print("factory_router registrado")
else:
    print("ya registrado")
PYEOF
log "factory router en main.py"

# ══════════════════════════════════════════════════════════════
head "5/8 · nexusApi — añadir endpoints factory"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
path = "/home/operator/NEXUS-PRO/nexus_frontend/src/api/client.js"
with open(path) as f:
    content = f.read()

if "factory/templates" not in content:
    content = content.replace(
        "  // Memory",
        """  // Factory — Software Factory + Pentest Flow
  factoryTemplates:      ()       => api.get('/factory/templates'),
  factoryAnalyze:        (md)     => api.post('/factory/analyze', { requirements_md: md, use_llm: true }),
  factoryApprove:        (id, by) => api.post(`/factory/projects/${id}/approve`, { approved_by: by }),
  factoryProjects:       ()       => api.get('/factory/projects'),
  factoryProject:        (id)     => api.get(`/factory/projects/${id}`),
  pentestAnalyze:        (md)     => api.post('/factory/pentest/analyze', { scope_md: md, use_llm: true }),
  pentestApprove:        (id, by) => api.post(`/factory/pentest/${id}/approve`, { approved_by: by }),
  pentestEngagements:    ()       => api.get('/factory/pentest'),
  pentestEngagement:     (id)     => api.get(`/factory/pentest/${id}`),

  // Memory"""
    )
    with open(path, "w") as f:
        f.write(content)
    print("nexusApi actualizado con factory endpoints")
else:
    print("ya estaba")
PYEOF
log "nexusApi factory endpoints"

# ══════════════════════════════════════════════════════════════
head "6/8 · pages/Factory.jsx — Software Factory UI"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
content = r"""import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, Btn, Dot } from '../components/ui'
import { nexusApi } from '../api/client'
import { useAuthStore } from '../store/authStore'

const STATUS_COLOR = {
  draft:'var(--text-dim)', analyzing:'var(--cyan)', pending_approval:'var(--yellow)',
  approved:'var(--cyan)', executing:'var(--orange)', completed:'var(--green)', failed:'var(--red)'
}
const STATUS_ICON = {
  draft:'○', analyzing:'⟳', pending_approval:'⏸', approved:'✓',
  executing:'▶', completed:'✅', failed:'✗'
}

export default function Factory() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const [tab, setTab]             = useState('projects')
  const [mdContent, setMdContent] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [plan, setPlan]           = useState(null)
  const [selectedProject, setSelectedProject] = useState(null)
  const [error, setError]         = useState('')

  const { data: templatesData } = useQuery({
    queryKey: ['factory-templates'],
    queryFn: () => nexusApi.factoryTemplates().then(r => r.data),
  })

  const { data: projectsData, refetch: refetchProjects } = useQuery({
    queryKey: ['factory-projects'],
    queryFn: () => nexusApi.factoryProjects().then(r => r.data),
    refetchInterval: 5000,
  })

  const { data: projectDetail } = useQuery({
    queryKey: ['factory-project', selectedProject],
    queryFn: () => nexusApi.factoryProject(selectedProject).then(r => r.data),
    enabled: !!selectedProject,
    refetchInterval: 3000,
  })

  const analyzeMutation = useMutation({
    mutationFn: () => nexusApi.factoryAnalyze(mdContent),
    onSuccess: (res) => { setPlan(res.data); setTab('plan'); setError('') },
    onError: (e) => setError(e.response?.data?.detail || 'Error analizando'),
  })

  const approveMutation = useMutation({
    mutationFn: (pid) => nexusApi.factoryApprove(pid, user?.name || 'admin'),
    onSuccess: () => { qc.invalidateQueries(['factory-projects']); setTab('projects'); setPlan(null) },
  })

  const loadTemplate = () => {
    setMdContent(templatesData?.software || '')
    setTab('new')
  }

  const projects = projectsData?.projects || []

  return (
    <div style={{ padding:24, height:'100%', display:'flex', flexDirection:'column', gap:16 }}>
      {/* Header */}
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between' }}>
        <div>
          <div style={{ fontFamily:'var(--display)', fontSize:22, fontWeight:700,
            color:'var(--text-bright)', letterSpacing:2 }}>Software Factory</div>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:4 }}>
            BAJIOWARE · PLAN MAESTRO · EJECUCIÓN POR FASES · DEVSECOS
          </div>
        </div>
        <div style={{ display:'flex', gap:4 }}>
          {['projects','new','plan'].map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              padding:'6px 14px', borderRadius:3,
              border:`1px solid ${tab===t?'var(--green)':'var(--border)'}`,
              background:tab===t?'#00ff9d08':'transparent',
              color:tab===t?'var(--green)':'var(--text-dim)',
              cursor:'pointer', fontFamily:'var(--mono)', fontSize:11
            }}>{t==='new'?'+ NUEVO':t==='plan'?'PLAN MAESTRO':t.toUpperCase()}</button>
          ))}
        </div>
      </div>

      {/* TAB: Projects */}
      {tab === 'projects' && (
        <div style={{ flex:1, overflowY:'auto', display:'flex', flexDirection:'column', gap:10 }}>
          <div style={{ display:'flex', gap:10, alignItems:'center' }}>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)' }}>
              {projects.length} PROYECTOS
            </div>
            <Btn variant="primary" onClick={loadTemplate}>+ NUEVO PROYECTO</Btn>
          </div>

          {projects.length === 0 ? (
            <div style={{ textAlign:'center', padding:'60px 0', border:'1px dashed var(--border)', borderRadius:4 }}>
              <div style={{ fontSize:48, opacity:.1, marginBottom:12 }}>🏭</div>
              <div style={{ fontFamily:'var(--display)', fontSize:16, color:'var(--text-dim)' }}>
                Sin proyectos aún
              </div>
              <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text-dim)', marginTop:6 }}>
                Descarga el template, llénalo y súbelo para generar el Plan Maestro
              </div>
            </div>
          ) : (
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:10 }}>
              {projects.map(p => {
                const sc = STATUS_COLOR[p.status] || 'var(--text-dim)'
                return (
                  <div key={p.id} onClick={() => setSelectedProject(p.id)}
                    style={{ padding:16, background:'var(--bg-card)',
                      border:`1px solid ${selectedProject===p.id?sc:'var(--border)'}`,
                      borderRadius:4, cursor:'pointer', transition:'all .15s' }}>
                    <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:8 }}>
                      <div style={{ fontSize:24 }}>🏭</div>
                      <div style={{ flex:1 }}>
                        <div style={{ fontSize:14, fontWeight:600, color:'var(--text-bright)' }}>{p.nombre}</div>
                        <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)' }}>{p.cliente}</div>
                      </div>
                      <div style={{ padding:'2px 8px', borderRadius:8,
                        border:`1px solid ${sc}`, color:sc,
                        fontFamily:'var(--mono)', fontSize:10, background:`${sc}10` }}>
                        {STATUS_ICON[p.status]} {p.status}
                      </div>
                    </div>
                    {p.status === 'pending_approval' && (
                      <Btn variant="primary" onClick={e => { e.stopPropagation(); approveMutation.mutate(p.id) }}
                        style={{ width:'100%', opacity: approveMutation.isPending ? .6 : 1 }}>
                        ✓ APROBAR Y EJECUTAR
                      </Btn>
                    )}
                    {p.status === 'executing' && selectedProject === p.id && projectDetail && (
                      <div style={{ marginTop:8 }}>
                        {(projectDetail.phases||[]).map(ph => (
                          <div key={ph.id} style={{ display:'flex', gap:8, padding:'3px 0',
                            fontFamily:'var(--mono)', fontSize:10 }}>
                            <span style={{ color: ph.status==='completed'?'var(--green)':ph.status==='running'?'var(--yellow)':'var(--text-dim)' }}>
                              {ph.status==='completed'?'✓':ph.status==='running'?'▶':'○'}
                            </span>
                            <span style={{ color:'var(--text-dim)' }}>F{ph.fase_num}</span>
                            <span style={{ color:'var(--text)' }}>{ph.nombre}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB: New project */}
      {tab === 'new' && (
        <div style={{ flex:1, display:'flex', flexDirection:'column', gap:10 }}>
          <div style={{ display:'flex', gap:8, alignItems:'center' }}>
            <Btn variant="ghost" onClick={loadTemplate}>⬇ CARGAR TEMPLATE</Btn>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)' }}>
              Llena el template y analiza con IA
            </div>
          </div>
          <textarea value={mdContent} onChange={e => setMdContent(e.target.value)}
            placeholder="Pega aquí el template de requerimientos llenado..."
            style={{ flex:1, background:'var(--bg-card)', border:'1px solid var(--border)',
              borderRadius:4, padding:16, color:'var(--text)', fontFamily:'var(--mono)',
              fontSize:12, outline:'none', resize:'none', lineHeight:1.6 }} />
          {error && (
            <div style={{ padding:'8px 12px', background:'#ff386015', border:'1px solid var(--red)',
              borderRadius:3, fontFamily:'var(--mono)', fontSize:11, color:'var(--red)' }}>
              ✗ {error}
            </div>
          )}
          <Btn variant="primary" onClick={() => analyzeMutation.mutate()}
            style={{ opacity: analyzeMutation.isPending ? .6 : 1 }}>
            {analyzeMutation.isPending ? '⟳ ANALIZANDO CON IA...' : '🧠 GENERAR PLAN MAESTRO'}
          </Btn>
        </div>
      )}

      {/* TAB: Plan Maestro */}
      {tab === 'plan' && plan && (
        <div style={{ flex:1, overflowY:'auto', display:'flex', flexDirection:'column', gap:12 }}>
          <Card style={{ border:'1px solid var(--green)' }}>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--green)',
              letterSpacing:2, marginBottom:12 }}>PLAN MAESTRO — {plan.nombre || plan.plan_maestro?.proyecto}</div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:10, marginBottom:14 }}>
              {[
                ['Proyecto', plan.plan_maestro?.proyecto || '—'],
                ['Cliente',  plan.plan_maestro?.cliente  || '—'],
                ['Fases',    plan.plan_maestro?.num_fases || '—'],
                ['Estimado', plan.plan_maestro?.estimacion || '—'],
              ].map(([k,v]) => (
                <div key={k} style={{ padding:'8px 12px', background:'var(--bg-base)',
                  border:'1px solid var(--border)', borderRadius:3 }}>
                  <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)',
                    letterSpacing:1, textTransform:'uppercase', marginBottom:4 }}>{k}</div>
                  <div style={{ fontSize:13, fontWeight:600, color:'var(--text-bright)' }}>{v}</div>
                </div>
              ))}
            </div>

            {/* Fases */}
            <div style={{ marginBottom:14 }}>
              <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)',
                letterSpacing:2, marginBottom:8 }}>FASES DE EJECUCIÓN</div>
              {(plan.plan_maestro?.fases || []).map(f => (
                <div key={f.num} style={{ display:'flex', gap:12, padding:'8px 0',
                  borderBottom:'1px solid var(--border)', alignItems:'flex-start' }}>
                  <div style={{ width:28, height:28, borderRadius:'50%',
                    background:'#00ff9d15', border:'1px solid var(--green)',
                    display:'flex', alignItems:'center', justifyContent:'center',
                    fontFamily:'var(--mono)', fontSize:11, color:'var(--green)', flexShrink:0 }}>
                    {f.num}
                  </div>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:13, fontWeight:600, color:'var(--text-bright)' }}>{f.nombre}</div>
                    <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:2 }}>{f.desc}</div>
                    <div style={{ display:'flex', gap:6, marginTop:4, flexWrap:'wrap' }}>
                      {(f.agentes||[]).map(a => (
                        <span key={a} style={{ padding:'1px 6px', borderRadius:8,
                          border:'1px solid var(--cyan)', color:'var(--cyan)',
                          fontFamily:'var(--mono)', fontSize:9 }}>{a}</span>
                      ))}
                      {(f.tools||[]).map(t => (
                        <span key={t} style={{ padding:'1px 6px', borderRadius:8,
                          border:'1px solid var(--border)', color:'var(--text-dim)',
                          fontFamily:'var(--mono)', fontSize:9 }}>{t}</span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Análisis LLM */}
            {plan.llm_analysis && (
              <div style={{ padding:12, background:'#8b5cf610', border:'1px solid var(--purple)',
                borderRadius:3, marginBottom:14 }}>
                <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--purple)',
                  letterSpacing:2, marginBottom:8 }}>ANÁLISIS DE ARQUITECTURA (GPT-4o)</div>
                <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text)',
                  lineHeight:1.7, whiteSpace:'pre-wrap' }}>{plan.llm_analysis}</div>
              </div>
            )}

            <Btn variant="primary"
              onClick={() => approveMutation.mutate(plan.project_id)}
              style={{ width:'100%', opacity: approveMutation.isPending ? .6 : 1 }}>
              {approveMutation.isPending ? '⟳ APROBANDO...' : '🚀 APROBAR PLAN Y EJECUTAR FÁBRICA'}
            </Btn>
          </Card>
        </div>
      )}
    </div>
  )
}
"""

with open("/home/operator/NEXUS-PRO/nexus_frontend/src/pages/Factory.jsx", "w") as f:
    f.write(content)
print("Factory.jsx —", len(content), "bytes")
PYEOF
log "pages/Factory.jsx"

# ══════════════════════════════════════════════════════════════
head "7/8 · App.jsx + Sidebar — agregar Factory"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
path = "/home/operator/NEXUS-PRO/nexus_frontend/src/App.jsx"
with open(path) as f:
    content = f.read()

if "import Factory" not in content:
    content = content.replace(
        "import Memory    from './pages/Memory'",
        "import Memory    from './pages/Memory'\nimport Factory   from './pages/Factory'"
    )
    content = content.replace(
        "users: Users, memory: Memory,",
        "users: Users, memory: Memory, factory: Factory,"
    )
    with open(path, "w") as f:
        f.write(content)
    print("App.jsx actualizado")
else:
    print("ya estaba")
PYEOF

python3 - << 'PYEOF'
path = "/home/operator/NEXUS-PRO/nexus_frontend/src/components/layout/Sidebar.jsx"
with open(path) as f:
    content = f.read()

if "'factory'" not in content:
    content = content.replace(
        "{ section:'IA Autónoma', items:[",
        "{ section:'IA Autónoma', items:["
    )
    content = content.replace(
        "{ id:'junior',  icon:'🤖', label:'Junior Agent',  highlight:true },",
        "{ id:'factory', icon:'🏭', label:'SW Factory',    highlight:true },\n    { id:'junior',  icon:'🤖', label:'Junior Agent',  highlight:true },"
    )
    with open(path, "w") as f:
        f.write(content)
    print("Sidebar actualizado con Factory")
else:
    print("ya estaba")
PYEOF
log "App.jsx + Sidebar con Factory"

# ══════════════════════════════════════════════════════════════
head "8/8 · Build + reiniciar + test"
# ══════════════════════════════════════════════════════════════
cd "$ROOT/nexus_frontend"
npm run build --silent 2>&1 | tail -3

pkill -f "uvicorn nexus_api" 2>/dev/null; sleep 2
cd "$ROOT" && source venv/bin/activate
uvicorn nexus_api.main:app --host 0.0.0.0 --port 8000 &
sleep 6

# Test endpoints
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@nexuspro.io","password":"synthetic-password"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

echo ""
echo "Test /factory/templates:"
curl -s http://localhost:8000/factory/templates \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('Templates:', list(d.keys()))"

echo "Test /factory/projects:"
curl -s http://localhost:8000/factory/projects \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('Projects:', d.get('total',0))"

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO — Punto 11: Software Factory ✓          ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Backend:${NC}"
echo -e "  GET  /factory/templates           → templates MD"
echo -e "  POST /factory/analyze             → MD → Plan Maestro + LLM"
echo -e "  POST /factory/projects/{id}/approve → ejecutar fases"
echo -e "  GET  /factory/projects            → listar proyectos"
echo -e "  POST /factory/pentest/analyze     → scope → plan pentest"
echo -e "  POST /factory/pentest/{id}/approve → ejecutar pentest"
echo ""
echo -e "  ${CYAN}Frontend:${NC}"
echo -e "  🏭 Factory page → nuevo proyecto → Plan Maestro → aprobar → ejecutar"
echo ""
echo -e "  ${BOLD}Flujo completo:${NC}"
echo -e "  1. Cliente llena template MD"
echo -e "  2. IA analiza y genera Plan Maestro (N fases)"
echo -e "  3. Humano revisa y aprueba con un click"
echo -e "  4. Factory ejecuta fase por fase con Junior"
echo -e "  5. Código entregado en /data/factory/projects/"
echo ""
echo -e "  ${BOLD}Siguiente → Punto 12: Junior JARVIS mode 24/7${NC}"
echo ""
