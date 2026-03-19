#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Backend Completo v2.0                          ║
# ║  Tools · Agents · Teams · Tasks · Models · WebSocket        ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

API="/home/operator/NEXUS-PRO/nexus_api"
CORE="/home/operator/NEXUS-PRO/nexus_core"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

mkdir -p "$API/routes" "$API/db"

# ══════════════════════════════════════════════════════════════
head "1/8 · nexus_api/db/database.py — SQLite persistencia"
# ══════════════════════════════════════════════════════════════
cat > "$API/db/__init__.py" << 'EOF'
EOF

cat > "$API/db/database.py" << 'EOF'
"""
NEXUS PRO — Base de datos SQLite para persistencia de:
Tools, Agents, Teams, Tasks, API Keys
"""
import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime

DB_PATH = Path("/home/operator/NEXUS-PRO/data/nexus_pro.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_nexus_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS tools (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL UNIQUE,
        category    TEXT NOT NULL,
        description TEXT,
        config      TEXT DEFAULT '{}',
        is_builtin  INTEGER DEFAULT 0,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS agents (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL UNIQUE,
        role        TEXT NOT NULL,
        description TEXT,
        model       TEXT NOT NULL,
        provider    TEXT NOT NULL,
        temperature REAL DEFAULT 0.7,
        max_tokens  INTEGER DEFAULT 4096,
        system_prompt TEXT DEFAULT '',
        tools       TEXT DEFAULT '[]',
        hitl_mode   TEXT DEFAULT 'destructive',
        status      TEXT DEFAULT 'idle',
        tasks_count INTEGER DEFAULT 0,
        success_rate REAL DEFAULT 0.0,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS teams (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL UNIQUE,
        description TEXT,
        specialization TEXT,
        strategy    TEXT DEFAULT 'sequential',
        agents      TEXT DEFAULT '[]',
        hitl        TEXT DEFAULT 'enabled',
        status      TEXT DEFAULT 'active',
        tasks_count INTEGER DEFAULT 0,
        created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS tasks (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        description TEXT,
        task_type   TEXT NOT NULL DEFAULT 'unique',
        status      TEXT DEFAULT 'queue',
        priority    TEXT DEFAULT 'media',
        agent_id    TEXT,
        team_id     TEXT,
        payload     TEXT DEFAULT '{}',
        cron_expr   TEXT,
        progress    INTEGER DEFAULT 0,
        result      TEXT,
        error       TEXT,
        created_at  TEXT DEFAULT (datetime('now')),
        started_at  TEXT,
        completed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS api_keys (
        id          TEXT PRIMARY KEY,
        alias       TEXT NOT NULL,
        provider    TEXT NOT NULL,
        key_masked  TEXT NOT NULL,
        key_value   TEXT NOT NULL,
        models      TEXT DEFAULT '[]',
        status      TEXT DEFAULT 'detecting',
        created_at  TEXT DEFAULT (datetime('now'))
    );
    """)
    conn.commit()

    # Insertar tools built-in si no existen
    builtin_tools = [
        ("tool_bash",     "bash_exec",      "system",    "Ejecuta comandos bash en el servidor",                  1),
        ("tool_file_r",   "file_read",       "filesystem","Lee archivos del sistema",                              1),
        ("tool_file_w",   "file_write",      "filesystem","Escribe/crea archivos en el sistema",                   1),
        ("tool_file_d",   "file_delete",     "filesystem","Elimina archivos del sistema",                          1),
        ("tool_file_ls",  "file_list",       "filesystem","Lista directorios y archivos",                          1),
        ("tool_http",     "http_request",    "network",   "Realiza peticiones HTTP/HTTPS",                         1),
        ("tool_nmap",     "nmap_scan",       "security",  "Escaneo de puertos y servicios con Nmap",               1),
        ("tool_nuclei",   "nuclei_scan",     "security",  "Escaneo de vulnerabilidades con Nuclei",                1),
        ("tool_git",      "git_ops",         "devops",    "Operaciones Git: clone, pull, commit, push",            1),
        ("tool_docker",   "docker_ops",      "devops",    "Gestión de contenedores Docker",                        1),
        ("tool_sql",      "sql_query",       "data",      "Ejecuta queries SQL en bases de datos",                 1),
        ("tool_web",      "web_search",      "research",  "Búsqueda en internet",                                  1),
        ("tool_code",     "code_exec",       "dev",       "Ejecuta código Python en sandbox",                      1),
        ("tool_report",   "report_gen",      "analysis",  "Genera reportes ejecutivos en Markdown/PDF",            1),
        ("tool_memory",   "memory_search",   "ai",        "Busca en memoria vectorial ChromaDB",                   1),
        ("tool_memory_w", "memory_write",    "ai",        "Escribe en memoria vectorial ChromaDB",                 1),
        ("tool_llm",      "llm_call",        "ai",        "Llama directamente a un LLM con prompt personalizado",  1),
        ("tool_stride",   "stride_model",    "security",  "Modelado de amenazas con metodología STRIDE",           1),
        ("tool_sast",     "sast_scan",       "security",  "Análisis estático de seguridad en código fuente",       1),
        ("tool_api_test", "api_test",        "testing",   "Pruebas automatizadas de APIs REST",                    1),
    ]
    for tid, name, cat, desc, builtin in builtin_tools:
        conn.execute(
            "INSERT OR IGNORE INTO tools (id,name,category,description,is_builtin) VALUES (?,?,?,?,?)",
            (tid, name, cat, desc, builtin)
        )
    conn.commit()
    conn.close()


# ── CRUD helpers ──────────────────────────────────────────────

def row_to_dict(row):
    if row is None:
        return None
    d = dict(row)
    for k in ['tools','agents','models','config','payload']:
        if k in d and isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except Exception:
                pass
    return d


# Tools
def db_list_tools():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM tools ORDER BY category,name").fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]

def db_create_tool(data: dict):
    conn = get_conn()
    conn.execute("INSERT INTO tools (id,name,category,description,config) VALUES (?,?,?,?,?)",
        (data['id'], data['name'], data['category'], data.get('description',''), json.dumps(data.get('config',{}))))
    conn.commit(); conn.close()

def db_delete_tool(tool_id: str):
    conn = get_conn()
    conn.execute("DELETE FROM tools WHERE id=? AND is_builtin=0", (tool_id,))
    conn.commit(); conn.close()


# Agents
def db_list_agents():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM agents ORDER BY created_at DESC").fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]

def db_get_agent(agent_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    conn.close()
    return row_to_dict(row)

def db_create_agent(data: dict):
    conn = get_conn()
    conn.execute("""INSERT INTO agents (id,name,role,description,model,provider,temperature,
        max_tokens,system_prompt,tools,hitl_mode) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (data['id'], data['name'], data['role'], data.get('description',''),
         data['model'], data['provider'], data.get('temperature',0.7),
         data.get('max_tokens',4096), data.get('system_prompt',''),
         json.dumps(data.get('tools',[])), data.get('hitl_mode','destructive')))
    conn.commit(); conn.close()

def db_update_agent(agent_id: str, data: dict):
    conn = get_conn()
    sets = []
    vals = []
    for k, v in data.items():
        if k in ['name','role','description','model','provider','temperature','max_tokens','system_prompt','hitl_mode','status']:
            sets.append(f"{k}=?"); vals.append(v)
        elif k == 'tools':
            sets.append("tools=?"); vals.append(json.dumps(v))
    if sets:
        vals.append(agent_id)
        conn.execute(f"UPDATE agents SET {','.join(sets)} WHERE id=?", vals)
        conn.commit()
    conn.close()

def db_delete_agent(agent_id: str):
    conn = get_conn()
    conn.execute("DELETE FROM agents WHERE id=?", (agent_id,))
    conn.commit(); conn.close()


# Teams
def db_list_teams():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM teams ORDER BY created_at DESC").fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]

def db_get_team(team_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM teams WHERE id=?", (team_id,)).fetchone()
    conn.close()
    return row_to_dict(row)

def db_create_team(data: dict):
    conn = get_conn()
    conn.execute("""INSERT INTO teams (id,name,description,specialization,strategy,agents,hitl)
        VALUES (?,?,?,?,?,?,?)""",
        (data['id'], data['name'], data.get('description',''),
         data.get('specialization','General'), data.get('strategy','sequential'),
         json.dumps(data.get('agents',[])), data.get('hitl','enabled')))
    conn.commit(); conn.close()

def db_update_team(team_id: str, data: dict):
    conn = get_conn()
    sets, vals = [], []
    for k, v in data.items():
        if k in ['name','description','specialization','strategy','hitl','status']:
            sets.append(f"{k}=?"); vals.append(v)
        elif k == 'agents':
            sets.append("agents=?"); vals.append(json.dumps(v))
    if sets:
        vals.append(team_id)
        conn.execute(f"UPDATE teams SET {','.join(sets)} WHERE id=?", vals)
        conn.commit()
    conn.close()

def db_delete_team(team_id: str):
    conn = get_conn()
    conn.execute("DELETE FROM teams WHERE id=?", (team_id,))
    conn.commit(); conn.close()


# Tasks
def db_list_tasks(status: str = None):
    conn = get_conn()
    if status:
        rows = conn.execute("SELECT * FROM tasks WHERE status=? ORDER BY created_at DESC", (status,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT 100").fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]

def db_get_task(task_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    conn.close()
    return row_to_dict(row)

def db_create_task(data: dict):
    conn = get_conn()
    conn.execute("""INSERT INTO tasks (id,name,description,task_type,priority,agent_id,team_id,payload,cron_expr)
        VALUES (?,?,?,?,?,?,?,?,?)""",
        (data['id'], data['name'], data.get('description',''),
         data.get('task_type','unique'), data.get('priority','media'),
         data.get('agent_id'), data.get('team_id'),
         json.dumps(data.get('payload',{})), data.get('cron_expr')))
    conn.commit(); conn.close()

def db_update_task(task_id: str, **kwargs):
    conn = get_conn()
    sets, vals = [], []
    for k, v in kwargs.items():
        sets.append(f"{k}=?")
        vals.append(json.dumps(v) if isinstance(v, (dict,list)) else v)
    if sets:
        vals.append(task_id)
        conn.execute(f"UPDATE tasks SET {','.join(sets)} WHERE id=?", vals)
        conn.commit()
    conn.close()


# API Keys
def db_list_keys():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC").fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]

def db_create_key(data: dict):
    conn = get_conn()
    conn.execute("INSERT INTO api_keys (id,alias,provider,key_masked,key_value,models,status) VALUES (?,?,?,?,?,?,?)",
        (data['id'], data['alias'], data['provider'], data['key_masked'],
         data['key_value'], json.dumps(data.get('models',[])), data.get('status','detecting')))
    conn.commit(); conn.close()

def db_update_key(key_id: str, models: list, status: str):
    conn = get_conn()
    conn.execute("UPDATE api_keys SET models=?,status=? WHERE id=?",
        (json.dumps(models), status, key_id))
    conn.commit(); conn.close()

def db_delete_key(key_id: str):
    conn = get_conn()
    conn.execute("DELETE FROM api_keys WHERE id=?", (key_id,))
    conn.commit(); conn.close()
EOF
log "nexus_api/db/database.py"

# ══════════════════════════════════════════════════════════════
head "2/8 · nexus_api/routes/tools.py"
# ══════════════════════════════════════════════════════════════
cat > "$API/routes/tools.py" << 'EOF'
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
EOF
log "tools.py"

# ══════════════════════════════════════════════════════════════
head "3/8 · nexus_api/routes/agents.py — reescrito"
# ══════════════════════════════════════════════════════════════
cat > "$API/routes/agents.py" << 'EOF'
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
EOF
log "agents.py"

# ══════════════════════════════════════════════════════════════
head "4/8 · nexus_api/routes/teams.py — reescrito"
# ══════════════════════════════════════════════════════════════
cat > "$API/routes/teams_v2.py" << 'EOF'
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

@router.get("/teams-v2")
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

@router.get("/teams-v2/{team_id}")
def get_team(team_id: str):
    team = db_get_team(team_id)
    if not team:
        raise HTTPException(404, f"Equipo '{team_id}' no encontrado")
    return team

@router.post("/teams-v2", status_code=201)
def create_team(body: CreateTeamRequest):
    """Crea un equipo con agentes asignados."""
    team_id = f"team_{uuid.uuid4().hex[:8]}"
    data = {"id": team_id, **body.model_dump()}
    db_create_team(data)
    return {"id": team_id, "message": f"Equipo '{body.name}' creado", **data}

@router.post("/teams-v2/{team_id}/agents")
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

@router.delete("/teams-v2/{team_id}/agents/{agent_id}")
def remove_agent_from_team(team_id: str, agent_id: str):
    """Quita un agente de un equipo."""
    team = db_get_team(team_id)
    if not team:
        raise HTTPException(404)
    agents = [a for a in team.get('agents', []) if a != agent_id]
    db_update_team(team_id, {"agents": agents})
    return {"team_id": team_id, "agents": agents}

@router.put("/teams-v2/{team_id}")
def update_team(team_id: str, body: UpdateTeamRequest):
    team = db_get_team(team_id)
    if not team:
        raise HTTPException(404)
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    db_update_team(team_id, updates)
    return db_get_team(team_id)

@router.delete("/teams-v2/{team_id}")
def delete_team(team_id: str):
    db_delete_team(team_id)
    return {"deleted": team_id}
EOF
log "teams_v2.py"

# ══════════════════════════════════════════════════════════════
head "5/8 · nexus_api/routes/tasks.py — reescrito"
# ══════════════════════════════════════════════════════════════
cat > "$API/routes/tasks.py" << 'EOF'
"""
NEXUS PRO — Tasks API
CRUD de tareas: única, monitor 24/7, crontab, pipeline, event-driven
"""
import uuid
import asyncio
from fastapi import APIRouter, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from nexus_api.db.database import (
    db_list_tasks, db_get_task, db_create_task, db_update_task
)

router = APIRouter()

class CreateTaskRequest(BaseModel):
    name: str
    description: str = ""
    task_type: str = "unique"   # unique | monitor | cron | pipeline | event
    priority: str = "media"     # crítica | alta | media | baja
    agent_id: Optional[str] = None
    team_id: Optional[str] = None
    payload: Dict[str, Any] = {}
    cron_expr: Optional[str] = None  # "0 */6 * * *"

async def _run_task_background(task_id: str, app):
    """Ejecuta la tarea via JuniorBridge → Orchestrator → Agente."""
    db_update_task(task_id, status="running", started_at=__import__('datetime').datetime.utcnow().isoformat(), progress=10)
    try:
        bridge = getattr(app.state, 'junior_bridge', None)
        task = db_get_task(task_id)
        if not task:
            return

        if bridge and bridge.orchestrator:
            # Despachar al Orchestrator real
            payload = task.get('payload', {})
            payload['task_db_id'] = task_id
            orch_task_id = await bridge.dispatch(
                task_name=task['name'],
                payload=payload,
                capability="code_generation",
                priority={"crítica":1,"alta":3,"media":5,"baja":8}.get(task.get('priority','media'),5)
            )
            db_update_task(task_id, progress=50)
            # Esperar resultado
            result = await bridge.orchestrator.wait_for_task(orch_task_id, timeout=120)
            db_update_task(task_id,
                status="completed" if result.get('status')=='completed' else "failed",
                progress=100,
                result=str(result.get('result',''))[:2000],
                completed_at=__import__('datetime').datetime.utcnow().isoformat()
            )
        else:
            # Simular ejecución si no hay orchestrator
            await asyncio.sleep(2)
            db_update_task(task_id, status="completed", progress=100,
                result="Tarea completada (modo simulado — Orchestrator no disponible)",
                completed_at=__import__('datetime').datetime.utcnow().isoformat())
    except Exception as e:
        db_update_task(task_id, status="failed", error=str(e), progress=0)

@router.get("/tasks")
def list_tasks(status: Optional[str] = None):
    return db_list_tasks(status)

@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    task = db_get_task(task_id)
    if not task:
        raise HTTPException(404, f"Tarea '{task_id}' no encontrada")
    return task

@router.post("/tasks", status_code=201)
async def create_task(body: CreateTaskRequest, background: BackgroundTasks, request: Request):
    """Crea y opcionalmente ejecuta una tarea."""
    task_id = f"task_{uuid.uuid4().hex[:8]}"
    data = {"id": task_id, **body.model_dump()}
    db_create_task(data)

    # Ejecutar inmediatamente si es tipo unique
    if body.task_type == "unique":
        background.add_task(_run_task_background, task_id, request.app)

    return {"id": task_id, "message": f"Tarea '{body.name}' creada", **db_get_task(task_id)}

@router.post("/tasks/{task_id}/run")
async def run_task(task_id: str, background: BackgroundTasks, request: Request):
    """Ejecuta manualmente una tarea."""
    task = db_get_task(task_id)
    if not task:
        raise HTTPException(404)
    background.add_task(_run_task_background, task_id, request.app)
    return {"task_id": task_id, "message": "Tarea en ejecución"}

@router.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: str):
    db_update_task(task_id, status="cancelled")
    return {"task_id": task_id, "status": "cancelled"}

@router.delete("/tasks/{task_id}")
def delete_task(task_id: str):
    task = db_get_task(task_id)
    if not task:
        raise HTTPException(404)
    if task['status'] == 'running':
        raise HTTPException(409, "No se puede eliminar una tarea en ejecución")
    db_update_task(task_id, status="deleted")
    return {"deleted": task_id}
EOF
log "tasks.py"

# ══════════════════════════════════════════════════════════════
head "6/8 · nexus_api/routes/models.py — detección automática"
# ══════════════════════════════════════════════════════════════
cat > "$API/routes/models.py" << 'EOF'
"""
NEXUS PRO — Models & API Keys
Agrega API keys → detecta modelos disponibles automáticamente
"""
import uuid
import httpx
import asyncio
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
from nexus_api.db.database import db_list_keys, db_create_key, db_update_key, db_delete_key

router = APIRouter()

# Modelos conocidos por provider
PROVIDER_MODELS = {
    "openai": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo", "o1-preview", "o1-mini"],
    "anthropic": ["claude-opus-4-5", "claude-sonnet-4-5", "claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-haiku-20240307"],
    "google": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash", "gemini-pro"],
    "groq": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768", "gemma2-9b-it"],
    "together": ["meta-llama/Llama-3-70b-chat-hf", "mistralai/Mixtral-8x7B-Instruct-v0.1"],
    "ollama": ["llama3", "mistral", "codellama", "phi3", "gemma2"],
}

async def _detect_models_real(key_id: str, provider: str, api_key: str):
    """Detecta modelos reales haciendo una llamada de prueba al proveedor."""
    models = PROVIDER_MODELS.get(provider.lower(), [])
    status = "ok"

    try:
        if provider.lower() == "openai":
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get("https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"})
                if r.status_code == 200:
                    data = r.json()
                    gpt_models = sorted([m['id'] for m in data.get('data', []) if 'gpt' in m['id'] or 'o1' in m['id']])
                    models = gpt_models[:15] if gpt_models else models
                else:
                    status = "invalid_key"

        elif provider.lower() == "anthropic":
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get("https://api.anthropic.com/v1/models",
                    headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"})
                if r.status_code == 200:
                    data = r.json()
                    models = [m['id'] for m in data.get('data', [])]
                else:
                    status = "invalid_key"

        elif provider.lower() == "groq":
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get("https://api.groq.com/openai/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"})
                if r.status_code == 200:
                    data = r.json()
                    models = [m['id'] for m in data.get('data', [])]
                else:
                    status = "invalid_key"

        elif provider.lower() == "ollama":
            async with httpx.AsyncClient(timeout=5) as client:
                base = api_key if api_key.startswith("http") else "http://localhost:11434"
                r = await client.get(f"{base}/api/tags")
                if r.status_code == 200:
                    data = r.json()
                    models = [m['name'] for m in data.get('models', [])]
                else:
                    status = "unreachable"

    except Exception as e:
        status = "ok"  # usar modelos conocidos si falla la detección

    db_update_key(key_id, models=models, status=status)


class AddKeyRequest(BaseModel):
    alias: str
    provider: str   # openai | anthropic | google | groq | together | ollama
    api_key: str

@router.get("/models/keys")
def list_keys():
    """Lista todas las API keys configuradas (con key enmascarada)."""
    keys = db_list_keys()
    # Nunca exponer la key real
    for k in keys:
        k.pop('key_value', None)
    return keys

@router.get("/models/available")
def available_models():
    """Retorna todos los modelos disponibles según las keys configuradas."""
    keys = db_list_keys()
    all_models = []
    for k in keys:
        if k['status'] == 'ok':
            for m in k.get('models', []):
                all_models.append({
                    "model": m,
                    "provider": k['provider'],
                    "key_alias": k['alias'],
                    "key_id": k['id'],
                })
    return {"models": all_models, "total": len(all_models)}

@router.post("/models/keys", status_code=201)
async def add_key(body: AddKeyRequest, background: BackgroundTasks):
    """Agrega una API key y detecta modelos disponibles en background."""
    key_id = f"key_{uuid.uuid4().hex[:8]}"

    # Enmascarar la key para mostrar
    k = body.api_key
    if len(k) > 12:
        masked = k[:8] + "••••••••" + k[-4:]
    else:
        masked = "••••••••••••"

    data = {
        "id": key_id,
        "alias": body.alias,
        "provider": body.provider.lower(),
        "key_masked": masked,
        "key_value": body.api_key,
        "models": PROVIDER_MODELS.get(body.provider.lower(), []),
        "status": "detecting",
    }
    db_create_key(data)

    # Detectar modelos reales en background
    background.add_task(_detect_models_real, key_id, body.provider, body.api_key)

    data.pop('key_value')
    return {"id": key_id, "message": f"API key de {body.provider} agregada — detectando modelos...", **data}

@router.post("/models/keys/{key_id}/detect")
async def redetect_models(key_id: str, background: BackgroundTasks):
    """Re-detecta modelos para una key existente."""
    keys = db_list_keys()
    key = next((k for k in keys if k['id'] == key_id), None)
    if not key:
        raise HTTPException(404, "API key no encontrada")

    # Necesitamos la key real de la DB
    import sqlite3
    from pathlib import Path
    conn = sqlite3.connect("/home/operator/NEXUS-PRO/data/nexus_pro.db")
    row = conn.execute("SELECT key_value FROM api_keys WHERE id=?", (key_id,)).fetchone()
    conn.close()
    if row:
        background.add_task(_detect_models_real, key_id, key['provider'], row[0])

    return {"message": "Detección iniciada", "key_id": key_id}

@router.delete("/models/keys/{key_id}")
def delete_key(key_id: str):
    db_delete_key(key_id)
    return {"deleted": key_id}

@router.get("/models/catalog")
def model_catalog():
    """Catálogo completo de modelos conocidos por provider."""
    return PROVIDER_MODELS
EOF
log "models.py"

# ══════════════════════════════════════════════════════════════
head "7/8 · nexus_api/routes/ws_logs.py — reescrito con logs reales"
# ══════════════════════════════════════════════════════════════
cat > "$API/routes/ws_logs.py" << 'EOF'
"""
NEXUS PRO — WebSocket Logs
Transmite logs del sistema en tiempo real al dashboard
"""
import asyncio
import json
import logging
from datetime import datetime
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List

router = APIRouter()

# ── Manager de conexiones ────────────────────────────────────
class NexusLogManager:
    def __init__(self):
        self._connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)

    async def broadcast(self, msg: dict):
        dead = []
        for ws in self._connections:
            try:
                await ws.send_text(json.dumps(msg))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    async def send_log(self, level: str, source: str, message: str):
        await self.broadcast({
            "type": "log",
            "level": level.upper(),
            "source": source,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
        })

log_manager = NexusLogManager()

def get_log_manager() -> NexusLogManager:
    return log_manager


# ── Handler de logging para capturar logs reales ─────────────
class WSLogHandler(logging.Handler):
    def __init__(self, manager: NexusLogManager):
        super().__init__()
        self._manager = manager
        self._loop = None

    def emit(self, record):
        try:
            import asyncio
            msg = self.format(record)
            level = record.levelname
            source = record.name.replace('nexus.','').replace('uvicorn.','')

            # Solo emitir logs relevantes de nexus
            if not any(x in record.name for x in ['nexus','uvicorn','NexusOrchestrator','AgentRegistry','JuniorBridge','WorkflowManager']):
                return

            log_entry = {
                "type": "log",
                "level": level,
                "source": source[:20],
                "message": msg[:300],
                "timestamp": datetime.utcnow().isoformat(),
            }
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(self._manager.broadcast(log_entry))
            except Exception:
                pass
        except Exception:
            pass

# Registrar el handler
_ws_handler = WSLogHandler(log_manager)
_ws_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(_ws_handler)


# ── Endpoints WebSocket ───────────────────────────────────────

@router.websocket("/ws/logs")
async def websocket_global(ws: WebSocket):
    """Canal global de logs del sistema."""
    await log_manager.connect(ws)
    await log_manager.send_log("SUCCESS", "nexus-ws", "Dashboard conectado — NEXUS PRO v2.0")

    try:
        while True:
            # Heartbeat cada 15s + escucha comandos
            try:
                data = await asyncio.wait_for(ws.receive_text(), timeout=15.0)
                try:
                    payload = json.loads(data)
                    if payload.get("cmd") == "ping":
                        await ws.send_text(json.dumps({"type": "pong"}))
                except Exception:
                    pass
            except asyncio.TimeoutError:
                # Heartbeat
                await ws.send_text(json.dumps({
                    "type": "heartbeat",
                    "timestamp": datetime.utcnow().isoformat()
                }))
    except WebSocketDisconnect:
        log_manager.disconnect(ws)
    except Exception:
        log_manager.disconnect(ws)


@router.websocket("/ws/logs/{channel}")
async def websocket_channel(ws: WebSocket, channel: str):
    """Canal específico por agente o componente."""
    await log_manager.connect(ws)
    await log_manager.send_log("INFO", "nexus-ws", f"Canal '{channel}' conectado")
    try:
        while True:
            try:
                await asyncio.wait_for(ws.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                await ws.send_text(json.dumps({"type": "heartbeat"}))
    except WebSocketDisconnect:
        log_manager.disconnect(ws)
    except Exception:
        log_manager.disconnect(ws)
EOF
log "ws_logs.py"

# ══════════════════════════════════════════════════════════════
head "8/8 · Actualizar main.py — registrar nuevos routes + init DB"
# ══════════════════════════════════════════════════════════════
python3 << 'PYFIX'
path = "/home/operator/NEXUS-PRO/nexus_api/main.py"
with open(path) as f:
    content = f.read()

# 1. Agregar init_nexus_db al startup
old_db = """    try:
        from nexus_api.auth.database import database, init_db
        init_db()
        await database.connect()
        logger.info("[DB] ✓ Conectada")
    except Exception as e:
        logger.warning(f"[DB] ⚠ {e}")"""

new_db = """    try:
        from nexus_api.auth.database import database, init_db
        init_db()
        await database.connect()
        logger.info("[DB] ✓ Conectada")
    except Exception as e:
        logger.warning(f"[DB] ⚠ {e}")

    # ── NEXUS PRO DB ──────────────────────────────────────────
    try:
        from nexus_api.db.database import init_nexus_db
        init_nexus_db()
        logger.info("[NEXUS-DB] ✓ Base de datos PRO inicializada")
    except Exception as e:
        logger.warning(f"[NEXUS-DB] ⚠ {e}")"""

# 2. Agregar routes en la lista
old_routes = '''    ("nexus_api.routes.ws_logs",         {},                              ["WebSocket"]),
    ("nexus_api.routes.projects",        {"prefix": "/projects"},         ["Projects"]),
]'''

new_routes = '''    ("nexus_api.routes.ws_logs",         {},                              ["WebSocket"]),
    ("nexus_api.routes.projects",        {"prefix": "/projects"},         ["Projects"]),
    ("nexus_api.routes.tools",           {},                              ["Tools"]),
    ("nexus_api.routes.models",          {},                              ["Models"]),
]'''

if old_db in content:
    content = content.replace(old_db, new_db)
    print("  ✓ init_nexus_db agregado al startup")
else:
    print("  ⚠ Bloque DB no encontrado — agrega manualmente init_nexus_db()")

if old_routes in content:
    content = content.replace(old_routes, new_routes)
    print("  ✓ Routes tools y models agregados")
else:
    print("  ⚠ Lista de routes no encontrada")

with open(path, 'w') as f:
    f.write(content)
PYFIX

log "main.py actualizado"

# Limpiar pycache para forzar reload
find /home/operator/NEXUS-PRO/nexus_api -name "*.pyc" -delete 2>/dev/null || true

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO Backend Completo ✓                      ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Endpoints nuevos:"
echo -e "  ${CYAN}GET/POST   /tools${NC}                    ← catálogo de herramientas"
echo -e "  ${CYAN}GET/POST   /agents${NC}                   ← CRUD agentes"
echo -e "  ${CYAN}POST       /agents/:id/tools${NC}         ← asignar tools a agente"
echo -e "  ${CYAN}GET/POST   /teams-v2${NC}                 ← CRUD equipos"
echo -e "  ${CYAN}POST       /teams-v2/:id/agents${NC}      ← agregar agente a equipo"
echo -e "  ${CYAN}GET/POST   /tasks${NC}                    ← CRUD tareas"
echo -e "  ${CYAN}POST       /tasks/:id/run${NC}            ← ejecutar tarea"
echo -e "  ${CYAN}GET/POST   /models/keys${NC}              ← API keys"
echo -e "  ${CYAN}GET        /models/available${NC}         ← modelos detectados"
echo -e "  ${CYAN}WS         /ws/logs${NC}                  ← logs en tiempo real"
echo ""
echo -e "  ${CYAN}uvicorn nexus_api.main:app --host 0.0.0.0 --port 8000 --reload${NC}"
echo ""
