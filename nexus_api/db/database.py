"""
NEXUS PRO — Base de datos SQLite para persistencia de:
Tools, Agents, Teams, Tasks, API Keys
"""
import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime
from nexus_api.config import NEXUS_DB_PATH

DB_PATH = NEXUS_DB_PATH
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

    CREATE TABLE IF NOT EXISTS junior_updates (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        title          TEXT NOT NULL,
        description    TEXT,
        category       TEXT DEFAULT 'mejora',
        priority       TEXT DEFAULT 'media',
        impact         TEXT,
        implementation TEXT,
        status         TEXT DEFAULT 'pending',
        approved_by    TEXT,
        approved_at    TEXT,
        created_at     TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS junior_chats (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        title      TEXT DEFAULT 'Nueva conversación',
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS junior_messages (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        role       TEXT NOT NULL,
        content    TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
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
