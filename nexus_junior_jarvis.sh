#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Junior JARVIS Mode Completo                   ║
# ║  Daemon 24/7 · Interfaz tipo Claude · Actualizaciones      ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

NEXUS="/home/operator/NEXUS-PRO"
CORE="$NEXUS/nexus_core"
API="$NEXUS/nexus_api"
FRONT="$NEXUS/nexus_frontend/src"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

mkdir -p "$NEXUS/data/logs" "$NEXUS/data/junior_updates"

# ══════════════════════════════════════════════════════════════
head "1/5 · junior_jarvis.py — Daemon 24/7 completo"
# ══════════════════════════════════════════════════════════════
cat > "$NEXUS/junior_jarvis.py" << 'EOF'
#!/usr/bin/env python3
"""
NEXUS PRO — Junior Daemon v2.0
Agente autónomo 24/7: monitorea, protege, propone mejoras.
Uso: python3 junior_jarvis.py
"""
import os, sys, json, time, asyncio, logging, sqlite3, subprocess, psutil
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

# Crear logs dir
(ROOT / "data/logs").mkdir(parents=True, exist_ok=True)
(ROOT / "data/junior_updates").mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [JUNIOR] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(ROOT / "data/logs/junior.log", mode="a"),
    ]
)
logger = logging.getLogger("junior")

DB_PATH  = os.getenv("NEXUS_DB_PATH", str(ROOT / "data/nexus_pro.db"))
API_URL  = "http://127.0.0.1:8000"
INTERVAL = int(os.getenv("JUNIOR_INTERVAL", "120"))  # cada 2 minutos
UPDATES_DB = str(ROOT / "data/junior_updates/updates.db")


# ══════════════════════════════════════════════════════════════
# DB helpers
# ══════════════════════════════════════════════════════════════
def get_conn(path=None):
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_tables():
    """Inicializar tablas de Junior."""
    with get_conn() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS jarvis_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT, tipo TEXT, detail TEXT,
            created_at TEXT DEFAULT (datetime('now')), read INTEGER DEFAULT 0
        )""")
        conn.commit()

    with get_conn(UPDATES_DB) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS junior_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT DEFAULT 'mejora',
            priority TEXT DEFAULT 'media',
            impact TEXT,
            implementation TEXT,
            status TEXT DEFAULT 'pending',
            approved_by TEXT,
            approved_at TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS junior_chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            title TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS junior_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        )""")
        conn.commit()

def save_notification(msg, tipo="info", detail=""):
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO jarvis_notifications(message,tipo,detail) VALUES(?,?,?)",
                (msg, tipo, detail)
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Error guardando notificación: {e}")

def save_update(title, description, category, priority, impact, implementation):
    """Guardar una propuesta de mejora de Junior."""
    try:
        with get_conn(UPDATES_DB) as conn:
            conn.execute("""INSERT INTO junior_updates
                (title,description,category,priority,impact,implementation)
                VALUES (?,?,?,?,?,?)""",
                (title, description, category, priority, impact, implementation)
            )
            conn.commit()
        logger.info(f"[Junior] 💡 Nueva propuesta guardada: {title}")
    except Exception as e:
        logger.error(f"Error guardando propuesta: {e}")


# ══════════════════════════════════════════════════════════════
# API helpers
# ══════════════════════════════════════════════════════════════
def api_get(endpoint, token=None):
    import urllib.request
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    req = urllib.request.Request(f"{API_URL}{endpoint}", headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

def api_post(endpoint, data, token=None):
    import urllib.request
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{API_URL}{endpoint}",
        data=json.dumps(data).encode(), headers=headers
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def get_token():
    try:
        return api_post("/auth/login", {
            "email": os.getenv("NEXUS_ADMIN_EMAIL", "admin@nexuspro.io"),
            "password": os.getenv("NEXUS_ADMIN_PASSWORD", "synthetic-password")
        })["access_token"]
    except Exception as e:
        logger.warning(f"Token fallido: {e}")
        return None


# ══════════════════════════════════════════════════════════════
# MONITORES
# ══════════════════════════════════════════════════════════════
def check_system_health():
    """Monitor de CPU, RAM, disco."""
    issues = []
    report = {}
    try:
        cpu = psutil.cpu_percent(interval=2)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        report = {
            "cpu_pct": cpu,
            "ram_pct": ram.percent,
            "ram_available_gb": round(ram.available / 1e9, 2),
            "disk_pct": disk.percent,
            "disk_free_gb": round(disk.free / 1e9, 2),
        }
        if cpu > 85:
            issues.append(f"CPU alta: {cpu}%")
            save_notification(
                f"⚠ CPU al {cpu}% — posible proceso intensivo",
                "warn",
                f"CPU: {cpu}% | RAM: {ram.percent}% | Disco: {disk.percent}%"
            )
        if ram.percent > 85:
            issues.append(f"RAM alta: {ram.percent}%")
            save_notification(
                f"⚠ RAM al {ram.percent}% — considera reiniciar servicios",
                "warn",
                f"Disponible: {report['ram_available_gb']}GB"
            )
        if disk.percent > 90:
            issues.append(f"Disco crítico: {disk.percent}%")
            save_notification(
                f"🔴 Disco al {disk.percent}% — limpiar archivos",
                "critical",
                f"Libre: {report['disk_free_gb']}GB"
            )
    except Exception as e:
        logger.warning(f"check_system_health: {e}")
    return report, issues

def check_nexus_api():
    """Verificar que la API de NEXUS responde."""
    try:
        data = api_get("/health")
        status = data.get("status", "unknown")
        if status != "healthy":
            save_notification(
                f"⚠ NEXUS API status: {status}",
                "warn",
                json.dumps(data, ensure_ascii=False)[:300]
            )
        return status, data
    except Exception as e:
        save_notification(
            "🔴 NEXUS API no responde",
            "critical",
            str(e)
        )
        return "down", {}

def check_failed_tasks():
    """Detectar tareas fallidas recientes."""
    try:
        token = get_token()
        if not token:
            return []
        tasks = api_get("/tasks", token)
        failed = [t for t in tasks if t.get("status") == "failed"]
        if failed:
            names = ", ".join(t["name"][:30] for t in failed[:3])
            save_notification(
                f"⚠ {len(failed)} tarea(s) fallida(s): {names}",
                "warn",
                json.dumps([{"id":t["id"],"name":t["name"],"error":t.get("error","")} for t in failed[:5]], ensure_ascii=False)
            )
        return failed
    except Exception as e:
        logger.warning(f"check_failed_tasks: {e}")
        return []

def check_open_ports():
    """Verificar puertos abiertos inesperados."""
    try:
        result = subprocess.run(
            ["ss", "-tlnp"], capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split("\n")
        ports = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3]
                port = addr.split(":")[-1]
                if port.isdigit():
                    ports.append(int(port))
        expected = {8000, 5173, 22, 80, 443, 5432, 3306, 6379}
        unexpected = [p for p in ports if p not in expected and p > 1024]
        if unexpected:
            save_notification(
                f"⚠ Puertos inesperados detectados: {unexpected}",
                "security",
                f"Puertos abiertos: {ports}"
            )
        return ports
    except Exception as e:
        logger.warning(f"check_open_ports: {e}")
        return []

def check_failed_logins():
    """Detectar intentos de login fallidos en auth.log."""
    try:
        result = subprocess.run(
            ["grep", "-c", "Failed password", "/var/log/auth.log"],
            capture_output=True, text=True, timeout=5
        )
        count = int(result.stdout.strip() or "0")
        if count > 10:
            save_notification(
                f"🔴 {count} intentos de login fallidos detectados",
                "security",
                "Ver /var/log/auth.log para detalles"
            )
        return count
    except Exception:
        return 0

def generate_improvement_proposals(health_report, api_status, failed_tasks):
    """Generar propuestas de mejora basadas en el estado del sistema."""
    proposals = []

    # Propuesta basada en CPU
    if health_report.get("cpu_pct", 0) > 70:
        proposals.append({
            "title": "Optimizar workers de uvicorn",
            "description": "CPU consistentemente alta. Considera aumentar workers o implementar async caching.",
            "category": "rendimiento",
            "priority": "alta",
            "impact": "Reducir latencia 30-40%, liberar CPU",
            "implementation": "uvicorn nexus_api.main:app --workers 4 --host 0.0.0.0 --port 8000"
        })

    # Propuesta basada en disco
    if health_report.get("disk_pct", 0) > 70:
        proposals.append({
            "title": "Limpiar archivos temporales y logs antiguos",
            "description": f"Disco al {health_report.get('disk_pct')}%. Limpiar scripts .sh temporales y logs.",
            "category": "mantenimiento",
            "priority": "media",
            "impact": "Liberar espacio en disco",
            "implementation": "rm ~/NEXUS-PRO/*.sh && find ~/NEXUS-PRO/data/logs -mtime +7 -delete"
        })

    # Propuesta de seguridad fija
    proposals.append({
        "title": "Agregar headers de seguridad HTTP a NEXUS API",
        "description": "La API no tiene HSTS, CSP, X-Frame-Options ni otros headers críticos.",
        "category": "seguridad",
        "priority": "alta",
        "impact": "Proteger contra XSS, clickjacking y MIME sniffing",
        "implementation": "Agregar SecurityHeadersMiddleware en nexus_api/main.py"
    })

    # Propuesta de tareas fallidas
    if failed_tasks:
        proposals.append({
            "title": f"Revisar {len(failed_tasks)} tarea(s) fallida(s)",
            "description": "Hay tareas con errores que requieren atención.",
            "category": "operaciones",
            "priority": "alta",
            "impact": "Restaurar operaciones normales",
            "implementation": "Ver sección Tareas en el dashboard y revisar logs"
        })

    return proposals


# ══════════════════════════════════════════════════════════════
# LOOP PRINCIPAL
# ══════════════════════════════════════════════════════════════
def run_cycle():
    """Un ciclo completo de monitoreo."""
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    logger.info(f"─── Ciclo Junior {ts} ───")

    # 1. Health del sistema
    health, sys_issues = check_system_health()
    logger.info(f"Sistema: CPU {health.get('cpu_pct',0)}% | RAM {health.get('ram_pct',0)}% | Disco {health.get('disk_pct',0)}%")

    # 2. API NEXUS
    api_status, api_data = check_nexus_api()
    logger.info(f"API NEXUS: {api_status}")

    # 3. Tareas fallidas
    failed = check_failed_tasks()

    # 4. Puertos
    ports = check_open_ports()
    logger.info(f"Puertos abiertos: {len(ports)}")

    # 5. Intentos de login
    login_attempts = check_failed_logins()

    # 6. Generar propuestas
    proposals = generate_improvement_proposals(health, api_status, failed)

    # 7. Guardar propuestas nuevas (evitar duplicados por título)
    try:
        with get_conn(UPDATES_DB) as conn:
            existing = {r["title"] for r in conn.execute(
                "SELECT title FROM junior_updates WHERE status='pending'"
            ).fetchall()}
            for p in proposals:
                if p["title"] not in existing:
                    save_update(**p)
    except Exception as e:
        logger.warning(f"Guardar propuestas: {e}")

    # 8. Guardar reporte JSON
    report = {
        "timestamp": ts,
        "system": health,
        "api_status": api_status,
        "failed_tasks": len(failed),
        "open_ports": ports,
        "login_attempts": login_attempts,
        "proposals_count": len(proposals),
        "issues": sys_issues,
    }
    report_path = ROOT / "data/logs/junior_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))

    # 9. Notificación de ciclo OK (cada 10 ciclos)
    cycle_file = ROOT / "data/logs/junior_cycle.txt"
    cycle = int(cycle_file.read_text().strip() or "0") + 1 if cycle_file.exists() else 1
    cycle_file.write_text(str(cycle))

    if cycle % 10 == 0:
        save_notification(
            f"✓ Junior monitoreando — ciclo #{cycle} completado",
            "info",
            f"Sistema estable | {len(proposals)} propuestas pendientes"
        )

    logger.info(f"Ciclo #{cycle} completado | {len(proposals)} propuestas")
    return report


def main():
    logger.info("═══════════════════════════════════════")
    logger.info("  NEXUS PRO — Junior Daemon v2.0")
    logger.info("  Autónomo 24/7 · Monitor · Protección")
    logger.info("═══════════════════════════════════════")

    init_tables()
    save_notification(
        "🟢 Junior iniciado — monitoreo 24/7 activo",
        "info",
        f"Intervalo: {INTERVAL}s | DB: {DB_PATH}"
    )

    while True:
        try:
            run_cycle()
        except Exception as e:
            logger.error(f"Error en ciclo: {e}")
            save_notification(f"⚠ Error en ciclo de Junior: {e}", "warn")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
EOF
log "junior_jarvis.py v2.0"

# ══════════════════════════════════════════════════════════════
head "2/5 · nexus_api/routes/jarvis.py — API completa"
# ══════════════════════════════════════════════════════════════
cat > "$API/routes/jarvis.py" << 'EOF'
"""
NEXUS PRO — Junior API (ex-JARVIS)
Notificaciones + Actualizaciones + Chat + Status + Control
"""
from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
import sqlite3, json, os, subprocess
from pathlib import Path
from datetime import datetime

router = APIRouter(prefix="/jarvis", tags=["Junior"])

ROOT     = Path(__file__).parent.parent.parent
DB_PATH  = os.getenv("NEXUS_DB_PATH", str(ROOT / "data/nexus_pro.db"))
UPD_DB   = str(ROOT / "data/junior_updates/updates.db")
LOG_PATH = ROOT / "data/logs/junior.log"


def _db(path=None):
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _ensure():
    """Crear tablas si no existen."""
    with _db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS jarvis_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT, tipo TEXT, detail TEXT,
            created_at TEXT DEFAULT (datetime('now')), read INTEGER DEFAULT 0
        )""")
        conn.commit()
    Path(ROOT / "data/junior_updates").mkdir(parents=True, exist_ok=True)
    with _db(UPD_DB) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS junior_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT, description TEXT,
            category TEXT DEFAULT 'mejora',
            priority TEXT DEFAULT 'media',
            impact TEXT, implementation TEXT,
            status TEXT DEFAULT 'pending',
            approved_by TEXT, approved_at TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS junior_chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            title TEXT DEFAULT 'Nueva conversación',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS junior_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        )""")
        conn.commit()

_ensure()

# ── Schemas ───────────────────────────────────────────────────
class ApproveUpdate(BaseModel):
    approved_by: str = "marcos"

class DenyUpdate(BaseModel):
    reason: str = ""

class ChatMessage(BaseModel):
    session_id: str
    message: str

class NewSession(BaseModel):
    title: Optional[str] = "Nueva conversación"


# ══════════════════════════════════════════════════════════════
# NOTIFICACIONES
# ══════════════════════════════════════════════════════════════
@router.get("/notifications")
async def get_notifications(limit: int = 50, unread_only: bool = False):
    with _db() as conn:
        q = "WHERE read=0 " if unread_only else ""
        rows = conn.execute(
            f"SELECT * FROM jarvis_notifications {q}ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        unread = conn.execute(
            "SELECT COUNT(*) as c FROM jarvis_notifications WHERE read=0"
        ).fetchone()["c"]
    return {
        "notifications": [dict(r) for r in rows],
        "unread": unread,
        "total": len(rows),
    }

@router.post("/notifications/{nid}/read")
async def mark_read(nid: int):
    with _db() as conn:
        conn.execute("UPDATE jarvis_notifications SET read=1 WHERE id=?", (nid,))
        conn.commit()
    return {"status": "ok"}

@router.post("/notifications/read-all")
async def mark_all_read():
    with _db() as conn:
        conn.execute("UPDATE jarvis_notifications SET read=1")
        conn.commit()
    return {"status": "ok"}


# ══════════════════════════════════════════════════════════════
# ACTUALIZACIONES / PROPUESTAS DE JUNIOR
# ══════════════════════════════════════════════════════════════
@router.get("/updates")
async def get_updates(status: str = "pending"):
    with _db(UPD_DB) as conn:
        rows = conn.execute(
            "SELECT * FROM junior_updates WHERE status=? ORDER BY id DESC",
            (status,)
        ).fetchall()
    return {"updates": [dict(r) for r in rows], "total": len(rows)}

@router.get("/updates/all")
async def get_all_updates():
    with _db(UPD_DB) as conn:
        rows = conn.execute(
            "SELECT * FROM junior_updates ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return {"updates": [dict(r) for r in rows], "total": len(rows)}

@router.post("/updates/{uid}/approve")
async def approve_update(uid: int, body: ApproveUpdate,
                          background: BackgroundTasks, request: Request):
    """Aprobar una propuesta — Junior ordena a los agentes ejecutarla."""
    with _db(UPD_DB) as conn:
        row = conn.execute(
            "SELECT * FROM junior_updates WHERE id=?", (uid,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Actualización no encontrada")
        update = dict(row)
        conn.execute(
            "UPDATE junior_updates SET status='approved',approved_by=?,approved_at=? WHERE id=?",
            (body.approved_by, datetime.utcnow().isoformat(), uid)
        )
        conn.commit()

    # Ejecutar via Junior Agent
    background.add_task(_execute_update, update, request.app)
    return {"status": "approved", "update": update}

@router.post("/updates/{uid}/deny")
async def deny_update(uid: int, body: DenyUpdate):
    with _db(UPD_DB) as conn:
        conn.execute(
            "UPDATE junior_updates SET status='denied' WHERE id=?", (uid,)
        )
        conn.commit()
    return {"status": "denied"}

@router.delete("/updates/{uid}")
async def delete_update(uid: int):
    with _db(UPD_DB) as conn:
        conn.execute("DELETE FROM junior_updates WHERE id=?", (uid,))
        conn.commit()
    return {"status": "deleted"}

async def _execute_update(update: dict, app):
    """Ejecutar la actualización via Junior Agent."""
    import datetime as dt
    from nexus_api.db.database import db_create_task, db_update_task
    import uuid
    task_id = f"junior_{uuid.uuid4().hex[:8]}"
    objective = (
        f"Ejecuta esta mejora aprobada para NEXUS PRO:\n"
        f"Título: {update['title']}\n"
        f"Descripción: {update['description']}\n"
        f"Implementación sugerida: {update.get('implementation','')}\n"
        f"Ejecuta los pasos necesarios y genera un reporte del resultado."
    )
    db_create_task({
        "id": task_id,
        "name": f"Update: {update['title'][:50]}",
        "description": objective,
        "task_type": "unique",
        "priority": "alta",
        "payload": {"objective": objective, "max_steps": 5},
    })
    try:
        from nexus_api.db.database import db_update_task
        db_update_task(task_id, status="running",
            started_at=dt.datetime.utcnow().isoformat(), progress=10)
        registry = getattr(app.state, 'registry', None)
        llm = getattr(app.state, 'llm', None)
        junior = None
        if registry:
            agents = await registry.get_all()
            for ag in agents.values():
                if ag.name == "Junior":
                    junior = ag
                    break
        if not junior:
            from nexus_core.agents.junior_agent import JuniorAgent
            junior = JuniorAgent(llm=llm)
        result = await junior.run(task_id, {
            "objective": objective, "max_steps": 5,
            "_task_name": update["title"]
        })
        inner = result.get("result", {})
        db_update_task(task_id,
            status="completed" if result.get("success") else "failed",
            progress=100,
            result=str(inner)[:2000],
            completed_at=dt.datetime.utcnow().isoformat()
        )
        with _db() as conn:
            conn.execute(
                "INSERT INTO jarvis_notifications(message,tipo,detail) VALUES(?,?,?)",
                (f"✓ Actualización ejecutada: {update['title']}", "success",
                 f"Task: {task_id}")
            )
            conn.commit()
    except Exception as e:
        db_update_task(task_id, status="failed", error=str(e), progress=0)


# ══════════════════════════════════════════════════════════════
# CHAT CON HISTORIAL
# ══════════════════════════════════════════════════════════════
@router.get("/chats")
async def list_chats():
    """Lista todas las sesiones de chat."""
    with _db(UPD_DB) as conn:
        rows = conn.execute(
            "SELECT * FROM junior_chats ORDER BY updated_at DESC LIMIT 50"
        ).fetchall()
    return {"chats": [dict(r) for r in rows]}

@router.post("/chats")
async def create_chat(body: NewSession):
    """Crear nueva sesión de chat."""
    import uuid
    sid = uuid.uuid4().hex[:12]
    with _db(UPD_DB) as conn:
        conn.execute(
            "INSERT INTO junior_chats(session_id,title) VALUES(?,?)",
            (sid, body.title)
        )
        conn.commit()
    return {"session_id": sid, "title": body.title}

@router.get("/chats/{session_id}/messages")
async def get_messages(session_id: str):
    """Obtener mensajes de una sesión."""
    with _db(UPD_DB) as conn:
        rows = conn.execute(
            "SELECT * FROM junior_messages WHERE session_id=? ORDER BY id ASC",
            (session_id,)
        ).fetchall()
    return {"messages": [dict(r) for r in rows]}

@router.post("/chats/{session_id}/messages")
async def send_message(session_id: str, body: ChatMessage, request: Request):
    """Enviar mensaje a Junior y obtener respuesta."""
    # Guardar mensaje del usuario
    with _db(UPD_DB) as conn:
        # Verificar sesión existe
        sess = conn.execute(
            "SELECT * FROM junior_chats WHERE session_id=?", (session_id,)
        ).fetchone()
        if not sess:
            conn.execute(
                "INSERT INTO junior_chats(session_id,title) VALUES(?,?)",
                (session_id, body.message[:50])
            )
        conn.execute(
            "INSERT INTO junior_messages(session_id,role,content) VALUES(?,?,?)",
            (session_id, "user", body.message)
        )
        # Actualizar título si es primer mensaje
        msg_count = conn.execute(
            "SELECT COUNT(*) as c FROM junior_messages WHERE session_id=?",
            (session_id,)
        ).fetchone()["c"]
        if msg_count <= 1:
            conn.execute(
                "UPDATE junior_chats SET title=? WHERE session_id=?",
                (body.message[:60], session_id)
            )
        conn.execute(
            "UPDATE junior_chats SET updated_at=datetime('now') WHERE session_id=?",
            (session_id,)
        )
        conn.commit()

    # Obtener historial para contexto
    with _db(UPD_DB) as conn:
        history = conn.execute(
            "SELECT role,content FROM junior_messages WHERE session_id=? ORDER BY id DESC LIMIT 10",
            (session_id,)
        ).fetchall()
    history = list(reversed([dict(h) for h in history]))

    # Llamar al LLM con contexto
    llm = getattr(request.app.state, 'llm', None)
    if not llm:
        raise HTTPException(503, "LLM no disponible")

    JUNIOR_SYSTEM = """Eres JUNIOR, el agente autónomo estrella de NEXUS PRO, creado por BAJIOWARE.

Personalidad: directo, técnico, proactivo, siempre propones soluciones concretas.
Tienes acceso completo al sistema NEXUS PRO en /home/operator/NEXUS-PRO.

Capacidades:
- Desarrollar software (Python, FastAPI, React, Docker, Terraform)
- Ciberseguridad (pentesting, STRIDE, análisis de vulnerabilidades)
- DevSecOps (CI/CD, contenedores, IaC)
- Monitoreo y optimización del sistema
- Generación de reportes ejecutivos

Cuando el usuario pida algo complejo (crear código, auditar, analizar), 
menciona que puedes ejecutarlo autónomamente con el botón RUN o via tarea.

Responde siempre en el idioma del usuario. Sé conciso y técnico."""

    # Construir contexto de conversación
    history_text = "\n".join([
        f"{'Usuario' if m['role']=='user' else 'Junior'}: {m['content']}"
        for m in history[:-1]  # excluir el último (ya es el mensaje actual)
    ])
    user_prompt = body.message
    if history_text:
        user_prompt = f"Conversación previa:\n{history_text}\n\nUsuario: {body.message}"

    try:
        response = await llm.ask(JUNIOR_SYSTEM, user_prompt)
    except Exception as e:
        response = f"Error en LLM: {e}"

    # Guardar respuesta
    with _db(UPD_DB) as conn:
        conn.execute(
            "INSERT INTO junior_messages(session_id,role,content) VALUES(?,?,?)",
            (session_id, "assistant", response)
        )
        conn.commit()

    return {
        "session_id": session_id,
        "response": response,
        "role": "assistant",
    }

@router.delete("/chats/{session_id}")
async def delete_chat(session_id: str):
    with _db(UPD_DB) as conn:
        conn.execute("DELETE FROM junior_chats WHERE session_id=?", (session_id,))
        conn.execute("DELETE FROM junior_messages WHERE session_id=?", (session_id,))
        conn.commit()
    return {"status": "deleted"}


# ══════════════════════════════════════════════════════════════
# STATUS Y CONTROL
# ══════════════════════════════════════════════════════════════
@router.get("/status")
async def junior_status():
    """Estado completo de Junior."""
    running = False
    try:
        result = subprocess.run(
            ["pgrep", "-f", "junior_jarvis.py"],
            capture_output=True, text=True
        )
        running = bool(result.stdout.strip())
    except Exception:
        pass

    last_lines = []
    if LOG_PATH.exists():
        with open(LOG_PATH) as f:
            last_lines = [l.strip() for l in f.readlines()[-15:]]

    report_path = ROOT / "data/logs/junior_report.json"
    last_report = {}
    if report_path.exists():
        try:
            last_report = json.loads(report_path.read_text())
        except Exception:
            pass

    with _db() as conn:
        unread = conn.execute(
            "SELECT COUNT(*) as c FROM jarvis_notifications WHERE read=0"
        ).fetchone()["c"]

    try:
        with _db(UPD_DB) as conn:
            pending_updates = conn.execute(
                "SELECT COUNT(*) as c FROM junior_updates WHERE status='pending'"
            ).fetchone()["c"]
    except Exception:
        pending_updates = 0

    return {
        "running": running,
        "unread_notifications": unread,
        "pending_updates": pending_updates,
        "last_report": last_report,
        "last_log": last_lines,
    }

@router.post("/start")
async def start_junior(background: BackgroundTasks):
    """Inicia el daemon de Junior."""
    def _start():
        subprocess.Popen(
            ["python3", str(ROOT / "junior_jarvis.py")],
            cwd=str(ROOT),
            stdout=open(ROOT / "data/logs/junior_daemon.log", "a"),
            stderr=subprocess.STDOUT,
        )
    background.add_task(_start)
    return {"status": "starting", "message": "Junior iniciando en background"}

@router.post("/stop")
async def stop_junior():
    """Detiene el daemon de Junior."""
    try:
        result = subprocess.run(
            ["pkill", "-f", "junior_jarvis.py"],
            capture_output=True
        )
        return {"status": "stopped" if result.returncode == 0 else "not_running"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

@router.get("/report")
async def get_report():
    report_path = ROOT / "data/logs/junior_report.json"
    if not report_path.exists():
        return {"status": "no_report", "message": "Junior aún no ha generado un reporte"}
    return json.loads(report_path.read_text())
EOF
log "jarvis.py API completa"

# ══════════════════════════════════════════════════════════════
head "3/5 · pages/Junior.jsx — Interfaz tipo Claude completa"
# ══════════════════════════════════════════════════════════════
cat > "$FRONT/pages/Junior.jsx" << 'EOF'
import { useState, useRef, useEffect, useCallback } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { nexusApi } from '../api/client'
import { Btn, Dot } from '../components/ui'

// ── API helpers ───────────────────────────────────────────────
const jApi = {
  chats:       () => nexusApi.api.get('/jarvis/chats'),
  newChat:     (title) => nexusApi.api.post('/jarvis/chats', { title }),
  deleteChat:  (sid) => nexusApi.api.delete(`/jarvis/chats/${sid}`),
  messages:    (sid) => nexusApi.api.get(`/jarvis/chats/${sid}/messages`),
  send:        (sid, msg) => nexusApi.api.post(`/jarvis/chats/${sid}/messages`, { session_id: sid, message: msg }),
  updates:     (status='pending') => nexusApi.api.get(`/jarvis/updates?status=${status}`),
  approveUpd:  (id) => nexusApi.api.post(`/jarvis/updates/${id}/approve`, { approved_by: 'marcos' }),
  denyUpd:     (id) => nexusApi.api.post(`/jarvis/updates/${id}/deny`, { reason: 'Descartado' }),
  deleteUpd:   (id) => nexusApi.api.delete(`/jarvis/updates/${id}`),
  notifs:      () => nexusApi.api.get('/jarvis/notifications?limit=20'),
  readAllNotifs:() => nexusApi.api.post('/jarvis/notifications/read-all'),
  status:      () => nexusApi.api.get('/jarvis/status'),
  start:       () => nexusApi.api.post('/jarvis/start'),
  stop:        () => nexusApi.api.post('/jarvis/stop'),
  runObjective:(obj, steps) => nexusApi.api.post('/junior/run', { objective: obj, max_steps: steps }),
  taskStatus:  (id) => nexusApi.api.get(`/junior/status/${id}`),
}

const PRIO_COLOR = { crítica:'var(--red)', alta:'var(--orange)', media:'var(--yellow)', baja:'var(--green)' }
const CAT_ICON   = { seguridad:'🛡️', rendimiento:'⚡', mantenimiento:'🔧', operaciones:'📋', mejora:'💡' }
const EXAMPLES   = [
  "Analiza todo el proyecto NEXUS PRO y dime qué archivos son basura",
  "¿Cuál es el estado actual del sistema?",
  "Crea una API FastAPI para una zapatería con login y catálogo",
  "Audita la seguridad de NEXUS y genera reporte ejecutivo",
  "¿Qué mejoras recomiendas para optimizar NEXUS?",
  "Genera Terraform para arquitectura Zero Trust en AWS",
]

// ── Componente de mensaje ─────────────────────────────────────
function Message({ msg }) {
  const isUser = msg.role === 'user'
  return (
    <div style={{ display:'flex', gap:12, alignItems:'flex-start',
      justifyContent: isUser ? 'flex-end' : 'flex-start',
      padding:'4px 0' }}>
      {!isUser && (
        <div style={{ width:32, height:32, borderRadius:8, flexShrink:0,
          background:'linear-gradient(135deg,#003d20,#001a40)',
          border:'1px solid var(--green)', display:'flex',
          alignItems:'center', justifyContent:'center', fontSize:16 }}>🤖</div>
      )}
      <div style={{ maxWidth:'80%', padding:'10px 14px', borderRadius:12,
        background: isUser ? 'var(--cyan)' : 'var(--bg-card)',
        border: isUser ? 'none' : '1px solid var(--border)',
        color: isUser ? 'var(--bg-base)' : 'var(--text)',
        fontFamily:'var(--ui)', fontSize:13, lineHeight:1.65,
        whiteSpace:'pre-wrap', wordBreak:'break-word' }}>
        {msg.content}
        <div style={{ fontFamily:'var(--mono)', fontSize:9,
          color: isUser ? 'rgba(0,0,0,.4)' : 'var(--text-dim)',
          marginTop:4 }}>
          {new Date(msg.created_at || Date.now()).toLocaleTimeString()}
        </div>
      </div>
      {isUser && (
        <div style={{ width:32, height:32, borderRadius:8, flexShrink:0,
          background:'var(--cyan)', display:'flex', alignItems:'center',
          justifyContent:'center', fontSize:14, fontWeight:700,
          color:'var(--bg-base)' }}>M</div>
      )}
    </div>
  )
}

// ── Panel de actualizaciones ──────────────────────────────────
function UpdatesPanel({ onClose }) {
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['junior-updates'],
    queryFn: () => jApi.updates('pending').then(r => r.data.updates || []),
    refetchInterval: 10000,
  })
  const updates = data || []

  const approveMut = useMutation({
    mutationFn: (id) => jApi.approveUpd(id),
    onSuccess: () => qc.invalidateQueries(['junior-updates']),
  })
  const denyMut = useMutation({
    mutationFn: (id) => jApi.denyUpd(id),
    onSuccess: () => qc.invalidateQueries(['junior-updates']),
  })

  return (
    <div style={{ position:'fixed', right:0, top:0, bottom:0, width:420,
      background:'var(--bg-panel)', borderLeft:'1px solid var(--border)',
      zIndex:200, display:'flex', flexDirection:'column',
      boxShadow:'-4px 0 20px rgba(0,0,0,.4)' }}>
      <div style={{ padding:'16px 20px', borderBottom:'1px solid var(--border)',
        display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <div>
          <div style={{ fontFamily:'var(--display)', fontSize:15, color:'var(--text-bright)', letterSpacing:1 }}>
            Actualizaciones Pendientes
          </div>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:2 }}>
            Junior propone · Tú autorizas · Agentes ejecutan
          </div>
        </div>
        <div style={{ display:'flex', gap:8 }}>
          <span style={{ fontFamily:'var(--mono)', fontSize:11,
            padding:'2px 8px', borderRadius:10,
            border:'1px solid var(--yellow)', color:'var(--yellow)' }}>
            {updates.length}
          </span>
          <button onClick={onClose} style={{ background:'none', border:'none',
            color:'var(--text-dim)', cursor:'pointer', fontSize:18 }}>✕</button>
        </div>
      </div>

      <div style={{ flex:1, overflowY:'auto', padding:16 }}>
        {updates.length === 0 ? (
          <div style={{ textAlign:'center', padding:'40px 0',
            fontFamily:'var(--mono)', fontSize:11, color:'var(--text-dim)' }}>
            <div style={{ fontSize:32, marginBottom:8 }}>💡</div>
            Sin propuestas pendientes<br/>Junior está analizando el sistema...
          </div>
        ) : updates.map(u => (
          <div key={u.id} style={{ background:'var(--bg-card)',
            border:'1px solid var(--border)', borderRadius:8,
            padding:14, marginBottom:10 }}>
            <div style={{ display:'flex', alignItems:'flex-start',
              gap:8, marginBottom:8 }}>
              <span style={{ fontSize:18 }}>{CAT_ICON[u.category] || '💡'}</span>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:13, fontWeight:600,
                  color:'var(--text-bright)', marginBottom:2 }}>{u.title}</div>
                <div style={{ display:'flex', gap:6 }}>
                  <span style={{ fontFamily:'var(--mono)', fontSize:9,
                    padding:'1px 6px', borderRadius:3,
                    border:`1px solid ${PRIO_COLOR[u.priority]||'var(--border)'}`,
                    color:PRIO_COLOR[u.priority]||'var(--text-dim)' }}>
                    {u.priority}
                  </span>
                  <span style={{ fontFamily:'var(--mono)', fontSize:9,
                    color:'var(--text-dim)' }}>{u.category}</span>
                </div>
              </div>
            </div>
            <div style={{ fontFamily:'var(--mono)', fontSize:11,
              color:'var(--text-dim)', marginBottom:8, lineHeight:1.6 }}>
              {u.description}
            </div>
            {u.impact && (
              <div style={{ fontFamily:'var(--mono)', fontSize:10,
                color:'var(--green)', marginBottom:8 }}>
                💥 Impacto: {u.impact}
              </div>
            )}
            {u.implementation && (
              <div style={{ background:'var(--bg-base)', border:'1px solid var(--border)',
                borderRadius:4, padding:'6px 10px', marginBottom:10,
                fontFamily:'var(--mono)', fontSize:10, color:'var(--cyan)',
                overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                $ {u.implementation}
              </div>
            )}
            <div style={{ display:'flex', gap:8 }}>
              <button onClick={() => approveMut.mutate(u.id)}
                style={{ flex:1, padding:'6px', borderRadius:4,
                  background:'#00ff9d15', border:'1px solid var(--green)',
                  color:'var(--green)', cursor:'pointer',
                  fontFamily:'var(--mono)', fontSize:11 }}>
                {approveMut.isPending && approveMut.variables === u.id ? '⟳' : '✓ APROBAR'}
              </button>
              <button onClick={() => denyMut.mutate(u.id)}
                style={{ flex:1, padding:'6px', borderRadius:4,
                  background:'#ff386015', border:'1px solid var(--red)',
                  color:'var(--red)', cursor:'pointer',
                  fontFamily:'var(--mono)', fontSize:11 }}>
                ✗ DESCARTAR
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Sidebar de Junior ─────────────────────────────────────────
function JuniorSidebar({ chats, activeChat, onSelect, onCreate, onDelete,
                         sidebarOpen, setSidebarOpen, updCount, onShowUpdates }) {
  return (
    <div style={{ width: sidebarOpen ? 260 : 0, flexShrink:0,
      overflow:'hidden', transition:'width .25s ease',
      background:'var(--bg-panel)', borderRight:'1px solid var(--border)',
      display:'flex', flexDirection:'column' }}>
      <div style={{ padding:'14px 12px', borderBottom:'1px solid var(--border)',
        display:'flex', gap:8 }}>
        <button onClick={onCreate}
          style={{ flex:1, padding:'8px 12px', borderRadius:6,
            background:'var(--bg-card)', border:'1px solid var(--border)',
            color:'var(--text)', cursor:'pointer', fontFamily:'var(--ui)',
            fontSize:12, display:'flex', alignItems:'center', gap:8,
            transition:'all .15s' }}>
          <span style={{ fontSize:14 }}>✎</span> Nueva conversación
        </button>
        <button onClick={() => setSidebarOpen(false)}
          style={{ padding:'8px', borderRadius:6, background:'var(--bg-card)',
            border:'1px solid var(--border)', color:'var(--text-dim)',
            cursor:'pointer', fontSize:14 }}>✕</button>
      </div>

      {/* Actualizaciones */}
      <button onClick={onShowUpdates}
        style={{ margin:'10px 12px', padding:'10px 12px', borderRadius:6,
          background: updCount > 0 ? '#ffc10710' : 'var(--bg-card)',
          border:`1px solid ${updCount > 0 ? 'var(--yellow)' : 'var(--border)'}`,
          color: updCount > 0 ? 'var(--yellow)' : 'var(--text-dim)',
          cursor:'pointer', display:'flex', alignItems:'center', gap:8,
          fontFamily:'var(--ui)', fontSize:12 }}>
        <span>💡</span>
        <span style={{ flex:1, textAlign:'left' }}>Actualizaciones</span>
        {updCount > 0 && (
          <span style={{ background:'var(--yellow)', color:'var(--bg-base)',
            borderRadius:10, padding:'1px 7px',
            fontFamily:'var(--mono)', fontSize:10, fontWeight:700 }}>
            {updCount}
          </span>
        )}
      </button>

      {/* Historial */}
      <div style={{ padding:'0 12px 6px',
        fontFamily:'var(--mono)', fontSize:9,
        color:'var(--text-dim)', letterSpacing:1, textTransform:'uppercase' }}>
        Conversaciones
      </div>
      <div style={{ flex:1, overflowY:'auto', padding:'0 8px' }}>
        {chats.length === 0 ? (
          <div style={{ padding:'20px 12px', fontFamily:'var(--mono)',
            fontSize:10, color:'var(--text-dim)', textAlign:'center' }}>
            Sin conversaciones
          </div>
        ) : chats.map(c => (
          <div key={c.session_id}
            onClick={() => onSelect(c.session_id)}
            style={{ padding:'8px 10px', borderRadius:6, cursor:'pointer',
              marginBottom:2, display:'flex', alignItems:'center', gap:8,
              background: activeChat === c.session_id ? 'var(--bg-card)' : 'transparent',
              border: activeChat === c.session_id ? '1px solid var(--border)' : '1px solid transparent',
              transition:'all .15s' }}>
            <span style={{ fontSize:12 }}>💬</span>
            <span style={{ flex:1, fontSize:12, overflow:'hidden',
              textOverflow:'ellipsis', whiteSpace:'nowrap',
              color: activeChat === c.session_id ? 'var(--text-bright)' : 'var(--text-dim)' }}>
              {c.title || 'Nueva conversación'}
            </span>
            <button onClick={e => { e.stopPropagation(); onDelete(c.session_id) }}
              style={{ background:'none', border:'none', color:'var(--text-dim)',
                cursor:'pointer', fontSize:11, opacity:.5,
                ':hover': { opacity:1 } }}>✕</button>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── COMPONENTE PRINCIPAL ──────────────────────────────────────
export default function Junior() {
  const qc = useQueryClient()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [activeChat, setActiveChat]   = useState(null)
  const [input, setInput]             = useState('')
  const [tab, setTab]                 = useState('chat') // chat | run
  const [showUpdates, setShowUpdates] = useState(false)
  const [activeTask, setActiveTask]   = useState(null)
  const [runObj, setRunObj]           = useState('')
  const [runSteps, setRunSteps]       = useState(6)
  const messagesEndRef = useRef(null)
  const inputRef = useRef(null)

  // Queries
  const { data: chatsData } = useQuery({
    queryKey: ['junior-chats'],
    queryFn: () => jApi.chats().then(r => r.data.chats || []),
    refetchInterval: 15000,
  })
  const chats = chatsData || []

  const { data: messagesData, refetch: refetchMessages } = useQuery({
    queryKey: ['junior-messages', activeChat],
    queryFn: () => activeChat ? jApi.messages(activeChat).then(r => r.data.messages || []) : Promise.resolve([]),
    enabled: !!activeChat,
  })
  const messages = messagesData || []

  const { data: statusData } = useQuery({
    queryKey: ['junior-status'],
    queryFn: () => jApi.status().then(r => r.data),
    refetchInterval: 30000,
  })

  const { data: updData } = useQuery({
    queryKey: ['junior-updates'],
    queryFn: () => jApi.updates('pending').then(r => r.data),
    refetchInterval: 10000,
  })
  const updCount = updData?.total || 0

  const { data: taskData } = useQuery({
    queryKey: ['junior-task-status', activeTask],
    queryFn: () => activeTask ? jApi.taskStatus(activeTask).then(r => r.data) : Promise.resolve(null),
    enabled: !!activeTask,
    refetchInterval: d => d?.status === 'running' ? 2000 : false,
  })

  // Scroll al fondo
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior:'smooth' })
  }, [messages])

  // Mutations
  const sendMut = useMutation({
    mutationFn: ({ sid, msg }) => jApi.send(sid, msg),
    onSuccess: () => {
      refetchMessages()
      qc.invalidateQueries(['junior-chats'])
    },
  })

  const newChatMut = useMutation({
    mutationFn: (title) => jApi.newChat(title),
    onSuccess: (data) => {
      setActiveChat(data.data.session_id)
      qc.invalidateQueries(['junior-chats'])
    },
  })

  const deleteChatMut = useMutation({
    mutationFn: (sid) => jApi.deleteChat(sid),
    onSuccess: (_, sid) => {
      if (activeChat === sid) setActiveChat(null)
      qc.invalidateQueries(['junior-chats'])
    },
  })

  const runMut = useMutation({
    mutationFn: ({ obj, steps }) => jApi.runObjective(obj, steps),
    onSuccess: (data) => setActiveTask(data.data.task_id),
  })

  const startMut = useMutation({ mutationFn: jApi.start })
  const stopMut  = useMutation({ mutationFn: jApi.stop })

  const handleSend = useCallback(async () => {
    if (!input.trim() || sendMut.isPending) return
    const msg = input.trim()
    setInput('')

    let sid = activeChat
    if (!sid) {
      const result = await newChatMut.mutateAsync(msg.slice(0, 60))
      sid = result.data.session_id
      setActiveChat(sid)
    }
    sendMut.mutate({ sid, msg })
    inputRef.current?.focus()
  }, [input, activeChat, sendMut, newChatMut])

  const handleExample = (ex) => {
    setInput(ex)
    inputRef.current?.focus()
  }

  return (
    <div style={{ display:'flex', height:'100%', overflow:'hidden', position:'relative' }}>
      {/* Sidebar */}
      <JuniorSidebar
        chats={chats}
        activeChat={activeChat}
        onSelect={setActiveChat}
        onCreate={() => newChatMut.mutate('Nueva conversación')}
        onDelete={(sid) => deleteChatMut.mutate(sid)}
        sidebarOpen={sidebarOpen}
        setSidebarOpen={setSidebarOpen}
        updCount={updCount}
        onShowUpdates={() => setShowUpdates(true)}
      />

      {/* Main */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', minWidth:0 }}>
        {/* Header */}
        <div style={{ padding:'12px 20px', borderBottom:'1px solid var(--border)',
          display:'flex', alignItems:'center', gap:12, flexShrink:0 }}>
          {!sidebarOpen && (
            <button onClick={() => setSidebarOpen(true)}
              style={{ background:'none', border:'none',
                color:'var(--text-dim)', cursor:'pointer', fontSize:18 }}>☰</button>
          )}
          <div style={{ width:36, height:36, borderRadius:8,
            background:'linear-gradient(135deg,#003d20,#001a40)',
            border:'1px solid var(--green)', display:'flex',
            alignItems:'center', justifyContent:'center', fontSize:20 }}>🤖</div>
          <div>
            <div style={{ fontSize:15, fontWeight:700, color:'var(--text-bright)' }}>Junior</div>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
              display:'flex', alignItems:'center', gap:6 }}>
              <Dot color={statusData?.running ? 'var(--green)' : 'var(--red)'} size={6} />
              {statusData?.running ? 'DAEMON ACTIVO · 24/7' : 'DAEMON INACTIVO'}
              {statusData?.pending_updates > 0 && (
                <span style={{ color:'var(--yellow)' }}>· {statusData.pending_updates} actualizaciones</span>
              )}
            </div>
          </div>
          <div style={{ marginLeft:'auto', display:'flex', gap:8 }}>
            {/* Tabs */}
            {['chat','run'].map(t => (
              <button key={t} onClick={() => setTab(t)}
                style={{ padding:'5px 14px', borderRadius:6,
                  border:`1px solid ${tab===t?'var(--green)':'var(--border)'}`,
                  background: tab===t ? '#00ff9d08' : 'transparent',
                  color: tab===t ? 'var(--green)' : 'var(--text-dim)',
                  cursor:'pointer', fontFamily:'var(--mono)', fontSize:11 }}>
                {t === 'chat' ? '💬 CHAT' : '🚀 EJECUTAR'}
              </button>
            ))}
            {/* Daemon control */}
            {statusData?.running ? (
              <button onClick={() => stopMut.mutate()}
                style={{ padding:'5px 12px', borderRadius:6,
                  border:'1px solid var(--red)', background:'#ff386008',
                  color:'var(--red)', cursor:'pointer',
                  fontFamily:'var(--mono)', fontSize:11 }}>
                ■ DETENER
              </button>
            ) : (
              <button onClick={() => startMut.mutate()}
                style={{ padding:'5px 12px', borderRadius:6,
                  border:'1px solid var(--green)', background:'#00ff9d08',
                  color:'var(--green)', cursor:'pointer',
                  fontFamily:'var(--mono)', fontSize:11 }}>
                ▶ INICIAR DAEMON
              </button>
            )}
          </div>
        </div>

        {/* TAB: CHAT */}
        {tab === 'chat' && (
          <>
            <div style={{ flex:1, overflowY:'auto', padding:'20px 24px',
              display:'flex', flexDirection:'column', gap:12 }}>
              {!activeChat ? (
                /* Pantalla de bienvenida */
                <div style={{ flex:1, display:'flex', flexDirection:'column',
                  alignItems:'center', justifyContent:'center', textAlign:'center', padding:'40px 20px' }}>
                  <div style={{ width:72, height:72, borderRadius:16, marginBottom:20,
                    background:'linear-gradient(135deg,#003d20,#001a40)',
                    border:'2px solid var(--green)', display:'flex',
                    alignItems:'center', justifyContent:'center', fontSize:36 }}>🤖</div>
                  <div style={{ fontFamily:'var(--display)', fontSize:24,
                    color:'var(--text-bright)', marginBottom:8, letterSpacing:1 }}>
                    Hola, soy Junior
                  </div>
                  <div style={{ fontFamily:'var(--ui)', fontSize:14,
                    color:'var(--text-dim)', marginBottom:32, maxWidth:400, lineHeight:1.6 }}>
                    Tu agente autónomo de NEXUS PRO. Puedo ayudarte con desarrollo,
                    ciberseguridad, DevOps y análisis del sistema.
                  </div>
                  <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr',
                    gap:8, maxWidth:520, width:'100%' }}>
                    {EXAMPLES.map((ex, i) => (
                      <button key={i} onClick={() => handleExample(ex)}
                        style={{ padding:'10px 14px', borderRadius:8, cursor:'pointer',
                          background:'var(--bg-card)', border:'1px solid var(--border)',
                          color:'var(--text-dim)', fontFamily:'var(--ui)', fontSize:12,
                          textAlign:'left', lineHeight:1.4, transition:'all .15s' }}
                        onMouseEnter={e => { e.target.style.borderColor='var(--green)'; e.target.style.color='var(--text)' }}
                        onMouseLeave={e => { e.target.style.borderColor='var(--border)'; e.target.style.color='var(--text-dim)' }}>
                        {ex}
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                <>
                  {messages.map((m, i) => <Message key={i} msg={m} />)}
                  {sendMut.isPending && (
                    <div style={{ display:'flex', gap:12, alignItems:'flex-start' }}>
                      <div style={{ width:32, height:32, borderRadius:8,
                        background:'linear-gradient(135deg,#003d20,#001a40)',
                        border:'1px solid var(--green)', display:'flex',
                        alignItems:'center', justifyContent:'center', fontSize:16 }}>🤖</div>
                      <div style={{ padding:'10px 14px', borderRadius:12,
                        background:'var(--bg-card)', border:'1px solid var(--border)',
                        fontFamily:'var(--mono)', fontSize:12, color:'var(--green)' }}>
                        Pensando...
                      </div>
                    </div>
                  )}
                  <div ref={messagesEndRef} />
                </>
              )}
            </div>

            {/* Input */}
            <div style={{ padding:'16px 24px', borderTop:'1px solid var(--border)',
              display:'flex', gap:10, alignItems:'flex-end' }}>
              <textarea
                ref={inputRef}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend() } }}
                placeholder="Escríbele algo a Junior... (Enter para enviar, Shift+Enter para nueva línea)"
                rows={input.split('\n').length > 1 ? Math.min(input.split('\n').length, 4) : 1}
                style={{ flex:1, background:'var(--bg-card)',
                  border:'1px solid var(--border)', borderRadius:10,
                  padding:'10px 14px', color:'var(--text)',
                  fontFamily:'var(--ui)', fontSize:13, outline:'none',
                  resize:'none', lineHeight:1.6, transition:'border-color .2s' }}
                onFocus={e => e.target.style.borderColor = 'var(--green)'}
                onBlur={e => e.target.style.borderColor = 'var(--border)'}
              />
              <button onClick={handleSend}
                disabled={!input.trim() || sendMut.isPending}
                style={{ padding:'10px 18px', borderRadius:10,
                  background: input.trim() ? 'var(--green)' : 'var(--bg-card)',
                  border:`1px solid ${input.trim() ? 'var(--green)' : 'var(--border)'}`,
                  color: input.trim() ? 'var(--bg-base)' : 'var(--text-dim)',
                  cursor: input.trim() ? 'pointer' : 'default',
                  fontFamily:'var(--mono)', fontSize:12, fontWeight:700,
                  transition:'all .2s' }}>
                {sendMut.isPending ? '⟳' : '▶'}
              </button>
            </div>
          </>
        )}

        {/* TAB: RUN */}
        {tab === 'run' && (
          <div style={{ flex:1, overflowY:'auto', padding:'24px' }}>
            <div style={{ maxWidth:640, margin:'0 auto' }}>
              <div style={{ background:'var(--bg-card)', border:'1px solid var(--border)',
                borderRadius:12, padding:20, marginBottom:16 }}>
                <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
                  letterSpacing:2, textTransform:'uppercase', marginBottom:12 }}>
                  Objetivo Autónomo — Junior ejecuta N pasos solo
                </div>
                <textarea value={runObj} onChange={e => setRunObj(e.target.value)}
                  placeholder="Ej: Analiza todo el proyecto NEXUS PRO, identifica archivos innecesarios y genera reporte con recomendaciones..."
                  rows={4}
                  style={{ width:'100%', background:'var(--bg-base)',
                    border:'1px solid var(--border)', borderRadius:8,
                    padding:'10px 14px', color:'var(--text)',
                    fontFamily:'var(--ui)', fontSize:13, outline:'none',
                    resize:'vertical', lineHeight:1.6 }}
                />
                <div style={{ display:'flex', alignItems:'center', gap:12, marginTop:12 }}>
                  <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                    <span style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)' }}>PASOS:</span>
                    <select value={runSteps} onChange={e => setRunSteps(parseInt(e.target.value))}
                      style={{ background:'var(--bg-base)', border:'1px solid var(--border)',
                        borderRadius:4, padding:'4px 8px', color:'var(--text)',
                        fontFamily:'var(--mono)', fontSize:11 }}>
                      {[3,4,5,6,7,8].map(n => <option key={n}>{n}</option>)}
                    </select>
                  </div>
                  <button onClick={() => runMut.mutate({ obj: runObj, steps: runSteps })}
                    disabled={!runObj.trim() || runMut.isPending}
                    style={{ flex:1, padding:'10px', borderRadius:8,
                      background: runObj.trim() ? '#00ff9d15' : 'var(--bg-base)',
                      border:`1px solid ${runObj.trim() ? 'var(--green)' : 'var(--border)'}`,
                      color: runObj.trim() ? 'var(--green)' : 'var(--text-dim)',
                      cursor: runObj.trim() ? 'pointer' : 'default',
                      fontFamily:'var(--mono)', fontSize:12, fontWeight:700 }}>
                    {runMut.isPending ? '⟳ INICIANDO...' : '🚀 EJECUTAR JUNIOR'}
                  </button>
                </div>
              </div>

              {/* Estado de tarea activa */}
              {activeTask && taskData && (
                <div style={{ background:'var(--bg-card)',
                  border:`1px solid ${taskData.status==='completed'?'var(--green)':taskData.status==='failed'?'var(--red)':'var(--yellow)'}`,
                  borderRadius:12, padding:16, marginBottom:16 }}>
                  <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:10 }}>
                    <Dot color={taskData.status==='completed'?'var(--green)':taskData.status==='running'?'var(--yellow)':'var(--red)'} />
                    <span style={{ fontFamily:'var(--mono)', fontSize:11 }}>{activeTask}</span>
                    <span style={{ marginLeft:'auto', fontFamily:'var(--mono)', fontSize:11,
                      color:taskData.status==='completed'?'var(--green)':'var(--yellow)' }}>
                      {taskData.status?.toUpperCase()} · {taskData.progress}%
                    </span>
                  </div>
                  <div style={{ height:4, background:'var(--border)', borderRadius:2, overflow:'hidden' }}>
                    <div style={{ height:'100%', width:`${taskData.progress||0}%`,
                      background:'var(--green)', transition:'width .5s' }} />
                  </div>
                </div>
              )}

              {/* Ejemplos */}
              <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)',
                letterSpacing:1, textTransform:'uppercase', marginBottom:8 }}>
                Ejemplos rápidos
              </div>
              {EXAMPLES.map((ex, i) => (
                <div key={i} onClick={() => setRunObj(ex)}
                  style={{ padding:'10px 14px', marginBottom:6,
                    background:'var(--bg-card)', border:'1px solid var(--border)',
                    borderRadius:8, cursor:'pointer', fontFamily:'var(--mono)',
                    fontSize:11, color:'var(--text-dim)', transition:'all .15s' }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor='var(--green)'; e.currentTarget.style.color='var(--text)' }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor='var(--border)'; e.currentTarget.style.color='var(--text-dim)' }}>
                  → {ex}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Panel de actualizaciones */}
      {showUpdates && <UpdatesPanel onClose={() => setShowUpdates(false)} />}
    </div>
  )
}
EOF
log "Junior.jsx — Interfaz tipo Claude"

# ══════════════════════════════════════════════════════════════
head "4/5 · Instalar psutil + build"
# ══════════════════════════════════════════════════════════════
source "$NEXUS/venv/bin/activate"
pip install --quiet psutil 2>/dev/null && log "psutil instalado" || echo "psutil ya instalado"

cd "$NEXUS/nexus_frontend"
npm run build --silent 2>&1 | tail -2

# ══════════════════════════════════════════════════════════════
head "5/5 · Arrancar daemon de Junior"
# ══════════════════════════════════════════════════════════════
# Matar instancia anterior si existe
pkill -f "junior_jarvis.py" 2>/dev/null || true
sleep 1

# Arrancar nuevo daemon
cd "$NEXUS"
source venv/bin/activate
nohup python3 junior_jarvis.py > data/logs/junior_daemon.log 2>&1 &
DAEMON_PID=$!
sleep 3

if kill -0 $DAEMON_PID 2>/dev/null; then
    log "Junior daemon corriendo — PID: $DAEMON_PID"
else
    echo "⚠ Daemon terminó — ver: tail -20 data/logs/junior_daemon.log"
fi

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO — Junior JARVIS Mode ✓                 ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Nuevas funcionalidades:"
echo -e "  ${CYAN}Interfaz tipo Claude${NC}   → sidebar colapsable + historial de chats"
echo -e "  ${CYAN}Nueva conversación${NC}     → botón en sidebar"
echo -e "  ${CYAN}Actualizaciones${NC}        → Junior propone → tú autorizas → agentes ejecutan"
echo -e "  ${CYAN}Daemon 24/7${NC}            → monitor CPU/RAM/Disco/API/Puertos"
echo -e "  ${CYAN}Historial persistente${NC}  → chats guardados en SQLite"
echo ""
echo -e "  API nuevos endpoints:"
echo -e "  ${CYAN}GET  /jarvis/chats${NC}              ← listar conversaciones"
echo -e "  ${CYAN}POST /jarvis/chats${NC}              ← nueva conversación"
echo -e "  ${CYAN}GET  /jarvis/chats/:id/messages${NC} ← mensajes"
echo -e "  ${CYAN}POST /jarvis/chats/:id/messages${NC} ← enviar mensaje"
echo -e "  ${CYAN}GET  /jarvis/updates${NC}            ← propuestas pendientes"
echo -e "  ${CYAN}POST /jarvis/updates/:id/approve${NC}← aprobar propuesta"
echo -e "  ${CYAN}POST /jarvis/start${NC}              ← iniciar daemon"
echo -e "  ${CYAN}GET  /jarvis/status${NC}             ← estado de Junior"
echo ""
echo -e "  Verificar daemon:"
echo -e "  ${CYAN}tail -f data/logs/junior.log${NC}"
echo -e "  ${CYAN}curl -s http://localhost:8000/jarvis/status | python3 -m json.tool${NC}"
echo ""
echo -e "  Dashboard: ${CYAN}http://192.168.220.134:5173${NC} → Junior Agent"
echo ""
