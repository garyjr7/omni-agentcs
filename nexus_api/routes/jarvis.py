"""
NEXUS PRO — Junior API (ex-JARVIS)
Notificaciones + Actualizaciones + Chat + Status + Control
"""
from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
import sqlite3, json, os
from pathlib import Path
from datetime import datetime
from nexus_api.auth.deps import get_current_user
from nexus_api.config import NEXUS_ROOT, NEXUS_DATA_PATH, NEXUS_DB_PATH

router = APIRouter(
    prefix="/jarvis", tags=["Junior"], dependencies=[Depends(get_current_user)]
)

ROOT     = NEXUS_ROOT
DB_PATH  = str(NEXUS_DB_PATH)
LOG_PATH = NEXUS_DATA_PATH / "logs" / "junior.log"


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
async def mark_read(
    nid: int,
    current_user: dict = Depends(get_current_user),
):
    with _db() as conn:
        conn.execute("UPDATE jarvis_notifications SET read=1 WHERE id=?", (nid,))
        conn.commit()
    return {"status": "ok"}

@router.post("/notifications/read-all")
async def mark_all_read(current_user: dict = Depends(get_current_user)):
    with _db() as conn:
        conn.execute("UPDATE jarvis_notifications SET read=1")
        conn.commit()
    return {"status": "ok"}


# ══════════════════════════════════════════════════════════════
# ACTUALIZACIONES / PROPUESTAS DE JUNIOR
# ══════════════════════════════════════════════════════════════
@router.get("/updates")
async def get_updates(status: str = "pending"):
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM junior_updates WHERE status=? ORDER BY id DESC",
            (status,)
        ).fetchall()
    return {"updates": [dict(r) for r in rows], "total": len(rows)}

@router.get("/updates/all")
async def get_all_updates():
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM junior_updates ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return {"updates": [dict(r) for r in rows], "total": len(rows)}

@router.post("/updates/{uid}/approve")
async def approve_update(uid: int, body: ApproveUpdate,
                          background: BackgroundTasks, request: Request,
                          current_user: dict = Depends(get_current_user)):
    """Aprobar una propuesta — Junior ordena a los agentes ejecutarla."""
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM junior_updates WHERE id=?", (uid,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Actualización no encontrada")
        update = dict(row)
        conn.execute(
            "UPDATE junior_updates SET status='approved',approved_by=?,approved_at=? WHERE id=?",
            (str(current_user["id"]), datetime.utcnow().isoformat(), uid)
        )
        conn.commit()

    from nexus_core.evolution import EvolutionLab
    from nexus_core.kernel.store_factory import get_control_store
    tenant_id = str(current_user.get("tenant_id", "system"))
    proposal = EvolutionLab(get_control_store(NEXUS_DB_PATH)).propose(
        tenant_id=tenant_id,
        title=update["title"],
        hypothesis=update.get("description") or "La mejora propuesta optimizará NEXUS de forma medible.",
        evidence={"legacy_update_id": uid, "implementation": update.get("implementation", "")},
        acceptance_criteria={"tests": "must_pass", "security_regressions": 0},
        risk="medium", proposed_by=str(current_user["id"]), baseline_version="current",
    )
    return {"status": "migrated_to_evolution", "proposal": proposal}

@router.post("/updates/{uid}/deny")
async def deny_update(
    uid: int,
    body: DenyUpdate,
    current_user: dict = Depends(get_current_user),
):
    with _db() as conn:
        conn.execute(
            "UPDATE junior_updates SET status='denied' WHERE id=?", (uid,)
        )
        conn.commit()
    return {"status": "denied"}

@router.delete("/updates/{uid}")
async def delete_update(
    uid: int,
    current_user: dict = Depends(get_current_user),
):
    with _db() as conn:
        conn.execute("DELETE FROM junior_updates WHERE id=?", (uid,))
        conn.commit()
    return {"status": "deleted"}

# ══════════════════════════════════════════════════════════════
# CHAT CON HISTORIAL
# ══════════════════════════════════════════════════════════════
@router.get("/chats")
async def list_chats():
    """Lista todas las sesiones de chat."""
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM junior_chats ORDER BY updated_at DESC LIMIT 50"
        ).fetchall()
    return {"chats": [dict(r) for r in rows]}

@router.post("/chats")
async def create_chat(
    body: NewSession,
    current_user: dict = Depends(get_current_user),
):
    """Crear nueva sesión de chat."""
    import uuid
    sid = uuid.uuid4().hex[:12]
    with _db() as conn:
        conn.execute(
            "INSERT INTO junior_chats(session_id,title) VALUES(?,?)",
            (sid, body.title)
        )
        conn.commit()
    return {"session_id": sid, "title": body.title}

@router.get("/chats/{session_id}/messages")
async def get_messages(session_id: str):
    """Obtener mensajes de una sesión."""
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM junior_messages WHERE session_id=? ORDER BY id ASC",
            (session_id,)
        ).fetchall()
    return {"messages": [dict(r) for r in rows]}

@router.post("/chats/{session_id}/messages")
async def send_message(
    session_id: str,
    body: ChatMessage,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Enviar mensaje a Junior y obtener respuesta."""
    # Guardar mensaje del usuario
    with _db() as conn:
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
    with _db() as conn:
        history = conn.execute(
            "SELECT role,content FROM junior_messages WHERE session_id=? ORDER BY id DESC LIMIT 10",
            (session_id,)
        ).fetchall()
    history = list(reversed([dict(h) for h in history]))

    # Llamar al LLM con contexto
    llm = getattr(request.app.state, 'llm', None)
    if not llm:
        raise HTTPException(503, "LLM no disponible")

    # ── Contexto real del sistema ────────────────────────────
    system_context = ""
    try:
        import psutil, sqlite3 as _sq
        excluded = {"venv", ".venv", "__pycache__", "node_modules", ".git"}
        files = []
        for item in NEXUS_ROOT.iterdir():
            if item.name in excluded:
                continue
            files.append(str(item))
            if item.is_dir():
                files.extend(str(child) for child in item.iterdir() if child.name not in excluded)
        cpu   = psutil.cpu_percent(interval=0.5)
        ram   = psutil.virtual_memory()
        disk  = psutil.disk_usage("/")
        conn2 = _sq.connect(NEXUS_DB_PATH)
        conn2.row_factory = _sq.Row
        recent = conn2.execute(
            "SELECT name,status FROM tasks ORDER BY created_at DESC LIMIT 5"
        ).fetchall()
        conn2.close()
        system_context = (
            f"CPU:{cpu}% RAM:{ram.percent}% Disco:{disk.percent}% "
            f"({round(disk.free/1e9,1)}GB libre)\n"
            f"Archivos proyecto ({len(files)}):\n" +
            "\n".join(files[:60]) +
            "\nTareas recientes:\n" +
            "\n".join([f"- {t['name']}: {t['status']}" for t in recent])
        )
    except Exception as _e:
        system_context = f"(contexto no disponible: {_e})"

    JUNIOR_SYSTEM = f"""Eres JUNIOR, el agente autónomo estrella de NEXUS PRO, creado por BAJIOWARE.

Personalidad: directo, técnico, proactivo, siempre propones soluciones concretas.
Tienes acceso completo al sistema NEXUS PRO en {NEXUS_ROOT}.

DATOS REALES DEL SISTEMA (úsalos, nunca inventes):
{{system_context}}

REGLA CRÍTICA: NUNCA inventes archivos, métricas o datos. Si no sabes algo del sistema, dilo.
Si el usuario pide analizar el sistema, usa los datos de arriba.

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
    with _db() as conn:
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
async def delete_chat(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    with _db() as conn:
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
        with _db() as conn:
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
async def start_junior(
    background: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
):
    """El daemon heredado fue reemplazado por el worker durable."""
    raise HTTPException(410, "Junior directo fue retirado; use nexus_worker y Evolution Lab")

@router.post("/stop")
async def stop_junior(current_user: dict = Depends(get_current_user)):
    """El worker se administra fuera del proceso API."""
    raise HTTPException(410, "El worker se detiene desde el supervisor de servicios")

@router.get("/report")
async def get_report():
    report_path = ROOT / "data/logs/junior_report.json"
    if not report_path.exists():
        return {"status": "no_report", "message": "Junior aún no ha generado un reporte"}
    return json.loads(report_path.read_text())
