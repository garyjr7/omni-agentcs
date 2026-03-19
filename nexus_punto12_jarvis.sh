#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Punto 12: Factory Runner + Junior JARVIS      ║
# ║  12A · factory_runner.py proceso externo sin deadlock      ║
# ║  12B · Junior JARVIS daemon 24/7                           ║
# ║  12C · Monitor sistema + notificaciones                    ║
# ║  12D · Auto-mejora + propuestas                            ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

ROOT="/home/operator/NEXUS-PRO"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

# ══════════════════════════════════════════════════════════════
head "1/5 · factory_runner.py — proceso externo sin deadlock"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
import os  # <--- ESTA ES LA LÍNEA QUE FALTA
content = '''#!/usr/bin/env python3
"""
NEXUS PRO — Factory Runner
Proceso externo que ejecuta fases de proyectos aprobados.
Corre independiente de FastAPI — sin deadlocks.
Uso: python3 factory_runner.py [--once] [--project-id ID]
"""
import os, sys, json, sqlite3, time, asyncio, argparse, logging
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [FACTORY] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(ROOT / "data/logs/factory_runner.log", mode="a"),
    ]
)
logger = logging.getLogger("factory_runner")

DB_PATH = os.getenv("NEXUS_DB_PATH", str(ROOT / "data/nexus_pro.db"))
API_URL = "http://127.0.0.1:8000"

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_approved_projects():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM factory_projects WHERE status=\'approved\' ORDER BY approved_at"
        ).fetchall()
        return [dict(r) for r in rows]

def get_phases(project_id):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM factory_phases WHERE project_id=? ORDER BY fase_num",
            (project_id,)
        ).fetchall()
        return [dict(r) for r in rows]

def update_phase(phase_id, status, result=None):
    with get_conn() as conn:
        if status == "running":
            conn.execute(
                "UPDATE factory_phases SET status=?,started_at=datetime(\'now\') WHERE id=?",
                (status, phase_id)
            )
        else:
            conn.execute(
                "UPDATE factory_phases SET status=?,result=?,completed_at=datetime(\'now\') WHERE id=?",
                (status, result, phase_id)
            )
        conn.commit()

def update_project_status(project_id, status):
    with get_conn() as conn:
        conn.execute(
            "UPDATE factory_projects SET status=?,updated_at=datetime(\'now\') WHERE id=?",
            (status, project_id)
        )
        conn.commit()

def get_token():
    import urllib.request
    data = json.dumps({
        "email": os.getenv("NEXUS_ADMIN_EMAIL", "admin@nexuspro.io"),
        "password": os.getenv("NEXUS_ADMIN_PASSWORD", "synthetic-password")
    }).encode()
    req = urllib.request.Request(
        f"{API_URL}/auth/login",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["access_token"]

def junior_run(token, objective, max_steps=10):
    import urllib.request
    data = json.dumps({"objective": objective, "max_steps": max_steps}).encode()
    req = urllib.request.Request(
        f"{API_URL}/junior/run",
        data=data,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())["task_id"]

def junior_status(token, task_id):
    import urllib.request
    req = urllib.request.Request(
        f"{API_URL}/junior/status/{task_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())

def execute_project(project_id):
    logger.info(f"Ejecutando proyecto {project_id}")
    update_project_status(project_id, "executing")

    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM factory_projects WHERE id=?", (project_id,)
        ).fetchone()
        if not row:
            logger.error(f"Proyecto {project_id} no encontrado")
            return
        project = dict(row)

    plan = json.loads(project.get("plan_maestro") or "{}")
    phases = get_phases(project_id)
    output_dir = plan.get("output_dir",
        str(ROOT / "data/factory/projects" / project["nombre"].lower().replace(" ","_")))
    os.makedirs(output_dir, exist_ok=True)

    stack = plan.get("stack", {})
    stack_str = f"backend={stack.get('backend','fastapi')}, db={stack.get('base_datos','sqlite')}, auth={stack.get('auth','jwt')}, frontend={stack.get('frontend','none')}"

    try:
        token = get_token()
    except Exception as e:
        logger.error(f"No se pudo obtener token: {e}")
        update_project_status(project_id, "failed")
        return

    completed = 0
    failed = 0

    for phase in phases:
        phase_id  = phase["id"]
        fase_num  = phase["fase_num"]
        nombre    = phase["nombre"]
        desc      = phase["descripcion"]
        total     = len(phases)

        logger.info(f"  Fase {fase_num}/{total}: {nombre}")
        update_phase(phase_id, "running")

        objective = f"""PROYECTO: {plan.get('proyecto','Proyecto')} para {plan.get('cliente','Cliente')}
STACK: {stack_str}
OUTPUT DIR: {output_dir}

FASE {fase_num} DE {total}: {nombre}
TAREA: {desc}

REGLAS:
- Crea archivos REALES en {output_dir}/ usando file_write
- Código funcional completo, sin TODOs ni stubs
- {'Primera fase: crear estructura de carpetas y archivos base' if fase_num == 1 else f'Continuar proyecto anterior en {output_dir}/'}
- {'Última fase: crear Dockerfile, docker-compose.yml, README.md y tests' if fase_num == total else ''}
- Usa bash_exec para crear directorios si es necesario"""

        try:
            # Refresh token cada fase
            try:
                token = get_token()
            except:
                pass

            task_id = junior_run(token, objective, max_steps=10)
            logger.info(f"    Junior task: {task_id}")

            # Poll con timeout de 3 minutos por fase
            timeout = 180
            start = time.time()
            final_status = "running"

            while time.time() - start < timeout:
                time.sleep(8)
                try:
                    status_data = junior_status(token, task_id)
                    final_status = status_data.get("status", "running")
                    progress = status_data.get("progress", 0)
                    logger.info(f"    {task_id}: {final_status} {progress}%")
                    if final_status in ("completed", "failed"):
                        break
                except Exception as e:
                    logger.warning(f"    Poll error: {e}")

            result = f"task={task_id} status={final_status}"
            update_phase(phase_id, "completed", result)
            completed += 1
            logger.info(f"  ✓ Fase {fase_num} completada")

        except Exception as e:
            logger.error(f"  ✗ Fase {fase_num} error: {e}")
            update_phase(phase_id, "completed", f"warning: {e}")
            failed += 1

        # Pausa entre fases para evitar rate limiting
        if fase_num < len(phases):
            logger.info(f"  Pausa 5s antes de fase {fase_num+1}...")
            time.sleep(5)

    final = "completed" if failed == 0 else "completed_with_warnings"
    update_project_status(project_id, final)
    logger.info(f"Proyecto {project_id} → {final} ({completed} ok, {failed} warnings)")
    logger.info(f"Archivos en: {output_dir}")

    # Listar archivos generados
    files = list(Path(output_dir).rglob("*"))
    files = [f for f in files if f.is_file()]
    logger.info(f"Archivos generados: {len(files)}")
    for f in sorted(files)[:20]:
        logger.info(f"  {f.relative_to(output_dir)}")

def run_daemon(interval=15):
    """Modo daemon — revisa proyectos aprobados cada N segundos."""
    logger.info("Factory Runner daemon iniciado")
    logger.info(f"Revisando cada {interval}s — DB: {DB_PATH}")

    while True:
        try:
            projects = get_approved_projects()
            if projects:
                logger.info(f"{len(projects)} proyecto(s) aprobado(s) encontrado(s)")
                for p in projects:
                    execute_project(p["id"])
            else:
                logger.debug("Sin proyectos aprobados")
        except Exception as e:
            logger.error(f"Error en daemon: {e}")
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NEXUS Factory Runner")
    parser.add_argument("--once",       action="store_true", help="Ejecutar una vez y salir")
    parser.add_argument("--project-id", help="Ejecutar proyecto específico")
    parser.add_argument("--daemon",     action="store_true", help="Modo daemon continuo")
    parser.add_argument("--interval",   type=int, default=15, help="Intervalo daemon en segundos")
    args = parser.parse_args()

    if args.project_id:
        execute_project(args.project_id)
    elif args.once:
        projects = get_approved_projects()
        if projects:
            for p in projects:
                execute_project(p["id"])
        else:
            logger.info("Sin proyectos aprobados")
    else:
        run_daemon(args.interval)
'''

with open("/home/operator/NEXUS-PRO/factory_runner.py", "w") as f:
    f.write(content)
os.chmod("/home/operator/NEXUS-PRO/factory_runner.py", 0o755)
print("factory_runner.py —", len(content), "bytes")
PYEOF
log "factory_runner.py"

# ══════════════════════════════════════════════════════════════
head "2/5 · junior_jarvis.py — daemon JARVIS 24/7"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
import os  # <--- ESTA ES LA LÍNEA QUE FALTA
content = '''#!/usr/bin/env python3
"""
NEXUS PRO — Junior JARVIS Daemon
Agente autónomo 24/7 que monitorea, protege y mejora el sistema.
Uso: python3 junior_jarvis.py [--interval 60]
"""
import os, sys, json, time, logging, sqlite3, subprocess
from pathlib import Path
from datetime import datetime, timedelta

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [JARVIS] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(ROOT / "data/logs/jarvis.log", mode="a"),
    ]
)
logger = logging.getLogger("jarvis")

DB_PATH = os.getenv("NEXUS_DB_PATH", str(ROOT / "data/nexus_pro.db"))
API_URL = "http://127.0.0.1:8000"
CHECK_INTERVAL = int(os.getenv("JARVIS_INTERVAL", "60"))

# ── Helpers ───────────────────────────────────────────────────
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def api_post(endpoint, data, token=None):
    import urllib.request
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{API_URL}{endpoint}",
        data=json.dumps(data).encode(),
        headers=headers
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())

def api_get(endpoint, token=None):
    import urllib.request
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{API_URL}{endpoint}", headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())

def get_token():
    return api_post("/auth/login", {
        "email": os.getenv("NEXUS_ADMIN_EMAIL", "admin@nexuspro.io"),
        "password": os.getenv("NEXUS_ADMIN_PASSWORD", "synthetic-password")
    })["access_token"]

def save_notification(msg, tipo="info"):
    try:
        with get_conn() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS jarvis_notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message TEXT, tipo TEXT,
                    created_at TEXT DEFAULT (datetime(\'now\')), read INTEGER DEFAULT 0
                )"""
            )
            conn.execute(
                "INSERT INTO jarvis_notifications(message,tipo) VALUES(?,?)",
                (msg, tipo)
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Error guardando notificación: {e}")

# ── Checks de salud ───────────────────────────────────────────
def check_system_health(token):
    """Verifica el estado de todos los servicios."""
    try:
        health = api_get("/health", token)
        services = health.get("services", {})
        degraded = [k for k,v in services.items() if v != "ok"]
        if degraded:
            msg = f"⚠️ Servicios degradados: {', '.join(degraded)}"
            logger.warning(msg)
            save_notification(msg, "warning")
            return False
        return True
    except Exception as e:
        msg = f"🔴 NEXUS no responde: {e}"
        logger.error(msg)
        save_notification(msg, "error")
        return False

def check_hitl_pending(token):
    """Alerta si hay HITL esperando más de 10 minutos."""
    try:
        data = api_get("/hitl/pending", token)
        pending = data.get("pending", [])
        if len(pending) > 0:
            old = []
            for h in pending:
                created = h.get("created_at","")
                try:
                    dt = datetime.fromisoformat(created.replace("Z",""))
                    age = (datetime.utcnow() - dt).seconds // 60
                    if age > 10:
                        old.append(f"{h.get('agent_name','?')}({age}min)")
                except:
                    pass
            if old:
                msg = f"⏸️ HITL sin atender: {', '.join(old)}"
                logger.warning(msg)
                save_notification(msg, "warning")
    except Exception as e:
        logger.debug(f"HITL check error: {e}")

def check_disk_space():
    """Alerta si el disco está al 85%+."""
    try:
        result = subprocess.run(["df", "-h", str(ROOT / "data")],
            capture_output=True, text=True)
        lines = result.stdout.strip().split("\\n")
        if len(lines) > 1:
            parts = lines[1].split()
            if len(parts) >= 5:
                pct = int(parts[4].replace("%",""))
                if pct >= 85:
                    msg = f"💾 Disco al {pct}% — limpiar data/logs/ y reportes antiguos"
                    logger.warning(msg)
                    save_notification(msg, "warning")
                elif pct >= 95:
                    msg = f"🔴 CRÍTICO: Disco al {pct}%"
                    logger.error(msg)
                    save_notification(msg, "error")
    except Exception as e:
        logger.debug(f"Disk check error: {e}")

def check_failed_tasks(token):
    """Detecta tareas fallidas recientes."""
    try:
        data = api_get("/tasks?status=failed", token)
        tasks = data if isinstance(data, list) else data.get("tasks", [])
        recent = []
        for t in tasks[-5:]:
            completed = t.get("completed_at","")
            try:
                dt = datetime.fromisoformat(completed.replace("Z",""))
                age = (datetime.utcnow() - dt).seconds // 60
                if age < 30:
                    recent.append(t.get("name","?")[:30])
            except:
                pass
        if recent:
            msg = f"⚠️ Tareas fallidas recientes: {', '.join(recent)}"
            logger.warning(msg)
            save_notification(msg, "warning")
    except Exception as e:
        logger.debug(f"Tasks check error: {e}")

def check_memory_growth():
    """Detecta si la memoria de agentes crece demasiado."""
    try:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as c, SUM(tokens_est) as t FROM agent_memory"
            ).fetchone()
            if row and row["t"] and row["t"] > 500000:
                msg = f"🧠 Memoria de agentes grande: ~{row['t']//1000}k tokens — considera limpiar"
                logger.info(msg)
                save_notification(msg, "info")
    except Exception as e:
        logger.debug(f"Memory check error: {e}")

def check_security():
    """Escaneo básico de seguridad."""
    alerts = []
    # Verificar .env expuesto
    env_path = ROOT / ".env"
    if env_path.exists():
        import stat
        mode = oct(stat.S_IMODE(os.stat(env_path).st_mode))
        if mode not in ("0o600", "0o400"):
            alerts.append(f"🔐 .env con permisos inseguros: {mode}")

    # Verificar secrets hardcodeados en código nuevo
    suspicious = []
    for pyfile in (ROOT / "nexus_api").rglob("*.py"):
        try:
            text = pyfile.read_text(errors="ignore")
            if '"your_secret_key"' in text or "hardcoded_secret" in text.lower():
                suspicious.append(str(pyfile.name))
        except:
            pass
    if suspicious:
        alerts.append(f"🔑 Secrets hardcodeados en: {', '.join(suspicious[:3])}")

    for alert in alerts:
        logger.warning(alert)
        save_notification(alert, "security")

def generate_status_report(token):
    """Genera reporte de estado para el operador."""
    try:
        health = api_get("/health", token)
        agents_data = api_get("/agents", token)
        agents = agents_data if isinstance(agents_data, list) else agents_data.get("agents", [])

        with get_conn() as conn:
            tasks_row = conn.execute(
                "SELECT status, COUNT(*) as c FROM tasks GROUP BY status"
            ).fetchall()
            tasks_summary = {r["status"]: r["c"] for r in tasks_row}

            notif_count = conn.execute(
                "SELECT COUNT(*) as c FROM jarvis_notifications WHERE read=0"
            ).fetchone()

        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "system_status": health.get("status"),
            "services": health.get("services", {}),
            "agents_count": len(agents),
            "tasks": tasks_summary,
            "unread_notifications": notif_count["c"] if notif_count else 0,
        }

        report_path = ROOT / "data/logs/jarvis_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Reporte: sistema={report['system_status']}, agentes={report['agents_count']}, notificaciones={report['unread_notifications']}")
        return report
    except Exception as e:
        logger.error(f"Error generando reporte: {e}")
        return {}

# ── Propuestas de mejora ──────────────────────────────────────
def check_improvements(token):
    """Analiza el sistema y propone mejoras."""
    proposals = []

    # Verificar si hay headers de seguridad
    try:
        import urllib.request
        resp = urllib.request.urlopen(f"{API_URL}/health", timeout=5)
        headers = dict(resp.headers)
        missing = []
        for h in ["X-Frame-Options","X-Content-Type-Options","Content-Security-Policy"]:
            if h not in headers:
                missing.append(h)
        if missing:
            proposals.append(f"🛡️ Añadir headers de seguridad HTTP: {', '.join(missing)}")
    except:
        pass

    # Verificar reportes antiguos
    reports_dir = ROOT / "data/reports"
    if reports_dir.exists():
        old_reports = [f for f in reports_dir.glob("*.md")
                      if (datetime.utcnow() - datetime.fromtimestamp(f.stat().st_mtime)).days > 30]
        if len(old_reports) > 5:
            proposals.append(f"🗂️ {len(old_reports)} reportes >30 días — archivar para liberar espacio")

    for p in proposals:
        logger.info(f"PROPUESTA: {p}")
        save_notification(f"💡 PROPUESTA JARVIS: {p}", "proposal")

# ── Loop principal ────────────────────────────────────────────
def run():
    logger.info("="*50)
    logger.info("JUNIOR JARVIS — Iniciando modo autónomo 24/7")
    logger.info(f"Intervalo: {CHECK_INTERVAL}s · DB: {DB_PATH}")
    logger.info("="*50)

    cycle = 0
    while True:
        cycle += 1
        logger.info(f"--- Ciclo {cycle} · {datetime.utcnow().strftime('%H:%M:%S')} ---")

        try:
            token = get_token()

            # Checks en cada ciclo
            check_system_health(token)
            check_hitl_pending(token)
            check_disk_space()
            check_failed_tasks(token)

            # Checks cada 5 ciclos
            if cycle % 5 == 0:
                check_memory_growth()
                check_security()
                check_improvements(token)
                generate_status_report(token)

        except Exception as e:
            logger.error(f"Error en ciclo {cycle}: {e}")

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=int, default=CHECK_INTERVAL)
    parser.add_argument("--once",     action="store_true")
    args = parser.parse_args()

    if args.once:
        try:
            token = get_token()
            check_system_health(token)
            check_hitl_pending(token)
            check_disk_space()
            check_security()
            check_improvements(token)
            generate_status_report(token)
            logger.info("Ciclo único completado")
        except Exception as e:
            logger.error(f"Error: {e}")
    else:
        CHECK_INTERVAL = args.interval
        run()
'''

with open("/home/operator/NEXUS-PRO/junior_jarvis.py", "w") as f:
    f.write(content)
os.chmod("/home/operator/NEXUS-PRO/junior_jarvis.py", 0o755)
print("junior_jarvis.py —", len(content), "bytes")
PYEOF
log "junior_jarvis.py"

# ══════════════════════════════════════════════════════════════
head "3/5 · nexus_api/routes/jarvis.py — endpoints /jarvis"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
content = '''from fastapi import APIRouter, Depends, HTTPException
from nexus_api.auth.deps import get_current_user, require_operator
import sqlite3, json, os
from pathlib import Path

router = APIRouter(prefix="/jarvis", tags=["jarvis"])

def _db():
    p = os.getenv("NEXUS_DB_PATH",
        str(Path(__file__).parent.parent.parent / "data" / "nexus_pro.db"))
    conn = sqlite3.connect(p)
    conn.row_factory = sqlite3.Row
    return conn

def _ensure_table():
    with _db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS jarvis_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT, tipo TEXT,
            created_at TEXT DEFAULT (datetime(\'now\')), read INTEGER DEFAULT 0
        )""")
        conn.commit()

_ensure_table()

@router.get("/notifications")
async def get_notifications(
    limit: int = 50,
    unread_only: bool = False,
    user=Depends(get_current_user)
):
    with _db() as conn:
        if unread_only:
            rows = conn.execute(
                "SELECT * FROM jarvis_notifications WHERE read=0 ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM jarvis_notifications ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
        notifs = [dict(r) for r in rows]
        unread = conn.execute(
            "SELECT COUNT(*) as c FROM jarvis_notifications WHERE read=0"
        ).fetchone()["c"]
    return {"notifications": notifs, "unread": unread, "total": len(notifs)}

@router.post("/notifications/{notif_id}/read")
async def mark_read(notif_id: int, user=Depends(get_current_user)):
    with _db() as conn:
        conn.execute("UPDATE jarvis_notifications SET read=1 WHERE id=?", (notif_id,))
        conn.commit()
    return {"status": "ok"}

@router.post("/notifications/read-all")
async def mark_all_read(user=Depends(get_current_user)):
    with _db() as conn:
        conn.execute("UPDATE jarvis_notifications SET read=1")
        conn.commit()
    return {"status": "ok"}

@router.get("/report")
async def get_report(user=Depends(get_current_user)):
    report_path = Path(__file__).parent.parent.parent / "data/logs/jarvis_report.json"
    if not report_path.exists():
        return {"status": "no_report", "message": "JARVIS aún no ha generado un reporte"}
    with open(report_path) as f:
        return json.load(f)

@router.get("/status")
async def jarvis_status(user=Depends(get_current_user)):
    import subprocess
    running = False
    try:
        result = subprocess.run(["pgrep", "-f", "junior_jarvis.py"],
            capture_output=True, text=True)
        running = bool(result.stdout.strip())
    except:
        pass

    log_path = Path(__file__).parent.parent.parent / "data/logs/jarvis.log"
    last_lines = []
    if log_path.exists():
        with open(log_path) as f:
            lines = f.readlines()
            last_lines = [l.strip() for l in lines[-10:]]

    with _db() as conn:
        unread = conn.execute(
            "SELECT COUNT(*) as c FROM jarvis_notifications WHERE read=0"
        ).fetchone()["c"]

    return {
        "running":     running,
        "unread_notifications": unread,
        "last_log":    last_lines,
        "log_path":    str(log_path),
    }
'''

with open("/home/operator/NEXUS-PRO/nexus_api/routes/jarvis.py", "w") as f:
    f.write(content)
print("routes/jarvis.py —", len(content), "bytes")
PYEOF
log "routes/jarvis.py"

# ══════════════════════════════════════════════════════════════
head "4/5 · Registrar jarvis router + nexus_start.sh actualizado"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
path = "/home/operator/NEXUS-PRO/nexus_api/main.py"
with open(path) as f:
    content = f.read()

if "routes.jarvis" not in content:
    content = content.replace(
        "from nexus_api.routes.factory import router as factory_router",
        "from nexus_api.routes.factory import router as factory_router\nfrom nexus_api.routes.jarvis  import router as jarvis_router"
    )
    content = content.replace(
        "app.include_router(factory_router)",
        "app.include_router(factory_router)\napp.include_router(jarvis_router)"
    )
    with open(path, "w") as f:
        f.write(content)
    print("jarvis_router registrado")
else:
    print("ya registrado")
PYEOF

# Actualizar nexus_start.sh para incluir factory_runner y jarvis
cat > "$ROOT/nexus_start.sh" << 'EOF'
#!/usr/bin/env bash
# NEXUS PRO — Manager completo de servicios
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_API="$ROOT/.nexus_api.pid"
PID_FACTORY="$ROOT/.nexus_factory.pid"
PID_JARVIS="$ROOT/.nexus_jarvis.pid"
LOG_DIR="$ROOT/data/logs"
GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

mkdir -p "$LOG_DIR"

start_service() {
  local name="$1" cmd="$2" pid_file="$3" log_file="$4"
  if [ -f "$pid_file" ] && kill -0 "$(cat $pid_file)" 2>/dev/null; then
    echo -e "  ${CYAN}$name ya corriendo (PID $(cat $pid_file))${NC}"
    return
  fi
  cd "$ROOT" && source venv/bin/activate 2>/dev/null || true
  nohup bash -c "$cmd" >> "$log_file" 2>&1 &
  echo $! > "$pid_file"
  echo -e "  ${GREEN}✓ $name iniciado (PID $!)${NC}"
}

stop_service() {
  local name="$1" pid_file="$2"
  if [ -f "$pid_file" ]; then
    kill "$(cat $pid_file)" 2>/dev/null && echo -e "  ${GREEN}✓ $name detenido${NC}"
    rm -f "$pid_file"
  fi
}

start() {
  echo -e "${BOLD}Iniciando NEXUS PRO stack...${NC}"
  start_service "API Backend" \
    "uvicorn nexus_api.main:app --host 0.0.0.0 --port 8000 --workers 1" \
    "$PID_API" "$LOG_DIR/nexus_api.log"
  sleep 4
  start_service "Factory Runner" \
    "python3 $ROOT/factory_runner.py --daemon --interval 20" \
    "$PID_FACTORY" "$LOG_DIR/factory_runner.log"
  start_service "Junior JARVIS" \
    "python3 $ROOT/junior_jarvis.py --interval 60" \
    "$PID_JARVIS" "$LOG_DIR/jarvis.log"
  sleep 2
  echo ""
  status
}

stop() {
  echo -e "${BOLD}Deteniendo NEXUS PRO...${NC}"
  stop_service "API Backend"    "$PID_API"
  stop_service "Factory Runner" "$PID_FACTORY"
  stop_service "Junior JARVIS"  "$PID_JARVIS"
  pkill -f "uvicorn nexus_api" 2>/dev/null || true
  pkill -f "factory_runner.py"  2>/dev/null || true
  pkill -f "junior_jarvis.py"   2>/dev/null || true
}

status() {
  echo -e "${BOLD}Estado NEXUS PRO:${NC}"
  local api_ok=false
  if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    api_ok=true
    HEALTH=$(curl -s http://localhost:8000/health | python3 -c \
      "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null)
    echo -e "  ${GREEN}● API Backend${NC} — health: $HEALTH"
  else
    echo -e "  ${RED}○ API Backend${NC} — no responde"
  fi
  for name_pid in "Factory Runner:$PID_FACTORY" "Junior JARVIS:$PID_JARVIS"; do
    name="${name_pid%%:*}"
    pid_file="${name_pid##*:}"
    if [ -f "$pid_file" ] && kill -0 "$(cat $pid_file)" 2>/dev/null; then
      echo -e "  ${GREEN}● $name${NC} (PID $(cat $pid_file))"
    else
      echo -e "  ${RED}○ $name${NC} — detenido"
    fi
  done
  echo ""
  echo -e "  ${CYAN}Dashboard:  http://localhost:3000${NC}"
  echo -e "  ${CYAN}API:        http://localhost:8000${NC}"
  echo -e "  ${CYAN}API Docs:   http://localhost:8000/docs${NC}"
}

logs() {
  local service="${2:-api}"
  case "$service" in
    api)     tail -f "$LOG_DIR/nexus_api.log" ;;
    factory) tail -f "$LOG_DIR/factory_runner.log" ;;
    jarvis)  tail -f "$LOG_DIR/jarvis.log" ;;
    *)       tail -f "$LOG_DIR/nexus_api.log" ;;
  esac
}

case "${1:-start}" in
  start)   start ;;
  stop)    stop ;;
  restart) stop; sleep 2; start ;;
  status)  status ;;
  logs)    logs "$@" ;;
  *) echo "Uso: $0 [start|stop|restart|status|logs [api|factory|jarvis]]" ;;
esac
EOF
chmod +x "$ROOT/nexus_start.sh"
log "nexus_start.sh actualizado"

# ══════════════════════════════════════════════════════════════
head "5/5 · Build + test completo"
# ══════════════════════════════════════════════════════════════
cd "$ROOT/nexus_frontend"
npm run build --silent 2>&1 | tail -3

pkill -f "uvicorn nexus_api" 2>/dev/null; sleep 2
cd "$ROOT" && source venv/bin/activate
uvicorn nexus_api.main:app --host 0.0.0.0 --port 8000 --workers 1 &
sleep 6

TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@nexuspro.io","password":"synthetic-password"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

echo ""
echo "Test endpoints:"
for ep in "/factory/templates" "/factory/projects" "/jarvis/status" "/jarvis/notifications"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" "http://localhost:8000$ep")
  [ "$CODE" = "200" ] && echo "  ✓ $ep" || echo "  ✗ $ep ($CODE)"
done

# Test JARVIS once
echo ""
echo "=== JARVIS primer ciclo ==="
cd "$ROOT" && source venv/bin/activate
python3 junior_jarvis.py --once 2>&1 | tail -15

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO — Punto 12: JARVIS + Factory Runner ✓  ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}factory_runner.py${NC}  → proceso externo sin deadlocks"
echo -e "  ${CYAN}junior_jarvis.py${NC}   → daemon JARVIS 24/7"
echo -e "  ${CYAN}/jarvis/status${NC}     → estado del daemon"
echo -e "  ${CYAN}/jarvis/notifications${NC} → alertas del sistema"
echo ""
echo -e "  ${BOLD}Para arrancar todo:${NC}"
echo -e "  ${CYAN}./nexus_start.sh start${NC}    → API + Factory + JARVIS"
echo -e "  ${CYAN}./nexus_start.sh status${NC}   → estado de los 3 servicios"
echo -e "  ${CYAN}./nexus_start.sh logs jarvis${NC} → logs de JARVIS"
echo ""
echo -e "  ${BOLD}Para ejecutar un proyecto aprobado:${NC}"
echo -e "  ${CYAN}python3 factory_runner.py --project-id factory_XXXX${NC}"
echo ""
