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
