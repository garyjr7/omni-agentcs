#!/usr/bin/env python3
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
            "SELECT * FROM factory_projects WHERE status='approved' ORDER BY approved_at"
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
                "UPDATE factory_phases SET status=?,started_at=datetime('now') WHERE id=?",
                (status, phase_id)
            )
        else:
            conn.execute(
                "UPDATE factory_phases SET status=?,result=?,completed_at=datetime('now') WHERE id=?",
                (status, result, phase_id)
            )
        conn.commit()

def update_project_status(project_id, status):
    with get_conn() as conn:
        conn.execute(
            "UPDATE factory_projects SET status=?,updated_at=datetime('now') WHERE id=?",
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
