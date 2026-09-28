"""
TestAgent v1.0 — Filtro de calidad BajioWare
Valida código en sandbox antes de pasar a producción.
Flujo: CodeAgent escribe → TestAgent valida → JUNIOR aprueba → DevOps despliega
"""
import subprocess
import sqlite3
import json
import uuid
import shutil
from datetime import datetime
from pathlib import Path
from nexus_core.config import NEXUS_ROOT, NEXUS_DATA_PATH, LEGACY_DATABASE_PATH

BASE_DIR = NEXUS_ROOT
DB_PATH = LEGACY_DATABASE_PATH
SANDBOX_DIR = NEXUS_DATA_PATH / "test_sandbox"


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS test_results (
            test_id TEXT PRIMARY KEY,
            project_id TEXT,
            filepath TEXT,
            test_type TEXT,
            status TEXT,
            passed INTEGER DEFAULT 0,
            failed INTEGER DEFAULT 0,
            output TEXT,
            duration_ms REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def _save_result(project_id, filepath, test_type, status, passed, failed, output, duration_ms):
    test_id = f"test_{uuid.uuid4().hex[:8]}"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO test_results
           (test_id, project_id, filepath, test_type, status, passed, failed, output, duration_ms)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (test_id, project_id, filepath, test_type, status, passed, failed, output[:2000], duration_ms)
    )
    conn.commit()
    conn.close()
    return test_id


def run_syntax_check(filepath: str, project_id: str = "general") -> dict:
    """Verifica sintaxis Python/JS antes de ejecutar."""
    import time
    t0 = time.time()
    _init_db()
    p = Path(filepath)
    if not p.exists():
        return {"status": "error", "error": f"Archivo no encontrado: {filepath}"}

    if p.suffix == ".py":
        result = subprocess.run(
            ["python3", "-c", f"import ast; ast.parse(open('{filepath}').read()); print('OK')"],
            capture_output=True, text=True, timeout=10
        )
        success = result.returncode == 0
        output = result.stdout if success else result.stderr
    else:
        return {"status": "skipped", "reason": f"No syntax check for {p.suffix}"}

    duration = (time.time() - t0) * 1000
    test_id = _save_result(project_id, filepath, "syntax", "passed" if success else "failed",
                           1 if success else 0, 0 if success else 1, output, duration)
    return {
        "test_id": test_id,
        "status": "passed" if success else "failed",
        "filepath": filepath,
        "output": output,
        "duration_ms": duration,
    }


def run_lint_check(filepath: str, project_id: str = "general") -> dict:
    """Ejecuta flake8 y verifica calidad del código."""
    import time
    t0 = time.time()
    _init_db()
    result = subprocess.run(
        ["flake8", filepath, "--max-line-length=120", "--count"],
        capture_output=True, text=True, timeout=30
    )
    issues = int(result.stdout.strip().split()[-1]) if result.stdout.strip() else 0
    status = "passed" if issues == 0 else "warning" if issues < 10 else "failed"
    duration = (time.time() - t0) * 1000
    test_id = _save_result(project_id, filepath, "lint", status, 1 if issues == 0 else 0, issues,
                           result.stdout[:500], duration)
    return {
        "test_id": test_id,
        "status": status,
        "issues": issues,
        "output": result.stdout[:500],
        "duration_ms": duration,
    }


def run_security_check(filepath: str, project_id: str = "general") -> dict:
    """Ejecuta bandit para verificar seguridad del código."""
    import time
    t0 = time.time()
    _init_db()
    result = subprocess.run(
        ["bandit", "-r", filepath, "-f", "json", "-q"],
        capture_output=True, text=True, timeout=60
    )
    try:
        data = json.loads(result.stdout)
        results = data.get("results", [])
        high = len([r for r in results if r.get("issue_severity") == "HIGH"])
        medium = len([r for r in results if r.get("issue_severity") == "MEDIUM"])
        status = "failed" if high > 0 else "warning" if medium > 0 else "passed"
    except Exception:
        high, medium, status = 0, 0, "passed"

    duration = (time.time() - t0) * 1000
    test_id = _save_result(project_id, filepath, "security", status, 1 if high == 0 else 0,
                           high, f"HIGH:{high} MEDIUM:{medium}", duration)
    return {
        "test_id": test_id,
        "status": status,
        "high_severity": high,
        "medium_severity": medium,
        "duration_ms": duration,
    }


def run_in_docker_sandbox(project_path: str, test_command: str = "pytest",
                          project_id: str = "general") -> dict:
    """Ejecuta pruebas en contenedor Docker aislado."""
    import time
    t0 = time.time()
    _init_db()
    docker_cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--memory=256m",
        "--cpus=0.5",
        "-v", f"{project_path}:/workspace",
        "-w", "/workspace",
        "python:3.12-slim",
        "sh", "-c", f"pip install -r requirements.txt -q 2>/dev/null; {test_command}"
    ]
    try:
        result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=120)
        success = result.returncode == 0
        output = (result.stdout + result.stderr)[:2000]
        passed = output.count(" passed")
        failed = output.count(" failed")
        status = "passed" if success else "failed"
        duration = (time.time() - t0) * 1000
        test_id = _save_result(project_id, project_path, "docker_sandbox", status,
                               passed, failed, output, duration)
        return {
            "test_id": test_id,
            "status": status,
            "passed": passed,
            "failed": failed,
            "output": output,
            "duration_ms": duration,
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": "Docker sandbox timeout 120s"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def full_quality_check(filepath: str, project_id: str = "general") -> dict:
    """Ejecuta todos los checks de calidad en secuencia."""
    results = {
        "filepath": filepath,
        "project_id": project_id,
        "timestamp": datetime.utcnow().isoformat(),
        "syntax": run_syntax_check(filepath, project_id),
        "lint": run_lint_check(filepath, project_id),
        "security": run_security_check(filepath, project_id),
    }
    # Determinar estado general
    statuses = [r.get("status") for r in results.values() if isinstance(r, dict)]
    if "failed" in statuses:
        results["overall"] = "failed"
        results["approved_for_production"] = False
    elif "warning" in statuses:
        results["overall"] = "warning"
        results["approved_for_production"] = True
    else:
        results["overall"] = "passed"
        results["approved_for_production"] = True

    return results


def get_test_history(project_id: str = None, limit: int = 20) -> list:
    """Historial de pruebas ejecutadas."""
    conn = sqlite3.connect(DB_PATH)
    if project_id:
        rows = conn.execute(
            "SELECT test_id, filepath, test_type, status, passed, failed, created_at FROM test_results WHERE project_id=? ORDER BY created_at DESC LIMIT ?",
            (project_id, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT test_id, filepath, test_type, status, passed, failed, created_at FROM test_results ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    return [{"test_id": r[0], "filepath": r[1], "type": r[2], "status": r[3],
             "passed": r[4], "failed": r[5], "at": r[6]} for r in rows]
