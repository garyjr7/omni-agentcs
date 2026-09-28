"""
Capacidades Compuestas v1.0 — Alto nivel para Junior
En lugar de 10 curls, Junior hace UNA llamada de intención.
"""
import subprocess
import json
import asyncio
from pathlib import Path
from nexus_core.config import NEXUS_ROOT

BASE_DIR = NEXUS_ROOT


async def explore_filesystem(query: str, base_path: str = None,
                              file_type: str = "*.py") -> dict:
    """Explorar y leer archivos relevantes en UNA operación."""
    base = Path(base_path or BASE_DIR)
    skip = {"venv", "__pycache__", ".git", "node_modules", "data"}
    results = []

    query_lower = query.lower()
    keywords = query_lower.split()

    for f in base.rglob(file_type):
        if any(s in str(f) for s in skip):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            score = sum(1 for kw in keywords if kw in content.lower() or kw in str(f).lower())
            if score > 0:
                results.append({
                    "path": str(f).replace(str(BASE_DIR) + "/", ""),
                    "score": score,
                    "preview": content[:500],
                    "lines": len(content.splitlines()),
                })
        except Exception:
            pass

    results.sort(key=lambda x: x["score"], reverse=True)
    return {
        "query": query,
        "files_found": len(results),
        "results": results[:10],
    }


async def analyze_project(project_path: str) -> dict:
    """Análisis completo de un proyecto en UNA operación."""
    p = Path(project_path)
    if not p.exists():
        return {"error": f"Proyecto no encontrado: {project_path}"}

    result = {
        "project_path": project_path,
        "structure": {},
        "python_files": [],
        "has_tests": False,
        "has_requirements": False,
        "has_dockerfile": False,
        "security_issues": 0,
        "total_lines": 0,
    }

    # Estructura de directorios
    for item in p.iterdir():
        if item.is_dir():
            result["structure"][item.name] = list(item.glob("*.*"))[:5]
        else:
            result["structure"][item.name] = None

    # Archivos Python
    py_files = list(p.rglob("*.py"))
    result["python_files"] = [str(f).replace(str(p) + "/", "") for f in py_files[:20]]
    result["total_lines"] = sum(
        len(f.read_text(errors="replace").splitlines()) for f in py_files
    )

    # Checks rápidos
    result["has_tests"] = any("test" in str(f).lower() for f in py_files)
    result["has_requirements"] = (p / "requirements.txt").exists()
    result["has_dockerfile"] = (p / "Dockerfile").exists()

    # Scan rápido de secretos
    import re
    secret_patterns = [
        "password",
        "secret_key",
        "api_key",
    ]
    for f in py_files:
        try:
            content = f.read_text(errors="replace")
            for pat in secret_patterns:
                if pat.lower() in content.lower():
                    result["security_issues"] += 1
        except Exception:
            pass

    return result


async def smart_patch(filepath: str, description: str,
                      old_text: str, new_text: str,
                      auto_test: bool = True) -> dict:
    """Patch quirúrgico con verificación automática en UNA operación."""
    p = Path(filepath)
    if not p.exists():
        return {"success": False, "error": f"Archivo no encontrado: {filepath}"}

    # Backup
    backup = Path(str(filepath) + ".bak")
    backup.write_text(p.read_text())

    # Aplicar patch
    content = p.read_text()
    if old_text not in content:
        return {"success": False, "error": "Texto a reemplazar no encontrado", "filepath": filepath}

    new_content = content.replace(old_text, new_text, 1)
    p.write_text(new_content)

    # Verificar sintaxis si es Python
    if filepath.endswith(".py"):
        try:
            import ast as _ast
            _ast.parse(new_content)
        except SyntaxError as e:
            # Revertir
            p.write_text(content)
            return {"success": False, "error": f"SyntaxError: {e} — revertido"}

    # Verificar que el nuevo texto está presente
    verified = p.read_text()
    if new_text not in verified:
        p.write_text(content)
        return {"success": False, "error": "Verificación falló — revertido"}

    result = {
        "success": True,
        "filepath": filepath,
        "description": description,
        "backup": str(backup),
        "verified": True,
    }

    # Auto-test si se pide
    if auto_test and filepath.endswith(".py"):
        try:
            proc = subprocess.run(
                ["bandit", "-r", filepath, "-f", "json", "-q"],
                capture_output=True, text=True, timeout=30
            )
            import json as _json
            data = _json.loads(proc.stdout or "{}")
            high = len([r for r in data.get("results", []) if r.get("issue_severity") == "HIGH"])
            result["security_check"] = {"high_issues": high, "passed": high == 0}
        except Exception:
            result["security_check"] = {"skipped": True}

    return result


async def system_health_check() -> dict:
    """Check completo del sistema en UNA operación."""
    import httpx
    result = {"timestamp": __import__("datetime").datetime.utcnow().isoformat()}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            health = (await client.get("http://127.0.0.1:8000/health")).json()
            result["api"] = health

            memory = (await client.get("http://127.0.0.1:8000/junior/memory/stats")).json()
            result["memory"] = memory

            guardian = (await client.get("http://127.0.0.1:8000/guardian/incidents")).json()
            result["security_incidents"] = guardian.get("total", 0)

            plans = (await client.get("http://127.0.0.1:8000/plans/pending")).json()
            result["pending_plans"] = plans.get("total", 0)

            ks = (await client.get("http://127.0.0.1:8000/killswitch/status")).json()
            result["kill_switch"] = ks.get("kill_switch_active", False)
    except Exception as e:
        result["error"] = str(e)

    # Disk + CPU
    try:
        proc = subprocess.run(
            "df -h / | tail -1 && uptime && free -h | grep Mem",
            shell=True, capture_output=True, text=True
        )
        result["system"] = proc.stdout.strip()
    except Exception:
        pass

    return result
