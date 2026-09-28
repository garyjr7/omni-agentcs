"""
BAJIOWARE NEXUS — FileAgent
Agente especializado en operaciones de archivos del sistema.
Junior lo usa para escribir, leer, editar y borrar archivos reales.
"""
from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
import asyncio
from pathlib import Path
from nexus_core.config import NEXUS_ROOT


class FileAgent(BaseAgent):
    """
    Agente de operaciones de archivos.
    
    Payload esperado:
    - action: "write" | "read" | "append" | "delete" | "chmod" | "mkdir" | "exists"
    - filepath: ruta absoluta o relativa al archivo
    - content: contenido a escribir (para write/append)
    - mode: permisos chmod (ej: "755")
    """
    capability = AgentCapability.FILE_OPERATIONS

    async def execute(self, task_id: str, payload: dict) -> dict:
        from nexus_core.kernel.legacy import require_legacy_execution
        require_legacy_execution()
        action   = payload.get("action", "write")
        filepath = payload.get("filepath", "")
        content  = payload.get("content", "")
        mode     = payload.get("mode", "644")

        if not filepath:
            return {"status": "failed", "error": "filepath requerido", "task_id": task_id}

        try:
            path = Path(filepath) if Path(filepath).is_absolute() else NEXUS_ROOT / filepath

            if action == "write":
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                # PEV — verificación post-escritura
                written = path.read_text(encoding="utf-8")
                if written == content:
                    return {"status": "completed", "task_id": task_id,
                            "result": f"Archivo escrito y verificado: {path} ({len(content)} bytes)"}
                else:
                    return {"status": "failed", "task_id": task_id,
                            "error": f"PEV: contenido no coincide tras escritura en {path}"}

            elif action == "read":
                if not path.exists():
                    return {"status": "failed", "error": f"No existe: {path}", "task_id": task_id}
                text = path.read_text(encoding="utf-8", errors="replace")
                return {"status": "completed", "task_id": task_id,
                        "result": text[:5000], "lines": len(text.splitlines())}

            elif action == "append":
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "a", encoding="utf-8") as f:
                    f.write(content)
                return {"status": "completed", "task_id": task_id,
                        "result": f"Contenido añadido a {path}"}

            elif action == "delete":
                if path.exists():
                    path.unlink()
                    return {"status": "completed", "task_id": task_id,
                            "result": f"Eliminado: {path}"}
                return {"status": "completed", "task_id": task_id,
                        "result": f"No existía: {path}"}

            elif action == "chmod":
                import stat, os
                perm = int(mode, 8)
                os.chmod(path, perm)
                return {"status": "completed", "task_id": task_id,
                        "result": f"Permisos {mode} aplicados a {path}"}

            elif action == "mkdir":
                path.mkdir(parents=True, exist_ok=True)
                return {"status": "completed", "task_id": task_id,
                        "result": f"Directorio creado: {path}"}

            elif action == "exists":
                return {"status": "completed", "task_id": task_id,
                        "exists": path.exists(), "path": str(path)}

            else:
                return {"status": "failed", "error": f"Acción desconocida: {action}", "task_id": task_id}

        except Exception as e:
            return {"status": "failed", "error": str(e), "task_id": task_id}
