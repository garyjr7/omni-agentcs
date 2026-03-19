"""
BAJIOWARE NEXUS — BashAgent
Agente especializado en ejecución de comandos bash reales.
Junior lo usa para instalar paquetes, gestionar servicios, correr scripts.
"""
from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
import asyncio
import os
import re
from pathlib import Path

BASE_DIR = Path("/home/operator/BW-AI")

HARD_BLOCKED = [
    r"rm\s+-rf\s+/\s*$",
    r"mkfs\.",
    r"dd\s+if=.*of=/dev/[sh]d",
    r":\(\)\{.*\}",   # fork bomb
]


class BashAgent(BaseAgent):
    """
    Agente de ejecución bash.
    
    Payload esperado:
    - command: comando bash a ejecutar
    - cwd: directorio de trabajo (default: /home/operator/BW-AI)
    - timeout: segundos máximos (default: 60)
    - sudo: bool — usar sudo (default: False)
    """
    capability = AgentCapability.FILE_OPERATIONS

    async def execute(self, task_id: str, payload: dict) -> dict:
        command = payload.get("command", "").strip()
        cwd     = payload.get("cwd", str(BASE_DIR))
        timeout = payload.get("timeout", 60)
        use_sudo = payload.get("sudo", False)

        if not command:
            return {"status": "failed", "error": "command requerido", "task_id": task_id}

        # Bloquear comandos destructivos
        for pattern in HARD_BLOCKED:
            if re.search(pattern, command, re.IGNORECASE):
                return {"status": "failed",
                        "error": f"Comando bloqueado por seguridad: {pattern}",
                        "task_id": task_id}

        if use_sudo:
            command = f"sudo {command}"

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env={**os.environ, "HOME": str(Path.home()), "USER": os.getenv("USER", "operator")},
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out = stdout.decode("utf-8", errors="replace").strip()
            err = stderr.decode("utf-8", errors="replace").strip()
            success = proc.returncode == 0

            return {
                "status": "completed" if success else "failed",
                "task_id": task_id,
                "returncode": proc.returncode,
                "output": out,
                "stderr": err if err else None,
                "command": command[:100],
            }

        except asyncio.TimeoutError:
            return {"status": "failed", "error": f"Timeout {timeout}s", "task_id": task_id}
        except Exception as e:
            return {"status": "failed", "error": str(e), "task_id": task_id}
