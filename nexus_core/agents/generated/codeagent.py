"""
BAJIOWARE NEXUS — CodeAgent
Agente especializado en análisis, modificación y validación de código Python.
Junior lo usa para refactorizar, agregar features y validar sintaxis antes de escribir.
"""
from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
import asyncio
import ast
import os
from pathlib import Path

BASE_DIR = Path("/home/operator/BW-AI")


class CodeAgent(BaseAgent):
    """
    Agente de operaciones de código.
    
    Payload esperado:
    - action: "validate" | "analyze" | "patch" | "search" | "generate"
    - filepath: ruta del archivo Python
    - code: código a validar/patchear
    - old_text: texto a reemplazar (para patch)
    - new_text: texto nuevo (para patch)
    - query: búsqueda en código (para search)
    - prompt: instrucción para generate (usa LLM)
    """
    capability = AgentCapability.CODE_GENERATION

    async def execute(self, task_id: str, payload: dict) -> dict:
        action   = payload.get("action", "validate")
        filepath = payload.get("filepath", "")
        code     = payload.get("code", "")

        try:
            if action == "validate":
                # Validar sintaxis Python
                target = code or (Path(filepath).read_text() if filepath else "")
                if not target:
                    return {"status": "failed", "error": "Se requiere code o filepath", "task_id": task_id}
                try:
                    ast.parse(target)
                    return {"status": "completed", "task_id": task_id,
                            "valid": True, "result": "Sintaxis OK"}
                except SyntaxError as e:
                    return {"status": "completed", "task_id": task_id,
                            "valid": False, "error": str(e)}

            elif action == "patch":
                # Reemplazar texto en archivo
                old_text = payload.get("old_text", "")
                new_text = payload.get("new_text", "")
                path = Path(filepath) if Path(filepath).is_absolute() else BASE_DIR / filepath
                if not path.exists():
                    return {"status": "failed", "error": f"No existe: {path}", "task_id": task_id}
                content = path.read_text(encoding="utf-8")
                if old_text not in content:
                    return {"status": "failed", "error": "old_text no encontrado en archivo",
                            "task_id": task_id}
                new_content = content.replace(old_text, new_text, 1)
                # Validar sintaxis si es .py
                if path.suffix == ".py":
                    try:
                        ast.parse(new_content)
                    except SyntaxError as e:
                        return {"status": "failed", "error": f"Sintaxis inválida tras patch: {e}",
                                "task_id": task_id}
                path.write_text(new_content, encoding="utf-8")
                # PEV — verificación post-patch
                verified = path.read_text(encoding="utf-8")
                if new_text in verified and old_text not in verified:
                    return {"status": "completed", "task_id": task_id,
                            "result": f"Patch aplicado y verificado en {path}",
                            "lines_before": len(content.splitlines()),
                            "lines_after": len(new_content.splitlines())}
                else:
                    return {"status": "failed", "task_id": task_id,
                            "error": f"PEV: patch no verificado en {path}"}

            elif action == "search":
                # Buscar en código
                import subprocess
                query   = payload.get("query", "")
                pattern = payload.get("file_pattern", "*.py")
                search_path = payload.get("search_path", str(BASE_DIR))
                if not query:
                    return {"status": "failed", "error": "query requerido", "task_id": task_id}
                proc = await asyncio.create_subprocess_shell(
                    f"grep -rn --include='{pattern}' '{query}' {search_path} 2>/dev/null | head -30",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode("utf-8", errors="replace").strip()
                output = output.replace(str(BASE_DIR) + "/", "")
                return {"status": "completed", "task_id": task_id,
                        "result": output or "(sin resultados)", "query": query}

            elif action == "analyze":
                # Leer archivo y analizarlo con LLM
                path = Path(filepath) if Path(filepath).is_absolute() else BASE_DIR / filepath
                if not path.exists():
                    return {"status": "failed", "error": f"No existe: {path}", "task_id": task_id}
                content = path.read_text(encoding="utf-8", errors="replace")
                prompt  = payload.get("prompt", "Analiza este código e identifica mejoras y bugs:")
                # Usar Gemini via JuniorAgent
                from nexus_core.agents.junior_agent import JuniorAgent
                agent = JuniorAgent()
                result = await agent.run(task_id + "_llm", {
                    "type": "llm_query",
                    "prompt": f"{prompt}\n\nArchivo: {filepath}\n\n```python\n{content[:6000]}\n```"
                })
                return {"status": "completed", "task_id": task_id,
                        "filepath": str(path),
                        "analysis": result.get("result", {}).get("response", ""),
                        "lines_analyzed": len(content.splitlines())}

            elif action == "generate":
                # Generar código nuevo con LLM
                prompt = payload.get("prompt", "")
                if not prompt:
                    return {"status": "failed", "error": "prompt requerido", "task_id": task_id}
                from nexus_core.agents.junior_agent import JuniorAgent
                agent = JuniorAgent()
                result = await agent.run(task_id + "_gen", {
                    "type": "llm_query",
                    "system_prompt": "Eres un experto en Python y FastAPI. Genera SOLO código, sin explicaciones. El código debe ser funcional y estar listo para usar.",
                    "prompt": prompt,
                })
                generated = result.get("result", {}).get("response", "")
                # Si hay filepath, escribir el archivo
                if filepath and generated:
                    path = Path(filepath) if Path(filepath).is_absolute() else BASE_DIR / filepath
                    # Limpiar markdown si viene con ```python
                    import re
                    clean = re.sub(r"```(?:python)?\s*|\s*```", "", generated).strip()
                    # Validar sintaxis
                    try:
                        ast.parse(clean)
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(clean, encoding="utf-8")
                        return {"status": "completed", "task_id": task_id,
                                "result": f"Código generado y guardado en {path}",
                                "lines": len(clean.splitlines())}
                    except SyntaxError as e:
                        return {"status": "failed", "task_id": task_id,
                                "error": f"Código generado tiene errores de sintaxis: {e}",
                                "generated_code": generated[:500]}
                return {"status": "completed", "task_id": task_id,
                        "result": generated}

            else:
                return {"status": "failed", "error": f"Acción desconocida: {action}", "task_id": task_id}

        except Exception as e:
            return {"status": "failed", "error": str(e), "task_id": task_id}
