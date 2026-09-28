"""
NEXUS PRO — DynamicAgent v2.0
Agente genérico con razonamiento LLM real (GPT-4o / Claude).

Flujo de ejecución:
  1. Recibe tarea con payload
  2. Si tiene LLM → GPT-4o razona y decide qué tool usar + cómo
  3. ToolExecutor ejecuta la tool decidida
  4. Resultado real del servidor
"""
import asyncio
import json
import os
import logging
from pathlib import Path
from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
from nexus_core.config import NEXUS_ROOT, REPORTS_DIR
from nexus_core.kernel.legacy import legacy_execution_enabled

logger = logging.getLogger("nexus.dynamic_agent")

# ── Mapeo role → capability ───────────────────────────────────
CAPABILITY_MAP = {
    "security":   AgentCapability.SECURITY_AUDIT,
    "devops":     AgentCapability.FILE_OPERATIONS,
    "data":       AgentCapability.DATA_ANALYSIS,
    "cloud":      AgentCapability.API_CALLS,
    "compliance": AgentCapability.REPORT_GENERATION,
    "red_team":   AgentCapability.SECURITY_AUDIT,
    "general":    AgentCapability.CODE_GENERATION,
    "code":       AgentCapability.CODE_GENERATION,
    "file":       AgentCapability.FILE_OPERATIONS,
    "bash":       AgentCapability.FILE_OPERATIONS,
}


# ══════════════════════════════════════════════════════════════
# TOOL EXECUTOR — ejecuta herramientas reales
# ══════════════════════════════════════════════════════════════
class ToolExecutor:

    @staticmethod
    async def bash_exec(payload: dict) -> dict:
        cmd = payload.get("command", payload.get("cmd", "echo hello"))
        cwd = payload.get("cwd", str(NEXUS_ROOT))
        timeout = int(payload.get("timeout", 60))
        blocked = ["rm -rf /", "mkfs", "dd if=", ":(){", "fork bomb"]
        if any(b in cmd for b in blocked):
            return {"status": "error", "error": "Comando bloqueado por seguridad"}
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, cwd=cwd,
                env={**os.environ}
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out = stdout.decode("utf-8", errors="replace").strip()
            err = stderr.decode("utf-8", errors="replace").strip()
            return {
                "status": "ok" if proc.returncode == 0 else "error",
                "output": out[:3000],
                "stderr": err[:500] if err else None,
                "returncode": proc.returncode,
                "command": cmd,
            }
        except asyncio.TimeoutError:
            return {"status": "error", "error": f"Timeout {timeout}s", "command": cmd}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def file_read(payload: dict) -> dict:
        path = payload.get("path", payload.get("filepath", ""))
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
            return {"status": "ok", "path": path,
                    "content": content[:5000], "lines": content.count("\n") + 1,
                    "size": len(content)}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def file_write(payload: dict) -> dict:
        path = payload.get("path", payload.get("filepath", ""))
        content = payload.get("content", "")
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(content, encoding="utf-8")
            return {"status": "ok", "path": path, "bytes": len(content)}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def file_list(payload: dict) -> dict:
        path = payload.get("path", str(NEXUS_ROOT))
        try:
            items = [
                {"name": f.name, "type": "dir" if f.is_dir() else "file",
                 "size": f.stat().st_size if f.is_file() else 0}
                for f in sorted(Path(path).iterdir())
                if not f.name.startswith(".")
            ]
            return {"status": "ok", "path": path, "items": items[:50], "total": len(items)}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def http_request(payload: dict) -> dict:
        import httpx
        url = payload.get("url", "")
        method = payload.get("method", "GET").upper()
        headers = payload.get("headers", {})
        body = payload.get("body", None)
        timeout = int(payload.get("timeout", 15))
        if not url:
            return {"status": "error", "error": "URL requerida"}
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.request(method, url, headers=headers, json=body)
                return {
                    "status": "ok", "status_code": resp.status_code,
                    "url": url, "body": resp.text[:3000],
                }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def code_exec(payload: dict) -> dict:
        code = payload.get("code", "print('NEXUS OK')")
        timeout = int(payload.get("timeout", 30))
        try:
            proc = await asyncio.create_subprocess_exec(
                "python3", "-c", code,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "status": "ok" if proc.returncode == 0 else "error",
                "output": stdout.decode("utf-8", errors="replace").strip()[:3000],
                "stderr": stderr.decode("utf-8", errors="replace").strip()[:500],
                "returncode": proc.returncode,
            }
        except asyncio.TimeoutError:
            return {"status": "error", "error": f"Timeout {timeout}s"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def nmap_scan(payload: dict) -> dict:
        target = payload.get("target", "localhost")
        flags = payload.get("flags", "-sV --top-ports 20 -T4")
        try:
            proc = await asyncio.create_subprocess_shell(
                f"nmap {flags} {target}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            return {"status": "ok", "target": target,
                    "output": stdout.decode("utf-8", errors="replace")[:4000]}
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Nmap timeout (120s)"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def report_gen(payload: dict) -> dict:
        import datetime
        title = payload.get("title", "Reporte NEXUS PRO")
        content = payload.get("content", "Sin contenido")
        agent_name = payload.get("agent", "NEXUS")
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        output_path = payload.get("output",
            str(REPORTS_DIR / f"{title.replace(' ','_').replace('/','_')}.md"))
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        report = f"""# {title}

**Generado por:** {agent_name}
**Fecha:** {ts}
**Plataforma:** NEXUS PRO v2.0

---

{content}

---
*Reporte generado automáticamente por NEXUS PRO*
"""
        Path(output_path).write_text(report, encoding="utf-8")
        return {"status": "ok", "path": output_path,
                "title": title, "size": len(report), "lines": report.count("\n")}

    @staticmethod
    async def llm_call(payload: dict, llm=None) -> dict:
        if not llm:
            return {"status": "error",
                    "error": "LLM no disponible — agrega una API key en Modelos & APIs"}
        system = payload.get("system", "Eres un asistente experto de NEXUS PRO.")
        user = payload.get("prompt", payload.get("user", ""))
        if not user:
            return {"status": "error", "error": "prompt requerido"}
        try:
            response = await llm.ask(system, user)
            return {"status": "ok", "response": response,
                    "tokens_approx": len(response.split())}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def git_ops(payload: dict) -> dict:
        git_cmd = payload.get("git_cmd", "status")
        cwd = payload.get("cwd", str(NEXUS_ROOT))
        return await ToolExecutor.bash_exec({"command": f"git {git_cmd}", "cwd": cwd})

    @staticmethod
    async def docker_ops(payload: dict) -> dict:
        docker_cmd = payload.get("docker_cmd", "ps")
        return await ToolExecutor.bash_exec({"command": f"docker {docker_cmd}"})

    @staticmethod
    async def sast_scan(payload: dict) -> dict:
        filepath = payload.get("filepath", payload.get("path", ""))
        if not filepath:
            return {"status": "error", "error": "filepath requerido"}
        result = await ToolExecutor.bash_exec({
            "command": f"python3 -m py_compile '{filepath}' && echo 'SYNTAX_OK' || echo 'SYNTAX_ERROR'"
        })
        # También buscar patrones peligrosos
        try:
            content = Path(filepath).read_text(errors="replace")
            issues = []
            patterns = [
                ("eval(", "Uso de eval() — riesgo de code injection"),
                ("exec(", "Uso de exec() — riesgo de code injection"),
                ("password =", "Posible contraseña hardcodeada"),
                ("secret =", "Posible secreto hardcodeado"),
                ("api_key =", "Posible API key hardcodeada"),
                ("subprocess.call(shell=True", "shell=True en subprocess — riesgo"),
            ]
            for pattern, msg in patterns:
                if pattern.lower() in content.lower():
                    issues.append(msg)
            result["security_issues"] = issues
            result["issues_count"] = len(issues)
        except Exception:
            pass
        return result

    @staticmethod
    async def stride_model(payload: dict) -> dict:
        target = payload.get("target", "sistema")
        context = payload.get("context", "")
        report = f"""# STRIDE Threat Model — {target}

## Spoofing (Suplantación de identidad)
- Verificar autenticación de {target}
- Implementar MFA donde sea posible

## Tampering (Manipulación de datos)
- Validar integridad de inputs/outputs
- Usar firmas digitales en datos críticos

## Repudiation (Repudio)
- Audit trail completo e inmutable
- Logs con timestamps firmados

## Information Disclosure (Divulgación)
- Cifrado en tránsito (TLS 1.3)
- Cifrado en reposo (AES-256)

## Denial of Service (Denegación de servicio)
- Rate limiting en APIs
- Circuit breakers

## Elevation of Privilege (Escalada de privilegios)
- Principio de mínimo privilegio
- RBAC estricto (Zero Trust)

**Contexto adicional:** {context or 'N/A'}
"""
        return await ToolExecutor.report_gen({
            "title": f"STRIDE_{target}",
            "content": report,
            "agent": "ThreatModeler"
        })

    @classmethod
    async def execute_tool(cls, tool_name: str, payload: dict, llm=None) -> dict:
        """Dispatcher central de herramientas."""
        if not legacy_execution_enabled():
            return {
                "status": "error",
                "error": "Legacy ToolExecutor is disabled; use the policy-enforced ToolGateway",
                "tool": tool_name,
            }
        tool_map = {
            "bash_exec":    lambda p: cls.bash_exec(p),
            "file_read":    lambda p: cls.file_read(p),
            "file_write":   lambda p: cls.file_write(p),
            "file_delete":  lambda p: cls.bash_exec({"command": f"rm '{p.get('path','')}'"}) if p.get("path") else {"status":"error","error":"path requerido"},
            "file_list":    lambda p: cls.file_list(p),
            "http_request": lambda p: cls.http_request(p),
            "code_exec":    lambda p: cls.code_exec(p),
            "nmap_scan":    lambda p: cls.nmap_scan(p),
            "report_gen":   lambda p: cls.report_gen(p),
            "llm_call":     lambda p: cls.llm_call(p, llm),
            "git_ops":      lambda p: cls.git_ops(p),
            "docker_ops":   lambda p: cls.docker_ops(p),
            "sast_scan":    lambda p: cls.sast_scan(p),
            "stride_model": lambda p: cls.stride_model(p),
            "api_test":     lambda p: cls.http_request(p),
            "web_search":   lambda p: {"status":"ok","note":"Requiere integración SerpAPI/Tavily"},
            "sql_query":    lambda p: {"status":"ok","note":"Requiere conexión DB configurada"},
            "memory_search":lambda p: {"status":"ok","note":"ChromaDB query pendiente"},
            "memory_write": lambda p: {"status":"ok","note":"ChromaDB write pendiente"},
            "nuclei_scan":  lambda p: cls.bash_exec({"command":f"nuclei -u {p.get('target','localhost')} -severity medium,high,critical"}) if p.get("target") else {"status":"error","error":"target requerido"},
        }
        executor = tool_map.get(tool_name)
        if not executor:
            return {"status": "error", "error": f"Tool '{tool_name}' no encontrada en el catálogo"}
        try:
            return await executor(payload)
        except Exception as e:
            return {"status": "error", "error": str(e), "tool": tool_name}


# ══════════════════════════════════════════════════════════════
# LLM REASONING ENGINE — GPT-4o planifica antes de ejecutar
# ══════════════════════════════════════════════════════════════
class LLMReasoningEngine:
    """
    Usa GPT-4o para razonar sobre la tarea y decidir:
    1. Qué tool usar
    2. Qué parámetros exactos pasar
    3. Cómo interpretar el resultado
    """

    PLANNER_SYSTEM = """Eres el motor de razonamiento de NEXUS PRO, un orquestador de agentes IA de grado militar.

Tu trabajo: analizar una tarea y decidir EXACTAMENTE qué herramienta usar y con qué parámetros.

Herramientas disponibles:
- bash_exec: ejecutar comandos shell. params: {command, cwd, timeout}
- file_read: leer archivo. params: {path}
- file_write: escribir archivo. params: {path, content}
- file_list: listar directorio. params: {path}
- http_request: petición HTTP. params: {url, method, headers, body}
- code_exec: ejecutar Python. params: {code, timeout}
- nmap_scan: escaneo de puertos. params: {target, flags}
- sast_scan: análisis seguridad código. params: {filepath}
- stride_model: modelado amenazas. params: {target, context}
- report_gen: generar reporte. params: {title, content}
- llm_call: consulta LLM adicional. params: {system, prompt}
- git_ops: operaciones git. params: {git_cmd, cwd}
- docker_ops: operaciones docker. params: {docker_cmd}

RESPONDE ÚNICAMENTE con JSON válido, sin markdown, sin explicaciones:
{
  "tool": "nombre_tool",
  "params": { ... },
  "reasoning": "una línea explicando por qué"
}"""

    INTERPRETER_SYSTEM = """Eres el intérprete de resultados de NEXUS PRO.
Recibes el output raw de una herramienta y debes:
1. Resumir qué encontraste
2. Destacar hallazgos importantes
3. Dar recomendaciones si aplica

Sé conciso, técnico y preciso. Máximo 200 palabras."""

    @classmethod
    async def plan(cls, llm, task_name: str, task_desc: str,
                   payload: dict, agent_tools: list, system_prompt: str) -> dict:
        """GPT-4o decide qué tool usar y con qué params."""
        user_msg = f"""Tarea: {task_name}
Descripción: {task_desc}
Payload proporcionado: {json.dumps(payload, ensure_ascii=False)}
Herramientas disponibles para este agente: {', '.join(agent_tools) if agent_tools else 'todas'}
System prompt del agente: {system_prompt[:200] if system_prompt else 'N/A'}

Decide la mejor herramienta y parámetros para completar esta tarea."""

        try:
            response = await llm.ask(cls.PLANNER_SYSTEM, user_msg)
            # Limpiar respuesta
            response = response.strip()
            if response.startswith("```"):
                response = response.split("```")[1]
                if response.startswith("json"):
                    response = response[4:]
            plan = json.loads(response.strip())
            return plan
        except json.JSONDecodeError as e:
            logger.warning(f"[LLM Planner] JSON inválido: {e} | response: {response[:200]}")
            return None
        except Exception as e:
            logger.warning(f"[LLM Planner] Error: {e}")
            return None

    @classmethod
    async def interpret(cls, llm, tool: str, result: dict,
                        task_name: str) -> str:
        """GPT-4o interpreta el resultado de la tool."""
        user_msg = f"""Tarea: {task_name}
Herramienta ejecutada: {tool}
Resultado: {json.dumps(result, ensure_ascii=False)[:2000]}

Interpreta este resultado."""
        try:
            return await llm.ask(cls.INTERPRETER_SYSTEM, user_msg)
        except Exception as e:
            return f"Interpretación no disponible: {e}"


# ══════════════════════════════════════════════════════════════
# DYNAMIC AGENT v2.0
# ══════════════════════════════════════════════════════════════
class DynamicAgent(BaseAgent):
    """
    Agente genérico instanciado desde DB con razonamiento LLM real.

    Flujo:
      1. Recibe tarea
      2. Si tiene LLM → GPT-4o planifica (tool + params)
      3. Ejecuta la tool planificada
      4. GPT-4o interpreta el resultado
      5. Retorna resultado estructurado
    """

    def __init__(self, agent_config: dict, llm=None):
        role = agent_config.get("role", "general")
        # Todas las capabilities para que el Orchestrator siempre encuentre este agente
        all_caps = list(AgentCapability)

        metadata = AgentMetadata(
            name=agent_config["name"],
            capabilities=all_caps,
            model=agent_config.get("model", "gpt-4o"),
            timeout_seconds=300,
            max_concurrent=3,
            tags=[role, "dynamic", agent_config.get("provider", "openai")],
        )
        super().__init__(metadata=metadata)
        self._config = agent_config
        self._llm = llm
        self._tools = agent_config.get("tools", [])
        self._system_prompt = agent_config.get("system_prompt", "")
        self._role = role

    async def execute(self, task_id: str, payload: dict) -> dict:
        """
        Ejecuta la tarea con razonamiento LLM + interceptor HITL.
        Si la acción requiere aprobación, pausa y espera al humano.
        """
        task_name = payload.get("_task_name", f"task_{task_id[:8]}")
        task_desc = payload.get("_task_desc", "")

        # Limpiar metadatos del payload antes de pasar a tools
        clean_payload = {k: v for k, v in payload.items()
                        if not k.startswith("_")}

        # ── Modo 1: Tool especificada directamente ────────────
        tool_name = clean_payload.get("tool") or clean_payload.get("type")

        # Inferir tool del payload si no está especificada
        if not tool_name:
            if "command" in clean_payload or "cmd" in clean_payload:
                tool_name = "bash_exec"
            elif "url" in clean_payload:
                tool_name = "http_request"
            elif "code" in clean_payload:
                tool_name = "code_exec"
            elif "filepath" in clean_payload or ("path" in clean_payload and clean_payload.get("path")):
                tool_name = "file_read"

        # ── Modo 2: LLM planifica si no hay tool explícita ───
        llm_plan = None
        if not tool_name and self._llm:
            logger.info(f"[{self.name}] 🧠 GPT-4o planificando tarea: {task_name}")
            llm_plan = await LLMReasoningEngine.plan(
                llm=self._llm,
                task_name=task_name,
                task_desc=task_desc,
                payload=clean_payload,
                agent_tools=self._tools,
                system_prompt=self._system_prompt,
            )
            if llm_plan:
                tool_name = llm_plan.get("tool", "bash_exec")
                # Merge params del LLM con el payload original
                llm_params = llm_plan.get("params", {})
                clean_payload = {**clean_payload, **llm_params}
                logger.info(f"[{self.name}] 🧠 Plan: {tool_name} | {llm_plan.get('reasoning','')}")

        # Fallback final
        if not tool_name:
            if self._tools:
                tool_name = self._tools[0]
            else:
                tool_name = "bash_exec"
                clean_payload["command"] = (
                    f"echo 'NEXUS Agent {self.name} ejecutado' && "
                    f"date && echo 'Role: {self._role}'"
                )

        logger.info(f"[{self.name}] ⚡ Ejecutando: {tool_name} | task: {task_id}")

        # ── HITL Check — ¿requiere aprobación humana? ─────────
        hitl_mode = self._config.get("hitl_mode", "destructive")
        if hitl_mode != "never":
            try:
                from nexus_core.hitl.manager import get_hitl_manager, HITLManager
                hitl = get_hitl_manager()
                risk = HITLManager.evaluate_risk(tool_name, clean_payload, hitl_mode)
                if risk is not None:
                    context = (
                        f"Agente {self.name} ({self._role}) quiere ejecutar '{tool_name}'.\n"
                        f"Tarea: {task_name}\n"
                        f"Params: {str(clean_payload)[:300]}"
                    )
                    logger.warning(
                        f"[{self.name}] ⏸ HITL requerido [{risk}] para {tool_name}"
                    )
                    status = await hitl.request(
                        agent_name=self.name,
                        agent_id=self.metadata.agent_id,
                        action=f"{task_name} → {tool_name}",
                        tool=tool_name,
                        params=clean_payload,
                        risk=risk,
                        context=context,
                        timeout=300,
                    )
                    from nexus_core.hitl.manager import HITLStatus
                    if status != HITLStatus.APPROVED:
                        return {
                            "agent": self.name,
                            "tool_used": tool_name,
                            "task_id": task_id,
                            "status": "hitl_denied",
                            "hitl_status": str(status),
                            "message": f"Acción bloqueada por HITL: {status}",
                        }
            except Exception as hitl_err:
                logger.warning(f"[{self.name}] HITL error (continuando): {hitl_err}")

        # ── Ejecutar la tool ──────────────────────────────────
        tool_result = await ToolExecutor.execute_tool(
            tool_name, clean_payload, self._llm
        )

        # ── Interpretar resultado con LLM ─────────────────────
        interpretation = None
        if self._llm and tool_result.get("status") == "ok":
            try:
                interpretation = await LLMReasoningEngine.interpret(
                    llm=self._llm,
                    tool=tool_name,
                    result=tool_result,
                    task_name=task_name,
                )
            except Exception as e:
                logger.warning(f"[{self.name}] Interpretación fallida: {e}")

        return {
            "agent": self.name,
            "role": self._role,
            "model": self._config.get("model", "gpt-4o"),
            "tool_used": tool_name,
            "task_id": task_id,
            "llm_reasoning": llm_plan.get("reasoning") if llm_plan else None,
            "llm_interpretation": interpretation,
            **tool_result,
        }
