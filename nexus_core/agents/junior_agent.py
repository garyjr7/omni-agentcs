"""
NEXUS PRO — Junior Agent v1.0
El agente autónomo estrella de NEXUS.

Junior es diferente a todos los demás agentes:
- Recibe un OBJETIVO en lenguaje natural
- GPT-4o genera un PLAN de N pasos
- Ejecuta cada paso encadenando resultados
- Cada paso puede usar cualquier tool
- El resultado de un paso alimenta el siguiente
- Genera un reporte final completo

Ejemplos de lo que Junior puede hacer solo:
  "Construye una API REST para una zapatería"
  "Audita la seguridad del proyecto NEXUS"
  "Analiza el código y genera documentación"
  "Crea un pipeline CI/CD seguro"
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
from nexus_core.agents.dynamic_agent import ToolExecutor

logger = logging.getLogger("nexus.junior")

WORKSPACE = Path("/home/operator/NEXUS-PRO/data/junior_workspace")
WORKSPACE.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════
# JUNIOR PLANNER — GPT-4o genera plan de N pasos
# ══════════════════════════════════════════════════════════════
class JuniorPlanner:

    SYSTEM = """Eres el planificador de JUNIOR, el agente autónomo de NEXUS PRO.

Tu trabajo: dado un objetivo, genera un plan de pasos concretos y ejecutables.

Herramientas disponibles:
- bash_exec:    {command, cwd, timeout}
- file_read:    {path}
- file_write:   {path, content}
- file_list:    {path}
- http_request: {url, method, headers, body}
- code_exec:    {code, timeout}
- nmap_scan:    {target, flags}
- sast_scan:    {filepath}
- stride_model: {target, context}
- report_gen:   {title, content}
- llm_call:     {system, prompt}

REGLAS CRÍTICAS:
1. Máximo 8 pasos por plan
2. Cada paso debe ser atómico y verificable
3. Usa {prev_result} en params para referenciar el resultado anterior
4. El último paso SIEMPRE debe ser report_gen con el resumen completo
5. Sé específico con los parámetros — nada genérico

RESPONDE ÚNICAMENTE con JSON válido:
{
  "objective": "descripción del objetivo",
  "estimated_duration": "X minutos",
  "steps": [
    {
      "step": 1,
      "name": "nombre descriptivo",
      "tool": "nombre_tool",
      "params": { ... },
      "description": "qué hace este paso",
      "depends_on_prev": false
    }
  ]
}"""

    @classmethod
    async def create_plan(cls, llm, objective: str, context: dict = None) -> dict:
        """GPT-4o genera el plan completo de ejecución."""
        ctx = ""
        if context:
            ctx = f"\nContexto adicional: {json.dumps(context, ensure_ascii=False)[:500]}"

        user_msg = f"""Objetivo: {objective}{ctx}

Workspace de Junior: /home/operator/NEXUS-PRO/data/junior_workspace/
Proyecto NEXUS en: /home/operator/NEXUS-PRO/

Genera el plan de pasos para completar este objetivo."""

        try:
            response = await llm.ask(cls.SYSTEM, user_msg)
            # Limpiar respuesta
            response = response.strip()
            if "```" in response:
                parts = response.split("```")
                for part in parts:
                    if "{" in part:
                        response = part.replace("json", "").strip()
                        break
            plan = json.loads(response)
            logger.info(f"[Junior Planner] Plan generado: {len(plan.get('steps',[]))} pasos")
            return plan
        except json.JSONDecodeError as e:
            logger.error(f"[Junior Planner] JSON inválido: {e}")
            # Plan de fallback
            return {
                "objective": objective,
                "estimated_duration": "2 minutos",
                "steps": [
                    {
                        "step": 1,
                        "name": "Explorar proyecto",
                        "tool": "file_list",
                        "params": {"path": "/home/operator/NEXUS-PRO"},
                        "description": "Listar estructura del proyecto",
                        "depends_on_prev": False
                    },
                    {
                        "step": 2,
                        "name": "Análisis con LLM",
                        "tool": "llm_call",
                        "params": {
                            "system": "Eres Junior, agente de NEXUS PRO.",
                            "prompt": f"Completa este objetivo: {objective}"
                        },
                        "description": "GPT-4o analiza y responde",
                        "depends_on_prev": False
                    },
                    {
                        "step": 3,
                        "name": "Reporte final",
                        "tool": "report_gen",
                        "params": {
                            "title": f"Junior_{objective[:30].replace(' ','_')}",
                            "content": "Reporte generado por Junior Agent"
                        },
                        "description": "Generar reporte de resultados",
                        "depends_on_prev": False
                    }
                ]
            }
        except Exception as e:
            logger.error(f"[Junior Planner] Error: {e}")
            raise


# ══════════════════════════════════════════════════════════════
# JUNIOR AGENT
# ══════════════════════════════════════════════════════════════
class JuniorAgent(BaseAgent):
    """
    El agente autónomo estrella de NEXUS PRO.

    Recibe un objetivo → planifica → ejecuta N pasos → entrega resultado.
    """

    JUNIOR_SYSTEM = """Eres JUNIOR, el agente autónomo más avanzado de NEXUS PRO.

Características:
- Trabajas de forma completamente autónoma
- Encadenas múltiples herramientas para completar objetivos complejos
- Piensas antes de actuar y verificas tus resultados
- Generas reportes detallados de todo lo que haces
- Eres preciso, eficiente y seguro

Especialidades:
- Desarrollo de software (APIs, scripts, automatización)
- Ciberseguridad (análisis, pentesting, documentación)
- DevOps (CI/CD, Docker, infraestructura)
- Análisis de código y generación de documentación"""

    def __init__(self, llm=None):
        metadata = AgentMetadata(
            name="Junior",
            capabilities=list(AgentCapability),  # todas
            model="gpt-4o",
            timeout_seconds=600,  # 10 min para tareas complejas
            max_concurrent=2,
            tags=["autonomous", "junior", "star_agent"],
        )
        super().__init__(metadata=metadata)
        self._llm = llm
        self._execution_log: List[dict] = []

    def _log_step(self, step: int, name: str, status: str,
                  tool: str = None, result: Any = None, error: str = None):
        """Registra cada paso de la ejecución."""
        entry = {
            "step": step,
            "name": name,
            "status": status,
            "tool": tool,
            "timestamp": datetime.utcnow().isoformat(),
            "result_preview": str(result)[:200] if result else None,
            "error": error,
        }
        self._execution_log.append(entry)
        emoji = "✓" if status == "completed" else "✗" if status == "failed" else "→"
        logger.info(f"[Junior] {emoji} Paso {step}: {name} [{status}]")

    def _inject_context(self, params: dict, prev_result: Any,
                        step_results: dict) -> dict:
        """
        Inyecta resultados previos en los parámetros del paso actual.
        Reemplaza {prev_result} y {step_N} con valores reales.
        """
        params_str = json.dumps(params, ensure_ascii=False)

        # Inyectar resultado previo
        if prev_result and "{prev_result}" in params_str:
            prev_str = str(prev_result)[:500] if prev_result else ""
            params_str = params_str.replace("{prev_result}", prev_str)

        # Inyectar resultados de pasos específicos
        for step_num, result in step_results.items():
            placeholder = f"{{step_{step_num}}}"
            if placeholder in params_str:
                params_str = params_str.replace(
                    placeholder, str(result)[:300]
                )

        try:
            return json.loads(params_str)
        except Exception:
            return params

    async def _enrich_params_with_llm(
        self, llm, step: dict, prev_result: Any,
        step_results: dict, objective: str
    ) -> dict:
        """
        Si el paso depende del anterior y tiene placeholders,
        GPT-4o decide cómo enriquecer los parámetros.
        """
        if not step.get("depends_on_prev") or not prev_result:
            return step.get("params", {})

        params = step.get("params", {})
        params_str = json.dumps(params, ensure_ascii=False)

        if "{prev_result}" not in params_str and not step.get("depends_on_prev"):
            return params

        prompt = f"""Objetivo general: {objective}
Paso actual: {step.get('name')} usando {step.get('tool')}
Resultado del paso anterior: {json.dumps(prev_result, ensure_ascii=False, default=str)[:800]}
Parámetros base del paso: {params_str}

Actualiza los parámetros para usar la información del paso anterior.
Responde SOLO con el JSON de parámetros actualizado."""

        try:
            response = await llm.ask(
                "Eres el motor de parámetros de Junior Agent. Actualiza parámetros JSON.",
                prompt
            )
            response = response.strip()
            if "```" in response:
                for part in response.split("```"):
                    if "{" in part:
                        response = part.replace("json", "").strip()
                        break
            return json.loads(response)
        except Exception:
            return params

    async def execute(self, task_id: str, payload: dict) -> dict:
        """
        Ejecuta el objetivo autónomamente.

        Payload esperado:
        - objective: string con el objetivo en lenguaje natural
        - context: dict opcional con contexto adicional
        - max_steps: int opcional (default: 8)
        """
        objective = payload.get(
            "objective",
            payload.get("prompt",
            payload.get("_task_name", "Analizar el proyecto NEXUS"))
        )
        context = payload.get("context", {})
        max_steps = int(payload.get("max_steps", 8))

        self._execution_log = []
        session_id = f"junior_{uuid.uuid4().hex[:8]}"

        logger.info(f"[Junior] 🚀 Iniciando sesión {session_id}")
        logger.info(f"[Junior] 🎯 Objetivo: {objective}")

        if not self._llm:
            return {
                "status": "error",
                "error": "Junior requiere LLM — configura una API key en Modelos & APIs",
                "objective": objective,
            }

        # ── FASE 1: Planificación ─────────────────────────────
        logger.info(f"[Junior] 🧠 GPT-4o generando plan...")
        try:
            plan = await JuniorPlanner.create_plan(
                self._llm, objective, context
            )
        except Exception as e:
            return {"status": "error", "error": f"Error en planificación: {e}"}

        steps = plan.get("steps", [])[:max_steps]
        logger.info(
            f"[Junior] 📋 Plan: {len(steps)} pasos | "
            f"ETA: {plan.get('estimated_duration','?')}"
        )

        # ── FASE 2: Ejecución paso a paso ─────────────────────
        step_results = {}
        prev_result = None
        failed_steps = []
        final_report = None

        for i, step in enumerate(steps):
            step_num = step.get("step", i + 1)
            step_name = step.get("name", f"Paso {step_num}")
            tool_name = step.get("tool", "llm_call")

            self._log_step(step_num, step_name, "running", tool_name)

            try:
                # Enriquecer params con contexto previo
                params = step.get("params", {})
                if step.get("depends_on_prev") and prev_result:
                    params = await self._enrich_params_with_llm(
                        self._llm, step, prev_result, step_results, objective
                    )
                else:
                    params = self._inject_context(params, prev_result, step_results)

                # Ejecutar la tool
                result = await ToolExecutor.execute_tool(
                    tool_name, params, self._llm
                )

                # Guardar resultado
                step_results[step_num] = result
                prev_result = result

                status = "completed" if result.get("status") != "error" else "failed"
                self._log_step(step_num, step_name, status, tool_name, result)

                if status == "failed":
                    failed_steps.append({
                        "step": step_num,
                        "name": step_name,
                        "error": result.get("error", "Unknown error"),
                    })
                    logger.warning(
                        f"[Junior] ⚠ Paso {step_num} falló: "
                        f"{result.get('error','?')} — continuando..."
                    )

                # Si es report_gen, guardar como reporte final
                if tool_name == "report_gen" and result.get("status") == "ok":
                    final_report = result

            except Exception as e:
                error_msg = f"{type(e).__name__}: {e}"
                self._log_step(step_num, step_name, "failed", tool_name, error=error_msg)
                failed_steps.append({"step": step_num, "name": step_name, "error": error_msg})
                logger.error(f"[Junior] ✗ Paso {step_num} excepción: {error_msg}")
                prev_result = {"status": "error", "error": error_msg}

        # ── FASE 3: Resumen final ─────────────────────────────
        completed = len(steps) - len(failed_steps)
        success_rate = (completed / len(steps) * 100) if steps else 0

        logger.info(
            f"[Junior] ✅ Sesión completada | "
            f"{completed}/{len(steps)} pasos OK | "
            f"{success_rate:.0f}% éxito"
        )

        # Guardar log de sesión
        log_path = WORKSPACE / f"{session_id}_log.json"
        log_path.write_text(
            json.dumps({
                "session_id": session_id,
                "objective": objective,
                "plan": plan,
                "execution_log": self._execution_log,
                "step_results": {
                    k: str(v)[:500] for k, v in step_results.items()
                },
                "timestamp": datetime.utcnow().isoformat(),
            }, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8"
        )

        return {
            "agent": "Junior",
            "session_id": session_id,
            "objective": objective,
            "status": "completed" if not failed_steps else "completed_with_errors",
            "steps_total": len(steps),
            "steps_completed": completed,
            "steps_failed": len(failed_steps),
            "success_rate": round(success_rate, 1),
            "estimated_duration": plan.get("estimated_duration"),
            "execution_log": self._execution_log,
            "failed_steps": failed_steps,
            "final_report": final_report,
            "log_path": str(log_path),
            "last_result": str(prev_result)[:1000] if prev_result else None,
        }
