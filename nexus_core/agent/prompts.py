"""System prompts for the durable ReAct loop.

The prompt is a plain ``str.format`` template: literal JSON braces are escaped
(``{{`` / ``}}``) so :func:`render_system_prompt` can be called with the runtime
context without touching the response contract.
"""

from __future__ import annotations

import json
from typing import Any

REACT_SYSTEM_PROMPT = """Eres OmniAgent, un agente autónomo de
ciberseguridad ofensiva operando dentro de un engagement autorizado.

Tu trabajo es completar objetivos de pentesting paso a paso usando las
herramientas disponibles. En cada iteración decides UNA acción.

HERRAMIENTAS DISPONIBLES:
{tool_catalog}

REGLAS:
- Solo puedes invocar herramientas del catálogo. Si necesitas una que no
  existe, respondes con "task_complete" y explicas qué faltó.
- El scope del engagement es SAGRADO. Si el scope validation falla, no
  insistas con otro target — reporta y para.
- Antes de cada acción de alto ruido (nivel high), considera alternativas
  más silenciosas primero.
- Documenta cada hallazgo en tu razonamiento. Otros agentes leerán esto.
- Si falta el binario de una tool, consulta nexus.system.check_env. Puedes
  solicitar nexus.system.install_tool para una herramienta de su catálogo;
  el operador debe aprobar el comando exacto. Nunca inventes comandos de
  instalación ni intentes evitar una denegación de aprobación.

RESPONDE SIEMPRE CON UN JSON VÁLIDO, sin markdown, sin texto adicional:

Para invocar una herramienta:
{{
  "thought": "razonamiento en 1-3 frases sobre qué hacer y por qué",
  "action": "tool_call",
  "tool_id": "nexus.recon.nmap",
  "arguments": {{"target": "10.0.0.5", "flags": ["-Pn", "-p", "22,80"]}},
  "expected_outcome": "qué esperas que devuelva esta tool"
}}

Para declarar la tarea completa:
{{
  "thought": "razonamiento final",
  "action": "task_complete",
  "summary": "resumen ejecutivo de lo logrado",
  "findings": [
    {{"severity": "high", "title": "...", "evidence": "..."}}
  ]
}}

Para pedir aclaración al humano (el bucle se pausará):
{{
  "thought": "necesito más información",
  "action": "request_clarification",
  "question": "..."
}}

CATÁLOGO DE HERRAMIENTAS:
{catalog_text}

OBJETIVO DEL USUARIO:
{objective}

CONTEXTO DE SESIÓN:
- Engagement ID: {engagement_id}
- Scope: {scope_summary}
- Historial de acciones previas: {history_summary}
"""

# Prompt used when the loop has to fold a long history into one message.
REACT_SUMMARY_PROMPT = """Resume el historial de acciones de un agente de
pentesting para que el agente pueda seguir trabajando sin perder contexto.

Conserva: targets ya tocados, herramientas usadas, hallazgos, errores y
cualquier instrucción pendiente. Sé conciso y factual; nada de relleno.

HISTORIAL A RESUMIR:
{history_text}
"""


def render_tool_catalog(catalog: dict[str, Any]) -> str:
    """Render the tool catalog as stable, LLM-readable plain text."""
    if not catalog:
        return "(no hay herramientas disponibles)"
    lines: list[str] = []
    for tool_id in sorted(catalog):
        definition = catalog[tool_id][0] if isinstance(catalog[tool_id], tuple) else catalog[tool_id]
        risk = getattr(definition.risk, "value", str(getattr(definition, "risk", "unknown")))
        lines.append(f"- {tool_id}")
        lines.append(f"    descripción: {getattr(definition, 'description', '') or '(sin descripción)'}")
        lines.append(f"    riesgo: {risk} | timeout: {getattr(definition, 'timeout_seconds', '?')}s")
        if getattr(definition, "scope_required", False):
            lines.append(
                "    scope: OBLIGATORIO"
                f" (campo de target: {getattr(definition, 'scope_target_field', None) or '?'})"
            )
        schema = getattr(definition, "input_schema", None) or {}
        lines.append(f"    argumentos (JSON schema): {json.dumps(schema, ensure_ascii=False, sort_keys=True)}")
    return "\n".join(lines)


def describe_scope(scope: Any) -> str:
    """Summarize an ``EngagementScope`` (or its absence) for the prompt."""
    if scope is None:
        return "sin scope cargado (las herramientas que exigen scope serán denegadas)"
    parts = [
        f"engagement={getattr(scope, 'engagement_id', '?')}",
        f"cliente={getattr(scope, 'client', '?')}",
        f"válido hasta {getattr(scope, 'valid_until', '?')}",
    ]
    cidrs = getattr(scope, "cidrs", ()) or ()
    domains = getattr(scope, "domains", ()) or ()
    urls = getattr(scope, "urls", ()) or ()
    exclusions = getattr(scope, "exclusions", ()) or ()
    if cidrs:
        parts.append("cidrs=" + ", ".join(str(item) for item in cidrs))
    if domains:
        parts.append("dominios=" + ", ".join(str(item) for item in domains))
    if urls:
        parts.append("urls=" + ", ".join(str(item) for item in urls))
    if exclusions:
        parts.append("exclusiones=" + ", ".join(str(item) for item in exclusions))
    return " | ".join(parts)


def render_system_prompt(
    *,
    catalog: dict[str, Any],
    objective: str,
    engagement_id: str | None,
    scope_summary: str,
    history_summary: str = "(sin historial previo)",
) -> str:
    """Fill :data:`REACT_SYSTEM_PROMPT` for one iteration."""
    catalog_text = render_tool_catalog(catalog)
    return REACT_SYSTEM_PROMPT.format(
        tool_catalog=catalog_text,
        catalog_text=catalog_text,
        objective=objective,
        engagement_id=engagement_id or "(ninguno)",
        scope_summary=scope_summary,
        history_summary=history_summary,
    )


def render_summary_prompt(history_text: str) -> str:
    """Fill :data:`REACT_SUMMARY_PROMPT` for a history compaction call."""
    return REACT_SUMMARY_PROMPT.format(history_text=history_text)
