"""System prompts for the durable ReAct loop.

The prompt is a plain ``str.format`` template: literal JSON braces are escaped
(``{{`` / ``}}``) so :func:`render_system_prompt` can be called with the runtime
context without touching the response contract.
"""

from __future__ import annotations

from typing import Any

REACT_SYSTEM_PROMPT = """Eres OmniAgent, un agente autónomo de
ciberseguridad ofensiva operando dentro de un engagement autorizado.

Tu trabajo es completar objetivos de pentesting paso a paso usando las
herramientas disponibles. En cada iteración decides UNA acción.

HERRAMIENTAS DISPONIBLES (una línea por tool):
{tool_catalog}

REGLAS:
- Solo puedes invocar herramientas del catálogo. Si necesitas una que no
  existe, respondes con "task_complete" y explicas qué faltó.
- El scope del engagement es SAGRADO. Si el scope validation falla, no
  insistas con otro target — reporta y para.
- Antes de cada acción de alto ruido (nivel high), considera alternativas
  más silenciosas primero.
- METODOLOGÍA DE RECONOCIMIENTO (obligatoria): antes de concluir cualquier
  análisis, empieza descubriendo TODOS los puertos TCP con la herramienta de
  escaneo nmap usando el profile "full_tcp" (equivale a `-p-`). Nunca asumas
  una lista de puertos "comunes": el vector suele estar en un puerto
  inesperado (p. ej. FTP en 21) que un escaneo corto no ve. Después usa el
  profile "service" para versiones/scripts y analiza cada servicio encontrado
  antes de decidir el siguiente paso.
- ENCADENAMIENTO: cada hallazgo es la entrada del siguiente paso. Un nombre
  de usuario, una lista de contraseñas, una credencial o un servicio nuevo
  deben convertirse en la siguiente acción (enumerar, probar, explotar),
  no quedarse como dato aislado. Tras descargar archivos, léelos con la
  búsqueda del workspace para extraer usuarios, pistas o listas, y después
  valida esas credenciales contra los servicios encontrados con la
  herramienta de prueba de credenciales.
- ESCALADA: si la enumeración revela derechos sudo, SUID o capabilities,
  correlaciónalos con vectores de escalada conocidos, ordena los candidatos y
  demuestra la escalada con un comando determinista que imprima `uid=0`,
  ejecutado bajo aprobación humana. No persistas cambios sin pedirlo.
- Estas reglas son genéricas: decide según lo que encuentres, no asumas que
  todos los objetivos tienen los mismos servicios ni la misma ruta de
  explotación. El flujo cambia con cada hallazgo.
- Documenta cada hallazgo en tu razonamiento. Otros agentes leerán esto.
- Si falta el binario de una tool, consulta nexus.system.check_env. Puedes
  solicitar nexus.system.install_tool para una herramienta de su catálogo;
  el operador debe aprobar el comando exacto. Nunca inventes comandos de
  instalación ni intentes evitar una denegación de aprobación.
- El historial de esta sesión de trabajo puede contener objetivos ya
  ejecutados con sus tool calls, preguntas informativas (`/ask`, sin ejecución)
  y aclaraciones. Si el usuario se refiere a algo mencionado antes en esta
  sesión, tienes acceso a ello: cita el contexto previo si es relevante y no
  repitas trabajo ya hecho sin motivo.

RESPONDE SIEMPRE CON UN JSON VÁLIDO, sin markdown, sin texto adicional:

Para invocar una herramienta:
{{
  "thought": "razonamiento en 1-3 frases sobre qué hacer y por qué",
  "action": "tool_call",
  "tool_id": "<tool_id del catálogo>",
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


#: Cap on the description copied into the compact catalog line.
CATALOG_DESCRIPTION_CHARS = 64
#: Cap on how many declared arguments are listed per tool.
CATALOG_MAX_ARGUMENTS = 5


def _schema_arguments(definition: Any) -> str:
    """Compact ``name:type`` list of a tool's declared arguments."""
    schema = getattr(definition, "input_schema", None) or {}
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(properties, dict):
        return "-"
    required = set(schema.get("required") or ())
    parts: list[str] = []
    for name, spec in properties.items():
        if len(parts) >= CATALOG_MAX_ARGUMENTS:
            parts.append("…")
            break
        kind = spec.get("type") if isinstance(spec, dict) else None
        if kind is None and isinstance(spec, dict) and "enum" in spec:
            kind = "enum"
        label = f"{name}:{kind or 'any'}"
        if name in required:
            label += "*"
        parts.append(label)
    return ", ".join(parts) or "-"


def render_tool_catalog(catalog: dict[str, Any]) -> str:
    """Render the tool catalog as one compact, stable line per tool.

    The full JSON schema is deliberately *not* embedded: the compact form (id,
    description, arguments, risk, scope) is enough for the model and keeps the
    prompt small. The catalog is rendered exactly once per prompt.
    """
    if not catalog:
        return "(no hay herramientas disponibles)"
    lines: list[str] = []
    for tool_id in sorted(catalog):
        definition = catalog[tool_id][0] if isinstance(catalog[tool_id], tuple) else catalog[tool_id]
        risk = getattr(definition.risk, "value", str(getattr(definition, "risk", "unknown")))
        description = " ".join(str(getattr(definition, "description", "") or "").split())
        if len(description) > CATALOG_DESCRIPTION_CHARS:
            description = description[:CATALOG_DESCRIPTION_CHARS].rstrip() + "…"
        if getattr(definition, "scope_required", False):
            scope = f"scope:{getattr(definition, 'scope_target_field', None) or '?'}"
        else:
            scope = "sin scope"
        lines.append(
            f"- {tool_id}: {description or '(sin descripción)'} | "
            f"args[{_schema_arguments(definition)}] | riesgo:{risk} | {scope}"
        )
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
        objective=objective,
        engagement_id=engagement_id or "(ninguno)",
        scope_summary=scope_summary,
        history_summary=history_summary,
    )


def render_summary_prompt(history_text: str) -> str:
    """Fill :data:`REACT_SUMMARY_PROMPT` for a history compaction call."""
    return REACT_SUMMARY_PROMPT.format(history_text=history_text)
