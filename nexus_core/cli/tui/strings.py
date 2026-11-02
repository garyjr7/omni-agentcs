"""Cadenas visibles de la TUI (fuente única, español).

Solo texto de presentación: los identificadores de tools, los nombres de
campos JSON y las claves internas nunca viven aquí. El flujo de aprobación
(``panels.py``/``frame.py``) conserva su redacción propia: es un contrato de
seguridad y no forma parte de este catálogo.
"""

#: Tarjeta durable del transcript.
THINKING_CARD = "Razonamiento"
#: Fila en vivo (mientras el modelo escribe el ``thought``).
THINKING_LIVE = "Razonando"
#: Pies del bloque de razonamiento.
SHOW_FULL_REASONING = "ctrl+t mostrar todo"
HIDE_REASONING = "ctrl+t colapsar"
#: Entrada pegada.
SHOW_PASTED_INPUT = "mostrar entrada pegada"
#: Editor vacío.
PLACEHOLDER = "Escribe una tarea o / para comandos"
#: El hint se dibuja entre corchetes dentro del editor vacío.
PLACEHOLDER_TEXT = f"[ {PLACEHOLDER} ]"
#: Fila de trabajo y cierre.
WORKING = "ejecutando"
WORKED_FOR = "completado en"
ESC_INTERRUPT = "esc para interrumpir"
#: Ayudas del footer.
HISTORY_HINT = "historial"
HELP_HINT = "ayuda"
#: Veredictos.
FAILED = "falló"
NOISE = "ruido"
SAVED = "guardado"
#: Prefijo genérico cuando una tool no tiene etiqueta propia.
TOOL_FALLBACK = "Herramienta"
#: Corrección del orquestador (no es un fallo de la tool).
GUARDRAIL = "corrección del orquestador"
#: Ayuda de /expand.
EXPAND_HINT = "clic en la tarjeta o ctrl+o"

__all__ = [
    "ESC_INTERRUPT",
    "EXPAND_HINT",
    "FAILED",
    "GUARDRAIL",
    "HELP_HINT",
    "HIDE_REASONING",
    "HISTORY_HINT",
    "NOISE",
    "PLACEHOLDER",
    "PLACEHOLDER_TEXT",
    "SAVED",
    "SHOW_FULL_REASONING",
    "SHOW_PASTED_INPUT",
    "THINKING_CARD",
    "THINKING_LIVE",
    "TOOL_FALLBACK",
    "WORKED_FOR",
    "WORKING",
]
