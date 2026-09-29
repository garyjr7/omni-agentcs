# REACT_RESULT.md — Bucle ReAct durable en el runtime NEXUS

Rama: `feat/react-loop` (desde `feat/nmap-tool`). Commit: ver `git log --oneline -3`.
Sin push.

## Qué se ha construido

El runtime deja de ser sólo un runner de workflows declarativos: `react.run` es
un executor durable nuevo en el que **el LLM decide un único step por iteración**,
el runtime lo ejecuta por el camino gobernado (`execute_tool` → `ToolGateway` →
policy/scope/approval/sandbox/audit) y el resultado vuelve al historial.

| Fichero | Contenido |
| --- | --- |
| `nexus_core/agent/__init__.py` | API pública del paquete |
| `nexus_core/agent/prompts.py` | `REACT_SYSTEM_PROMPT`, `REACT_SUMMARY_PROMPT`, `render_tool_catalog`, `describe_scope`, `render_system_prompt` |
| `nexus_core/agent/parser.py` | `ReActAction`, `ReActParseError`, `parse_react_response` (tolerante) |
| `nexus_core/agent/memory.py` | historial durable sobre `kernel_conversations`/`kernel_messages` + compactación |
| `nexus_core/agent/react.py` | `ReActConfig`, `ReActResult`, `run_react_loop` |
| `nexus_core/kernel/runtime.py` | `execute_react(payload, context)` + `registry.register("react.run", execute_react)` |
| `nexus_core/tests/fixtures/react/` | 5 prompts de prueba + 1 fixture de LLM fake determinista |
| `nexus_core/tests/unit/test_react_{parser,memory,loop}.py` | 43 tests nuevos |
| `nexus_core/tests/integration/test_react_e2e.py` | 2 tests E2E opt-in (`NEXUS_E2E=1`) |

`execute_brain` queda intacto: sigue siendo el runner declarativo de workflows.
`execute_tool`, `ToolGateway` y `execute_agent` conservan su firma pública.

## Cómo se cumple cada regla de la misión

**Regla de hierro (nada implícito).** El loop construye cada invocación con
`tool_id` + `arguments` que salieron del JSON del modelo. Si el `tool_id` no está
en `durable_tool_definitions(tenant)`, **no se llama a `execute_tool`**: se
inyecta al historial la observación `tool '<x>' does not exist in the catalog`
con la lista de tools disponibles y se cuenta como fallo consecutivo
(`test_loop_rejects_unknown_tool_without_executing`).
No hay atajos: `grep -rnE "ToolGateway|from nexus_core.tools.handlers|subprocess"`
sobre `nexus_core/agent/` sale limpio; el único camino a una tool es
`runtime.execute_tool`.

**Scope.** `engagement_id` se propaga en cada invocación
(`test_loop_propagates_engagement_id_to_tools`). Una `ScopeViolation` aborta el
bucle **en el primer intento** con `status="scope_violation_aborted"`, se
persiste como observación y se audita `react.step` con
`reason="scope_violation"` (`test_loop_aborts_on_scope_violation_immediately`).

**Fallos consecutivos.** 3 fallos de tool consecutivos (excepción del gateway o
`success=False`) → `status="failed"` con el motivo en `final_summary`
(`test_loop_aborts_after_3_consecutive_tool_failures`). Un éxito resetea el
contador.

**Parse errors.** `ReActParseError` no mata el bucle: se persiste la respuesta
cruda (`kind="react.action"`, `action="parse_error"`), se inyecta un mensaje
correctivo y el bucle continúa, consumiendo una iteración
(`test_loop_handles_llm_json_parse_error_gracefully`).

**Durabilidad y reanudación.** Cada iteración escribe en
`kernel_conversations`/`kernel_messages` (sin tocar el schema). La conversación
se localiza por título determinista `react:<run_id>`, y el contador de iteración
se reconstruye desde los `react.action` persistidos, así que un worker nuevo que
reclame la task retoma el bucle en el step siguiente
(`test_loop_conversation_is_resumable`: 1 step persistido → reanuda en el 2).

**Cancelación cooperativa.** Antes de cada iteración se consultan los run events
buscando `react.cancel_requested`; si aparece, el bucle para con
`status="cancelled"` y emite `react.cancelled`
(`test_loop_stops_on_cancel_run_event`).

**Auditoría.** Un evento `action="react.step"` por iteración con
`{iteration, action, tool_id, success/…}` y `decision` `allow|deny`
(`test_loop_audits_each_step`). La cadena de hashes del `AuditWriter` se mantiene
(no se ha tocado).

**Compactación.** Si el historial supera `config.max_history_messages` (40) o
`max_tokens≈8000` estimados, se resume con el LLM preservando el system prompt y
los últimos 10 mensajes (`test_summarize_*`, 6 tests).

**Iteración máxima.** Default 12, configurable por `max_iterations` en el
payload. Al agotarse: `status="max_iterations"`
(`test_loop_respects_max_iterations`).

**Parser tolerante.** JSON puro → bloque ```` ```json ```` → primer `{...}`
balanceado (string/escape-aware). Múltiples acciones apiladas → se toma la
primera y se registra `warnings=("response contained multiple actions; …",)`.
`raw_response` siempre se preserva para auditoría, incluso en error.

## Verificación (salida real)

```
$ .venv/bin/python -c "import nexus_api.main"      → api OK
$ .venv/bin/python -c "import nexus_core.kernel.runtime" → kernel OK
$ .venv/bin/python -c "import nexus_core.agent.react"    → react OK
$ .venv/bin/python -c "import nexus_core.agent.parser"   → parser OK
$ .venv/bin/python -c "import nexus_core.agent.memory"   → memory OK
$ .venv/bin/python -c "import nexus_core.tools.registry" → registry OK
$ .venv/bin/python -c "import nexus_worker"              → worker OK
$ .venv/bin/python -c "import nexus_mcp.server"          → mcp OK
                                                          → 8/8 OK

$ .venv/bin/python -m pytest nexus_core/tests/unit -q
142 passed in 6.05s          # 99 previos + 43 nuevos (15 parser + 13 memoria + 15 loop)

$ .venv/bin/python -m pytest nexus_core/tests/unit/test_react_*.py -q
42 passed in 4.15s           # antes de añadir el test de registry (43 en total)

$ .venv/bin/ruff check nexus_core/agent nexus_core/kernel/runtime.py \
      nexus_core/tests/unit/test_react_*.py --select F,E9
All checks passed!

$ grep -rnE "TODO|FIXME|XXX|HACK|raise NotImplementedError" nexus_core/agent/ nexus_core/kernel/runtime.py
(exit 1, sin resultados)

$ NEXUS_E2E=1 .venv/bin/python -m pytest nexus_core/tests/integration/test_react_e2e.py -v
test_e2e_react_nmap_scanme SKIPPED        [ 50%]
test_e2e_react_denies_out_of_scope SKIPPED [100%]
2 skipped in 2.15s
```

### E2E: por qué se saltan (no se oculta)

`.env` existe pero **todas** las API keys están vacías
(`OPENAI_API_KEY=`, `GEMINI_API_KEY=`, `GROQ_API_KEY=`), no hay
`OLLAMA_BASE_URL`, y el binario `nmap` no está instalado en esta máquina. Los
dos tests E2E requieren un modelo real y están marcados
`skipif` por esa razón, siguiendo la convención de `test_nmap_e2e.py`. **No se
han ejecutado contra red ni contra un proveedor externo**: no hay ninguna
evidencia E2E que reportar. El resto del bucle está cubierto de forma
determinista con LLM scriptado y `execute_tool` espiado.

## Decisiones de diseño no cubiertas por el prompt

1. **Orden de providers en `execute_react`.** `LLMFactory.create_from_env()`
   devuelve siempre el provider `"fake"` como primera clave, así que copiar el
   snippet del spec (`primary = providers[0]`) hacía que el agente usara *siempre*
   el LLM fake y ningún modelo real. Implementado: los providers reales tienen
   prioridad y `fake` queda como último recurso (`providers = [p for p in clients
   if p != "fake"] or ["fake"]`). Fallback = segundo provider real si existe.
2. **`run_react_loop` no recibe `identity`.** La firma pedida no lo incluye, y
   las tools deben seguir pasando por policy/approval con la identidad original.
   Se deriva de `context.task["payload"]` (`identity`, `permissions`,
   `approval_id`). Documentado en el docstring de `execute_react`.
3. **Compactación lógica, no borrado.** `kernel_messages` es append-only y el
   schema no se puede tocar: el resumen se persiste como marcador
   `react.history_summary` con `covers=<n>` y `load_history` colapsa lo que el
   marcador reemplaza, conservando el system prompt y los últimos 10 mensajes.
4. **`scope_violation` aborta en el primer intento**, no "tras N intentos": el
   requisito duro dice aborto inmediato y así lo hace el test.
5. **Rechazo de tool inexistente = fallo consecutivo.** Un LLM que alucina la
   misma tool 3 veces seguidas agota el presupuesto igual que uno que falla 3
   veces ejecutando. Evita bucles infinitos de alucinación.
6. **Observaciones truncadas a 20 000 caracteres** (`MAX_OBSERVATION_CHARS`)
   antes de persistirlas: un XML de nmap puede llegar a 4 MB y el store es
   texto; el flag `truncated` queda en el metadata. El artefacto completo
   pertenece al artifact store (fuera de alcance de esta misión).
7. **`ReActAction.warnings` y `ReActResult.question`** son campos extra con
   default sobre las dataclasses del spec: hacía falta un sitio para registrar
   el warning de "múltiples acciones" y para devolver la pregunta de
   `request_clarification` al CLI. Son aditivos y no rompen los campos pedidos.
8. **Timeout por tool.** `config.timeout_per_tool_seconds` se aplica con
   `asyncio.wait_for` alrededor de `execute_tool` (el gateway ya aplica además el
   `ToolDefinition.timeout_seconds`); un timeout es una observación de fallo, no
   un crash.
9. **`react.run` también escribe run events** (`react.action`, `react.parse_error`,
   `react.scope_violation`, `react.clarification_requested`, `react.cancelled`,
   `react.finished`) para que la UI/CLI siga el bucle en vivo.

## Limitaciones / trabajo pendiente (fuera de alcance)

- Sin CLI/API que recoja `question` y reanude un bucle en `clarification`
  (el executor ya devuelve el `conversation_id` y la pregunta).
- El historial no se marca como "consumido" al cerrar el bucle: re-ejecutar la
  misma task tras un `completed` seguiría desde la última iteración persistida.
- `OCISandbox` fuerza `--network none` (documentado en la misión anterior), así
  que un nmap real en producción requiere una excepción de sandbox específica.
- La compactación usa el mismo `llm_client` del bucle (una llamada extra al
  modelo cuando el historial es grande).

## Ficheros que NO se han commiteado (preexistentes, ajenos a la misión)

- `nexus_core/tests/integration/test_nmap_e2e.py`: tenía una modificación sin
  commitear al empezar (`domains=("scanme.nmap.org",)`), presumiblemente WIP del
  operador. Se ha dejado tal cual, sin commitear ni revertir.
- `list_models.sh`: script local sin trackear (curl+jq contra Groq). No se toca.

Por eso el commit de esta misión **no** usa `git add -A`, sino una lista
explícita de ficheros.
