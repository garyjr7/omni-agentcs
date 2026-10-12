# Súper Auditoría de Potencia — OmniAgentCS-CLI

**Rol:** Arquitecto de Software Principal + UX de CLI/TUI.
**Fecha:** 2026-10-07 · **Rama:** `feat/manual-fixes-phase-4-1`
**Método:** lectura directa del código de producción (orquestador, TUI, kernel), de
los entry points y de la documentación de misión. **No** se ejecutó el CLI ni la
suite en este turno; las afirmaciones se anclan al código citado.
**Naturaleza del producto:** agente **autónomo de pentesting ofensivo**, no un
coding agent. La comparación con Claude Code / Codex / Gemini CLI es de *factores*
(loop, TUI, extensibilidad), no de paridad funcional: el dominio cambia lo que
significa "verificación" o "plan mode".

---

## 1. Resumen Ejecutivo

**Veredicto: 8.3 / 10.** Este no es un proyecto inmaduro que "hay que escalar": es
un CLI de agente **de núcleo senior** con una capa de gobernanza que las CLIs de
vanguardia *no tienen para este dominio*. Lo que falta es **pulido de producto y
UX**, no arquitectura. La deuda técnica está controlada (2245 tests verdes,
handler→parser→test, fail-closed por diseño).

| Dimensión | Nota | Lectura |
|---|---|---|
| Orquestación (el cerebro) | **9.0** | ReAct durable + planner determinista + subagentes + verificación por post-condición. |
| UI/UX (la cara) | **6.5** | TUI sólida pero con huecos de ergonomía (pegado, plan mode, medidor de contexto). |
| Arquitectura y lenguaje | **8.5** | Modular, extensible (MCP/skills), estado durable. Python es adecuado, no óptimo. |
| Extensibilidad/ecosistema | **8.0** | MCP, skills, instrucciones de proyecto; **faltan hooks de ciclo de vida**. |
| Gobernanza y seguridad | **9.5** | Scope HMAC, cadena de auditoría, aprobaciones durables, anti-inyección. Su foso. |

### Las 3 mejoras más críticas

1. **Colapso de prompts largos + Plan Mode de solo lectura.** Hoy un pegado grande
   inunda el buffer editable (tope visual de 5 líneas, sin marcador
   `[Pasted Content N chars]`) y **no existe un modo "propón plan antes de
   escribir"** como el Plan Mode de Claude Code. Es la brecha UX de mayor impacto
   y la más barata de cerrar.
2. **Hooks de ciclo de vida + verificador externo enchufable (Stop-style),
   fail-safe.** No hay `nexus_core/hooks/`. La verificación existe, pero está
   *cableada dentro de los handlers* (post-condición) y de las completion gates;
   no hay una capa plug-in que ejecute un comando externo y exija `exit code 0`
   antes de aceptar un `task_complete`.
3. **Instrumentación de contexto y paralelismo visible.** La status line muestra
   *tokens gastados*, no *% de ventana de contexto restante* ni disparador de
   auto-compact; el fan-out read-only (`gather_readonly`) es solo un helper interno
   y **no se expone** como comando del REPL, y no hay progreso vivo de subagentes
   en paralelo.

**Conclusión:** no reescribas. Con 2–4 sprints de UX + hooks + instrumentación,
esto se percibe como una CLI de élite **en el nicho donde el estado del arte no
juega**: pentesting autónomo con trazabilidad no repudiable.

---

## 2. Auditoría de Orquestación (El Cerebro)

### 2.1 ¿Reactivo o proactivo? — **Proactivo y acotado (excelente)**

El bucle vive en `nexus_core/agent/react.py` (`run_react_loop`). No es un
"prompt → tool → prompt" ingenuo:

- **Marco planificado, no improvisado.** `nexus_core/agent/planner.py` deriva del
  *blackboard* la fase del kill chain (`recon → enumeration → exploitation →
  privilege_escalation → post_exploitation → [lateral_movement] → reporting`) y la
  inyecta en **cada** system prompt (`plan.render()`). El modelo planifica *dentro*
  de un marco estable y auditable; el planner **nunca llama al LLM**.
- **Contrato de una acción por turno.** `nexus_core/agent/parser.py` exige un único
  objeto JSON (`tool_call` / `task_complete` / `request_clarification`). Es una
  decisión deliberada y defendible (aprobación y auditoría por acción), pero es
  también el techo de latencia: ver §4.
- **Presupuesto real**: `max_iterations` (12 por defecto), `budget_tokens` por run
  (`NEXUS_RUN_BUDGET_TOKENS`, `store.usage_total`), y un marco de
  `subagent` con su propio presupuesto de tokens e iteraciones.

### 2.2 Verificación externa determinista — **Sí, pero cableada**

Aquí el proyecto usa un patrón **distinto y, para su dominio, más fuerte** que un
Stop hook de tests:

- **Post-condición determinista en el handler.** El gateway solo marca `success`
  cuando una post-condición ejecutable se cumple; la evidencia (`verification_method`,
  `evidence`) viaja al modelo.
- **Completion gates** (`_completion_objections` en `react.py`): un `task_complete`
  se **rechaza** mientras el planner no esté en `reporting`, y si los *findings*
  citan evidencia que ninguna observación del run soporta (`fabricated_evidence`,
  `nexus_core/agent/evidence.py`). Es exactamente "evitar que el agente alucine que
  terminó". Hasta 3 rechazos antes de cerrar con `premature_completion`.
- **Degradación en lugar de muerte**: 3 fallos consecutivos **como tool** retiran la
  herramienta del run (`react.tool_unavailable`), `_failure_kind` distingue input
  inválido (no retira) de tool rota (retira); preflight retira tools con binario o
  módulo ausente (paramiko) antes de gastar una iteración.

**Brecha real:** no existe una capa de **verificación plug-in** que el operador
pueda añadir (p.ej. un script por engagement que valide el estado antes de aceptar
el cierre, o un hook `Stop`). La verificación está **dentro del binario**; un cliente
no puede enchufar la suya sin tocar código. Eso sí es comparable al estado del arte.

### 2.3 Subagentes con contexto aislado — **Sí (destacable)**

`nexus_core/agent/subagents.py` define **9 perfiles** (`recon`, `services`, `web`,
`cred`, `exploit`, `privesc`, `postexploit`, `lateral`, `reporter`), cada uno con:

- **Subconjunto de tools** exacto; el bucle intersecta el catálogo durable
  (`filter_catalog`) y **falla cerrado** ante cualquier tool fuera del subconjunto.
- **Presupuesto aislado** (tokens + iteraciones) contabilizado en su propio carril
  (`subagent_budget_subject`), para que una fase no drene a otra.
- **Marco de contexto** en el prompt (`subagent.describe()`), de modo que el modelo
  razona dentro de una fase.
- **Selección determinista y blackboard-driven** (`select_for_plan`); el modelo
  **nunca** elige su propio subagente → imposible de manipular por prompt.
- **Grace de transición** (`with_phase_grace`): las 2 primeras iteraciones de un
  perfil heredan tools **read-only** del anterior, para no retirar la tool que
  *descubrió* el servicio en la misma iteración que debe *enumerarlo*.

Esto es un subagente como *capability profile* con **aislamiento de contexto y
presupuesto**, no un segundo proceso. No hay fan-out de LLM por subagente, pero el
objetivo de "no contaminar la ventana principal" se cumple por diseño.

### 2.4 Decisión dinámica de herramienta — **Sí**

El modelo decide la next action a partir de: catálogo permitido del subagente,
fase del planner, blackboard renderizado, playbooks deterministas aplicables
(`_playbook_guidance`) e historial resumido. La elección es libre dentro del
subconjunto; el gateway gobierna (scope → policy → approval → sandbox → audit).

### 2.5 Refactorizaciones propuestas del orquestador

- **A) Verificador externo enchufable (`StopVerifier`).** Registro fail-safe de
  verificadores del operador (por engagement o por `OMNI.md`) que devuelven
  `(ok: bool, detalle)`. Si alguno falla, el `task_complete` se rechaza como
  hoy lo hace `_completion_objections`. Coste: **S–M**. Impacto: **alto**.
- **B) Paralelismo read-only *intra-iteración*.** Hoy el contrato es 1 acción/turno.
  Añadir un campo opcional `parallel: [tool_call, ...]` **solo** cuando el perfil
  activo es `parallel_safe`, ejecutado por `gather_readonly` (ya existe, con tope
  duro de 4 y cancelación) y devuelto como una observación agregada. No rompe
  aprobación/auditoría: cada call sigue pasando por `execute_tool`. Coste: **M**.
- **C) Presupuesto por fase configurable en runtime.** Ya hay env
  (`NEXUS_SUBAGENT_BUDGET_<ID>`) y `phase_timeout`; falta un checkpoint de estado
  del engagement (`/rewind` a nivel de blackboard, no "deshacer exploit").

---

## 3. Auditoría de UI/UX (La Cara)

Base: `prompt_toolkit` con **4 regiones** (`cli/tui/layout.py`): scrollback,
indicador busy, entrada multilínea y status bar; más *floats* (panel de plan,
modal de aprobación, respuesta en streaming, pensamiento `💭`). Modo
pantalla-alternativa por defecto, `--no-fullscreen` para inline. Es una TUI
**por encima de la media**.

### 3.1 Manejo de prompts largos — **BREGA CRÍTICA (no cumplida)**

- `cli/tui/session.py::_input_height` → `min(5, rows)`: el editor **crece hasta 5
  filas** y el resto se desplaza dentro del buffer editable.
- El pegado largo **no se colapsa**: no hay marcador `[Pasted Content N chars]`
  ni "chip" que oculte el contenido y lo restaure al enviar. Un volcado de
  configuración, una wordlist o una respuesta HTTP llena la región de entrada y
  degrada el renderizado (el historial en disco sí convierte saltos de línea en
  espacios, `cli/tui/history.py`, pero eso no resuelve el buffer en vivo).
- **Recomendación (P0, coste S):** interceptar `BracketedPaste` en el binding de
  prompt_toolkit; si `len(texto) > 1000` o `líneas > 4`, sustituir el buffer por un
  marcador `[Pasted Content <N> chars]` y guardar el texto real en un side-buffer
  que el `accept_handler` reexpande. Idéntico a Claude Code/Codex. Sin tocar el
  orquestador.

### 3.2 Status line (HUD) — **Sí, y bien pensada**

`cli/tui/status.py` es **priority-aware**: segmentos `alert(tokens) · phase ·
provider · tokens · cost · time · facts · engagement`; cuando la terminal es
estrecha **descarta el menos importante primero** (el engagement cae primero) y
**nunca** sacrifica alerta ni fase (se truncan por celda, `get_cwidth`). Colores
por segmento. `render_status_plain` para `/status show`.

**Brecha:** muestra **tokens acumulados**, no **% de ventana de contexto** ni
"cuánto queda antes del auto-compact". Claude Code muestra el contexto restante.
- **Recomendación (P1, coste S–M):** añadir segmento `ctx NN%` con umbrales de
  color y, al superar ~80%, sugerir/ejecutar compactación. Requiere que el modelo
  exponga `context_window` (config por proveedor).

### 3.3 Feedback visual — **Bien, con un hueco**

- **Spinner animado no bloqueante en braille** (`cli/spinner.py`: `⠋⠙⠹…`), en un
  hilo daemon, escribe a **stderr** para no corromper stdout/readline, con tiempo
  transcurrido y `stop()` idempotente. En TUI se desactiva y la línea busy del HUD
  lo sustituye (`⠋ Working... (29s · esc to interrupt)`). Refresh adaptativo (4 Hz
  busy / 0.5 Hz idle) con `min_redraw_interval=0.25`.
- **Streaming** de la respuesta y del *pensamiento* token a token (`_complete_turn`,
  `extract_partial_thought`, `MeteredClient`).
- **Hueco:** **no hay progreso de subagentes en paralelo** en la UI. El fan-out
  read-only no se muestra como N barras/tareas; solo un `subagent_id` viaja en el
  NDJSON del modo headless. Para el estándar actual (Claude/Gemini muestran
  subagentes en paralelo) es una carencia visible.

### 3.4 Plan Mode (solo lectura) — **NO existe como modo**

Hay aprobación humana por tool HIGH/DESTRUCTIVE (modal superpuesto,
`cli/approval.py`), trust-mode con auditoría, y un planner determinista que
*framea* al modelo. Pero **no hay un modo explícito "solo lectura / propón plan
antes de ejecutar escrituras"** que el operador active (p.ej. `--plan` o
`/plan mode on`) y que **bloquee toda tool activa** hasta aprobación de un plan.
- **Recomendación (P1, coste S–M):** un modo binario de sesión: "solo permitir
  tools `read_only`; para cualquier `ACTIVE_TOOLS`/`DESTRUCTIVE`, exigir plan + aprobación
  explícita". Reutiliza `subagents.ACTIVE_TOOLS` y el modal de aprobación ya
  existentes. Es la mejora que más "se siente" como Claude Code.

### 3.5 Otras observaciones honestas

- **Markdown**: renderizador ligero propio (`cli/tui/markdown.py`) válido para un
  subconjunto; tablas con wrap y `<br>` ya tratados, pero no es CommonMark completo.
  Reconocido y acotado.
- **Memoria del transcript**: el scrollback se conserva **entero en memoria**
  (sin el límite previo de 2000 líneas). Conversaciones largas → crecimiento de
  memoria; conviene ventana visible + persistencia lazy.
- **Selección/copia**: en alt-screen con captura de ratón, copiar exige **Shift**.
  Elección documentada y razonable, pero no hay fallback de copia integrado.
- **Sin temas claro/oscuro** ni i18n (ES-only). Impacto medio en percepción.

---

## 4. Auditoría de Arquitectura y Lenguaje

### 4.1 ¿Es Python el lenguaje óptimo?

**Para este producto, sí: es la decisión correcta, no la óptima en abstracto.**
Razones medidas por inspección:

- La carga es **I/O-bound** (subprocess de binarios, RPC de MSF, gRPC de Sliver,
  HTTP de LLM): asyncio + hilos rinde bien; el GIL no es el cuello de botella.
- El ecosistema (pydantic, openai, google-genai, sliver-py, prompt_toolkit, mcp)
  es Python-first; el coste de migrar supera con creces el beneficio.
- **Dónde Python sí duele**: (a) *startup* del CLI (~import de pydantic/openai/
  prompt_toolkit); (b) el **renderizador TUI en proceso** a 4 Hz sobre transcripts
  grandes; (c) ~163 errores mypy preexistentes sin config → tipado **no** es una
  puerta de calidad (FASE41 §Verificación).

**Recomendación:** mantener Python; si se mide latencia de teclado > 50 ms o
disparo de memoria, **extraer solo el renderizador** a un binario pequeño, no
reescribir el agente. No hay justificación para Rust/Go en el core.

### 4.2 Estado de la conversación e historial

Sólido y bien separado:

- **Store durable** (`kernel/store`, SQLite/Postgres) con `kernel_conversations` /
  `kernel_messages`, reanudable tras muerte del worker.
- **Sesión de trabajo compartida** con filtrado por `run_id` (`_run_messages`):
  un run razona sobre **sus** observaciones, no las de runs previos, mientras el
  **blackboard** permanece compartido.
- **Compactación** (`memory.summarize_history_if_large`) + `bounded_context` para
  no reventar el límite por-request del proveedor.
- **Blackboard tipado** con procedencia y `verified` — la memoria del engagement.
- **Auditoría encadenada por hash** y **scope firmado HMAC** vía el gateway.

Es un diseño de *durabilidad e integridad* superior al de la mayoría de CLIs de
coding.

### 4.3 Modularidad y extensibilidad

- Patrón consistente **handler → parser → test**; registro de tools
  (`tools/registry.py`, 42 tools); gateway único (`execute_tool`).
- **MCP cliente** real (`integrations/mcp/`: `client.py`, `registry.py`,
  `gateway_bridge.py`) — los servidores MCP entran **detrás del gateway**, con
  salida envuelta como dato no confiable y aprobación para clases peligrosas. Muy
  bien: evita el "tool poisoning" que aqueja a MCP en otras CLIs.
- **Skills** cargables (`.agents/skills/<name>/SKILL.md`, `agent/skills.py`) con
  firma opcional reutilizando el secreto de scope y previsualización.
- **Instrucciones de proyecto** (`OMNI.md`, `agent/project_context.py`) con hash y
  procedencia auditada.
- **Defensa anti prompt-injection** (`agent/injection.py`: `render_for_model`,
  `scan_untrusted_text`): el output de tools se envuelve y se marca como datos,
  no instrucciones. Crítico en pentesting (lees banners/páginas del objetivo).
- **ROE** (`scope/roe.py`): rate/concurrency, ventanas, kill switch — política de
  engagement como código.

**Única carencia estructural:** **hooks de ciclo de vida** (pre/post tool use,
session start/end, pre-compact, stop) no existen. Sin ellos, la automatización de
política del operador (notificar, bloquear por nombre, auto-registrar hechos,
encadenar verificadores) exige tocar el core. Es el hueco que más limita
"extender sin forkear".

### 4.4 Concurrencia

- `gather_readonly` (`subagents.py`): fan-out read-only **acotado** (Semaphore,
  tope duro 4), **cancelable** y **fail-closed** (rechaza perfiles activos *antes*
  de agendar), con excepciones en su lugar. Implementación de calidad.
- `fan_out_tool` (`cli/session.py`) lo usa para lanzar una tool read-only sobre N
  targets, cada uno por el gateway gobernado y auditado (`fanout.started`).
- **Pero**: (a) no está expuesto como comando del REPL; (b) no se usa *dentro* de
  una iteración del ReAct (contrato 1 acción/turno); (c) no hay visualización.

---

## 5. Matriz de Brechas vs. Estado del Arte

> Para un agente de pentesting, "verificación externa" = post-condición + completion
> gates (equivalente funcional del Stop hook), y "Plan Mode" = gate de solo lectura.
> Se marca ✅ / ⚠️ parcial / ❌ ausente. Prioridad en la columna final.

| Característica | Este Proyecto | Claude Code / Codex / Gemini | Prioridad |
|---|---|---|---|
| Loop Plan→Act→Verify | ✅ Planner determinista + gates de evidencia | ✅ | — (fortaleza) |
| Verificación externa determinista | ⚠️ Post-condición + gates, **no plug-in** | ✅ Stop hooks / tests | **P1** |
| Subagentes con contexto/presupuesto aislado | ✅ 9 perfiles, selección determinista | ✅ | — (fortaleza) |
| Progreso de subagentes en paralelo (UI) | ❌ solo `subagent_id` en NDJSON | ✅ | P2 |
| Paralelismo intra-iteración | ⚠️ helper read-only, no en el loop | ✅ | P2 |
| Colapso de prompts largos `[Pasted N chars]` | ❌ buffer editable, tope 5 filas | ✅ | **P0** |
| Status line HUD (tokens/coste/fase/git) | ✅ priority-aware (tokens/coste/fase) | ✅ | — |
| % de ventana de contexto + auto-compact visible | ❌ solo tokens acumulados | ✅ | **P1** |
| Spinner no bloqueante (braille) | ✅ stderr, hilo daemon | ✅ | — |
| Plan Mode (solo lectura, propón antes de escribir) | ❌ solo aprobación por tool | ✅ | **P0/P1** |
| Aprobaciones humanas durables | ✅✅ (HMAC + separación de deberes) | ⚠️ | — (foso) |
| MCP cliente (stdio + HTTP) | ✅ detrás del gateway | ✅ | — |
| Hooks de ciclo de vida | ❌ | ✅ | **P1** |
| Skills/instrucciones de proyecto | ✅ firmables + `OMNI.md` | ✅ | — |
| Headless CI + JSON/NDJSON | ✅ `omni run --json` / `--stream-json` | ✅ | — |
| Checkpoints / rewind | ❌ | ✅ | P2 |
| Anti prompt-injection | ✅ delimita/escanea output no confiable | ⚠️ | — (fuerte) |
| Multi-modelo + local-first | ✅ OpenAI/Groq/Gemini/Ollama/Anthropic/Fake | ✅/⚠️ | — |
| Audit chain + scope firmado | ✅✅ (no repudiable) | ❌ | — (foso) |
| Terminal: alt-screen + inline | ✅ `--no-fullscreen` | ✅ | — |
| Temas claro/oscuro · i18n | ❌ ES-only | ✅ | P3 |
| Markdown completo en TUI | ⚠️ subconjunto propio | ✅ | P2 |

**Lectura estratégica:** la columna "Este Proyecto" es **superior** en gobernanza,
anti-inyección y verificación de dominio; **inferior** en ergonomía de terminal
(pegado, plan mode, contexto restante) y en la capa de automatización (hooks).
La estrategia correcta **no es clonar** Claude Code, sino montar la capa UX/hooks
sobre el foso de gobernanza existente.

---

## 6. Plan de Acción (Roadmap de Potenciación)

Esfuerzo: **S** ≤ 3 días · **M** 1–2 semanas · **L** 3+ semanas (1 dev senior).

### P0 — Quick wins (alto impacto, bajo riesgo)

| # | Tarea | Detalle | Esfuerzo |
|---|---|---|---|
| P0-1 | **Colapso de pegado** | `BracketedPaste` → `[Pasted Content N chars]` con side-buffer reexpandible; umbral >4 líneas / >1000 chars. `cli/tui/session.py`. | S |
| P0-2 | **Plan Mode (solo lectura)** | Flag `--plan` + `/plan mode on\|off`: permite solo `read_only`; toda `ACTIVE_TOOLS`/`DESTRUCTIVE` exige plan + aprobación. Reutiliza `subagents.ACTIVE_TOOLS` y el modal. | S–M |
| P0-3 | **Medidor de contexto en HUD** | Segmento `ctx NN%` con umbral de color y aviso de auto-compact a ~80%. Requiere `context_window` por modelo. `cli/tui/status.py`. | S–M |

### P1 — Plataforma y confianza

| # | Tarea | Detalle | Esfuerzo |
|---|---|---|---|
| P1-1 | **Hooks de ciclo de vida** | `nexus_core/hooks/`: `pre_tool_use`, `post_tool_use`, `session_start/end`, `pre_compact`, `stop`. Ejecución **fail-safe** (un hook que falla no rompe el run; se audita). Config en `~/.config/omni/hooks.json`. | M |
| P1-2 | **Verificador externo enchufable (Stop)** | Registro de verificadores del operador (`(ok, detalle)`); si fallan, se rechaza `task_complete` como `_completion_objections`. | S–M |
| P1-3 | **Exponer fan-out read-only** | Comando REPL `/fanout <tool> <targets…>` sobre `fan_out_tool`; cada call por el gateway. | S |
| P1-4 | **Checkpoint de estado del engagement** | Snapshot blackboard + fase en el audit trail; `/rewind <checkpoint>` (estado, no "deshacer exploit"). | M |
| P1-5 | **CI más estricto** | Config de `mypy` incremental, `pip-audit`, cobertura con badge; job e2e opcional. Hoy mypy no es puerta. | S–M |

### P2 — UX de clase mundial y orquestación avanzada

| # | Tarea | Detalle | Esfuerzo |
|---|---|---|---|
| P2-1 | **Paralelismo intra-iteración** | Campo opcional `parallel: [...]` solo en perfiles `parallel_safe`; ejecuta con `gather_readonly`, observación agregada. No rompe aprobación/auditoría. | M |
| P2-2 | **Progreso de subagentes en vivo** | Panel/lineas de tareas concurrentes sobre los floats existentes. | M |
| P2-3 | **Transcript con ventana** | Renderizar solo la porción visible + persistencia lazy; acotar memoria. | M |
| P2-4 | **Markdown completo** | Tablas con wrap, listas anidadas; opcional dependencia madura. | M |
| P2-5 | **Temas + i18n (ES/EN)** | Paleta claro/oscuro en TUI y HTML del reporte; i18n de UI. | M |

### P3 — Producto y cobertura (continuo)

Distribución (Docker, PyPI público, `omni update`), cobertura OSINT/AD/cloud/K8s,
CVSS 4.0 + marcos (PTES/WSTG/NIST/D3FEND) + SARIF, enriquecimiento CVE
(NVD/EPSS/KEV), telemetría opt-in.

---

## Anexo — Límites de esta auditoría

- Basada en **lectura de código** (react.py, subagents.py, planner.py, parser,
  evidence, skills, project_context, injection, roe, integrations/mcp, cli/tui/*,
  spinner, headless, main) y documentación de misión. **No** se ejecutó el CLI ni
  la suite; no se midió latencia de teclado ni memoria en PTY.
- Las notas son **relativas al dominio** (pentesting), no una comparación de
  paridad con coding agents.
- No se modificó código de producción. Este documento es el único artefacto.
- Evidencia previa relevante: `TUI_UX_AUDIT.md` (corrupción de logs ya resuelta),
  `potencializar_cli.md` y `AUD_OMNI_BW.md` (parcialmente superados: subagentes,
  MCP, skills y headless **ya existen** en la rama actual).
