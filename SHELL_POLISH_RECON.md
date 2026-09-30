# SHELL_POLISH_RECON — Presentación del CLI (banner + spinner + prompt)

Reconocimiento previo a la implementación. Rama base: `feat/report-generation`
(commit `95797c0`), 721 tests en verde. Nueva rama: `feat/shell-polish-core`.

## 1. Cómo se decide hoy entre REPL y one-shot

El flujo real tiene **dos** parsers sobre el mismo `argparse`:

| Paso | Fichero | Qué decide |
|---|---|---|
| 1 | `omni.py::main` | onboarding, `--config-path`, `--config`, `--doctor`, `--reset-config`, wizard, `apply_environment`; luego delega en `cli_main` |
| 2 | `nexus_core/cli/main.py::main` | `--list-engagements`, selección de engagement, construcción del LLM client y **REPL vs one-shot** |

```python
# nexus_core/cli/main.py
if args.objective:
    result = session.run_objective(args.objective)   # one-shot: sale sin REPL
    return 0 if result.status in ACCEPTABLE_ONESHOT_STATUSES else 1
session.run_repl()                                    # REPL
return 0
```

Consecuencia de diseño (y requisito de la misión): el banner **no** se decide en
`omni.py` ni en `main.py`, porque ninguno de los dos conoce a la vez el
engagement cargado, el catálogo de tools, la cadena de auditoría y el proveedor
LLM. El único punto con todo ese contexto es `OmniSession.run_repl()`.

Los flags `--help`/`--version` los consume `argparse` (`SystemExit` antes de
cualquier `run_repl`), y `--config-path`, `--config`, `--doctor`,
`--reset-config` retornan desde `omni.py`. `--list-engagements` retorna desde
`main.py`. Ninguno llega a `run_repl`.

## 2. Dónde se construye el prompt actual

`OmniSession.prompt` es una `@property` (no un `_build_prompt()`):

```python
return f"┌──(OmniAgentCS)─[{name}]{trust}{session}{report}\n└─$ "
```

- `name` — `engagement.name` o `"(sin engagement)"`.
- `trust` — `"─[TRUST MODE]"` (el sufijo `─` lo aporta el propio token).
- `session` — `"─[session <uuid>/<type>]"`.
- `report` — `"─[report <basename>]"`, añadido en la misión anterior.

Ya existían tests que fijan estos substrings
(`test_cli_session_stateful.py::test_prompt_includes_session_uuid_and_type`,
`test_trust_mode_flag_still_shown_in_session_mode`), así que la política de
color se decidió para **no romperlos**: se pinta *alrededor* del token, nunca
dentro (`"─" + paint("[TRUST MODE]", RED, BOLD)`), de modo que el texto plano
sigue siendo idéntico byte a byte.

## 3. Ancho de terminal

`shutil.get_terminal_size().columns` (stdlib) es la única fuente. No había uso
previo de ancho en el CLI. Umbral elegido: **80 columnas**; por debajo se omite
el ASCII art y queda el bloque de stats.

## 4. Render helpers existentes (`nexus_core/cli/render.py`)

- Paleta ANSI cruda: `RESET BOLD DIM RED GREEN YELLOW BLUE MAGENTA CYAN`.
- `configure_color(no_color=...)` → `set_color_enabled(not no_color and NO_COLOR is None)`;
  estado global `_COLOR_ENABLED`; `paint(text, *codes)` es no-op si está off.
- `noise_color(level)` mapea riesgo de tool → color.
- Helpers de salida: `render_status`, `render_error`, `render_thought`,
  `render_tool_call`, `render_tool_result`, `render_summary`,
  `render_approval_prompt`, `render_trust_mode`, `render_session_list`,
  `render_session_attached`, `render_session_died`, `render_session_output`.

**Decisión:** banner y spinner usan `render.paint` para heredar el mismo switch
global de color, pero el banner **además** recibe `no_color` explícito. El motivo
es real: `render.paint` depende del estado global, y `build_banner(no_color=True)`
debe ser determinista aunque el módulo global esté en modo color (es el caso del
flag `--no-color` en tests que aún no han llamado a `configure_color`).

## 5. Puntos de intercepción para el spinner

| Ruta | Método | Naturaleza |
|---|---|---|
| REPL → tool meta (`/report`, `/kill-session`, `/session attach`) | `OmniSession.invoke_tool` | gobernada, `asyncio.run(execute_tool(...))` |
| REPL → comando a sesión | `OmniSession.run_session_command` → `invoke_tool` | hereda el spinner |
| REPL → objetivo | `OmniSession.run_objective` | `asyncio.run(run_react_loop(...))` |
| One-shot | `main.py` → `run_objective` | hereda el spinner |

`invoke_tool` es el único cuello de botella de las tool calls del REPL: envolver
`asyncio.run(execute_tool(...))` cubre todo el catálogo sin tocar ningún handler.
`run_objective` arranca ya un `_stream_run_events` (daemon thread) que escribe en
stdout; el spinner escribe en **stderr**, así que no compiten por el mismo
stream. Ambos se detienen en el mismo `finally` lógico (`__exit__` del spinner,
`stop_event`+`join` del streamer).

## 6. Proveedores LLM: por qué el banner no puede usar `LLMFactory`

Primer intento: `LLMFactory.create_from_env()` para contar proveedores y obtener
el modelo. Medido en el repo real:

```
02:30:44.161 [INFO] LLMFactory → Groq client created from environment variables.
```

`LLMFactory.create_from_env()` llama a `get_logger("LLMFactory")`, que **crea un
`StreamHandler(sys.stdout)` nuevo y hace `setLevel(INFO)` en cada llamada**
(`nexus_core/utils/logger.py`). Es decir: subir el nivel del logger no silencia
nada, porque el logger se reconfigura solo. Ese log caería en medio del banner
(en producción con 7 proveedores, 7 líneas).

**Decisión:** el banner no construye clientes. `OmniSession._llm_stats()` replica
la *resolución* de `select_llm_client()` leyendo solo el entorno:

| Orden | Variable de clave | Variable de modelo | Default del factory |
|---|---|---|---|
| 1 | `OPENAI_API_KEY` | `OPENAI_MODEL` | `gpt-4o-mini` |
| 2 | `GEMINI_API_KEY` | `GEMINI_MODEL` | `gemini-1.5-flash` |
| 3 | `GROQ_API_KEY` | `GROQ_MODEL` | `llama-3.3-70b-versatile` |
| 4 | `ANTHROPIC_API_KEY` | `ANTHROPIC_MODEL` | `claude-sonnet-4-20250514` |
| 5 | `OLLAMA_BASE_URL` | `OLLAMA_MODEL` | `llama3` |
| — | (siempre) `fake` | `FAKE_LLM_MODEL` | `nexus-fake-v1` |

Precedencia copiada de `runtime.select_llm_client`: `NEXUS_LLM_DEFAULT_PROVIDER`
si está definido y tiene clave; si no, el primer proveedor real; si no hay
ninguno, `fake`. Un proveedor seleccionado **sin** clave cae a `fake`, nunca a
otro cloud. Coste: 0 clientes construidos, 0 líneas de log, 0 llamadas de red.

## 7. msfrpcd

`nexus_core/integrations/metasploit/client.py` expone `MetasploitClient` con
`_rpc("core.version", [])` (el `authenticate()` ya lo usa). `MetasploitConfig.from_env()`
es barato y no abre socket. Se usa el cliente existente (no `subprocess`) con
`asyncio.wait_for(..., 2.0)`; daemon muerto → `None` → banner muestra `n/a`.

## 8. Estado real medido en este checkout

- Catálogo: **16 tools** (`durable_tool_definitions("system")`).
- LLM resuelto: `groq/openai/gpt-oss-120b` (1 proveedor real con clave; `OPENAI`,
  `GEMINI`, `ANTHROPIC` vacíos; sin `OLLAMA_BASE_URL`).
- msfrpcd: vivo, `6.5.3-dev-`.
- Cadena de auditoría: válida.
- Engagement `eng-scanme` (`scanme-lab`).
- `LLM_PROVIDER=fake` en `.env`, pero `select_llm_client()` ignora esa variable
  (usa `NEXUS_LLM_DEFAULT_PROVIDER`, que no está definida) y elige el primer
  proveedor real → Groq.

## 9. Riesgos identificados y mitigación

| Riesgo | Mitigación |
|---|---|
| El spinner ensucia stdout y rompe `capsys`/pipelines | escribe solo en `sys.stderr`; `enabled` exige `stdout.isatty() and stderr.isatty()` |
| Hilo huérfano si el tool lanza | `daemon=True` + `join(timeout=1.0)` en `stop()` + `__exit__` siempre llamado |
| Ctrl+C durante el tool | `__exit__` recibe `KeyboardInterrupt`, hace `stop(success=False)` y **re-lanza** (`return False`) |
| `readline` pisado por el spinner | spinner en stderr; el REPL lee de stdin y escribe el prompt en stdout |
| Tests con TTY simulado | toda la detección pasa por `isatty()` y por `render.color_enabled()`, ambos mockeables |
| Banner en CI | `NEXUS_NO_BANNER` + no-TTY lo desactivan; `--no-color` lo deja en ASCII |