# Reconocimiento de la migración TUI

Fecha: 2026-09-30. Rama: `feat/tui-prompt-toolkit`.
Base: `2d20360`. No se modificó código de producto ni tests.

## Entrada y ciclo de ejecución

- `nexus_core/cli/session.py:723`, `OmniSession.run_repl`: instala readline,
  muestra el banner y el estado inicial, comprueba la sesión activa y lee con
  `(self.input_reader or input)(self.prompt)` en la línea 734. No existe
  `readline.input`. Las líneas vacías continúan; EOF termina; Ctrl+C imprime
  un aviso y continúa. Los comandos, sesiones y objetivos se ejecutan de
  forma síncrona. Al salir guarda el historial y anuncia el cierre.
- `session.py:287`, propiedad `prompt`: conserva el prompt de dos líneas,
  nombre truncado, trust, sesión y marcador de reporte. Debe mantenerse
  idéntica en fallback.
- `render.py:130-150`, `render_approval_prompt`: utiliza `input(question)`
  o un lector inyectado; con lector imprime primero la pregunta y hace flush.
- `commands.py`, `_read_answer`: entrada secundaria para confirmaciones.
- `approval.py`, `edit_arguments` y `make_approval_callback`: entrada
  interactiva adicional durante una operación; debe coordinarse con la TUI.
- `main.py`, `select_engagement`: selección previa al REPL mediante
  `(reader or input)`. No necesita convertirse en el prompt principal.

## Inventario exacto de salida del REPL

Las ubicaciones son las del commit base, antes de cualquier migración.

### session.py

- `print` directos: 441 (`detach_session`), 736 (Ctrl+C), 740 (EOF).
- `attach_session`: `render_error` 422/426; `render_session_attached` 431.
- `check_active_session`: `render_session_died` 451.
- `invoke_tool`: `render_error` 477/506/520.
- `run_session_command`: `render_error` 614; `render_session_output` 617;
  `render_session_died` 621.
- `run_objective`: `render_error` 629/699; `render_status` 673/716;
  `render_summary` 711; `render_clarification` 715.
- `run_repl`: `render_status` 727/737/756.
- `_render_run_event`: `render_error` 807/809; `render_status` 815.
- `_render_message`: `render_thought` 840; `render_tool_call` 841.
- `_render_observation`: `render_tool_result` 865.

### render.py

Funciones que imprimen a stdout y requieren el punto común de routing:

| Función | Líneas con print |
| --- | --- |
| render_thought | 71 |
| render_tool_call | 76, 79, 82, 85, 88 |
| render_tool_result | 94, 98, 118, 127 |
| render_approval_prompt | 139-145, 149 |
| render_trust_mode | 155-158, 161-163 |
| render_summary | 175-178, 180, 182, 188-189 |
| render_answer | 194-195, 197-198 |
| render_error | 203 |
| render_status | 208 |
| render_clarification | 213-214 |
| render_engagement | 220, 222-227, 236, 239 |
| render_messages | 246, 253 |
| render_findings | 263 |
| render_session_list | 295, 305-306, 308 |
| render_session_attached | 314, 321-323 |
| render_session_died | 329-330 |
| render_session_output | 343 |

### commands.py y aprobaciones

Hay salida directa en `cmd_scope`, `cmd_tools`, `cmd_history`, `cmd_clear`,
`cmd_export`, `cmd_approvals`, `_read_answer`, `cmd_session`, `cmd_detach`,
`_kill_one`, `cmd_kill_session`, `cmd_findings`, `_report_generate`,
`_report_export`, `cmd_timeline`, `cmd_trust`, `cmd_help` y `cmd_exit`.
Además llaman a `render.*`; `cmd_ask` presenta la respuesta con
`render.render_answer`. `cmd_help` obtiene los comandos de `COMMANDS`.

`approval.py` también imprime en `_show_definition` (74-78, 80),
`edit_arguments` (89) y el callback de aprobación (219). Esas salidas deben
convivir con `patch_stdout` y el lector de aprobación sin duplicar prompts.

## Banner, spinner e hilo de eventos

- `_show_banner` (`session.py:346`) llama a `build_banner`/`render_banner`.
  `banner.py:173-174` escribe y vacía stdout directamente. Ocurre antes del
  primer prompt. Se omite si stdout no es TTY o existe `NEXUS_NO_BANNER`.
- `spinner.py`, `Spinner._write` (113): escribe a su stream, stderr por
  defecto, desde un hilo daemon. Se activa actualmente con stdout/stderr TTY
  y color habilitado. `OmniSession._spinner_enabled` añade `NEXUS_NO_SPINNER`.
  `invoke_tool` y `run_objective` usan su context manager.
- `run_objective` inicia el daemon `omni-event-stream` (667-679), ejecuta
  `asyncio.run(run_react_loop(...))` en el hilo principal y detiene/espera al
  daemon en `finally` (704-706).
- `_stream_run_events` (760) sondea cada `stream_interval` (0,5 s por defecto)
  mediante `_drain_stream` (776), con un drenaje final. Lee eventos del run y
  mensajes persistidos; las funciones `_render_run_event`, `_render_message`
  y `_render_observation` imprimen indirectamente mediante `render.*`.
  El hilo no llama a `print` directamente. El router debe instalarse también
  en este hilo: un contexto del hilo principal no basta por sí solo.

## Flags y persistencia existentes

- `main.main` construye `OmniSession` con store, tenant, engagement, cliente
  LLM, max_iterations, run_id (`--resume`), trust_mode y no_color.
- `--objective` evita el REPL. No existe `--no-tui`.
- `omni.py` procesa configuración/onboarding/doctor y después delega en
  `main.main`; importar el entry point no arranca la CLI.
- `_install_readline` (132) usa `resolve_xdg_paths().state_dir / 'history'`,
  carga historial y limita a 1000 entradas. `_save_readline_history` (150)
  escribe al salir y aplica permisos 600; el directorio se crea con 700.
- XDG solo admite overrides absolutos; por defecto el historial ya vive en
  `~/.local/state/omni/history`. FileHistory y readline tienen formatos
  distintos: la migración debe decidir cómo conservarlos al alternar modos.
- La configuración principal usa un esquema TOML cerrado en
  `nexus_core/config/schema.py`. Añadir una sección arbitraria invalidaría
  la configuración. Dentro del alcance autorizado puede utilizarse un archivo
  de preferencias TUI separado bajo el directorio XDG de configuración.
- El store expone `usage_total` y el ledger de consumo por run; los clientes
  LLM tienen tokens de entrada/salida. Falta verificar la disponibilidad de
  costes y evitar inventar tarifas o duplicar consumo entre actualizaciones.

## Discrepancias y aspectos pendientes

1. La demo por pipe pide banner, pero el comportamiento existente y su test
   `test_banner_not_shown_when_not_tty` lo ocultan. La regla de fallback
   idéntico requiere conservar esa ausencia de banner.
2. Devolver `""` tanto por EOF como por línea vacía exige distinguir EOF para
   evitar un bucle infinito del REPL.
3. Un PromptSession que solo corre durante la lectura no mantiene una barra
   activa durante una operación síncrona. Se necesita resolver su ciclo de
   vida para cumplir el estado busy y el input persistente.
4. El despacho al loop de prompt_toolkit desde el daemon debe verificarse;
   no basta asumir que llamar a `run_in_terminal` desde cualquier hilo
   garantiza el routing correcto.
5. La misión autoriza expresamente `.env.example`, los nuevos tests y estos
   informes en sus fases, además de la lista general de archivos editables.

## Resultado del reconocimiento

La verificación de base falló antes de implementar. Se detuvo la misión
según la instrucción «Si algo falla, PARA y reporta». Este reconocimiento es
el registro histórico del código base. La migración se reanudó después; los
bloqueos quedaron resueltos. Véanse `TUI_RESULT.md` y `TUI_FIX_RESULT.md`
para la validación final.
