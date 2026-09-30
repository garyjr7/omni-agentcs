# SINGLE_WRITER_RECON — Frontera única de escritura al terminal

Rama: `fix/single-writer-boundary` (base `feat/tui-live-stream`, commit `824dbc7`).
Objetivo: inventariar todo escritor que pueda saltarse el router de la TUI
(`nexus_core/cli/tui/output.py`) y corromper el layout del terminal.

## Comandos de inventario

```bash
grep -rn "print(" nexus_core/cli/ | grep -v "#" | grep -v test
grep -rn "sys\.stdout" nexus_core/ | grep -v test
grep -rn "sys\.stderr" nexus_core/ | grep -v test
grep -rn "StreamHandler" nexus_core/ | grep -v test
grep -rn "logging\.getLogger" nexus_core/ | grep -v test
grep -rn "basicConfig" nexus_core/ | grep -v test   # sin coincidencias
```

Router = `render.write` → `tui.output.write` → `TuiOutput`/`PlainOutput`.
Durante el REPL con TUI, `run_repl` abre `capture_output(session)`, que sustituye
`sys.stdout` y `sys.stderr` por un proxy hacia `session.append_scrollback`.

## Inventario

| Archivo:línea | Tipo | ¿Tras arranque del REPL? | ¿Pasa por el router? | Acción |
| --- | --- | --- | --- | --- |
| `nexus_core/utils/logger.py:84` | `logging.StreamHandler(sys.stdout)` | sí (logs durante `/ask` y tools) | **NO** → captura el stdout original al construir | **FIX**: `DeferredStreamHandler` que resuelve `sys.stdout` en cada `emit` |
| `nexus_core/cli/render.py` (todos los helpers) | `write()` | sí | sí (`write` → router) | sin cambio |
| `nexus_core/cli/tui/output.py:16` | `print()` en `PlainOutput` | sí (solo fallback) | N/A (fallback es dueño del terminal) | sin cambio |
| `nexus_core/cli/tui/output.py:64-83` | `redirect_stdout/redirect_stderr` | activo durante `run_repl` | es el router | refactor a `TuiStreamProxy` + `excepthook` |
| `nexus_core/cli/tui/session.py:264,270` | `print()` en `TuiSession.print/append_scrollback` | sí (solo fallback) | N/A | sin cambio |
| `nexus_core/cli/banner.py:173-174` | `sys.stdout.write/flush` | sí, pero **solo en fallback** (la ruta TUI usa `_output.write`) | N/A / sí | sin cambio |
| `nexus_core/cli/spinner.py:69` | `stream = sys.stderr` | solo si el spinner está activo (nunca con TUI) | N/A | sin cambio |
| `nexus_core/cli/live_jobs.py:109-111,120` | `print()` | **no** en el REPL: `watch()` vive en una terminal secundaria dedicada | N/A (proceso aparte) | sin cambio |
| `nexus_core/cli/live_jobs.py` (`show_job`) | `session._output.write` | sí | sí | sin cambio |
| `nexus_core/cli/doctor.py:131-158` | `print()` | no (pre-flight `--doctor`) | N/A | sin cambio |
| `nexus_core/cli/wizard.py:90-162` | `print()` | no (onboarding previo al REPL) | N/A | sin cambio |
| `nexus_core/cli/main.py:93-118` | `print()` | no (selección de engagement previa) | N/A | sin cambio |
| `nexus_core/config/loader.py:49-62` | `print(..., file=sys.stderr)` | no (carga de config previa) | N/A | sin cambio |
| `nexus_core/llm/abstraction.py:58` | `logging.StreamHandler()` | **no**: vive en el fallback `except ImportError` de `get_logger`; `nexus_core.utils.logger` siempre importa | N/A (código muerto) | sin cambio |
| `nexus_core/utils/security.py:122,201` | `logging.getLogger(__name__)` | sí | sí: sin handler propio, el `logging.lastResort` (`_StderrHandler`) resuelve `sys.stderr` en `emit` → proxy | sin cambio |
| `nexus_core/cli/llm_env.py:92` | `logging.getLogger(name).setLevel` | configuración, no escribe | N/A | sin cambio |
| `nexus_core/utils/logger.py:80` | `logging.getLogger(name)` | sí | tras el FIX, sí | FIX |

## Escritores que hoy escapan (conclusión)

1. **`NexusLogger` → `StreamHandler(sys.stdout)` (`logger.py:84`).** Es el único
   consumidor real de escritura directa a un stream físico almacenado. Se
   construye antes de que exista el proxy, de modo que en `emit` escribe al
   terminal real: mueve el cursor sin que prompt_toolkit lo sepa. **Causa raíz
   confirmada por la auditoría.**
2. **`sys.excepthook` por defecto.** Una excepción no capturada escribe el
   traceback a `sys.stderr`; hoy no se instala un hook que lo envíe al buffer.

Todos los demás escritores están o bien antes de que exista el router
(pre-flight), o bien en la ruta de fallback sin TUI, o ya pasan por `write()`.

## Plan del fix

- `nexus_core/utils/logger.py`: `DeferredStreamHandler` (resuelve
  `sys.stdout`/`sys.stderr` en `emit`), sustituyendo el `StreamHandler` fijo.
- `nexus_core/cli/tui/output.py`: `TuiStreamProxy` + `capture_output` que instala
  también un `sys.excepthook` que vuelca al buffer. Restaura ambos al salir.
- `.env` / `.env.example`: `NEXUS_LOG_LEVEL=warning` por defecto.
- Verificación en PTY real (`nexus_core/tests/integration/test_tui_pty_integrity.py`).
