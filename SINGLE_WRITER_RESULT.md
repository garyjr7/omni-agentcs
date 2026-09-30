# SINGLE_WRITER_RESULT — Frontera única de escritura + /ask contextual + Markdown

Rama: `fix/single-writer-boundary`. Base: `feat/tui-live-stream` (`824dbc7`).
Cambios limitados a `nexus_core/cli/**`, `nexus_core/utils/logger.py`,
`nexus_core/tests/**`, `README.md`, `.env.example` y `.env` (local).
No se tocó kernel, scope, agent, tools, integrations ni provisioner
(verificado con `git status`). Cero dependencias nuevas.

## 1. Frontera única de escritura

**Causa raíz.** `NexusLogger` instalaba `logging.StreamHandler(sys.stdout)`,
que guarda una referencia al stdout que existía **antes** de que la TUI lo
reemplace. Sus logs seguían escribiendo al terminal físico y movían el cursor
detrás del renderer.

**Fix.** `nexus_core/utils/logger.py`: nuevo `DeferredStreamHandler`, que
resuelve `sys.stdout`/`sys.stderr` en cada `emit` (no al construirse) y contiene
cualquier fallo del stream. Sustituye al `StreamHandler` fijo.

**Refuerzos.** `nexus_core/cli/tui/output.py`:

- `TuiStreamProxy`: proxy con soporte de introspección (`isatty`, `fileno`,
  `__getattr__`) que envía toda escritura al scrollback.
- `capture_output(session)`: instala los proxies de stdout/stderr **y** un
  `sys.excepthook` que vuelca las excepciones no capturadas (excepto
  `KeyboardInterrupt`) al mismo buffer. Restaura ambos al salir, incluso con
  excepción. Sigue siendo exclusivo de la TUI: el fallback no instala nada.

Con esto, toda escritura visible durante el REPL pasa por el router: output del
agente, tools, logs de Python, warnings y mensajes de librerías.

## 2. `.env` a warning

- `.env.example`: ya traía `NEXUS_LOG_LEVEL=warning` (documentado).
- `.env` real: cambiado de `info` a `warning` (archivo local, gitignored).
- README "Logging": documentada la precedencia entorno → `.env` → `warning`.

## 3. `/ask` contextual

`nexus_core/cli/commands.py`: `_build_ask_system_prompt(session)` construye el
system prompt con el estado real: comandos de `COMMANDS`, tools durables
(`durable_tool_definitions`), engagement activo con dominios/CIDRs y proveedor
LLM resuelto. `_ask_messages` lo usa. La persona base (`ASK_SYSTEM_PROMPT`) se
conserva como encabezado.

## 4. Markdown

`nexus_core/cli/tui/markdown.py`:

- `<br>`, `<br/>`, `<br />` (case-insensitive) → salto de línea real.
  Dentro de una celda de tabla el salto es **intra-celda**, de modo que la fila
  no se parte (regresión detectada durante la misión y cubierta por test).
- Ancho de lectura por defecto 100 columnas; `cmd_ask` usa
  `min(100, columnas_terminal - 4)`. Envoltura por palabras respetando ANSI.
- Tablas adaptables: presupuesto por columna y recorte de celdas largas con `…`.
- Encabezados con color: H1 `1;4;36` (negrita+subrayado+cian), H2 `1;36`,
  H3+ negrita.

## 5. Verificación

```
=== imports ===            logger, tui.session, tui.output, tui.markdown, commands, omni  → todos OK
=== tests (NO_COLOR=1) === 1074 passed, 18 skipped in 41.47s
=== tests (sin NO_COLOR) === 1074 passed, 18 skipped in 41.60s
=== ruff (F,E9) ===        All checks passed
```

Baseline antes de la misión: **1041 passed, 18 skipped**. Se añadieron 33 tests
(14 deferred, 6 `/ask` contextuales, 11 markdown, 1 PTY, 1 nivel por defecto).
Los 1041 previos siguen pasando, con y sin `NO_COLOR`.

### PTY real

`nexus_core/tests/integration/test_tui_pty_integrity.py` (marker `pty`) lanza un
`TuiSession` real sobre un `pty` de stdlib con `NEXUS_LOG_LEVEL=info`, emite una
línea INFO, envía entrada y comprueba que el **frame final** (el que ve el
operador tras el repintado de prompt_toolkit) contiene la línea de log
exactamente una vez, integrada en el layout, sin duplicados ni basura.
Pasa en ~3.5 s. Añadido el marker `pty` a `pytest.ini`; CI puede usar
`pytest -m "not pty"`.

### Captura `/ask que puedes hacer` — ANTES vs DESPUÉS

Con proveedor real resuelto (`groq/openai/gpt-oss-120b`).

**ANTES** (system prompt genérico de ciberseguridad) — respuesta de asesor
genérico, sin mencionar la CLI:

```text
OmniAgent ·
  ## Mis capacidades como asistente…
  3. **No ejecuto ni distribuyo herramientas**
     - Solo describo su uso y configuración.
  4. **Ética y legalidad**
     - Insisto en que cualquier actividad ofensiva debe contar con
       autorización explícita del propietario del sistema.
  ## ¿Qué necesitas de mí ahora?
  - **Un caso de uso concreto** (por ejemplo, "quiero explotar una
    vulnerabilidad de SMB en Windows 10" …)
```

**DESPUÉS** (`_build_ask_system_prompt(session)`) — capacidades reales, comandos
y tools exactos, engagement activo:

```text
OmniAgent ·
  ## Capacidades de OmniAgentCS v3.0.0

  | Área | Qué puedo hacer | Comando / Tool |
  |------|----------------|----------------|
  | Gestión de engagement | Ver alcance, historial, timeline, hallazgos | /scope, /history, /timeline, /findings, /approvals |
  | Reconocimiento | Fingerprint HTTP <br> Escaneo Nmap | nexus.recon.httpx, nexus.recon.nmap, nexus.recon.subfinder |
  | Explotación (Metasploit) | Buscar módulos <br> Ejecutar exploits | nexus.exploit.msf_search, nexus.exploit.msf_exploit |
  ...
  **Nota:** Todas las herramientas requieren que el objetivo esté dentro del
  scope firmado del engagement (`scanme-lab`).
```

El renderizado de esa misma respuesta (con `<br>` y tabla ancha) produce una
tabla intacta, celdas recortadas con `…`, saltos intra-celda y ancho máximo 95
≤ 100:

```text
+----------------+------------------+--------------------------------+
| Area           | Que puedo hacer  | Comando                        |
+----------------+------------------+--------------------------------+
| Reconocimiento | Fingerprint HTTP | nexus.recon.httpx, nexus.reco… |
|                | Escaneo Nmap     |                                |
|                | Subdominios      |                                |
+----------------+------------------+--------------------------------+
```

### Parpadeo / corrupción

No hay TTY interactivo en el entorno del agente, así que **no** se afirma una
inspección visual del emulador del operador. Lo verificado es el mecanismo y su
efecto medido: (a) el handler ya no puede escribir fuera del stream actual
(tests de resolución en `emit`); (b) en un PTY real, el log aparece dentro del
frame que gobierna el renderer, una sola vez por frame, y el proceso cierra
limpio (test `pty`). Combinado con `NEXUS_LOG_LEVEL=warning` por defecto, no
queda ninguna escritura fuera del router durante el REPL.

## Archivos

- `nexus_core/utils/logger.py` — `DeferredStreamHandler`; `logging.handlers` explícito.
- `nexus_core/cli/tui/output.py` — `TuiStreamProxy`, `capture_exceptions`, `capture_output`.
- `nexus_core/cli/commands.py` — `_build_ask_system_prompt`, ancho de lectura.
- `nexus_core/cli/tui/markdown.py` — `<br>`, envoltura, tablas adaptables, encabezados.
- `nexus_core/tests/unit/test_logger_deferred.py` (14)
- `nexus_core/tests/unit/test_cli_ask_contextual.py` (6)
- `nexus_core/tests/unit/test_tui_markdown_wrap.py` (11)
- `nexus_core/tests/integration/test_tui_pty_integrity.py` (1, marker `pty`)
- `nexus_core/tests/unit/test_llm_logging_silent.py` — `test_default_log_level_is_warning`.
- `nexus_core/tests/pytest.ini` — marker `pty`.
- `README.md` — "Frontera única de escritura", "Ayuda contextual", Markdown, Logging.
- `.env.example` (ya correcto) y `.env` local.
