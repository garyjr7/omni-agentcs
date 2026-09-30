# FIX_LLM_RECON — Diagnóstico de los 3 bugs

Rama `fix/llm-selection-logging-ask`. Base: `feat/shell-polish-core` (790 tests
en verde). Los tres bugs se **reprodujeron primero** contra el `.env` real de
este host; abajo están las salidas literales.

---

## BUG #1 — `execute_react` corre con `fake` aunque Groq está configurado

### Diagnóstico: **Caso C** (confirmado, con matiz importante)

El prompt de la misión planteaba tres hipótesis. La correcta es la **C**
(`LLM_PROVIDER=fake` en `.env` sobreescribe la selección), pero la causa raíz
exacta no es `_select_client` ni `select_llm_client`: es la **traducción del
alias `LLM_PROVIDER` a `NEXUS_LLM_DEFAULT_PROVIDER` que hacen los entry points**.

### Reproducción

```console
$ .venv/bin/python -c "
import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path('.env'), override=False)
print('GROQ_API_KEY en os.environ:', 'GROQ_API_KEY' in os.environ, bool(os.environ.get('GROQ_API_KEY')))
print('LLM_PROVIDER            :', repr(os.environ.get('LLM_PROVIDER')))
print('NEXUS_LLM_DEFAULT_PROVIDER:', repr(os.environ.get('NEXUS_LLM_DEFAULT_PROVIDER')))
from nexus_core.llm.abstraction import LLMFactory
clients = LLMFactory.create_from_env()
print('Keys de create_from_env:', list(clients.keys()))
"

GROQ_API_KEY en os.environ: True True
LLM_PROVIDER            : 'fake'
NEXUS_LLM_DEFAULT_PROVIDER: None
Keys de create_from_env: ['fake', 'groq']
```

Puntos clave:

- `GROQ_API_KEY` **sí** está presente en `os.environ` (hipótesis A descartada).
- `create_from_env()` devuelve `['fake', 'groq']`: `fake` primero por diseño
  (es el fallback offline), y `groq` construido correctamente. La lógica de
  `select_llm_client()` **sí filtra** `fake` (hipótesis B descartada).
- `LLM_PROVIDER=fake` está definido en `.env`.

El paso que lo rompe es `omni.py::main`:

```python
os.environ.setdefault(
    "NEXUS_LLM_DEFAULT_PROVIDER", os.getenv("LLM_PROVIDER", config.llm.default_provider)
)
```

`os.getenv("LLM_PROVIDER")` devuelve `"fake"` → se publica
`NEXUS_LLM_DEFAULT_PROVIDER=fake`. Después, en `select_llm_client()`:

```python
selected = os.getenv("NEXUS_LLM_DEFAULT_PROVIDER")   # "fake"
if selected:
    # Missing keys use offline fake, never silently choose a different cloud.
    providers = [selected] if selected in clients else ["fake"]
```

La rama "selección explícita" gana, así que el primary pasa a ser `fake`.

### Reproducción end-to-end (lo que ve el usuario)

```console
$ .venv/bin/python -c "
# exactamente lo que hace omni.py tras apply_environment(config, paths)
os.environ.setdefault('NEXUS_LLM_DEFAULT_PROVIDER', os.getenv('LLM_PROVIDER', config.llm.default_provider))
from nexus_core.kernel.runtime import select_llm_client
llm = select_llm_client()
print('primary:', llm.primary.config.provider.value, '/', llm.primary.config.model)
"

config.llm.default_provider : groq
os.getenv(LLM_PROVIDER)     : fake
-> NEXUS_LLM_DEFAULT_PROVIDER: fake
select_llm_client() primary  : fake / nexus-fake-v1
             fallback        : None
```

### Cadena causal completa

| Paso | Valor |
|---|---|
| `.env` | `LLM_PROVIDER=fake` (heredado del `.env.example`) |
| `config.toml` | `llm.default_provider = "groq"` (lo que el usuario eligió en el wizard) |
| `omni.py` | `os.getenv("LLM_PROVIDER")` → `"fake"` → publica `NEXUS_LLM_DEFAULT_PROVIDER=fake` |
| `select_llm_client()` | rama "selección explícita" → `primary = fake`, `fallback = None` |
| `execute_react()` | `llm = select_llm_client()` → ReAct corre con el LLM determinista offline |

Síntoma visible: 12 iteraciones con `✗ respuesta no parseable del LLM: response
does not contain a parsable JSON object` (el `fake` no produce el JSON del
protocolo ReAct), y `estado=max_iterations`.

### El mismo bug en el worker

`nexus_worker.py` tenía una variante aún más frágil:

```python
os.environ.setdefault("NEXUS_LLM_DEFAULT_PROVIDER", os.environ["LLM_PROVIDER"])
```

Sin `.env` cargado, esto lanzaba `KeyError: 'LLM_PROVIDER'`; con él, publicaba
`fake` igual que el CLI.

### Dos consumidores, una sola decisión

Hoy conviven tres resoluciones distintas del mismo concepto:

| Consumidor | Cómo decide |
|---|---|
| `omni.py` | `os.getenv("LLM_PROVIDER", config.llm.default_provider)` |
| `nexus_worker.py` | `os.environ["LLM_PROVIDER"]` |
| `kernel/runtime.select_llm_client` | `NEXUS_LLM_DEFAULT_PROVIDER` + "primer real" |
| `kernel/runtime._select_client` | `LLM_PROVIDER` + `NEXUS_ALLOW_MODEL_FALLBACK` |
| `cli/session._llm_stats` (banner) | lectura propia del entorno |

`execute_react`, `execute_agent` y `build_llm_client` **ya** llaman a
`select_llm_client()`; el problema no está en ellos sino en que los entry points
publican un valor equivocado antes de que se llame.

### Fix aplicado

Nuevo módulo **`nexus_core/cli/llm_env.py`** como única fuente de verdad
(`publish_default_provider`, `resolve_provider`, `available_providers`,
`provider_summary`). Lo llaman `omni.py`, `nexus_worker.py` y el banner, y su
precedencia es:

1. `NEXUS_LLM_DEFAULT_PROVIDER` explícito (gana siempre, sin validar: es una
   elección deliberada del operador).
2. `LLM_PROVIDER`, luego `config.llm.default_provider` — **solo si ese
   proveedor tiene credenciales**.
3. El primer proveedor real disponible.
4. `fake` si no hay ninguno.

Regla clave: un alias `fake` heredado nunca desplaza a un proveedor real ya
configurado, y un proveedor **sin credenciales nunca se publica** (si no,
`select_llm_client` devolvería `fake` igualmente, pero el entorno mentiría
diciendo `groq`).

Resultado medido tras el fix:

```console
published: groq
NEXUS_LLM_DEFAULT_PROVIDER: groq
summary: ('groq/openai/gpt-oss-120b', 1)
select_llm_client primary: groq / openai/gpt-oss-120b
fallback: None
```

---

## BUG #2 — Los logs `[INFO]` rompen el spinner

### Causa raíz (doble)

**a) `NexusLogger` se reconfigura en cada instanciación.** En
`nexus_core/utils/logger.py`:

```python
self.logger.setLevel(logging.DEBUG)          # ← fuerza DEBUG siempre
console_handler = logging.StreamHandler(sys.stdout)   # ← handler NUEVO cada vez
self.logger.addHandler(console_handler)
```

`get_logger("LLMFactory")` se llama en **cada** `LLMFactory.create_from_env()`,
así que el nivel volvía a `DEBUG` y se apilaba un `StreamHandler` extra por
llamada. Subir el nivel desde fuera no servía: la siguiente llamada lo revertía.

**b) El formateador de consola no aplica el nivel.** El handler escribe en
`sys.stdout` y `NexusConsoleFormatter` no consulta `record.levelno`; el filtrado
depende exclusivamente del nivel del logger. Por eso hay que arreglar el nivel en
origen.

Medición del ruido real (una sola llamada a `create_from_env` con 1 proveedor
configurado, antes del fix):

```text
02:30:44.161 [INFO] LLMFactory → Groq client created from environment variables.
```

Con 7 proveedores serían 7 líneas, más 2 por cada llamada al modelo
(`Attempting completion with primary provider` + `LLM call successful`), todas
intercaladas en la línea del spinner.

### Fix aplicado

1. `nexus_core/utils/logger.py`: `_default_level()` lee `NEXUS_LOG_LEVEL`
   (por defecto **warning**) y el handler de consola se instala **una sola vez**
   por nombre (marcado con `_nexus_console`), de modo que no se duplican líneas.
2. `nexus_core/llm/abstraction.py`: las 4 trazas de construcción de cliente
   siguen en `info`. Primer intento: bajarlas a `debug`, pero la demo de
   verificación mostró que entonces `NEXUS_LOG_LEVEL=info` tampoco las mostraba,
   incumpliendo el criterio "`NEXUS_LOG_LEVEL=info` reactiva los logs". El nivel
   es el único interruptor; las trazas se quedan en `info`.
3. `nexus_core/cli/llm_env.py::configure_logging()` aplica el nivel a los
   loggers ruidosos (`LLMFactory`, `NexusLLM`, `LLMClient.*`) y lo llaman
   `omni.py` y `nexus_worker.py` **después** de `apply_environment`, porque
   `get_logger` vuelve a reconfigurar.
4. `.env.example`: nueva variable documentada
   `NEXUS_LOG_LEVEL=warning`.

Verificación (misma llamada real a Groq, antes/depués):

```console
$ NEXUS_LOG_LEVEL=warning ... llm.ask(...)      # antes: 3 líneas [INFO]
provider: groq
Respuesta: ¡Hola, qué tal!

$ NEXUS_LOG_LEVEL=info ... configure_logging()  # reactivado a demanda
level: 20
```

---

## BUG #3 — El REPL manda cualquier línea a ReAct

### Causa

`OmniSession.run_repl()` tiene exactamente dos rutas para una línea sin `/`:

```python
if self.active_session_uuid:
    self.run_session_command(text)   # modo sesión
    continue
self.run_objective(text)             # todo lo demás → ReAct
```

No hay ninguna ruta conversacional. Una pregunta como "qué puedo hacer" entra a
`run_react_loop`, el modelo intenta producir el JSON del protocolo y el bucle
consume las 12 iteraciones para terminar en `max_iterations`.

### Fix aplicado

- `nexus_core/cli/commands.py`: nuevos `cmd_ask` y `cmd_chat` (alias),
  registrados en `COMMANDS` (`/ask`, `/chat`).
- `cmd_ask` construye `system prompt + historial local + pregunta` y llama a
  `llm.complete(...)` **sin tools y sin ReAct**; envuelto en `Spinner`.
- El historial vive en `OmniSession.ask_history` (últimos 20 mensajes) y **no**
  se persiste: no hay run, no hay conversación durable, no hay evento de
  auditoría.
- `nexus_core/cli/render.py`: `render_answer` para dar formato a la respuesta.
- `nexus_core/cli/banner.py`: nuevo tip mencionando `/ask`.
- `/help` lista `/ask` automáticamente (recorre `COMMANDS`).

---

## Hallazgo adicional: el mensaje de `/report` sobre CVSS era engañoso

No estaba en el encargo, pero salió al revisar la ruta de LLM. `cmd_report`
imprimía siempre:

```python
"LLM (vector validado localmente)" if llm_cvss else "heurística determinista (...)"
```

`llm_cvss` es lo que pidió el usuario, no si el LLM llegó a usarse: el handler
cae a la heurística cuando no hay proveedor. Ahora el mensaje refleja la fuente
real (`cvss_source` que ya devuelve el handler: `llm` / `tool` / `heuristic`).

---

## Riesgo detectado y corregido de paso: tests que llamaban a la nube

Al arreglar el bug #1, la suite unitaria empezó a resolver `groq` desde el `.env`
real y **los tests hicieron llamadas HTTP de verdad** a la API de Groq
(782 passed pero 160 s de ejecución, con `429 Too Many Requests` y
`413 Payload Too Large` en los logs). Eso es exactamente lo que un test unitario
no debe hacer.

Corrección: `test_cli_banner_integration.py` fija
`NEXUS_LLM_DEFAULT_PROVIDER=fake` en un fixture que **depende de
`onboarding_env`** (ese fixture hace `os.environ.clear()`, así que fijarlo antes
se perdía). La suite vuelve a 20 s y no toca la red.