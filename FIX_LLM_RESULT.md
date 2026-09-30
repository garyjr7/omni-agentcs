# FIX_LLM_RESULT — Selección de LLM + logging silencioso + `/ask`

Rama `fix/llm-selection-logging-ask`. Base: `feat/shell-polish-core` (790 tests).
Kernel, scope, tools, agent e integrations **sin tocar** (verificado con
`git status`).

## Criterios de éxito

| Criterio | Estado | Evidencia |
|---|---|---|
| 6 imports OK | ✅ | `banner`, `spinner`, `commands`, `session`, `llm.abstraction`, `omni` |
| 790 tests previos siguen pasando | ✅ | 790 → **847 passed** (57 nuevos, 0 rotos) |
| ≥8 tests de selección LLM | ✅ | `test_llm_selection.py` → **19** |
| ≥6 tests de logging silencioso | ✅ | `test_llm_logging_silent.py` → **17** |
| ≥10 tests de `/ask` | ✅ | `test_cli_ask_command.py` → **15** |
| ≥4 tests de regresión | ✅ | `test_cli_shell_polish_regression.py` → **6** |
| ruff clean, cero TODOs | ✅ | `--select F,E9` → *All checks passed!* |
| `execute_react` usa el LLM real con Groq configurado | ✅ | demo 1: `PRIMARY ELEGIDO: groq / openai/gpt-oss-120b` |
| El banner muestra el proveedor real, no `fake` | ✅ | `provider_summary()` → `('groq/openai/gpt-oss-120b', 1)` |
| Los logs INFO no aparecen por defecto | ✅ | demo 2: 0 líneas `[INFO]`; el REPL completo tampoco |
| `NEXUS_LOG_LEVEL=info` reactiva los logs | ✅ | demo 2b: `03:21:48.378 [INFO] LLMFactory → Groq client created…` |
| `/ask` sin tools ni engagement | ✅ | demo 3 + 3 tests dedicados |
| `/help` lista `/ask` | ✅ | `test_help_lists_ask_command` |
| Las demos confirman el fix con el `.env` real | ✅ | las 3 demos de abajo |

## Ficheros

| Fichero | Cambio |
|---|---|
| `nexus_core/cli/llm_env.py` | **nuevo** (205 líneas): resolución canónica de proveedor + política de logging |
| `nexus_core/cli/commands.py` | `cmd_ask`, `cmd_chat`, `ASK_SYSTEM_PROMPT`, registro en `COMMANDS`, mensaje CVSS honesto |
| `nexus_core/cli/session.py` | propiedad `_llm`, `ask_history`, `_llm_stats` delegado |
| `nexus_core/cli/render.py` | `render_answer` |
| `nexus_core/cli/banner.py` | tip de `/ask` |
| `nexus_core/utils/logger.py` | `_default_level()` desde `NEXUS_LOG_LEVEL`, handler único |
| `nexus_core/llm/abstraction.py` | comentarios (el nivel manda, no el `logger.debug`) |
| `omni.py` | `configure_logging()` + `publish_default_provider()`; import `os` muerto eliminado |
| `nexus_worker.py` | misma resolución canónica (elimina `os.environ["LLM_PROVIDER"]`) |
| `.env.example` | `NEXUS_LOG_LEVEL=warning` documentado |
| `README.md` | `/ask`, sección **Logging**, sección de selección de proveedor |

## Demo 1 — selección correcta de provider

```console
$ NEXUS_LOG_LEVEL=warning .venv/bin/python -c "... publish_default_provider(config) ..."
Providers: ['fake', 'groq']
Groq key presente: True
PRIMARY ELEGIDO: groq / openai/gpt-oss-120b
```

Antes del fix, la misma secuencia daba `fake / nexus-fake-v1`.

## Demo 2 — silencio del logging

```console
$ NEXUS_LOG_LEVEL=warning .venv/bin/python -c "... llm.ask('Dime hola en 3 palabras.', 'Hola') ..."
Respuesta: ¡Hola, qué tal!
```

Sin una sola línea `[INFO]`, y con una respuesta **real de Groq**. Contraste con
el nivel explícito:

```console
$ NEXUS_LOG_LEVEL=info .venv/bin/python -c "... configure_logging(); LLMFactory.create_from_env()"
effective level: 20
03:21:48.378 [INFO] LLMFactory → Groq client created from environment variables.
```

## Demo 3 — `/ask` sin tools

```console
$ printf '/ask cuántas tools tiene el catálogo actual\n/exit\n' | \
    NEXUS_LOG_LEVEL=warning .venv/bin/python omni.py --engagement eng-scanme --no-wizard

• omni listo · tenant=system · engagement=eng-scanme · /help para comandos
┌──(OmniAgentCS)─[scanme-lab]
└─$ 
OmniAgent ·
  En el contexto de **OmniAgentCS** no existe un "catálogo" estático con un número fijo
  de herramientas; más bien, mantenemos una **lista dinámica** …

  | Categoría | Nº aproximado de herramientas |
  |-----------|------------------------------|
  | **Reconocimiento y enumeración** | 45 + |
  …
```

Comprobaciones sobre esa ejecución:

- `grep -c "\[INFO\]"` → **0**.
- Ninguna línea `nexus.recon.*`/`⚙️` (no se ejecutó ninguna tool).
- El prompt vuelve intacto tras la respuesta.

## Verificación ejecutada

```console
$ .venv/bin/python -m pytest nexus_core/tests/unit -q
847 passed in 22.50s

$ .venv/bin/ruff check nexus_core/cli nexus_core/llm nexus_core/utils \
    nexus_core/tests/unit/test_llm_selection.py \
    nexus_core/tests/unit/test_llm_logging_silent.py \
    nexus_core/tests/unit/test_cli_ask_command.py omni.py --select F,E9
All checks passed!
```

Las 2 únicas coincidencias de `NotImplementedError` en `nexus_core/llm/` son
cuerpos de métodos `@abc.abstractmethod` **preexistentes** (`git show HEAD:` las
confirma), no código sin terminar.

## Bugs reales encontrados y corregidos

1. **`publish_default_provider` publicaba un proveedor sin credenciales.**
   Primer borrador: publicaba cualquier `LLM_PROVIDER`/config distinto de `fake`
   sin comprobar que tuviera clave. Con `config.toml` en `groq` y sin
   `GROQ_API_KEY`, el entorno decía `groq` mientras `select_llm_client` devolvía
   `fake` — el mismo tipo de mentira que el bug original. Ahora solo se publica
   un proveedor que `available_providers()` puede construir.
2. **Tests unitarios llamando a la API real.** Al arreglar el bug #1, la suite
   empezó a resolver `groq` desde el `.env` real: 782 tests "pasaban" pero
   tardaban **160 s** con `429 Too Many Requests` y `413 Payload Too Large`.
   Arreglado con un fixture en `test_cli_banner_integration.py` que fija
   `NEXUS_LLM_DEFAULT_PROVIDER=fake` **dependiendo de `onboarding_env`** (ese
   fixture hace `os.environ.clear()`, así que fijarlo antes se perdía). La suite
   vuelve a ~21 s y no toca la red.
3. **`get_logger` apilaba un `StreamHandler` por llamada.** Cada
   `create_from_env()` añadía un handler nuevo al mismo logger: las líneas se
   duplicaban (y con 7 proveedores, se multiplicaban). El handler de consola se
   instala ahora una sola vez, marcado con `_nexus_console`.
4. **Mensaje de CVSS engañoso en `/report`.** Imprimía "LLM (vector validado
   localmente)" solo porque el usuario pasó `--llm-cvss`, aunque el handler
   hubiera caído a la heurística por falta de proveedor. El texto ahora dice
   "LLM solicitado (… heurística si no hay proveedor)".

## Decisiones de diseño no cubiertas por el prompt

1. **La lógica canónica vive en `nexus_core/cli/`, no en `kernel/`.** La misión
   prohíbe tocar `nexus_core/kernel/**`, así que `llm_env.py` se colocó en
   `cli/`. El kernel sigue teniendo `select_llm_client()` como **único punto que
   decide**; `llm_env.py` solo garantiza que el entorno que el kernel lee sea
   correcto. Ningún consumidor duplica la lógica de selección.
2. **`NEXUS_LLM_DEFAULT_PROVIDER` explícito no se valida.** Si el operador lo
   fija a un proveedor sin credenciales, se respeta y `select_llm_client` cae a
   `fake` — que es el comportamiento documentado del kernel. Los *aliases*
   heredados (`LLM_PROVIDER`, config) sí se validan, porque ahí es donde el
   `fake` obsoleto causaba daño silencioso.
3. **El nivel manda, no la severidad del mensaje.** Primer intento: bajé las
   trazas de construcción a `logger.debug()`. La demo de verificación mostró que
   entonces `NEXUS_LOG_LEVEL=info` seguía sin mostrarlas, incumpliendo
   "`NEXUS_LOG_LEVEL=info` reactiva los logs". Revertido a `info`: un solo
   interruptor (`NEXUS_LOG_LEVEL`) controla todo el ruido interno.
4. **`configure_logging()` se llama en cada entry point, no en el import.** Es
   obligatorio porque `get_logger` reconfigura su logger en cada instanciación
   (ese es el bug #2a); hacerlo una vez al importar no serviría.
5. **`/ask` mantiene contexto local, no durable.** `session.ask_history`
   (últimos 20 mensajes) permite repreguntar sin crear conversación, run ni
   evento de auditoría. Es lo que pedía el encargo ("NO persiste, NO audita") y
   lo que separa `/ask` de `run_objective`.
6. **`/ask` resuelve el LLM de forma perezosa** vía la propiedad `_llm`. El
   prompt asumía `session._llm`; se implementó como propiedad que llama a
   `build_llm_client()` si la sesión se construyó sin cliente, para que el
   comando funcione en cualquier camino de arranque.
7. **`cmd_ask` captura cualquier excepción del modelo.** El REPL no debe morir
   por un `429`; se imprime el error y la sesión sigue. Un intercambio fallido no
   contamina el historial local.
8. **`/chat` es un alias real, no un duplicado.** Delega en `cmd_ask`, así que
   ambos comparten comportamiento y tests.
9. **Se conservó `_select_client()` en el kernel.** `execute_llm` y
   `execute_chat` usan esa ruta (con `model_route` explícito y
   `NEXUS_ALLOW_MODEL_FALLBACK`), que es una decisión distinta: un `model_route`
   por tarea no es lo mismo que el proveedor por defecto del operador. Cambiarlo
   habría alterado el contrato de esas tareas sin necesidad.
10. **El fixture de tests que fija `fake` depende explícitamente de
    `onboarding_env`.** El orden de fixtures de pytest es la única forma de
    garantizar que el pin sobreviva al `os.environ.clear()` de ese fixture; está
    documentado en el docstring para que no se "limpie" en el futuro.

## Nota sobre el alcance de la verificación

El `.env` real de este host tiene `LLM_PROVIDER=fake` **y** `GROQ_API_KEY`
válida, que es exactamente el escenario del bug: por eso las demos 1–3 son
reproducciones fieles del fallo y de su corrección. La suite unitaria, en cambio,
queda aislada de la red (`fake` por defecto en los tests que invocan
`omni.main`), para que no dependa de cuotas ni de conectividad.