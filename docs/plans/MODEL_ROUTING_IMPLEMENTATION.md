# Enrutador de modelos dinámico — implementación

**Fecha:** 2026-10-28 · **Alcance:** que cada tipo de turno (planificar,
ejecutar, resumir, informar) corra en el modelo que el operador elija, que un
fallo de ese modelo se reintente en **otro proveedor**, y que el run diga
siempre qué modelo usó y por qué.

**Punto de partida (auditoría de `nexus_core/kernel/model_router.py`):** el
`ModelRouter` existente no es el sitio donde vive esta decisión. Recibe clientes
**ya construidos** y los enruta por *nombre de ruta durable* (`route`), con
presupuesto de tokens por run y cortacircuitos por proveedor; no sabe qué está
haciendo el agente, y no aparece en la ruta real del bucle ReAct (solo lo usa un
test). Y `select_llm_client()` construía un único `NexusLLM` con una cadena de
proveedores, es decir **un modelo por proveedor para todo el run**: el plan, la
ejecución y el resumen compartían proveedor, modelo y temperatura.

Lo que faltaba era una capa por encima: *dado un tipo de tarea, qué
proveedor/modelo*, con la configuración como única fuente de verdad. Eso es
`DynamicModelSelector`, y no toca `ModelRouter`: el router durable sigue
haciendo su trabajo (presupuesto y cortacircuitos) cuando alguien registre rutas
durables, y el selector decide qué cliente entra en el bucle.

---

## 1. Archivos modificados y creados

| Archivo | Cambio |
|---|---|
| `nexus_core/config/schema.py` | **Nuevo** `[model_routing]`: `RouteTarget` (provider/model/fallbacks), `ModelRoutingConfig` con `enabled` y los cuatro perfiles, `ROUTING_TASKS`, `is_default()`. El escritor TOML emite `[model_routing.<tarea>]` solo para los perfiles fijados; `_parse_routing` valida proveedor, modelo, lista de fallbacks y claves desconocidas. |
| `nexus_core/llm/dynamic_selector.py` | **Nuevo.** `ModelTarget`, `RoutingDecision`, `resolve_route` (puro), `DynamicModelSelector`, `RoutedLLM` (cliente sustituto con fallback y journaling), `build_model_selector`, `routed_for_task`, `select_llm_for_task`, `describe_routing`. |
| `nexus_core/agent/react_coordinator.py` | `model_selector` opcional; `_model_client(task, journal=…)` es el único punto por el que el bucle pide cliente. Turno del ejecutor → `"executor"` (+ evento `model.route`); compactación de contexto → `"reflection"`. |
| `nexus_core/agent/react.py` | `run_react_loop(..., model_selector=…)`: el motor no lee la config por su cuenta (un test o una librería no deben depender del `config.toml` de quien ejecuta); `None` = comportamiento histórico. |
| `nexus_core/cli/session.py` | `_model_selector` (con `MeteredClient` alrededor de cada cliente elegido, para que el coste de la TUI sobreviva al cambio de modelo) y el turno de planificación por `routed_for_task("planner", …)`. |
| `nexus_core/cli/headless.py` | Resuelve el selector una vez por run y lo pasa al bucle; el PLAN MODE también pasa por el perfil `planner`. |
| `nexus_core/tools/handlers/report_generate.py` | El scoring CVSS del informe usa `select_llm_for_task("reporting")`. |
| `nexus_core/cli/doctor.py` | Sección **Enrutamiento de modelos**: estado, modelo por tarea, `efectivo` cuando el pin no se puede honrar y fallbacks; también en `--doctor --json` bajo `model_routing`. |
| `nexus_core/tests/unit/test_model_routing.py` | **Nuevo**, 25 tests: parseo/round-trip/validación, selección por tarea, herencia, pin sin clave, clonado mismo proveedor, fallback entre proveedores, presupuesto que **no** se reintenta, journaling del turno real del bucle, y doctor. |

Sin dependencias nuevas.

---

## 2. `[model_routing]` en `~/.config/omni/config.toml`

```toml
[model_routing]
enabled = true

[model_routing.planner]        # planificación del engagement
provider = "openai"
model = "o3"
fallbacks = ["anthropic/claude-sonnet-4-20250514", "deepseek"]

[model_routing.executor]       # cada turno del bucle ReAct
provider = "deepseek"
model = "deepseek-flash"
fallbacks = ["groq/qwen/qwen3.8-27b"]

[model_routing.reflection]     # compactación de contexto
provider = "deepseek"
model = "deepseek-flash"

[model_routing.reporting]      # scoring CVSS del informe
provider = "groq"
model = "qwen/qwen3.8-27b"
```

Reglas:

* **Perfil ausente = heredar.** Sin sección, esa tarea usa
  `[llm] default_provider`/`default_model`, que es el comportamiento de siempre.
  Por eso una config sin `[model_routing]` (o con `enabled = false`) no cambia
  nada: `build_model_selector` devuelve `None` y el bucle usa el cliente con el
  que arrancó, byte por byte.
* **`model` sin `provider`** usa el proveedor por defecto con ese modelo.
* **`fallbacks`** acepta `"proveedor/modelo"` o `"proveedor"` (reutiliza el
  modelo configurado de ese proveedor). Se prueban **después** del principal y
  los de **otro proveedor primero**: es lo que sobrevive a un endpoint caído, una
  key revocada o una caída del proveedor. `fake` se rechaza como fallback (daría
  una respuesta de mentira en vez de un error visible).
* **Sin `fallbacks`**, cualquier otro proveedor con clave utilizable pasa a ser
  backup implícito. No hay que enumerarlos.
* **Un pin a un proveedor sin clave** no rompe el run: esa tarea hereda el
  default y `--doctor` lo dice (`source = "config"`, `effective` distinto).
* Se valida al cargar: proveedor inexistente, perfil con nombre desconocido,
  fallback repetido o tipo incorrecto hacen que `load_config` use defaults y
  respalde el fichero, como cualquier config corrupta.

---

## 3. Flujo de ejemplo

```
operador: omni --headless --objective "comprometer 10.0.0.1 y capturar user.txt"
        │
        ├─ PLAN MODE      perfil planner  → openai/o3
        │                 escribe loot/ENGAGEMENT_PLAN.md (5–12 TODOs)
        │                 journal: model.route {task: planner, provider: openai, model: o3}
        │
        ├─ turno 1        perfil executor → deepseek/deepseek-flash
        │                 acción: nexus.recon.nmap -sV 10.0.0.1 → 22/tcp, 80/tcp
        │                 journal: model.route {task: executor, provider: deepseek, model: deepseek-flash,
        │                                        source: config, reason: "[model_routing.executor] fija …"}
        │
        ├─ turno 2        perfil executor → deepseek/deepseek-flash
        │                 deepseek responde 429 / timeout
        │                 journal: model.fallback {task: executor,
        │                                        from: deepseek/deepseek-flash,
        │                                        to: groq/qwen/qwen3.8-27b,
        │                                        reason: rate_limit, attempt: 1}
        │                 el turno continúa con groq: la acción y el journal no se pierden
        │
        └─ informe        perfil reporting → groq/qwen/qwen3.8-27b (CVSS best-effort)
```

Con el ejemplo de la sección 2 el backup del ejecutor es groq; si el operador
prefiere `gpt-5.6-sol` como red de seguridad, basta
`fallbacks = ["openai/gpt-5.6-sol"]` (o añadirlo al final de la lista): el orden
de la lista es el orden de intento, con los de otro proveedor por delante.

Cada transición se escribe en el journal del run (`kernel_run_events`) **antes**
de la llamada, así que un `provider_error` posterior sigue dejando a la vista qué
modelo falló y qué política lo eligió.

---

## 4. Comprobación

```bash
# política activa tal cual la leerá el próximo run
omni --doctor
#   Enrutamiento de modelos:
#     estado:             activo (default deepseek/deepseek-flash)
#     planner     openai/o3  [config]
#                 efectivo: deepseek/deepseek-flash     <- no hay key de openai
#                 fallback: anthropic/claude-sonnet-4-20250514, deepseek/deepseek-flash
#                 motivo:   [model_routing.planner] fija openai/o3; sin clave utilizable…
#     executor    deepseek/deepseek-flash  [config]
#                 fallback: groq/qwen/qwen3.8-27b
#     reflection  deepseek/deepseek-flash  [inherit]
#     reporting   groq/qwen/qwen3.8-27b    [config]

omni --doctor --json | python -c "import json,sys;print(json.load(sys.stdin)['model_routing'])"
```

En el journal de un run:

```sql
SELECT sequence, event_type, payload FROM kernel_run_events
 WHERE run_id = ? AND event_type IN ('model.route', 'model.fallback')
 ORDER BY sequence;
```

Tests: `pytest nexus_core/tests/unit/test_model_routing.py -q` (25). El resto de
la suite sigue verde salvo los 2 fallos preexistentes de `test_bench_runner`
(exigen `config.toml` con `scope.signing_secret`).

---

## 5. Límites conocidos

* `RoutedLLM.stream()` no hace fallback a mitad de stream: repetir en otro
  proveedor duplicaría la respuesta visible. El bucle ya reintenta el turno
  completo con `complete()` cuando el stream falla, y ahí sí entran los backups.
* Un `PermissionError` de presupuesto **no** se reintenta en otro proveedor:
  gastaría justo los tokens que el presupuesto acaba de denegar.
* El router por ruta durable (`ModelRouter`) sigue fuera de la ruta ReAct; si en
  el futuro se registran rutas durables, el selector puede alimentarlo con
  clientes ya resueltos sin cambiar la config.
