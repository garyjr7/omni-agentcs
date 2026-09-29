# NMAP_RESULT — Registro central + nexus.recon.nmap durable

Fecha: 2026-09-29
Rama: `feat/nmap-tool`
Entorno: `.venv/bin/python` (Python 3.12.3), `pytest 9.1.1`, `ruff 0.16.1`.
`nmap` no está instalado en este host; `rg` tampoco. La DNS sí funciona.

## Cambios

- **Nuevo** `nexus_core/tools/`:
  - `registry.py` → `durable_tool_definitions(tenant_id="system")` y
    `register_durable_tools(gateway, tenant_id="system")`.
  - `handlers/system.py`, `handlers/workspace.py` → movidos desde `execute_tool`
    preservando `ToolResult` y `evidence` exactos.
  - `handlers/nmap.py` → allowlist de flags, cálculo de nivel de ruido, sandbox, parseo.
  - `parsers/nmap.py` → parser XML → JSON (`NmapScan`, `NmapHost`, `empty_scan`).
- **Modificado** `nexus_core/kernel/runtime.py`: `execute_tool` ya no tiene el dict
  `definitions` ni las funciones anidadas; usa `durable_tool_definitions(context.tenant_id)`
  y registra sólo la tool invocada.
- **Modificado** `nexus_core/kernel/models.py`: `RunContext` incorpora `store`
  (`compare=False, repr=False`) y `worker_id` para que los handlers migrados
  conserven el acceso al control store y al worker.
- **Modificado** `nexus_core/kernel/sandbox.py`: `sandbox_for_environment` acepta
  `allowed_programs` opcional (el handler de nmap pasa `("python3","git","rg","nmap")`).
- **Nuevo** fixtures `nexus_core/tests/fixtures/nmap/*.xml` (6).
- **Nuevos** tests: `test_nmap_parser.py` (10), `test_nmap_handler.py` (13),
  `integration/test_nmap_e2e.py` (2, opt-in).

No se tocó el schema de la DB. No hay dependencias nuevas (`xml.etree.ElementTree`).
No se tocaron los 2 tests del gateway ni los 5 de scope-wiring.

## 1. Imports

```
nexus_api.main OK
nexus_core.kernel.runtime OK
nexus_core.tools.registry OK
nexus_core.tools.parsers.nmap OK
nexus_core.tools.handlers.nmap OK
nexus_core.scope OK
nexus_worker OK
nexus_mcp.server OK
```

## 2. Tests

```
$ .venv/bin/python -m pytest nexus_core/tests/unit -q
============================== 99 passed in 4.05s ==============================
```

- 76 tests previos: **siguen pasando** sin modificación.
- 23 tests nuevos unitarios: **todos pasan**
  - `test_nmap_parser.py` → 10/10
  - `test_nmap_handler.py` → 13/13 (12 pedidos + 1 de la definición)

```
$ .venv/bin/python -m pytest nexus_core/tests/unit/test_nmap_parser.py -v   → 10 passed
$ .venv/bin/python -m pytest nexus_core/tests/unit/test_nmap_handler.py -v  → 13 passed
```

### E2E opt-in (salida real, `NEXUS_E2E=1`)

```
$ NEXUS_E2E=1 .venv/bin/python -m pytest nexus_core/tests/integration/test_nmap_e2e.py -v
collected 2 items
test_e2e_nmap_against_scanme_in_scope SKIPPED [ 50%]
test_e2e_nmap_denied_when_target_out_of_scope PASSED [100%]
==================== 1 passed, 1 skipped in 2.09s ====================
```

- `test_e2e_nmap_denied_when_target_out_of_scope` **PASÓ** en vivo: `example.com`
  resuelve fuera del scope de scanme → `ScopeViolation` + audit `scope.denied`.
- `test_e2e_nmap_against_scanme_in_scope` **SKIPPED** porque el binario `nmap` no
  está instalado en este host (`shutil.which("nmap") is None`). El test está
  escrito y listo; se ejecutará donde exista nmap. El skip es explícito, no oculto.

DNS verificado desde este host:
`scanme.nmap.org → 45.33.32.156 (A) + 2600:3c01::f03c:91ff:fe18:bb2f (AAAA)`, por
lo que el fixture de scope incluye el /32 y el /128.

## 3. Lint y residuales

```
$ .venv/bin/ruff check nexus_core/tools nexus_core/kernel nexus_core/tests/unit/test_nmap_*.py nexus_core/tests/integration/test_nmap_e2e.py --select F,E9
All checks passed!

$ grep -rnE "TODO|FIXME|XXX|HACK|raise NotImplementedError" nexus_core/tools/ nexus_core/kernel/runtime.py
(exit 1, sin coincidencias)

$ grep -rnE "create_subprocess|subprocess|Popen|os.system|shell=True" nexus_core/tools/
(exit 1, sin coincidencias)  # el handler nunca ejecuta subprocess directo
```

## 4. Criterios de éxito

| Criterio | Estado |
|---|---|
| 8 imports OK | ✅ |
| 76 tests originales siguen pasando | ✅ (99 totales) |
| ≥10 tests nuevos del parser | ✅ (10) |
| ≥12 tests nuevos del handler | ✅ (13) |
| ≥2 tests E2E (opt-in) | ✅ (2; 1 ejecutado en vivo, 1 skip por falta de nmap) |
| ruff clean | ✅ |
| Cero TODOs | ✅ |
| `nexus_core/tools/registry.py` con `durable_tool_definitions()` | ✅ |
| `execute_tool` sin dict `definitions` hardcodeado | ✅ |
| `nexus.recon.nmap` con `scope_target_field="target"`, `scope_required=True`, `risk=MEDIUM` | ✅ |
| Parser maneja XML con namespaces | ✅ |
| Handler nunca ejecuta subprocess directo | ✅ (verificado con grep) |
| Noise level calculado e incluido en evidence | ✅ |
| sha256 del XML crudo en evidence | ✅ |

## 5. Decisiones de diseño no cubiertas por el prompt

1. **`RunContext.store` / `RunContext.worker_id`**: los handlers del registro sólo
   reciben `RunContext`, pero `nexus.system.status` necesitaba el `ControlStore` y el
   `worker_id`. Se añadieron ambos campos con default (`store=None`, `worker_id=""`,
   `compare=False, repr=False`) para preservar el comportamiento exacto sin cambiar la
   firma del handler. `execute_tool` los rellena desde `ExecutionContext`.
2. **Registro multi-tenant**: `durable_tool_definitions(tenant_id="system")` y las
   factorías `*_definition(tenant_id="system")` aceptan tenant. Antes las definiciones
   usaban `context.tenant_id`; hardcodear `"system"` habría roto el aislamiento
   multi-tenant en el policy check. El default mantiene `durable_tool_definitions()`
   invocable sin argumentos. El tenant físico sigue siendo el de la task.
3. **`sandbox_for_environment` con allowlist explícita**: se añadió el parámetro
   opcional `allowed_programs`; el handler de nmap lo pasa explícitamente en vez de
   ampliar la allowlist global por defecto.
4. **E2E con AAAA**: scanme.nmap.org publica A y AAAA; el scope de test incluye ambos
   porque el validator exige que **todas** las IPs resueltas estén dentro del scope.
5. **Skip honesto del E2E de escaneo**: además de `NEXUS_E2E=1`, el test de escaneo se
   auto-salta si `shutil.which("nmap")` es `None`, para no reportar un rojo por entorno.
6. **Timeout del sandbox acotado**: el handler limita el timeout pedido a `[10, 600]`s
   (la definición usa `timeout_seconds=600`, que es el techo del gateway).
7. **Warnings de ruido**: además del nivel, `validate_and_canonicalize_flags` añade
   warnings para perfiles `high` y para `-sS`.

## 6. Limitaciones de producción (documentadas)

- `OCISandbox` fuerza `--network none`: **bloquea cualquier escaneo de red**. El perfil
  OCI de nmap requerirá una variante con red; hoy el E2E real sólo funciona en dev
  (`LocalSandbox`).
- La imagen por defecto de prod (`python:3.12-alpine`) no trae nmap. Hay que añadir una
  imagen con nmap (`instrumentisto/nmap` por defecto vía `NEXUS_NMAP_IMAGE`) a
  `NEXUS_SANDBOX_IMAGES`.

## 7. Commit

```
git add -A && git commit -m "feat(tools): registro central + nexus.recon.nmap durable con parser XML y noise level"
```

NO se hizo push.
