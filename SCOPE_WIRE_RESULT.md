# SCOPE_WIRE_RESULT — Cableado del EngagementScope al runtime durable

Fecha: 2026-09-29
Rama: `feat/scope-wire`
Entorno: `.venv/bin/python` (Python 3.12.3), `pytest 9.1.1`, `ruff 0.16.1`.

## Cambios

- **Nuevo** `nexus_core/kernel/scope_loader.py`:
  - `load_engagement_scope(store, tenant_id, engagement_id)` → carga el
    `EngagementScope` del `EngagementStore`, o `None` si no hay
    `engagement_id`. Lanza `PermissionError` si el engagement no existe.
  - `scope_signing_secret()` → lee `NEXUS_SCOPE_SIGNING_SECRET` (o `None`).
- **Modificado** `nexus_core/kernel/runtime.py`:
  - `execute_tool` carga el scope con `load_engagement_scope(...)`, lo inyecta
    en `RunContext(..., scope=scope)` y pasa
    `make_scope_validator(signing_secret=scope_signing_secret())` al
    `ToolGateway`. Imports perezosos dentro de la función (sin acoplar el
    kernel al paquete scope en tiempo de import).
  - `execute_brain` propaga `"engagement_id": payload.get("engagement_id")` en
    el dict de invocation de cada step.
- **Nuevo** `nexus_core/tests/unit/test_scope_wiring.py` con 5 tests.

`nexus_core/scope/**` no se tocó. No se añadieron dependencias. No se cambió la
firma pública de `ToolGateway.invoke()` ni de `execute_tool()`.

## 1. Imports

```
$ .venv/bin/python -c "import nexus_api.main"                 → nexus_api.main OK
$ .venv/bin/python -c "import nexus_core.kernel.runtime"      → nexus_core.kernel.runtime OK
$ .venv/bin/python -c "import nexus_core.scope"               → nexus_core.scope OK
$ .venv/bin/python -c "import nexus_core.kernel.scope_loader" → nexus_core.kernel.scope_loader OK
$ .venv/bin/python -c "import nexus_worker"                   → nexus_worker OK
$ .venv/bin/python -c "import nexus_mcp.server"               → nexus_mcp.server OK
```

> Nota: `python`/`pytest`/`ruff`/`rg` no están en el PATH global; se usó el
> `.venv` del repo y `grep` en lugar de `rg`.

## 2. Tests

```
$ .venv/bin/python -m pytest nexus_core/tests/unit -q
============================== 76 passed in 3.95s ==============================
```

- 71 tests previos: **siguen pasando** (incluidos los 2 del gateway, sin modificar).
- 5 tests nuevos en `test_scope_wiring.py`: **todos pasan**.
  1. `test_execute_tool_loads_scope_from_engagement_id`
  2. `test_execute_tool_denies_when_engagement_not_found`
  3. `test_execute_tool_denies_when_target_out_of_scope`
  4. `test_execute_tool_allows_no_scope_when_tool_does_not_require_it`
  5. `test_execute_brain_propagates_engagement_id_to_steps`

## 3. Lint

```
$ .venv/bin/ruff check nexus_core/kernel nexus_core/tests/unit/test_scope.py nexus_core/tests/unit/test_scope_wiring.py --select F,E9
All checks passed!
```

## 4. Residuales

```
$ grep -rnE "TODO|FIXME|XXX|HACK|raise NotImplementedError" nexus_core/kernel/scope_loader.py nexus_core/kernel/runtime.py
(exit 1, sin coincidencias)
```

## 5. Criterios de éxito

| Criterio | Estado |
|---|---|
| 6 imports OK | ✅ |
| 71 tests + 5 nuevos = 76 pasan | ✅ |
| ruff clean | ✅ |
| Cero TODOs | ✅ |
| `execute_tool` carga scope desde `engagement_id` y lo pasa al gateway | ✅ |
| `execute_brain` propaga `engagement_id` a los steps | ✅ |
| Los 2 tests existentes del gateway siguen pasando | ✅ |

## 6. Decisión de diseño no especificada en el prompt

- **Inyección de un tool scope-aware en los tests**: el catálogo de
  `execute_tool` sólo contiene las dos tools existentes
  (`nexus.system.status`, `nexus.workspace.search`), ambas con
  `scope_required=False`. Para ejercitar la rama de scope sin cambiar el
  catálogo de producción, `test_scope_wiring.py` parchea
  `ToolGateway.register` y promueve temporalmente `nexus.system.status` a
  `scope_required=True` + `scope_target_field="target"` con un schema que
  acepta `target`. Así los tests recorren el `execute_tool` real (carga del
  scope, `RunContext.scope`, `make_scope_validator`) sin añadir tools de
  producción.
- **Fail-closed en carga**: `load_engagement_scope` lanza `PermissionError`
  cuando el `engagement_id` no existe. La expiración y la firma se validan en
  `ScopeValidator` (en el momento de validar un target), tal como indica el
  prompt.

## 7. Commit

```
git add -A && git commit -m "feat(scope): cablear EngagementScope al runtime durable"
```

NO se hizo push.
