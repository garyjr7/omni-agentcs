# RESIDUALS RESULT

Cierre de residuales post-purga del runtime legado.

## Verificación final

```text
=== imports ===
nexus_api.main                -> OK
nexus_core.kernel.runtime     -> OK
nexus_worker                  -> OK
nexus_mcp.server              -> OK

=== tests unit ===
43 passed in 3.38s

=== tests mcp ===
4 passed in 2.11s

=== ruff (nexus_core/kernel nexus_core/llm nexus_api/main.py --select F) ===
All checks passed!

=== residual grep (junior_agent|junior_bridge|agent_team_manager|workflow_manager|
     dynamic_agent|pentest_agent|composite_tools|hitl.manager|bashagent|codeagent|
     nmap_scan|nuclei_scan) en *.py ===
ZERO
```

> Nota: el comando original de ruff incluía `nexus_api/routes/nexus.py`, que fue
> eliminado en el PASO 3; se ejecutó sin esa ruta. `nexus_api/db/database.py`
> conserva 3 `F401` **preexistentes** (`os`, `pathlib.Path`, `datetime` sin usar,
> presentes ya en HEAD y ajenos a la purga) — se reportan, no se tocan.

## Archivos eliminados (`git rm`)

Legacy residuales (PASO 2):
- `nexus_core/agents/junior_agent.py`
- `nexus_core/main.py`
- `nexus_core/junior_bridge.py`
- `nexus_core/agent_team_manager.py`
- `nexus_core/workflow_manager.py`

Puente legacy de la API (PASO 3, opción **a**):
- `nexus_api/services/nexus_service.py`
- `nexus_api/routes/nexus.py`

## Archivos modificados

| Archivo | Cambio |
|---|---|
| `nexus_api/main.py` | Removida la entrada `("nexus_api.routes.nexus", {}, ["Nexus"])` de `_routes`. |
| `nexus_core/config.py` | Eliminadas constantes ya sin uso `JUNIOR_WORKSPACE` y `PROJECTS_DIR`. Se conservan `NEXUS_ROOT/NEXUS_DATA_PATH/NEXUS_DB_PATH/REPORTS_DIR/PENTEST_DIR/CHROMA_PATH/LEGACY_DATABASE_PATH`. |
| `nexus_api/db/database.py` | Eliminadas 2 filas del catálogo seed que referenciaban las skills borradas (`tool_nmap`/`tool_nuclei`). |
| `.gitignore` | `.env/` (directorio) → `.env` + `.env.*` + `!.env.example` para que `.env` quede realmente ignorado. |

## Decisiones

- **PASO 3 — opción (a).** `NexusService` dependía al 100% del stack legado
  (`core.orchestrator`, `agents.registry`, `core.planner`); además su
  `initialize()` nunca era invocado por la ruta, así que sólo servía datos demo
  "offline". Sin utilidad durable real ⇒ se elimina el servicio y su router.
- **Config.** `JUNIOR_WORKSPACE` pertenecía al `junior_agent.py` eliminado;
  `PROJECTS_DIR` ya no se usaba fuera de `config.py`. El resto sobrevive y se
  mantiene.
- **Tests.** `nexus_core/tests/unit` ni `nexus_mcp/tests` importan los módulos
  eliminados; no se modificó ningún test en este paso.

## Referencias restantes (no-código, no bloquean)

- Documentación histórica: `OMNIAGENT_CONTEXT.md`, `CODEBASE_MAP.md`,
  `INFORME_ARQUITECTONICO_NEXUS_2026-08-08.md`, `AUDITORIA_NEXUS_2026-08-04.md`.
- Scripts shell (fuera de alcance): `nexus_junior_jarvis.sh`, `nexus_upgrade.sh`,
  `nexus_core/run_nexus.sh`, `nexus_core/setup_nexus.sh`.
- `docker/entrypoint.sh` sólo arranca `uvicorn nexus_api.main:app`; no invoca
  `nexus_core.main`, por lo que la eliminación no rompe el contenedor.

## Criterios de éxito

- [x] Los 4 imports críticos funcionan
- [x] 43 tests pasan en `nexus_core/tests/unit`
- [x] 4 tests pasan en `nexus_mcp/tests`
- [x] ruff sin errores `F` en las rutas objetivo
- [x] Cero referencias a los módulos eliminados en archivos `.py`
- [x] `RESIDUALS_DIAG.md` y `RESIDUALS_RESULT.md` generados
- [x] Commit creado
