# RESIDUALS DIAG

Diagnóstico previo al cierre de residuales. Entorno: `.venv/bin/python` (3.12).

## 1. Estado de import de los 6 archivos residuales

| Módulo | Resultado | Causa |
|---|---|---|
| `nexus_core.agents.junior_agent` | **ROTO** (`ModuleNotFoundError`) | `line 28: from nexus_core.agents.dynamic_agent import ToolExecutor` (eliminado) |
| `nexus_core.main` | **ROTO** (`ModuleNotFoundError`) | `line 29: from nexus_core.skills.registry import SkillRegistry` (eliminado) |
| `nexus_core.junior_bridge` | importa OK | refs perezosas a `bashagent`/`codeagent`/`fileagent` (eliminados), dentro de `try/except` |
| `nexus_core.agent_team_manager` | importa OK | ref perezosa a `agents.junior_agent` en runtime |
| `nexus_core.workflow_manager` | importa OK | ref perezosa a `agents.junior_agent` en runtime |
| `nexus_api.services.nexus_service` | importa OK | `try/except` con el stack legado `core.orchestrator` → degrada a `offline` |

```text
### nexus_core.agents.junior_agent
  File ".../nexus_core/agents/junior_agent.py", line 28, in <module>
    from nexus_core.agents.dynamic_agent import ToolExecutor
ModuleNotFoundError: No module named 'nexus_core.agents.dynamic_agent'

### nexus_core.main
  File ".../nexus_core/main.py", line 29, in <module>
    from nexus_core.skills.registry import SkillRegistry
ModuleNotFoundError: No module named 'nexus_core.skills.registry'
```

## 2. Quién importa cada archivo (grep repo-wide)

```text
junior_agent|junior_bridge|agent_team_manager|workflow_manager  -> NONE
nexus_core.main                                                  -> NONE
nexus_service                                                    -> nexus_api/routes/nexus.py (SUPERVIVIENTE)
```

- Ningún archivo que sobrevive importa `junior_agent`, `junior_bridge`,
  `agent_team_manager`, `workflow_manager` ni `nexus_core.main`.
- `docker/entrypoint.sh` sólo arranca `uvicorn nexus_api.main:app` — **no**
  invoca `nexus_core.main`, por lo que su eliminación no rompe el contenedor.
- `nexus_core/agents/__init__.py`, `nexus_core/__init__.py` y
  `nexus_core/agents/generated/__init__.py` están vacíos (sin imports ocultos).
- Tests: `NONE` (ni `nexus_core/tests` ni `nexus_mcp/tests` los referencian).

## 3. Referencias en documentación / scripts (no-código, no bloquean)

- `OMNIAGENT_CONTEXT.md`, `CODEBASE_MAP.md`, `INFORME_ARQUITECTONICO_*.md`,
  `AUDITORIA_*.md`: documentación; se dejan como histórico.
- `nexus_junior_jarvis.sh`, `nexus_upgrade.sh`, `nexus_core/run_nexus.sh`,
  `nexus_core/setup_nexus.sh`: scripts shell, fuera de alcance.

## 4. Decisión

Los 5 módulos son legacy puro sin consumidores vivos → se eliminan con `git rm`.
`nexus_api/services/nexus_service.py` es consumido por la ruta superviviente
`nexus_api/routes/nexus.py` → se decide en el PASO 3.
