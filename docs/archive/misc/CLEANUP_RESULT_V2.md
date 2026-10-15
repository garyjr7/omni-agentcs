# Cleanup: resultado V2

Estado: **bloqueado en fase 1 por imports desde tests protegidos**.
Rama: `chore/final-cleanup`. Sin push.

Solo se añaden este informe y CLEANUP_RECON_V2.md. No se aplicó Ruff --fix,
no se borraron carpetas ni archivos, no se movieron reportes ni scripts,
no se modificó README, no se migró la DB y no se tocó ninguna ruta protegida.

La autorización para limpiar utils/ y eliminar agents/ plural está vigente;
la ejecución se detuvo por las referencias a core/, state/ y evolution/ desde
los tests que ahora están protegidos. Ver [referencias exactas](CLEANUP_RECON_V2.md).
Además hay dos F841 en test_sovereign_runtime.py, también protegido.

La suite no se volvió a ejecutar porque no hubo cambios de código. No se
certifican 470 tests posteriores a un cleanup que todavía no se ha realizado.
Los criterios finales de borrado, migración, raíz limpia y lint siguen pendientes.

## Salida real de --list-engagements --no-wizard

```text
  eng-scanme               scanme-lab                   cliente=NEXUS  hasta 2030-01-01T00:00:00+00:00
```

## Ruff F/E9: salida completa en formato concise

Comando: `.venv/bin/ruff check nexus_core omni.py nexus_worker.py --select F,E9 --output-format concise`.

```text
nexus_core/agents/generated/dataanalysisagent.py:1:47: F401 [*] `nexus_core.agents.base.AgentMetadata` imported but unused
nexus_core/agents/generated/dataanalysisagent.py:2:8: F401 [*] `asyncio` imported but unused
nexus_core/agents/generated/dataanalysisagent.py:3:8: F401 [*] `json` imported but unused
nexus_core/agents/generated/doc_agent.py:9:8: F401 [*] `subprocess` imported but unused
nexus_core/agents/generated/doc_agent.py:11:21: F401 [*] `pathlib.Path` imported but unused
nexus_core/agents/generated/guardian_agent.py:4:35: F401 [*] `os` imported but unused
nexus_core/agents/generated/kill_switch_agent.py:9:21: F401 [*] `pathlib.Path` imported but unused
nexus_core/agents/generated/plan_agent.py:8:8: F401 [*] `asyncio` imported but unused
nexus_core/agents/generated/plan_agent.py:11:21: F401 [*] `pathlib.Path` imported but unused
nexus_core/agents/generated/plan_agent.py:142:44: F541 [*] f-string without any placeholders
nexus_core/agents/generated/reportgenerationagent.py:1:47: F401 [*] `nexus_core.agents.base.AgentMetadata` imported but unused
nexus_core/agents/generated/reportgenerationagent.py:1:62: F401 [*] `nexus_core.agents.base.AgentCapability` imported but unused
nexus_core/agents/generated/reportgenerationagent.py:2:8: F401 [*] `asyncio` imported but unused
nexus_core/agents/generated/reportgenerationagent.py:3:8: F401 [*] `json` imported but unused
nexus_core/agents/generated/test_agent.py:10:8: F401 [*] `shutil` imported but unused
nexus_core/core/agent_factory.py:5:8: F401 [*] `uuid` imported but unused
nexus_core/core/agent_factory.py:7:36: F401 [*] `nexus_core.agents.base.BaseAgent` imported but unused
nexus_core/core/orchestrator.py:10:8: F401 [*] `pathlib` imported but unused
nexus_core/state/manager.py:11:8: F401 [*] `copy` imported but unused
nexus_core/team_orchestrator.py:5:8: F401 [*] `asyncio` imported but unused
nexus_core/team_orchestrator.py:11:22: F401 [*] `datetime.datetime` imported but unused
nexus_core/tests/unit/test_sovereign_runtime.py:38:5: F841 Local variable `task` is assigned to but never used
nexus_core/tests/unit/test_sovereign_runtime.py:78:5: F841 Local variable `task` is assigned to but never used
nexus_core/utils/logger.py:9:8: F401 [*] `contextlib` imported but unused
nexus_core/utils/security.py:4:8: F401 [*] `typing` imported but unused
nexus_core/utils/security.py:5:8: F401 [*] `re` imported but unused
nexus_core/utils/security.py:7:8: F401 [*] `pathlib` imported but unused
nexus_core/utils/security.py:9:8: F401 [*] `json` imported but unused
nexus_core/utils/security.py:11:8: F401 [*] `functools` imported but unused
Found 29 errors.
[*] 27 fixable with the `--fix` option (2 hidden fixes can be enabled with the `--unsafe-fixes` option).
```

## Raíz al detener la auditoría (ls -la)

Captura anterior a añadir los dos informes V2, que son los únicos archivos
nuevos de esta ejecución. No se ha ejecutado ningún borrado.

```text
total 1432
drwxrwxr-x 26 operator operator   4096 Sep 29 22:44 .
drwxr-x--- 12 operator operator   4096 Sep 29 22:46 ..
drwxr-xr-x  2 operator operator   4096 Aug  4 22:52 .agents
drwxrwxr-x  4 operator operator   4096 Aug  4 23:03 .backups
drwxr-xr-x  2 operator operator   4096 Aug  4 22:52 .codex
-rw-rw-r--  1 operator operator    272 Aug  4 22:17 .dockerignore
-rw-------  1 operator operator   4353 Sep 29 20:18 .env
-rw-rw-r--  1 operator operator   4590 Sep 29 20:21 .env.example
drwx------  2 operator operator   4096 Sep 28 00:35 .freebuff
drwxrwxr-x  8 operator operator   4096 Sep 29 22:49 .git
drwxrwxr-x  3 operator operator   4096 Aug  4 21:54 .github
-rw-rw-r--  1 operator operator    435 Sep 29 05:56 .gitignore
drwxrwxr-x  3 operator operator   4096 Sep 27 23:43 .mypy_cache
-rw-rw-r--  1 operator operator      3 Aug  5 20:50 .nvmrc
drwxrwxr-x  3 operator operator   4096 Sep 28 00:30 .pytest_cache
drwxrwxr-x  3 operator operator   4096 Aug  4 22:50 .ruff_cache
drwxrwxr-x  5 operator operator   4096 Sep 29 06:11 .sandbox_home
drwx------  3 operator operator   4096 Sep 29 05:31 .uncover-config
drwxrwxr-x  5 operator operator   4096 Aug  4 22:49 .venv
-rw-rw-r--  1 operator operator  15250 Aug  4 23:22 AUDITORIA_NEXUS_2026-08-04.md
-rw-rw-r--  1 operator operator   1412 Jun  9 14:13 CHANGELOG.md
-rw-rw-r--  1 operator operator   1412 Sep 29 02:24 CHANGELOG.txt
-rw-rw-r--  1 operator operator   3701 Sep 29 22:44 CLEANUP_AUDIT.md
-rw-rw-r--  1 operator operator  19090 Sep 29 22:44 CLEANUP_RESULT.md
-rw-rw-r--  1 operator operator   6320 Sep 29 04:30 CLI_RECON.md
-rw-rw-r--  1 operator operator  10133 Sep 29 04:43 CLI_RESULT.md
-rw-rw-r--  1 operator operator  57900 Jun  9 14:55 CODEBASE_MAP.md
-rw-rw-r--  1 operator operator   1894 Aug  4 23:02 Dockerfile.backend
-rw-rw-r--  1 operator operator    969 Aug  4 22:17 Dockerfile.frontend
-rw-rw-r--  1 operator operator   5665 Sep 29 06:02 FIX_SANDBOX_RECON.md
-rw-rw-r--  1 operator operator   7001 Sep 29 06:15 FIX_SANDBOX_RESULT.md
-rw-rw-r--  1 operator operator  22206 Aug  8 00:17 INFORME_ARQUITECTONICO_NEXUS_2026-08-08.md
-rw-rw-r--  1 operator operator   5040 Sep 29 20:26 MSF_DAEMON_DIAG.md
-rw-rw-r--  1 operator operator   2584 Sep 29 20:26 MSF_DAEMON_RESULT.md
-rw-rw-r--  1 operator operator   4107 Sep 29 20:26 MSF_RESULT.md
-rw-rw-r--  1 operator operator   1749 Aug  5 20:56 Makefile
-rw-rw-r--  1 operator operator   5517 Sep 29 03:00 NMAP_RECON.md
-rw-rw-r--  1 operator operator   7043 Sep 29 03:02 NMAP_RESULT.md
-rw-rw-r--  1 operator operator 469634 Sep 28 00:10 OMNIAGENT_CONTEXT.md
-rw-rw-r--  1 operator operator   1932 Sep 29 22:17 ONBOARDING_RECON.md
-rw-rw-r--  1 operator operator   9362 Sep 29 22:31 ONBOARDING_RESULT.md
-rw-rw-r--  1 operator operator  16307 Aug  4 23:22 PLAN_IMPLEMENTACION_NEXUS.md
-rw-rw-r--  1 operator operator   5527 Aug  8 00:42 PLAN_MAESTRO_BAJIOWARE.md
-rw-rw-r--  1 operator operator   3148 Jun  9 14:13 PRICING.md
-rw-rw-r--  1 operator operator   2804 Sep 28 00:25 PURGE_RECON.md
-rw-rw-r--  1 operator operator   9356 Sep 28 00:44 PURGE_RESULT.md
-rw-rw-r--  1 operator operator   9094 Sep 29 04:03 REACT_RECON.md
-rw-rw-r--  1 operator operator  10474 Sep 29 04:09 REACT_RESULT.md
-rw-rw-r--  1 operator operator  21680 Sep 29 22:23 README.md
-rw-rw-r--  1 operator operator   3407 Aug  4 23:22 REPORTE_IMPLEMENTACION_NEXUS_2026-08-04.md
-rw-rw-r--  1 operator operator   2823 Sep 28 00:55 RESIDUALS_DIAG.md
-rw-rw-r--  1 operator operator   3435 Sep 28 00:56 RESIDUALS_RESULT.md
-rw-rw-r--  1 operator operator   6518 Sep 29 02:37 SCOPE_RECON.md
-rw-rw-r--  1 operator operator   5300 Sep 29 02:39 SCOPE_RESULT.md
-rw-rw-r--  1 operator operator   4317 Sep 29 02:51 SCOPE_WIRE_RESULT.md
-rw-rw-r--  1 operator operator   9348 Sep 29 05:43 TOOLKIT_RECON.md
-rw-rw-r--  1 operator operator   9988 Sep 29 05:45 TOOLKIT_RESULT.md
drwxrwxr-x  2 operator operator   4096 Sep 29 21:31 __pycache__
drwxrwxr-x  2 operator operator   4096 Jun  9 14:13 bajioware_landing
drwxrwxr-x  4 operator operator   4096 Sep 29 22:43 data
drwxrwxr-x  3 operator operator   4096 Aug  4 21:52 departments
drwxrwxr-x  2 operator operator   4096 Aug  5 00:46 docker
-rw-rw-r--  1 operator operator   7777 Aug  5 00:47 docker-compose.yml
drwxrwxr-x  4 operator operator   4096 Aug  5 20:53 docs
-rwxrwxr-x  1 operator operator   8985 Jun  9 14:13 factory_runner.py
-rw-rw-r--  1 operator operator   1226 Aug  4 23:21 install.sh
-rwxrwxr-x  1 operator operator  15692 Jun  9 15:15 junior_jarvis.py
-rwxrwxr-x  1 operator operator    440 Sep 29 03:58 list_models.sh
drwxrwxr-x 10 operator operator   4096 Aug  4 22:51 nexus_api
-rwxrwxr-x  1 operator operator    257 Aug  4 23:04 nexus_backup.sh
-rw-rw-r--  1 operator operator   2856 Aug  4 22:04 nexus_cli.py
-rw-rw-r--  1 operator operator   3943 Aug  4 23:12 nexus_connector.py
drwxrwxr-x 24 operator operator   4096 Sep 29 21:17 nexus_core
drwxrwxr-x  6 operator operator   4096 Aug  4 23:09 nexus_frontend
-rwxrwxr-x  1 operator operator   2893 Jun  9 14:13 nexus_healthcheck.sh
-rwxrwxr-x  1 operator operator  69278 Jun  9 14:13 nexus_junior_jarvis.sh
drwxrwxr-x  4 operator operator   4096 Aug  4 23:14 nexus_mcp
-rw-rw-r--  1 operator operator   4002 Aug  4 23:04 nexus_ops.py
-rwxrwxr-x  1 operator operator    258 Aug  4 23:04 nexus_restore.sh
-rwxrwxr-x  1 operator operator   3329 Jun  9 14:13 nexus_start.sh
-rwxrwxr-x  1 operator operator  12727 Jun  9 14:13 nexus_upgrade.sh
-rw-rw-r--  1 operator operator   2040 Aug  5 20:56 nexus_worker.py
-rwxrwxr-x  1 operator operator   2464 Sep 29 21:31 omni.py
-rw-rw-r--  1 operator operator   1839 Sep 29 04:19 react_e2e_manual.py
-rw-rw-r--  1 operator operator    106 Aug  4 21:54 requirements-dev.txt
-rw-rw-r--  1 operator operator     61 Aug  4 23:02 requirements-prod.in
-rw-rw-r--  1 operator operator 125780 Aug  4 23:16 requirements-prod.lock
-rw-rw-r--  1 operator operator 152699 Aug  4 23:16 requirements.lock
-rw-rw-r--  1 operator operator     99 Aug  4 22:50 ruff.toml
drwxrwxr-x  3 operator operator   4096 Sep 29 19:58 scripts
drwxrwxr-x  3 operator operator   4096 Sep 29 04:52 tests
```

## git log --oneline -10 al comenzar esta auditoría

```text
efa4227 docs: auditar cleanup y documentar bloqueo en rutas protegidas
5885267 feat(onboarding): XDG config + provisioner + wizard + doctor
e5fcc99 feat(metasploit): cliente RPC + msf_search + msf_auxiliary + systemd service
650c541 fix(sandbox+nuclei): HOME efímero por run y templates estables
0f71610 chore: ignorar .sandbox_home/ (HOME efímero del sandbox)
bb81fb9 feat(tools): añadir subfinder, httpx, nuclei y ffuf al catálogo durable
8d00639 chore(dev-tools): scripts de diagnóstico manual
104ba49 test(nmap-e2e): añadir domains al scope de scanme
33f483d feat(cli): REPL interactivo omni con approval callback y stream en vivo
0b2caab feat(agent): bucle ReAct durable con parser, memoria y auditoría
```
