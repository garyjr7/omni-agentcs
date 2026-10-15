# OMNIAGENT_CONTEXT

Extracción estática del repositorio actual. No se ejecutaron tests, instalaciones ni servidores.

## 1. Árbol completo del proyecto

```text
./.backups/pre_cleanup_generated_data_20260804.tar.gz
./.dockerignore
./.env
./.env.example
./.github/workflows/ci.yml
./.gitignore
./.nvmrc
./AUDITORIA_NEXUS_2026-08-04.md
./CHANGELOG.md
./CODEBASE_MAP.md
./Dockerfile.backend
./Dockerfile.frontend
./INFORME_ARQUITECTONICO_NEXUS_2026-08-08.md
./Makefile
./PLAN_IMPLEMENTACION_NEXUS.md
./PLAN_MAESTRO_BAJIOWARE.md
./PRICING.md
./README.md
./REPORTE_IMPLEMENTACION_NEXUS_2026-08-04.md
./bajioware_landing/index.html
./data/factory/templates/pentest_scope.md
./data/factory/templates/software_requirements.md
./data/nexus_pro.db
./departments/marketing/evals/marketing.json
./departments/marketing/manifest.json
./docker-compose.yml
./docker/connector-mtls.conf.template
./docker/entrypoint.sh
./docker/mcp-remote.conf.template
./docker/nginx.conf
./docs/CLEANUP_2026-08-04.md
./docs/DEPLOYMENT_ON_PREM.md
./docs/NEXUS_SOVEREIGN.md
./docs/SCIM_PROVISIONING.md
./docs/adr/ADR-001-kernel-gateways.md
./docs/adr/ADR-002-zero-trust-execution.md
./docs/adr/ADR-003-governed-evolution.md
./docs/runbooks/BACKUP_RESTORE.md
./docs/runbooks/CLAUDE_MCP.md
./docs/runbooks/CONNECTOR_MTLS.md
./docs/runbooks/DATA_GOVERNANCE.md
./docs/runbooks/DEVELOPMENT_OFFLINE.md
./docs/runbooks/INCIDENT_RESPONSE.md
./docs/runbooks/SLO_SLI.md
./factory_runner.py
./install.sh
./junior_jarvis.py
./nexus_api/__init__.py
./nexus_api/auth/__init__.py
./nexus_api/auth/deps.py
./nexus_api/auth/oidc.py
./nexus_api/auth/service.py
./nexus_api/config.py
./nexus_api/core/config.py
./nexus_api/db/__init__.py
./nexus_api/db/database.py
./nexus_api/main.py
./nexus_api/requirements.txt
./nexus_api/routes/__init__.py
./nexus_api/routes/a2a.py
./nexus_api/routes/agents.py
./nexus_api/routes/approvals.py
./nexus_api/routes/audit.py
./nexus_api/routes/auth.py
./nexus_api/routes/composite.py
./nexus_api/routes/connectors.py
./nexus_api/routes/directory.py
./nexus_api/routes/docagent.py
./nexus_api/routes/evolution.py
./nexus_api/routes/factory.py
./nexus_api/routes/guardian.py
./nexus_api/routes/hitl.py
./nexus_api/routes/jarvis.py
./nexus_api/routes/junior.py
./nexus_api/routes/killswitch.py
./nexus_api/routes/memory.py
./nexus_api/routes/models.py
./nexus_api/routes/nexus.py
./nexus_api/routes/packages.py
./nexus_api/routes/pentest.py
./nexus_api/routes/plans.py
./nexus_api/routes/policies.py
./nexus_api/routes/project_manager.py
./nexus_api/routes/projects.py
./nexus_api/routes/scheduler.py
./nexus_api/routes/sovereign.py
./nexus_api/routes/tasks.py
./nexus_api/routes/teams_v2.py
./nexus_api/routes/testagent.py
./nexus_api/routes/tools.py
./nexus_api/routes/workflows.py
./nexus_api/routes/ws_logs.py
./nexus_api/scheduler/__init__.py
./nexus_api/scheduler/manager.py
./nexus_api/services/__init__.py
./nexus_api/services/factory_service.py
./nexus_api/services/integration_guide.md
./nexus_api/services/memory_service.py
./nexus_api/services/nexus_service.py
./nexus_api/services/project_service.py
./nexus_api/services/workspace_manager.py
./nexus_api/tests/api_smoke.py
./nexus_backup.sh
./nexus_cli.py
./nexus_connector.py
./nexus_core/.gitignore
./nexus_core/Makefile
./nexus_core/README.md
./nexus_core/__init__.py
./nexus_core/agent_team_manager.py
./nexus_core/agents/__init__.py
./nexus_core/agents/base.py
./nexus_core/agents/data_analyst.py
./nexus_core/agents/dynamic_agent.py
./nexus_core/agents/generated/__init__.py
./nexus_core/agents/generated/bashagent.py
./nexus_core/agents/generated/codeagent.py
./nexus_core/agents/generated/dataanalysisagent.py
./nexus_core/agents/generated/doc_agent.py
./nexus_core/agents/generated/fileagent.py
./nexus_core/agents/generated/guardian_agent.py
./nexus_core/agents/generated/kill_switch_agent.py
./nexus_core/agents/generated/loganalyzeragent.py
./nexus_core/agents/generated/plan_agent.py
./nexus_core/agents/generated/project_manager_agent.py
./nexus_core/agents/generated/reportgenerationagent.py
./nexus_core/agents/generated/test_agent.py
./nexus_core/agents/junior_agent.py
./nexus_core/agents/pentest_agent.py
./nexus_core/agents/registry.py
./nexus_core/composite_tools.py
./nexus_core/config.py
./nexus_core/core/__init__.py
./nexus_core/core/agent_factory.py
./nexus_core/core/agent_generator.py
./nexus_core/core/event_bus.py
./nexus_core/core/orchestrator.py
./nexus_core/core/planner.py
./nexus_core/evolution/__init__.py
./nexus_core/evolution/lab.py
./nexus_core/evolution/runner.py
./nexus_core/hitl/__init__.py
./nexus_core/hitl/manager.py
./nexus_core/junior_bridge.py
./nexus_core/kernel/__init__.py
./nexus_core/kernel/approvals.py
./nexus_core/kernel/artifacts.py
./nexus_core/kernel/audit.py
./nexus_core/kernel/connectors.py
./nexus_core/kernel/control_store.py
./nexus_core/kernel/directory.py
./nexus_core/kernel/knowledge.py
./nexus_core/kernel/legacy.py
./nexus_core/kernel/memory.py
./nexus_core/kernel/migrations.py
./nexus_core/kernel/model_router.py
./nexus_core/kernel/models.py
./nexus_core/kernel/packages.py
./nexus_core/kernel/policy.py
./nexus_core/kernel/postgres_store.py
./nexus_core/kernel/runtime.py
./nexus_core/kernel/sandbox.py
./nexus_core/kernel/schema_validation.py
./nexus_core/kernel/store_factory.py
./nexus_core/kernel/telemetry.py
./nexus_core/kernel/tool_gateway.py
./nexus_core/kernel/workflows.py
./nexus_core/llm/__init__.py
./nexus_core/llm/abstraction.py
./nexus_core/llm/fixtures/responses.json
./nexus_core/llm/gemini_provider.py
./nexus_core/llm/openai_provider.py
./nexus_core/main.py
./nexus_core/memory/__init__.py
./nexus_core/memory/manager.py
./nexus_core/memory/models.py
./nexus_core/memory/store.py
./nexus_core/nexus_state.json
./nexus_core/plan_maestro.md
./nexus_core/planner/__init__.py
./nexus_core/requirements.txt
./nexus_core/run_nexus.sh
./nexus_core/setup_nexus.sh
./nexus_core/skills/__init__.py
./nexus_core/skills/base.py
./nexus_core/skills/file_reader.py
./nexus_core/skills/http_client.py
./nexus_core/skills/nmap_scan.py
./nexus_core/skills/nuclei_scan.py
./nexus_core/skills/registry.py
./nexus_core/state/__init__.py
./nexus_core/state/manager.py
./nexus_core/team_orchestrator.py
./nexus_core/tests/conftest.py
./nexus_core/tests/integration/postgres_smoke.py
./nexus_core/tests/pytest.ini
./nexus_core/tests/unit/test_event_bus.py
./nexus_core/tests/unit/test_kernel_offline.py
./nexus_core/tests/unit/test_security.py
./nexus_core/tests/unit/test_sovereign_runtime.py
./nexus_core/tests/unit/test_state_manager.py
./nexus_core/utils/__init__.py
./nexus_core/utils/logger.py
./nexus_core/utils/security.py
./nexus_core/vector/__init__.py
./nexus_core/vector/embeddings.py
./nexus_core/vector/memory.py
./nexus_core/vector/store.py
./nexus_core/workflow_manager.py
./nexus_core/workforce/__init__.py
./nexus_frontend/.env
./nexus_frontend/.gitignore
./nexus_frontend/README.md
./nexus_frontend/eslint.config.js
./nexus_frontend/index.html
./nexus_frontend/package-lock.json
./nexus_frontend/package.json
./nexus_frontend/public/favicon.svg
./nexus_frontend/public/icons.svg
./nexus_frontend/src/App.css
./nexus_frontend/src/App.jsx
./nexus_frontend/src/api/client.js
./nexus_frontend/src/assets/hero.png
./nexus_frontend/src/components/layout/Sidebar.jsx
./nexus_frontend/src/components/layout/TopBar.jsx
./nexus_frontend/src/components/ui/Form.jsx
./nexus_frontend/src/components/ui/Modal.jsx
./nexus_frontend/src/components/ui/index.jsx
./nexus_frontend/src/hooks/useNexusData.js
./nexus_frontend/src/hooks/useWebSocket.js
./nexus_frontend/src/index.css
./nexus_frontend/src/main.jsx
./nexus_frontend/src/pages/Agents.jsx
./nexus_frontend/src/pages/Audit.jsx
./nexus_frontend/src/pages/ControlPlane.jsx
./nexus_frontend/src/pages/Factory.jsx
./nexus_frontend/src/pages/Guardian.jsx
./nexus_frontend/src/pages/HITL.jsx
./nexus_frontend/src/pages/Junior.jsx
./nexus_frontend/src/pages/Login.jsx
./nexus_frontend/src/pages/Memory.jsx
./nexus_frontend/src/pages/Models.jsx
./nexus_frontend/src/pages/Overview.jsx
./nexus_frontend/src/pages/Pentest.jsx
./nexus_frontend/src/pages/RBAC.jsx
./nexus_frontend/src/pages/Settings.jsx
./nexus_frontend/src/pages/Tasks.jsx
./nexus_frontend/src/pages/Teams.jsx
./nexus_frontend/src/pages/Terminal.jsx
./nexus_frontend/src/pages/Users.jsx
./nexus_frontend/src/pages/Vault.jsx
./nexus_frontend/src/store/authStore.js
./nexus_frontend/src/store/nexusStore.js
./nexus_frontend/vite.config.js
./nexus_healthcheck.sh
./nexus_junior_jarvis.sh
./nexus_mcp/__init__.py
./nexus_mcp/server.py
./nexus_mcp/tests/__init__.py
./nexus_mcp/tests/smoke.py
./nexus_mcp/tests/test_remote_security.py
./nexus_ops.py
./nexus_restore.sh
./nexus_start.sh
./nexus_upgrade.sh
./nexus_worker.py
./requirements-dev.txt
./requirements-prod.in
./requirements-prod.lock
./requirements.lock
./ruff.toml
```

## 2. Estadísticas por archivo

| Archivo | Líneas | Lenguaje |
|---|---|---|
| nexus_frontend/package-lock.json | 3224 | json |
| nexus_junior_jarvis.sh | 1581 | bash |
| CODEBASE_MAP.md | 1068 | markdown |
| nexus_core/kernel/control_store.py | 801 | python |
| nexus_core/llm/abstraction.py | 656 | python |
| nexus_frontend/src/pages/Junior.jsx | 645 | jsx |
| nexus_core/agent_team_manager.py | 638 | python |
| nexus_core/agents/dynamic_agent.py | 576 | python |
| nexus_core/tests/unit/test_kernel_offline.py | 574 | python |
| nexus_api/main.py | 565 | python |
| nexus_core/agents/pentest_agent.py | 535 | python |
| PLAN_IMPLEMENTACION_NEXUS.md | 499 | markdown |
| nexus_core/agents/junior_agent.py | 416 | python |
| junior_jarvis.py | 412 | python |
| nexus_api/routes/jarvis.py | 412 | python |
| nexus_api/routes/factory.py | 398 | python |
| nexus_core/workflow_manager.py | 376 | python |
| nexus_upgrade.sh | 373 | bash |
| nexus_core/agents/base.py | 353 | python |
| nexus_api/db/database.py | 344 | python |
| nexus_core/kernel/runtime.py | 337 | python |
| INFORME_ARQUITECTONICO_NEXUS_2026-08-08.md | 292 | markdown |
| nexus_api/routes/sovereign.py | 290 | python |
| nexus_core/hitl/manager.py | 277 | python |
| nexus_frontend/src/pages/Agents.jsx | 277 | jsx |
| nexus_api/services/factory_service.py | 267 | python |
| nexus_frontend/src/pages/Factory.jsx | 257 | jsx |
| nexus_api/routes/directory.py | 253 | python |
| docker-compose.yml | 252 | yaml |
| nexus_core/agents/generated/doc_agent.py | 252 | python |
| nexus_frontend/src/pages/Memory.jsx | 252 | jsx |
| nexus_frontend/src/pages/Teams.jsx | 252 | jsx |
| factory_runner.py | 251 | python |
| nexus_core/team_orchestrator.py | 245 | python |
| nexus_core/agents/registry.py | 240 | python |
| nexus_core/evolution/lab.py | 233 | python |
| nexus_api/routes/junior.py | 231 | python |
| nexus_frontend/src/pages/Tasks.jsx | 229 | jsx |
| nexus_core/state/manager.py | 223 | python |
| nexus_core/junior_bridge.py | 222 | python |
| nexus_core/agents/generated/test_agent.py | 218 | python |
| nexus_api/auth/service.py | 216 | python |
| nexus_core/utils/security.py | 215 | python |
| AUDITORIA_NEXUS_2026-08-04.md | 214 | markdown |
| nexus_core/agents/generated/plan_agent.py | 214 | python |
| nexus_core/kernel/workflows.py | 207 | python |
| nexus_frontend/src/pages/Models.jsx | 205 | jsx |
| nexus_core/main.py | 204 | python |
| nexus_frontend/src/pages/Users.jsx | 201 | jsx |
| nexus_core/composite_tools.py | 198 | python |
| nexus_api/routes/projects.py | 197 | python |
| nexus_frontend/src/pages/Pentest.jsx | 196 | jsx |
| nexus_frontend/src/api/client.js | 188 | javascript |
| nexus_mcp/server.py | 188 | python |
| nexus_core/core/orchestrator.py | 180 | python |
| nexus_frontend/src/components/layout/TopBar.jsx | 180 | jsx |
| nexus_api/tests/api_smoke.py | 178 | python |
| nexus_api/routes/models.py | 177 | python |
| nexus_core/kernel/policy.py | 171 | python |
| nexus_core/kernel/directory.py | 169 | python |
| nexus_core/agents/generated/kill_switch_agent.py | 166 | python |
| nexus_frontend/src/pages/Login.jsx | 165 | jsx |
| nexus_api/routes/tasks.py | 164 | python |
| nexus_api/services/memory_service.py | 164 | python |
| nexus_api/services/nexus_service.py | 164 | python |
| nexus_core/kernel/sandbox.py | 161 | python |
| nexus_api/routes/hitl.py | 160 | python |
| nexus_api/scheduler/manager.py | 159 | python |
| nexus_core/README.md | 159 | markdown |
| nexus_api/routes/agents.py | 158 | python |
| nexus_core/agents/generated/codeagent.py | 158 | python |
| nexus_core/kernel/models.py | 155 | python |
| nexus_core/kernel/memory.py | 152 | python |
| nexus_frontend/src/pages/Settings.jsx | 151 | jsx |
| nexus_frontend/src/pages/HITL.jsx | 147 | jsx |
| nexus_api/routes/ws_logs.py | 142 | python |
| nexus_core/kernel/tool_gateway.py | 142 | python |
| nexus_api/routes/pentest.py | 139 | python |
| nexus_core/agents/generated/guardian_agent.py | 138 | python |
| nexus_frontend/src/pages/Guardian.jsx | 138 | jsx |
| nexus_core/kernel/connectors.py | 130 | python |
| nexus_core/core/event_bus.py | 127 | python |
| nexus_core/utils/logger.py | 124 | python |
| nexus_core/kernel/model_router.py | 122 | python |
| nexus_frontend/src/components/ui/index.jsx | 122 | jsx |
| nexus_core/kernel/packages.py | 119 | python |
| nexus_core/kernel/audit.py | 118 | python |
| nexus_core/plan_maestro.md | 115 | markdown |
| PLAN_MAESTRO_BAJIOWARE.md | 109 | markdown |
| nexus_api/auth/deps.py | 107 | python |
| .github/workflows/ci.yml | 104 | yaml |
| nexus_frontend/src/hooks/useWebSocket.js | 104 | javascript |
| nexus_ops.py | 104 | python |
| nexus_frontend/src/pages/Terminal.jsx | 103 | jsx |
| nexus_connector.py | 102 | python |
| nexus_start.sh | 102 | bash |
| nexus_api/routes/evolution.py | 101 | python |
| nexus_api/routes/teams_v2.py | 101 | python |
| nexus_api/routes/auth.py | 100 | python |
| nexus_frontend/src/pages/Vault.jsx | 100 | jsx |
| nexus_core/setup_nexus.sh | 99 | bash |
| nexus_api/routes/a2a.py | 98 | python |
| nexus_core/tests/unit/test_sovereign_runtime.py | 96 | python |
| nexus_frontend/src/components/layout/Sidebar.jsx | 96 | jsx |
| nexus_api/routes/memory.py | 95 | python |
| nexus_api/routes/workflows.py | 94 | python |
| nexus_api/routes/connectors.py | 93 | python |
| nexus_core/agents/generated/fileagent.py | 92 | python |
| PRICING.md | 90 | markdown |
| nexus_frontend/src/pages/RBAC.jsx | 89 | jsx |
| nexus_core/kernel/telemetry.py | 87 | python |
| nexus_core/agents/generated/bashagent.py | 86 | python |
| README.md | 84 | markdown |
| nexus_api/config.py | 84 | python |
| nexus_api/services/workspace_manager.py | 82 | python |
| nexus_healthcheck.sh | 82 | bash |
| nexus_core/core/agent_factory.py | 81 | python |
| nexus_core/evolution/runner.py | 81 | python |
| nexus_frontend/src/App.jsx | 81 | jsx |
| nexus_api/auth/oidc.py | 80 | python |
| nexus_api/routes/plans.py | 78 | python |
| nexus_api/routes/killswitch.py | 77 | python |
| nexus_api/routes/scheduler.py | 76 | python |
| nexus_cli.py | 72 | python |
| nexus_core/kernel/approvals.py | 71 | python |
| nexus_core/agents/generated/dataanalysisagent.py | 70 | python |
| nexus_core/core/planner.py | 70 | python |
| nexus_core/kernel/knowledge.py | 70 | python |
| docs/runbooks/CLAUDE_MCP.md | 69 | markdown |
| nexus_api/routes/policies.py | 69 | python |
| nexus_core/kernel/postgres_store.py | 68 | python |
| nexus_frontend/src/components/ui/Form.jsx | 66 | jsx |
| nexus_api/routes/docagent.py | 65 | python |
| nexus_frontend/src/pages/ControlPlane.jsx | 65 | jsx |
| nexus_frontend/src/pages/Overview.jsx | 63 | jsx |
| nexus_core/kernel/artifacts.py | 61 | python |
| nexus_core/kernel/migrations.py | 60 | python |
| docs/NEXUS_SOVEREIGN.md | 59 | markdown |
| nexus_api/routes/tools.py | 58 | python |
| nexus_core/tests/integration/postgres_smoke.py | 58 | python |
| nexus_api/services/integration_guide.md | 57 | markdown |
| nexus_core/tests/unit/test_event_bus.py | 57 | python |
| nexus_core/tests/unit/test_security.py | 57 | python |
| nexus_api/routes/project_manager.py | 56 | python |
| nexus_core/agents/generated/reportgenerationagent.py | 56 | python |
| nexus_core/run_nexus.sh | 53 | bash |
| nexus_core/tests/unit/test_state_manager.py | 53 | python |
| nexus_api/routes/testagent.py | 52 | python |
| nexus_worker.py | 52 | python |
| nexus_api/routes/composite.py | 50 | python |
| nexus_core/memory/store.py | 50 | python |
| nexus_frontend/src/hooks/useNexusData.js | 49 | javascript |
| nexus_api/services/project_service.py | 48 | python |
| nexus_core/kernel/schema_validation.py | 48 | python |
| nexus_frontend/src/pages/Audit.jsx | 48 | jsx |
| data/factory/templates/pentest_scope.md | 47 | markdown |
| data/factory/templates/software_requirements.md | 47 | markdown |
| REPORTE_IMPLEMENTACION_NEXUS_2026-08-04.md | 46 | markdown |
| nexus_core/memory/manager.py | 44 | python |
| nexus_api/routes/packages.py | 43 | python |
| nexus_frontend/src/store/nexusStore.js | 43 | javascript |
| nexus_mcp/tests/test_remote_security.py | 42 | python |
| nexus_core/core/agent_generator.py | 41 | python |
| nexus_api/routes/approvals.py | 39 | python |
| nexus_api/routes/guardian.py | 37 | python |
| nexus_frontend/src/store/authStore.js | 37 | javascript |
| departments/marketing/manifest.json | 35 | json |
| nexus_core/kernel/store_factory.py | 35 | python |
| nexus_core/skills/nmap_scan.py | 35 | python |
| nexus_core/vector/store.py | 34 | python |
| nexus_frontend/package.json | 34 | json |
| nexus_mcp/tests/smoke.py | 34 | python |
| CHANGELOG.md | 33 | markdown |
| nexus_core/config.py | 33 | python |
| nexus_core/skills/nuclei_scan.py | 32 | python |
| install.sh | 31 | bash |
| nexus_frontend/eslint.config.js | 29 | javascript |
| nexus_core/kernel/__init__.py | 27 | python |
| nexus_core/tests/conftest.py | 27 | python |
| nexus_api/routes/audit.py | 26 | python |
| nexus_core/llm/fixtures/responses.json | 26 | json |
| nexus_api/routes/nexus.py | 25 | python |
| docker/entrypoint.sh | 22 | bash |
| nexus_core/llm/openai_provider.py | 22 | python |
| nexus_core/vector/memory.py | 22 | python |
| nexus_core/skills/http_client.py | 21 | python |
| nexus_frontend/vite.config.js | 21 | javascript |
| nexus_core/nexus_state.json | 20 | json |
| nexus_frontend/src/components/ui/Modal.jsx | 20 | jsx |
| nexus_core/llm/gemini_provider.py | 19 | python |
| nexus_core/vector/embeddings.py | 19 | python |
| nexus_core/agents/generated/loganalyzeragent.py | 18 | python |
| departments/marketing/evals/marketing.json | 17 | json |
| nexus_core/agents/generated/project_manager_agent.py | 17 | python |
| nexus_core/kernel/legacy.py | 17 | python |
| nexus_core/skills/file_reader.py | 16 | python |
| nexus_core/skills/registry.py | 16 | python |
| nexus_frontend/README.md | 16 | markdown |
| nexus_api/core/config.py | 15 | python |
| nexus_core/agents/data_analyst.py | 13 | python |
| docs/runbooks/SLO_SLI.md | 11 | markdown |
| nexus_core/memory/models.py | 10 | python |
| nexus_frontend/src/main.jsx | 10 | jsx |
| docs/adr/ADR-001-kernel-gateways.md | 9 | markdown |
| docs/runbooks/DEVELOPMENT_OFFLINE.md | 9 | markdown |
| docs/runbooks/INCIDENT_RESPONSE.md | 9 | markdown |
| nexus_backup.sh | 9 | bash |
| nexus_restore.sh | 9 | bash |
| docs/DEPLOYMENT_ON_PREM.md | 7 | markdown |
| docs/adr/ADR-002-zero-trust-execution.md | 7 | markdown |
| docs/adr/ADR-003-governed-evolution.md | 7 | markdown |
| docs/runbooks/BACKUP_RESTORE.md | 7 | markdown |
| docs/runbooks/CONNECTOR_MTLS.md | 7 | markdown |
| docs/runbooks/DATA_GOVERNANCE.md | 7 | markdown |
| nexus_core/evolution/__init__.py | 6 | python |
| nexus_core/skills/base.py | 6 | python |
| docs/CLEANUP_2026-08-04.md | 5 | markdown |
| docs/SCIM_PROVISIONING.md | 5 | markdown |
| ruff.toml | 5 | toml |
| nexus_api/__init__.py | 2 | python |
| nexus_mcp/__init__.py | 1 | python |
| nexus_mcp/tests/__init__.py | 1 | python |
| nexus_api/auth/__init__.py | 0 | python |
| nexus_api/db/__init__.py | 0 | python |
| nexus_api/routes/__init__.py | 0 | python |
| nexus_api/scheduler/__init__.py | 0 | python |
| nexus_api/services/__init__.py | 0 | python |
| nexus_core/__init__.py | 0 | python |
| nexus_core/agents/__init__.py | 0 | python |
| nexus_core/agents/generated/__init__.py | 0 | python |
| nexus_core/core/__init__.py | 0 | python |
| nexus_core/hitl/__init__.py | 0 | python |
| nexus_core/llm/__init__.py | 0 | python |
| nexus_core/memory/__init__.py | 0 | python |
| nexus_core/planner/__init__.py | 0 | python |
| nexus_core/skills/__init__.py | 0 | python |
| nexus_core/state/__init__.py | 0 | python |
| nexus_core/utils/__init__.py | 0 | python |
| nexus_core/vector/__init__.py | 0 | python |
| nexus_core/workforce/__init__.py | 0 | python |


## 3. Archivos clave

### Núcleo del kernel

### nexus_core/kernel/__init__.py — 27 líneas

```python
"""Provider-neutral contracts for the NEXUS control and execution planes."""

from .models import (
    AgentDefinition,
    Artifact,
    Identity,
    PolicyDecision,
    Resource,
    RiskLevel,
    RunContext,
    ToolDefinition,
    ToolResult,
)
from .policy import PolicyEngine

__all__ = [
    "AgentDefinition",
    "Artifact",
    "Identity",
    "PolicyDecision",
    "PolicyEngine",
    "Resource",
    "RiskLevel",
    "RunContext",
    "ToolDefinition",
    "ToolResult",
]
```

### nexus_core/kernel/approvals.py — 71 líneas

```python
"""Durable human approval service with separation of duties."""

from __future__ import annotations

from typing import Any, Dict
from uuid import uuid4

from .control_store import ControlStore
from .models import RunContext, utc_now


class ApprovalService:
    def __init__(self, store: ControlStore):
        self.store = store

    def request(self, context: RunContext, action: str) -> Dict[str, Any]:
        approval_id = f"approval_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_approvals
                (id,tenant_id,run_id,action,status,requested_by,created_at)
                VALUES(?,?,?,?,?,?,?)""",
                (approval_id, context.tenant_id, context.run_id, action, "pending",
                 context.identity.subject_id, utc_now()),
            )
        return self.get(approval_id, context.tenant_id)

    def get(self, approval_id: str, tenant_id: str) -> Dict[str, Any]:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM kernel_approvals WHERE id=? AND tenant_id=?",
                (approval_id, tenant_id),
            ).fetchone()
        if not row:
            raise KeyError("approval not found")
        return dict(row)

    def decide(
        self,
        approval_id: str,
        tenant_id: str,
        actor_id: str,
        approved: bool,
        reason: str = "",
    ) -> Dict[str, Any]:
        approval = self.get(approval_id, tenant_id)
        if approval["status"] != "pending":
            raise ValueError("approval is already decided")
        if approval["requested_by"] == actor_id:
            raise PermissionError("requester cannot approve their own action")
        status = "approved" if approved else "denied"
        with self.store.connect() as conn:
            conn.execute(
                """UPDATE kernel_approvals SET status=?,decided_by=?,reason=?,decided_at=?
                WHERE id=? AND tenant_id=? AND status='pending'""",
                (status, actor_id, reason, utc_now(), approval_id, tenant_id),
            )
        return self.get(approval_id, tenant_id)

    def verify(
        self,
        approval_id: str,
        context: RunContext,
        expected_action: str,
    ) -> bool:
        approval = self.get(approval_id, context.tenant_id)
        return (
            approval["run_id"] == context.run_id
            and approval["action"] == expected_action
            and approval["status"] == "approved"
        )
```

### nexus_core/kernel/artifacts.py — 61 líneas

```python
"""Content-addressed artifact storage; local now, object storage adapters later."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

from .control_store import ControlStore
from .models import utc_now


class LocalArtifactStore:
    def __init__(self, store: ControlStore, root: str | Path):
        self.store = store
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, tenant_id: str, content: bytes, media_type: str,
            run_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        digest = hashlib.sha256(content).hexdigest()
        artifact_id = f"artifact_{uuid4().hex}"
        directory = self.root / tenant_id / digest[:2]
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / digest
        if not target.exists():
            temporary = directory / f".{digest}.{uuid4().hex}.tmp"
            with temporary.open("wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        now = utc_now()
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_artifacts
                (id,tenant_id,run_id,media_type,storage_uri,sha256,size_bytes,metadata,created_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (artifact_id, tenant_id, run_id, media_type, str(target), digest,
                 len(content), json.dumps(metadata or {}), now),
            )
        return {"id": artifact_id, "sha256": digest, "size_bytes": len(content), "media_type": media_type}

    def get(self, tenant_id: str, artifact_id: str) -> bytes:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT storage_uri,sha256 FROM kernel_artifacts WHERE id=? AND tenant_id=?",
                (artifact_id, tenant_id),
            ).fetchone()
        if not row:
            raise KeyError("artifact not found")
        path = Path(row["storage_uri"]).resolve()
        if self.root not in path.parents:
            raise RuntimeError("artifact path escaped configured storage root")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != row["sha256"]:
            raise RuntimeError("artifact integrity check failed")
        return content
```

### nexus_core/kernel/audit.py — 118 líneas

```python
"""Append-only, hash-chained audit writer."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict
from uuid import uuid4

from .control_store import ControlStore
from .models import utc_now


class AuditWriter:
    def __init__(self, store: ControlStore):
        self.store = store

    def append(
        self,
        *,
        tenant_id: str,
        trace_id: str,
        actor_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: Dict[str, Any],
        decision: str | None = None,
    ) -> str:
        event_id = f"audit_{uuid4().hex}"
        created_at = utc_now()
        sanitized = self._sanitize(payload)
        with self.store.connect() as conn:
            previous = conn.execute(
                "SELECT event_hash FROM kernel_audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous["event_hash"] if previous else ""
            canonical = json.dumps({
                "event_id": event_id,
                "tenant_id": tenant_id,
                "trace_id": trace_id,
                "actor_id": actor_id,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "decision": decision,
                "payload": sanitized,
                "previous_hash": previous_hash,
                "created_at": created_at,
            }, sort_keys=True, separators=(",", ":"))
            event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            conn.execute(
                """INSERT INTO kernel_audit_events
                (event_id,tenant_id,trace_id,actor_id,action,resource_type,resource_id,
                 decision,payload,previous_hash,event_hash,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (event_id, tenant_id, trace_id, actor_id, action, resource_type,
                 resource_id, decision, json.dumps(sanitized, sort_keys=True),
                 previous_hash, event_hash, created_at),
            )
        return event_id

    def export(self, tenant_id: str, *, trace_id: str | None = None,
               run_id: str | None = None) -> list[Dict[str, Any]]:
        clauses = ["tenant_id=?"]
        params: list[Any] = [tenant_id]
        if trace_id:
            clauses.append("trace_id=?")
            params.append(trace_id)
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM kernel_audit_events WHERE " + " AND ".join(clauses) + " ORDER BY sequence",
                tuple(params),
            ).fetchall()
        values = []
        for row in rows:
            value = dict(row)
            value["payload"] = json.loads(value["payload"])
            if run_id and value["payload"].get("run_id") != run_id:
                continue
            values.append(value)
        return values

    def verify_chain(self) -> tuple[bool, int | None]:
        """Verify the global append chain; return the first corrupt sequence."""
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM kernel_audit_events ORDER BY sequence"
            ).fetchall()
        previous_hash = ""
        for row in rows:
            value = dict(row)
            canonical = json.dumps({
                "event_id": value["event_id"], "tenant_id": value["tenant_id"],
                "trace_id": value["trace_id"], "actor_id": value["actor_id"],
                "action": value["action"], "resource_type": value["resource_type"],
                "resource_id": value["resource_id"], "decision": value["decision"],
                "payload": json.loads(value["payload"]), "previous_hash": previous_hash,
                "created_at": value["created_at"],
            }, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if value["previous_hash"] != previous_hash or not hmac.compare_digest(value["event_hash"], expected):
                return False, value["sequence"]
            previous_hash = value["event_hash"]
        return True, None

    @classmethod
    def _sanitize(cls, value: Any) -> Any:
        secret_terms = {"password", "secret", "token", "api_key", "authorization"}
        if isinstance(value, dict):
            return {
                key: "[REDACTED]" if key.lower() in secret_terms else cls._sanitize(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._sanitize(item) for item in value]
        return value
```

### nexus_core/kernel/connectors.py — 130 líneas

```python
"""Connector enrollment and revocation service using one-time bootstrap tokens."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable
from uuid import uuid4

from .control_store import ControlStore
from .models import utc_now


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ConnectorRegistry:
    def __init__(self, store: ControlStore):
        self.store = store

    def create_enrollment_token(
        self, tenant_id: str, created_by: str, ttl_minutes: int = 10
    ) -> str:
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)).isoformat()
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO connector_enrollment_tokens
                (token_hash,tenant_id,expires_at,created_by,created_at) VALUES(?,?,?,?,?)""",
                (digest(token), tenant_id, expires_at, created_by, utc_now()),
            )
        return token

    def enroll(
        self,
        enrollment_token: str,
        *,
        name: str,
        device_id: str,
        capabilities: Iterable[str],
        allowed_roots: Iterable[str],
        certificate_fingerprint: str | None = None,
    ) -> Dict[str, Any]:
        now = utc_now()
        connector_id = f"connector_{uuid4().hex}"
        credential = secrets.token_urlsafe(48)
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """SELECT tenant_id FROM connector_enrollment_tokens
                WHERE token_hash=? AND used_at IS NULL AND expires_at>?""",
                (digest(enrollment_token), now),
            ).fetchone()
            if not row:
                raise PermissionError("invalid or expired enrollment token")
            conn.execute(
                "UPDATE connector_enrollment_tokens SET used_at=? WHERE token_hash=?",
                (now, digest(enrollment_token)),
            )
            conn.execute(
                """INSERT INTO kernel_connectors
                (id,tenant_id,name,device_id,credential_hash,status,capabilities,
                 allowed_roots,certificate_fingerprint,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (connector_id, row["tenant_id"], name, device_id, digest(credential),
                 "active", json.dumps(sorted(set(capabilities))),
                 json.dumps(sorted(set(allowed_roots))), certificate_fingerprint, now),
            )
        return {"connector_id": connector_id, "credential": credential, "tenant_id": row["tenant_id"]}

    def authenticate(self, connector_id: str, credential: str,
                     certificate_fingerprint: str | None = None) -> Dict[str, Any]:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM kernel_connectors WHERE id=? AND status='active'",
                (connector_id,),
            ).fetchone()
        if not row or not hmac.compare_digest(row["credential_hash"], digest(credential)):
            raise PermissionError("invalid connector credential")
        if row["certificate_fingerprint"] and not hmac.compare_digest(
            row["certificate_fingerprint"], certificate_fingerprint or ""
        ):
            raise PermissionError("connector certificate does not match enrollment")
        value = dict(row)
        value["capabilities"] = json.loads(value["capabilities"])
        value["allowed_roots"] = json.loads(value["allowed_roots"])
        value.pop("credential_hash", None)
        return value

    def heartbeat(self, connector_id: str, credential: str,
                  certificate_fingerprint: str | None = None) -> Dict[str, Any]:
        connector = self.authenticate(connector_id, credential, certificate_fingerprint)
        now = utc_now()
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE kernel_connectors SET last_seen_at=? WHERE id=?", (now, connector_id)
            )
        connector["last_seen_at"] = now
        return connector

    def rotate_credential(self, connector_id: str, credential: str,
                          certificate_fingerprint: str | None = None) -> str:
        self.authenticate(connector_id, credential, certificate_fingerprint)
        replacement = secrets.token_urlsafe(48)
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE kernel_connectors SET credential_hash=?,credential_rotated_at=? WHERE id=?",
                (digest(replacement), utc_now(), connector_id),
            )
        return replacement

    def revoke(self, connector_id: str, tenant_id: str | None = None) -> None:
        now = utc_now()
        with self.store.connect() as conn:
            if tenant_id and tenant_id != "system":
                updated = conn.execute(
                    """UPDATE kernel_connectors SET status='revoked',revoked_at=?
                    WHERE id=? AND tenant_id=?""",
                    (now, connector_id, tenant_id),
                )
            else:
                updated = conn.execute(
                    "UPDATE kernel_connectors SET status='revoked',revoked_at=? WHERE id=?",
                    (now, connector_id),
                )
            if updated.rowcount != 1:
                raise KeyError("connector not found in tenant")
```

### nexus_core/kernel/control_store.py — 801 líneas

Archivo >800 líneas (801).

Índice de clases/funciones:
- L287: ClassDef ControlStore
- L288: FunctionDef __init__
- L292: FunctionDef connect
- L299: FunctionDef initialize
- L309: FunctionDef _migrate_sqlite
- L336: FunctionDef migrate_legacy_users
- L360: FunctionDef create_tenant
- L370: FunctionDef create_organization
- L381: FunctionDef list_organizations
- L387: FunctionDef list_tenants
- L393: FunctionDef put_definition
- L418: FunctionDef list_definitions
- L428: FunctionDef create_run
- L454: FunctionDef get_run
- L461: FunctionDef append_run_event
- L478: FunctionDef list_run_events
- L487: FunctionDef create_conversation
- L505: FunctionDef list_conversations
- L512: FunctionDef get_conversation
- L523: FunctionDef append_message
- L545: FunctionDef list_messages
- L555: FunctionDef delete_conversation
- L565: FunctionDef enqueue_task
- L595: FunctionDef claim_task
- L625: FunctionDef complete_task
- L659: FunctionDef fail_or_retry_task
- L699: FunctionDef request_task_cancel
- L719: FunctionDef list_task_transitions
- L725: FunctionDef record_usage
- L752: FunctionDef set_quota
- L766: FunctionDef usage_total
- L777: FunctionDef _transition
- L785: FunctionDef _outbox
- L796: FunctionDef _decode_row

Primeras 100 líneas:
```python
"""Durable SQLite control store for development and single-node deployments.

The repository contract deliberately avoids SQLite-specific types so a PostgreSQL
implementation can replace it without changing gateways or agents.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from uuid import uuid4

from .models import utc_now

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kernel_tenants (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kernel_organizations (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kernel_environments (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    classification TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL, UNIQUE(tenant_id,name)
);
CREATE TABLE IF NOT EXISTS kernel_groups (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    created_at TEXT NOT NULL, UNIQUE(tenant_id,name)
);
CREATE TABLE IF NOT EXISTS kernel_group_memberships (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, group_id TEXT NOT NULL,
    subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, created_at TEXT NOT NULL,
    UNIQUE(group_id,subject_type,subject_id)
);
CREATE TABLE IF NOT EXISTS kernel_service_accounts (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    credential_hash TEXT NOT NULL, roles TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT, created_at TEXT NOT NULL, UNIQUE(tenant_id,name)
);
CREATE TABLE IF NOT EXISTS kernel_resources (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, environment_id TEXT,
    kind TEXT NOT NULL, name TEXT NOT NULL, classification TEXT NOT NULL,
    owner_id TEXT, attributes TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL, UNIQUE(tenant_id,kind,name)
);
CREATE TABLE IF NOT EXISTS kernel_capabilities (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    description TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(tenant_id,name)
);
CREATE TABLE IF NOT EXISTS kernel_agent_capabilities (
    agent_id TEXT NOT NULL, capability_id TEXT NOT NULL,
    PRIMARY KEY(agent_id,capability_id)
);
CREATE TABLE IF NOT EXISTS kernel_tool_resources (
    tool_id TEXT NOT NULL, resource_id TEXT NOT NULL, scopes TEXT NOT NULL,
    PRIMARY KEY(tool_id,resource_id)
);
CREATE TABLE IF NOT EXISTS kernel_users (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, email TEXT NOT NULL,
    name TEXT NOT NULL, hashed_pw TEXT NOT NULL, role TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
    UNIQUE(tenant_id, email),
    FOREIGN KEY(tenant_id) REFERENCES kernel_tenants(id)
);
CREATE TABLE IF NOT EXISTS auth_refresh_sessions (
    jti TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at TEXT NOT NULL,
    revoked_at TEXT, created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES kernel_users(id)
);
CREATE TABLE IF NOT EXISTS auth_revoked_tokens (
    jti TEXT PRIMARY KEY, expires_at TEXT NOT NULL, revoked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kernel_departments (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    created_at TEXT NOT NULL, UNIQUE(tenant_id, name),
    FOREIGN KEY(tenant_id) REFERENCES kernel_tenants(id)
);
CREATE TABLE IF NOT EXISTS kernel_packages (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, package_name TEXT NOT NULL,
    version TEXT NOT NULL, manifest TEXT NOT NULL, status TEXT NOT NULL,
    installed_by TEXT NOT NULL, installed_at TEXT NOT NULL,
    UNIQUE(tenant_id, package_name, version),
    FOREIGN KEY(tenant_id) REFERENCES kernel_tenants(id)
);
CREATE TABLE IF NOT EXISTS kernel_policies (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    version TEXT NOT NULL, effect TEXT NOT NULL, actions TEXT NOT NULL,
    resource_kinds TEXT NOT NULL, conditions TEXT NOT NULL,
    requires_approval INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, UNIQUE(tenant_id,name,version),
    FOREIGN KEY(tenant_id) REFERENCES kernel_tenants(id)
```

Últimas 50 líneas:
```python
    def set_quota(self, tenant_id: str, subject_type: str, subject_id: str,
                  metric: str, limit_value: float) -> None:
        if limit_value < 0:
            raise ValueError("quota cannot be negative")
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_quotas
                (id,tenant_id,subject_type,subject_id,metric,limit_value,created_at)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant_id,subject_type,subject_id,metric)
                DO UPDATE SET limit_value=excluded.limit_value,enabled=1""",
                (f"quota_{uuid4().hex}", tenant_id, subject_type, subject_id,
                 metric, limit_value, utc_now()),
            )

    def usage_total(self, tenant_id: str, run_id: str, subject_type: str,
                    subject_id: str, metric: str) -> float:
        with self.connect() as conn:
            row = conn.execute(
                """SELECT COALESCE(SUM(amount),0) AS total FROM kernel_usage_ledger
                WHERE tenant_id=? AND run_id=? AND subject_type=? AND subject_id=? AND metric=?""",
                (tenant_id, run_id, subject_type, subject_id, metric),
            ).fetchone()
        return float(row["total"])

    @staticmethod
    def _transition(conn, task_id: str, old: Optional[str], new: str, reason: Optional[str], actor: str) -> None:
        conn.execute(
            """INSERT INTO kernel_task_transitions
            (task_id,from_status,to_status,reason,actor_id,created_at) VALUES(?,?,?,?,?,?)""",
            (task_id, old, new, reason, actor, utc_now()),
        )

    @staticmethod
    def _outbox(conn, tenant_id: str, aggregate_type: str, aggregate_id: str,
                event_type: str, payload: Dict[str, Any]) -> None:
        conn.execute(
            """INSERT INTO kernel_outbox
            (id,tenant_id,aggregate_type,aggregate_id,event_type,payload,created_at)
            VALUES(?,?,?,?,?,?,?)""",
            (f"evt_{uuid4().hex}", tenant_id, aggregate_type, aggregate_id,
             event_type, json.dumps(payload), utc_now()),
        )

    @staticmethod
    def _decode_row(row: sqlite3.Row, fields: Iterable[str]) -> Dict[str, Any]:
        value = dict(row)
        for field in fields:
            if value.get(field):
                value[field] = json.loads(value[field])
        return value
```


### nexus_core/kernel/directory.py — 169 líneas

```python
"""Tenant-scoped AI Directory repositories and service identities."""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any, Dict, List, Optional
from uuid import uuid4

from .control_store import ControlStore
from .models import utc_now


class DirectoryRepository:
    def __init__(self, store: ControlStore):
        self.store = store

    def create_environment(self, tenant_id: str, name: str,
                           classification: str = "internal") -> Dict[str, Any]:
        if name not in {"development", "staging", "production"}:
            raise ValueError("environment must be development, staging or production")
        entity_id = f"env_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_environments
                (id,tenant_id,name,classification,created_at) VALUES(?,?,?,?,?)""",
                (entity_id, tenant_id, name, classification, utc_now()),
            )
        return {"id": entity_id, "tenant_id": tenant_id, "name": name, "classification": classification}

    def create_group(self, tenant_id: str, name: str) -> Dict[str, Any]:
        group_id = f"group_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                "INSERT INTO kernel_groups(id,tenant_id,name,created_at) VALUES(?,?,?,?)",
                (group_id, tenant_id, name, utc_now()),
            )
        return {"id": group_id, "tenant_id": tenant_id, "name": name}

    def create_department(self, tenant_id: str, name: str) -> Dict[str, Any]:
        department_id = f"department_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_departments(id,tenant_id,name,created_at)
                VALUES(?,?,?,?)""", (department_id, tenant_id, name, utc_now()),
            )
        return {"id": department_id, "tenant_id": tenant_id, "name": name}

    def create_capability(self, tenant_id: str, name: str,
                          description: str = "") -> Dict[str, Any]:
        capability_id = f"capability_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_capabilities
                (id,tenant_id,name,description,created_at) VALUES(?,?,?,?,?)""",
                (capability_id, tenant_id, name, description, utc_now()),
            )
        return {"id": capability_id, "tenant_id": tenant_id, "name": name,
                "description": description}

    def assign_agent_capability(self, tenant_id: str, agent_id: str,
                                capability_id: str) -> None:
        with self.store.connect() as conn:
            agent = conn.execute(
                "SELECT id FROM kernel_agents WHERE id=? AND tenant_id=?",
                (agent_id, tenant_id),
            ).fetchone()
            capability = conn.execute(
                "SELECT id FROM kernel_capabilities WHERE id=? AND tenant_id=?",
                (capability_id, tenant_id),
            ).fetchone()
            if not agent or not capability:
                raise KeyError("agent or capability not found in tenant")
            conn.execute(
                """INSERT OR IGNORE INTO kernel_agent_capabilities
                (agent_id,capability_id) VALUES(?,?)""", (agent_id, capability_id),
            )

    def bind_tool_resource(self, tenant_id: str, tool_id: str,
                           resource_id: str, scopes: list[str]) -> None:
        with self.store.connect() as conn:
            tool = conn.execute(
                "SELECT id FROM kernel_tools WHERE id=? AND tenant_id=?",
                (tool_id, tenant_id),
            ).fetchone()
            resource = conn.execute(
                "SELECT id FROM kernel_resources WHERE id=? AND tenant_id=?",
                (resource_id, tenant_id),
            ).fetchone()
            if not tool or not resource:
                raise KeyError("tool or resource not found in tenant")
            conn.execute(
                """INSERT OR IGNORE INTO kernel_tool_resources(tool_id,resource_id,scopes)
                VALUES(?,?,?)""", (tool_id, resource_id, json.dumps(sorted(set(scopes)))),
            )

    def add_member(self, tenant_id: str, group_id: str,
                   subject_type: str, subject_id: str) -> str:
        if subject_type not in {"user", "service_account", "agent"}:
            raise ValueError("unsupported group member type")
        membership_id = f"membership_{uuid4().hex}"
        with self.store.connect() as conn:
            group = conn.execute(
                "SELECT id FROM kernel_groups WHERE id=? AND tenant_id=?", (group_id, tenant_id)
            ).fetchone()
            if not group:
                raise KeyError("group not found")
            conn.execute(
                """INSERT INTO kernel_group_memberships
                (id,tenant_id,group_id,subject_type,subject_id,created_at) VALUES(?,?,?,?,?,?)""",
                (membership_id, tenant_id, group_id, subject_type, subject_id, utc_now()),
            )
        return membership_id

    def create_service_account(self, tenant_id: str, name: str,
                               roles: List[str], expires_at: Optional[str] = None) -> Dict[str, Any]:
        if not set(roles).issubset({"viewer", "operator"}):
            raise ValueError("service accounts cannot receive admin role")
        account_id = f"service_{uuid4().hex}"
        credential = secrets.token_urlsafe(48)
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_service_accounts
                (id,tenant_id,name,credential_hash,roles,expires_at,created_at)
                VALUES(?,?,?,?,?,?,?)""",
                (account_id, tenant_id, name, hashlib.sha256(credential.encode()).hexdigest(),
                 json.dumps(roles), expires_at, utc_now()),
            )
        return {"id": account_id, "tenant_id": tenant_id, "name": name,
                "roles": roles, "credential": credential, "expires_at": expires_at}

    def create_resource(self, tenant_id: str, kind: str, name: str,
                        classification: str, environment_id: Optional[str] = None,
                        owner_id: Optional[str] = None,
                        attributes: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        resource_id = f"resource_{uuid4().hex}"
        with self.store.connect() as conn:
            if environment_id and not conn.execute(
                "SELECT id FROM kernel_environments WHERE id=? AND tenant_id=?",
                (environment_id, tenant_id),
            ).fetchone():
                raise KeyError("environment not found in tenant")
            conn.execute(
                """INSERT INTO kernel_resources
                (id,tenant_id,environment_id,kind,name,classification,owner_id,attributes,created_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (resource_id, tenant_id, environment_id, kind, name, classification,
                 owner_id, json.dumps(attributes or {}), utc_now()),
            )
        return {"id": resource_id, "tenant_id": tenant_id, "kind": kind, "name": name,
                "classification": classification, "environment_id": environment_id}

    def list_kind(self, table: str, tenant_id: str) -> List[Dict[str, Any]]:
        allowed = {
            "kernel_environments", "kernel_groups", "kernel_service_accounts",
            "kernel_resources", "kernel_departments", "kernel_capabilities",
        }
        if table not in allowed:
            raise ValueError("unsupported directory entity")
        with self.store.connect() as conn:
            rows = conn.execute(f"SELECT * FROM {table} WHERE tenant_id=? ORDER BY created_at", (tenant_id,)).fetchall()
        values = [dict(row) for row in rows]
        for value in values:
            value.pop("credential_hash", None)
            for field in ("roles", "attributes"):
                if value.get(field):
                    value[field] = json.loads(value[field])
        return values
```

### nexus_core/kernel/knowledge.py — 70 líneas

```python
"""Tenant-scoped sovereign knowledge with verifiable citations."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import uuid4

from .models import utc_now


class KnowledgeStore:
    CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}

    def __init__(self, store):
        self.store = store

    def ingest(self, *, tenant_id: str, title: str, source_uri: str, content: str,
               created_by: str, classification: str = "internal",
               metadata: dict[str, Any] | None = None) -> dict:
        if classification not in self.CLASSIFICATIONS:
            raise ValueError("unsupported data classification")
        if not content.strip() or not source_uri.strip():
            raise ValueError("knowledge content and source URI are required")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        document = {"id": f"document_{uuid4().hex}", "tenant_id": tenant_id,
                    "title": title[:200], "source_uri": source_uri,
                    "sha256": digest, "classification": classification,
                    "metadata": metadata or {}, "created_by": created_by,
                    "created_at": utc_now()}
        with self.store.connect() as conn:
            existing = conn.execute(
                """SELECT * FROM kernel_knowledge_documents
                WHERE tenant_id=? AND source_uri=? AND sha256=?""",
                (tenant_id, source_uri, digest),
            ).fetchone()
            if existing:
                value = dict(existing)
                value["metadata"] = json.loads(value["metadata"])
                value.pop("content", None)
                return value
            conn.execute(
                """INSERT INTO kernel_knowledge_documents
                (id,tenant_id,title,source_uri,content,sha256,classification,metadata,
                 created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (document["id"], tenant_id, document["title"], source_uri, content,
                 digest, classification, json.dumps(document["metadata"]),
                 created_by, document["created_at"]),
            )
        return document

    def search(self, tenant_id: str, query: str, *, allowed_classifications: set[str],
               limit: int = 10) -> list[dict]:
        allowed = sorted(self.CLASSIFICATIONS.intersection(allowed_classifications))
        if not allowed:
            return []
        placeholders = ",".join("?" for _ in allowed)
        params: list[Any] = [tenant_id, *allowed, f"%{query}%", f"%{query}%", min(limit, 50)]
        with self.store.connect() as conn:
            rows = conn.execute(
                f"""SELECT id,title,source_uri,sha256,classification,
                substr(content,1,1000) AS excerpt,created_at
                FROM kernel_knowledge_documents WHERE tenant_id=?
                AND classification IN ({placeholders}) AND (title LIKE ? OR content LIKE ?)
                ORDER BY created_at DESC LIMIT ?""", tuple(params),
            ).fetchall()
        return [{**dict(row), "citation": {"document_id": row["id"],
                 "source_uri": row["source_uri"], "sha256": row["sha256"]}}
                for row in rows]
```

### nexus_core/kernel/legacy.py — 17 líneas

```python
"""Hard gate for pre-kernel tools that do not yet use ToolGateway/SandboxRuntime."""

import os


def legacy_execution_enabled() -> bool:
    return (
        os.getenv("NEXUS_ENV", "development").lower() != "production"
        and os.getenv("NEXUS_ENABLE_LEGACY_EXECUTION", "false").lower() == "true"
    )


def require_legacy_execution() -> None:
    if not legacy_execution_enabled():
        raise PermissionError(
            "Legacy direct execution is disabled; register this operation through ToolGateway"
        )
```

### nexus_core/kernel/memory.py — 152 líneas

```python
"""Tenant-scoped durable memory and knowledge records.

This store deliberately uses lexical search. A future vector backend is an
optional index, never the source of truth, so offline and private deployments
remain fully functional.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from .models import utc_now


class MemoryStore:
    def __init__(self, store):
        self.store = store

    def save_message(self, tenant_id: str, agent_id: str, agent_name: str,
                     role: str, content: str, session_id: str | None = None,
                     classification: str = "internal",
                     retention_days: int | None = None) -> str:
        if not content.strip():
            raise ValueError("memory content cannot be empty")
        expires_at = None
        if retention_days is not None:
            if retention_days < 1:
                raise ValueError("retention_days must be positive")
            expires_at = (datetime.now(timezone.utc) + timedelta(days=retention_days)).isoformat()
        memory_id = f"mem_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_memories
                (id,tenant_id,agent_id,agent_name,session_id,role,content,
                 classification,tokens_est,expires_at,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (memory_id, tenant_id, agent_id, agent_name, session_id, role,
                 content, classification, int(len(content.split()) * 1.3),
                 expires_at, utc_now()),
            )
        return memory_id

    def context(self, tenant_id: str, agent_id: str, session_id: str | None = None,
                limit: int = 20) -> list[dict]:
        params: list[object] = [tenant_id, agent_id, utc_now()]
        session = ""
        if session_id is not None:
            session = " AND session_id=?"
            params.append(session_id)
        params.append(limit)
        with self.store.connect() as conn:
            rows = conn.execute(
                f"""SELECT id,role,content,session_id,classification,created_at
                FROM kernel_memories WHERE tenant_id=? AND agent_id=?
                AND (expires_at IS NULL OR expires_at>?) {session}
                ORDER BY created_at DESC LIMIT ?""",
                tuple(params),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def search(self, tenant_id: str, agent_id: str, query: str,
               limit: int = 10) -> list[dict]:
        with self.store.connect() as conn:
            rows = conn.execute(
                """SELECT id,role,content,session_id,classification,created_at
                FROM kernel_memories WHERE tenant_id=? AND agent_id=?
                AND (expires_at IS NULL OR expires_at>?) AND content LIKE ?
                ORDER BY created_at DESC LIMIT ?""",
                (tenant_id, agent_id, utc_now(), f"%{query}%", limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def save_summary(self, tenant_id: str, agent_id: str, summary: str,
                     session_id: str | None = None, msg_count: int = 0,
                     classification: str = "internal") -> str:
        summary_id = f"summary_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_memory_summaries
                (id,tenant_id,agent_id,session_id,summary,msg_count,
                 classification,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                (summary_id, tenant_id, agent_id, session_id, summary, msg_count,
                 classification, None, utc_now()),
            )
        return summary_id

    def summary(self, tenant_id: str, agent_id: str,
                session_id: str | None = None) -> str | None:
        clause = " AND session_id=?" if session_id is not None else ""
        params = [tenant_id, agent_id, utc_now()]
        if session_id is not None:
            params.append(session_id)
        with self.store.connect() as conn:
            row = conn.execute(
                f"""SELECT summary FROM kernel_memory_summaries
                WHERE tenant_id=? AND agent_id=?
                AND (expires_at IS NULL OR expires_at>?) {clause}
                ORDER BY created_at DESC LIMIT 1""", tuple(params),
            ).fetchone()
        return row["summary"] if row else None

    def clear(self, tenant_id: str, agent_id: str,
              session_id: str | None = None) -> int:
        clause = " AND session_id=?" if session_id is not None else ""
        params: tuple[object, ...] = (tenant_id, agent_id)
        if session_id is not None:
            params += (session_id,)
        with self.store.connect() as conn:
            cursor = conn.execute(
                f"DELETE FROM kernel_memories WHERE tenant_id=? AND agent_id=?{clause}",
                params,
            )
            conn.execute(
                f"DELETE FROM kernel_memory_summaries WHERE tenant_id=? AND agent_id=?{clause}",
                params,
            )
            return cursor.rowcount

    def purge_expired(self, tenant_id: str) -> int:
        with self.store.connect() as conn:
            cursor = conn.execute(
                "DELETE FROM kernel_memories WHERE tenant_id=? AND expires_at<=?",
                (tenant_id, utc_now()),
            )
            conn.execute(
                "DELETE FROM kernel_memory_summaries WHERE tenant_id=? AND expires_at<=?",
                (tenant_id, utc_now()),
            )
            return cursor.rowcount

    def agents(self, tenant_id: str) -> list[dict]:
        with self.store.connect() as conn:
            rows = conn.execute(
                """SELECT agent_id,MAX(agent_name) AS agent_name,COUNT(*) AS total_msgs,
                SUM(tokens_est) AS total_tokens,MAX(created_at) AS last_activity
                FROM kernel_memories WHERE tenant_id=?
                AND (expires_at IS NULL OR expires_at>?) GROUP BY agent_id
                ORDER BY last_activity DESC""", (tenant_id, utc_now()),
            ).fetchall()
        return [dict(row) for row in rows]

    def stats(self, tenant_id: str, agent_id: str) -> dict:
        with self.store.connect() as conn:
            total = conn.execute(
                """SELECT COUNT(*) AS total_messages,
                COALESCE(SUM(tokens_est),0) AS total_tokens_est
                FROM kernel_memories WHERE tenant_id=? AND agent_id=?
                AND (expires_at IS NULL OR expires_at>?)""",
                (tenant_id, agent_id, utc_now()),
            ).fetchone()
        return dict(total)
```

### nexus_core/kernel/migrations.py — 60 líneas

```python
"""Minimal reversible migration runner for control-plane schema changes."""

from __future__ import annotations

from dataclasses import dataclass

from .models import utc_now


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    up: str
    down: str


class MigrationRunner:
    def __init__(self, store, migrations: tuple[Migration, ...]):
        versions = [migration.version for migration in migrations]
        if versions != sorted(set(versions)):
            raise ValueError("migration versions must be unique and ordered")
        self.store = store
        self.migrations = migrations

    def applied(self) -> set[int]:
        with self.store.connect() as conn:
            rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
        return {int(row["version"]) for row in rows}

    def upgrade(self, target: int | None = None) -> list[int]:
        completed = self.applied()
        changed = []
        for migration in self.migrations:
            if migration.version in completed or (
                target is not None and migration.version > target
            ):
                continue
            with self.store.connect() as conn:
                conn.executescript(migration.up)
                conn.execute(
                    "INSERT INTO schema_migrations(version,name,applied_at) VALUES(?,?,?)",
                    (migration.version, migration.name, utc_now()),
                )
            changed.append(migration.version)
        return changed

    def downgrade(self, target: int) -> list[int]:
        completed = self.applied()
        changed = []
        for migration in reversed(self.migrations):
            if migration.version <= target or migration.version not in completed:
                continue
            with self.store.connect() as conn:
                conn.executescript(migration.down)
                conn.execute(
                    "DELETE FROM schema_migrations WHERE version=?", (migration.version,)
                )
            changed.append(migration.version)
        return changed
```

### nexus_core/kernel/model_router.py — 122 líneas

```python
"""Policy-aware provider routing with token budgets and deterministic fallback."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List

from nexus_core.llm.abstraction import (
    BaseLLMClient,
    LLMMessage,
    LLMResponse,
    NexusLLMError,
)

from .control_store import ControlStore
from .models import RunContext
from .telemetry import metrics, telemetry


@dataclass(frozen=True)
class RoutePolicy:
    name: str
    providers: tuple[str, ...]
    classifications: tuple[str, ...] = ("public", "internal")
    allow_cloud: bool = True
    timeout_seconds: float = 60
    retries_per_provider: int = 1
    circuit_failures: int = 3
    circuit_cooldown_seconds: float = 30


class ModelRouter:
    def __init__(self, clients: Dict[str, BaseLLMClient], policies: Iterable[RoutePolicy],
                 store: ControlStore | None = None):
        self.clients = clients
        self.policies = {policy.name: policy for policy in policies}
        self._usage: Dict[str, int] = {}
        self.store = store
        self._circuits: Dict[str, tuple[int, float]] = {}

    async def complete(
        self,
        route: str,
        messages: List[LLMMessage],
        context: RunContext,
        *,
        classification: str = "internal",
        **kwargs,
    ) -> LLMResponse:
        policy = self.policies.get(route)
        if not policy:
            raise KeyError(f"unknown model route: {route}")
        if classification not in policy.classifications:
            raise PermissionError("classification is not allowed by this model route")
        used = int(self.store.usage_total(
            context.tenant_id, context.run_id, "model_route", route, "tokens"
        )) if self.store else self._usage.get(context.run_id, 0)
        if context.budget_tokens and used >= context.budget_tokens:
            raise PermissionError("run token budget exhausted")

        errors = []
        for provider_name in policy.providers:
            client = self.clients.get(provider_name)
            if not client:
                continue
            if not policy.allow_cloud and provider_name not in {"fake", "ollama", "vllm"}:
                continue
            failures, opened_at = self._circuits.get(provider_name, (0, 0.0))
            if failures >= policy.circuit_failures and time.monotonic() - opened_at < policy.circuit_cooldown_seconds:
                errors.append(f"{provider_name}: circuit open")
                continue
            for attempt in range(policy.retries_per_provider + 1):
                try:
                    with telemetry.span("gen_ai.chat", {
                        "nexus.tenant.id": context.tenant_id,
                        "nexus.run.id": context.run_id,
                        "nexus.trace.id": context.trace_id,
                        "gen_ai.provider.name": provider_name,
                        "gen_ai.request.model": client.config.model,
                    }):
                        response = await asyncio.wait_for(
                            client.complete(messages, **kwargs), timeout=policy.timeout_seconds
                        )
                    new_usage = used + response.total_tokens
                    if context.budget_tokens and new_usage > context.budget_tokens:
                        raise PermissionError("model response exceeded run token budget")
                    if self.store:
                        self.store.record_usage(
                            context.tenant_id, context.run_id, "model_route", route,
                            "tokens", response.total_tokens,
                            {"provider": provider_name, "model": client.config.model,
                             "trace_id": context.trace_id},
                        )
                    self._usage[context.run_id] = new_usage
                    self._circuits[provider_name] = (0, 0.0)
                    metrics.increment(
                        "nexus_model_requests_total", provider=provider_name,
                        route=route, status="success", tenant_id=context.tenant_id,
                    )
                    metrics.increment(
                        "nexus_model_tokens_total", response.total_tokens,
                        provider=provider_name, route=route, tenant_id=context.tenant_id,
                    )
                    return response
                except PermissionError:
                    raise
                except Exception as exc:
                    metrics.increment(
                        "nexus_model_requests_total", provider=provider_name,
                        route=route, status="error", tenant_id=context.tenant_id,
                    )
                    failures += 1
                    self._circuits[provider_name] = (failures, time.monotonic())
                    errors.append(f"{provider_name}[{attempt + 1}]: {exc}")
                    if attempt < policy.retries_per_provider:
                        await asyncio.sleep(min(1.0, 0.1 * (2 ** attempt)))
        raise NexusLLMError("No model provider completed the request: " + "; ".join(errors))

    def usage(self, run_id: str) -> int:
        return self._usage.get(run_id, 0)
```

### nexus_core/kernel/models.py — 155 líneas

```python
"""Canonical, serializable models shared by every NEXUS gateway."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RiskLevel(str, Enum):
    READ_ONLY = "read_only"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DESTRUCTIVE = "destructive"


@dataclass(frozen=True)
class Identity:
    subject_id: str
    tenant_id: str
    kind: str = "user"
    roles: tuple[str, ...] = ()
    departments: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    attributes: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Resource:
    resource_id: str
    tenant_id: str
    kind: str
    owner_id: Optional[str] = None
    classification: str = "internal"
    environment: str = "development"
    attributes: Dict[str, str] = field(default_factory=dict)


@dataclass
class AgentDefinition:
    name: str
    tenant_id: str
    version: str = "1.0.0"
    agent_id: str = field(default_factory=lambda: f"agent_{uuid4().hex}")
    description: str = ""
    capabilities: List[str] = field(default_factory=list)
    tool_ids: List[str] = field(default_factory=list)
    model_route: str = "default"
    department_id: Optional[str] = None
    enabled: bool = True
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolDefinition:
    name: str
    tenant_id: str
    input_schema: Dict[str, Any]
    version: str = "1.0.0"
    tool_id: str = field(default_factory=lambda: f"tool_{uuid4().hex}")
    description: str = ""
    risk: RiskLevel = RiskLevel.READ_ONLY
    required_permissions: List[str] = field(default_factory=list)
    timeout_seconds: int = 30
    max_output_bytes: int = 1_000_000
    effect: str = "read_only"
    scopes: List[str] = field(default_factory=list)
    enabled: bool = True
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["risk"] = self.risk.value
        return value


@dataclass(frozen=True)
class ToolResult:
    """Canonical, evidence-backed result returned by every governed tool.

    ``verified`` is a deterministic observation of the requested
    post-condition, not an LLM assertion or the mere absence of an exception.
    """
    output: Dict[str, Any] = field(default_factory=dict)
    verified: bool = False
    verification_method: str = "unspecified"
    evidence: Dict[str, Any] = field(default_factory=dict)
    exit_code: Optional[int] = None
    accepted_exit_codes: tuple[int, ...] = (0,)
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.verified and not self.timed_out and (
            self.exit_code is None or self.exit_code in self.accepted_exit_codes
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "output": self.output,
            "verified": self.verified,
            "verification_method": self.verification_method,
            "evidence": self.evidence,
            "exit_code": self.exit_code,
            "accepted_exit_codes": list(self.accepted_exit_codes),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
        }


@dataclass(frozen=True)
class RunContext:
    tenant_id: str
    identity: Identity
    run_id: str = field(default_factory=lambda: f"run_{uuid4().hex}")
    trace_id: str = field(default_factory=lambda: uuid4().hex)
    environment: str = "development"
    budget_tokens: int = 0
    budget_usd: float = 0.0


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    policy_id: str
    policy_version: str = "1.0.0"
    requires_approval: bool = False
    obligations: tuple[str, ...] = ()


@dataclass
class Artifact:
    tenant_id: str
    run_id: str
    kind: str
    uri: str
    sha256: str
    artifact_id: str = field(default_factory=lambda: f"artifact_{uuid4().hex}")
    classification: str = "internal"
    created_at: str = field(default_factory=utc_now)
```

### nexus_core/kernel/packages.py — 119 líneas

```python
"""Install versioned department packages without modifying kernel code."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict
from uuid import uuid4

from .control_store import ControlStore
from .models import AgentDefinition, utc_now


class PackageManager:
    def __init__(self, store: ControlStore, packages_root: str | Path):
        self.store = store
        self.packages_root = Path(packages_root).resolve()

    def load_manifest(self, package_path: str) -> tuple[Path, Dict[str, Any]]:
        root = (self.packages_root / package_path).resolve()
        if root != self.packages_root and self.packages_root not in root.parents:
            raise PermissionError("package path escapes package root")
        manifest_path = root / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        required = {"schema_version", "package", "version", "agents", "workflows", "policies"}
        missing = required - set(manifest)
        if missing:
            raise ValueError(f"package manifest missing: {sorted(missing)}")
        if not isinstance(manifest["agents"], list) or not manifest["agents"]:
            raise ValueError("package must define at least one agent")
        expected = manifest.get("manifest_sha256")
        unsigned = dict(manifest)
        unsigned.pop("manifest_sha256", None)
        calculated = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if expected and expected != calculated:
            raise ValueError("package manifest checksum is invalid")
        manifest["verified_sha256"] = calculated
        return root, manifest

    def install(
        self, package_path: str, tenant_id: str, installed_by: str
    ) -> Dict[str, Any]:
        root, manifest = self.load_manifest(package_path)
        package_id = f"package_{uuid4().hex}"
        department_id = f"department_{uuid4().hex}"
        now = utc_now()
        installed_agents = []
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT INTO kernel_departments(id,tenant_id,name,created_at)
                VALUES(?,?,?,?)""",
                (department_id, tenant_id, manifest["package"], now),
            )
            conn.execute(
                """INSERT INTO kernel_packages
                (id,tenant_id,package_name,version,manifest,status,installed_by,installed_at)
                VALUES(?,?,?,?,?,?,?,?)""",
                (package_id, tenant_id, manifest["package"], manifest["version"],
                 json.dumps(manifest, sort_keys=True), "installed", installed_by, now),
            )
            for agent_name in manifest["agents"]:
                definition = AgentDefinition(
                    name=f"{manifest['package']}.{agent_name}", tenant_id=tenant_id,
                    version=manifest["version"],
                    description=f"Agent installed from {manifest['package']}",
                    capabilities=list(manifest.get("required_capabilities", [])),
                    department_id=department_id,
                ).to_dict()
                conn.execute(
                    """INSERT INTO kernel_agents
                    (id,tenant_id,name,version,definition,status,created_at,department_id)
                    VALUES(?,?,?,?,?,'active',?,?)""",
                    (definition["agent_id"], tenant_id, definition["name"], definition["version"],
                     json.dumps(definition, sort_keys=True), now, department_id),
                )
                installed_agents.append(definition["agent_id"])
        return {
            "package_id": package_id,
            "package": manifest["package"],
            "version": manifest["version"],
            "tenant_id": tenant_id,
            "department_id": department_id,
            "agent_ids": installed_agents,
            "evaluation_suite": str(root / manifest.get("evaluation_suite", "")),
            "manifest_sha256": manifest["verified_sha256"],
        }

    def rollback(self, package_id: str, tenant_id: str, actor_id: str) -> Dict[str, Any]:
        now = utc_now()
        with self.store.connect() as conn:
            package = conn.execute(
                "SELECT * FROM kernel_packages WHERE id=? AND tenant_id=? AND status='installed'",
                (package_id, tenant_id),
            ).fetchone()
            if not package:
                raise KeyError("installed package not found")
            manifest = json.loads(package["manifest"])
            names = [f"{manifest['package']}.{name}" for name in manifest["agents"]]
            for name in names:
                conn.execute(
                    "UPDATE kernel_agents SET status='disabled' WHERE tenant_id=? AND name=? AND version=?",
                    (tenant_id, name, package["version"]),
                )
            conn.execute("UPDATE kernel_packages SET status='rolled_back' WHERE id=?", (package_id,))
            self.store._outbox(conn, tenant_id, "package", package_id, "package.rolled_back", {"actor_id": actor_id})
        return {"package_id": package_id, "status": "rolled_back", "disabled_agents": names, "at": now}

    def list_installed(self, tenant_id: str) -> list[Dict[str, Any]]:
        with self.store.connect() as conn:
            rows = conn.execute(
                """SELECT id,tenant_id,package_name,version,status,installed_by,installed_at
                FROM kernel_packages WHERE tenant_id=? ORDER BY installed_at""",
                (tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]
```

### nexus_core/kernel/policy.py — 171 líneas

```python
"""Small deny-by-default PDP used until an external policy engine is configured."""

from __future__ import annotations

import json
from typing import Any, Iterable
from uuid import uuid4

from .models import Identity, PolicyDecision, Resource, RiskLevel, ToolDefinition


class PolicyEngine:
    """Central authorization point shared by REST, CLI, MCP and workers."""

    def __init__(self, store=None):
        self.store = store

    def decide(
        self,
        identity: Identity,
        action: str,
        resource: Resource,
        permissions: Iterable[str] = (),
        tool: ToolDefinition | None = None,
    ) -> PolicyDecision:
        if identity.tenant_id != resource.tenant_id:
            return PolicyDecision(False, "cross-tenant access denied", "tenant-isolation")

        explicit = self._explicit_decision(identity, action, resource)
        if explicit is not None:
            if (
                explicit.allowed
                and tool
                and tool.risk in {RiskLevel.HIGH, RiskLevel.DESTRUCTIVE}
                and not explicit.requires_approval
            ):
                return PolicyDecision(
                    True,
                    "explicit allow constrained by tool risk",
                    explicit.policy_id,
                    explicit.policy_version,
                    requires_approval=True,
                    obligations=("audit", "sandbox", "human-approval"),
                )
            return explicit

        roles = set(identity.roles)
        granted = set(permissions)
        if "admin" in roles:
            allowed = True
        elif action.startswith("read:") and roles.intersection({"viewer", "operator"}):
            allowed = True
        elif action.startswith(("execute:", "write:")) and "operator" in roles:
            allowed = True
        else:
            allowed = action in granted or "*" in granted

        if not allowed:
            return PolicyDecision(False, "identity lacks required permission", "role-and-permission")

        if tool and tool.risk in {RiskLevel.HIGH, RiskLevel.DESTRUCTIVE}:
            return PolicyDecision(
                True,
                "allowed after human approval",
                "risk-approval",
                requires_approval=True,
                obligations=("audit", "sandbox", "human-approval"),
            )

        obligations = ("audit",) if tool is None else ("audit", "sandbox")
        return PolicyDecision(True, "allowed", "role-and-permission", obligations=obligations)

    def _explicit_decision(
        self, identity: Identity, action: str, resource: Resource
    ) -> PolicyDecision | None:
        if not self.store:
            return None
        subjects = [("identity", identity.subject_id)] + [
            ("role", role) for role in identity.roles
        ] + [("group", group) for group in identity.groups]
        matches: list[dict[str, Any]] = []
        with self.store.connect() as conn:
            for subject_type, subject_id in subjects:
                rows = conn.execute(
                    """SELECT p.* FROM kernel_policies p
                    JOIN kernel_policy_bindings b ON b.policy_id=p.id
                    WHERE p.tenant_id=? AND p.enabled=1
                      AND b.subject_type=? AND b.subject_id=?""",
                    (identity.tenant_id, subject_type, subject_id),
                ).fetchall()
                matches.extend(dict(row) for row in rows)
        applicable = []
        for policy in matches:
            actions = json.loads(policy["actions"])
            resource_kinds = json.loads(policy["resource_kinds"])
            conditions = json.loads(policy["conditions"])
            if action not in actions and "*" not in actions:
                continue
            if resource.kind not in resource_kinds and "*" not in resource_kinds:
                continue
            if conditions.get("classification") not in (None, resource.classification):
                continue
            if conditions.get("environment") not in (None, resource.environment):
                continue
            applicable.append(policy)
        denies = [policy for policy in applicable if policy["effect"] == "deny"]
        if denies:
            policy = denies[0]
            return PolicyDecision(False, "explicit policy deny", policy["id"], policy["version"])
        allows = [policy for policy in applicable if policy["effect"] == "allow"]
        if allows:
            policy = allows[0]
            approval = bool(policy["requires_approval"])
            return PolicyDecision(
                True, "explicit policy allow", policy["id"], policy["version"],
                requires_approval=approval,
                obligations=("audit", "human-approval") if approval else ("audit",),
            )
        return None


class PolicyRepository:
    def __init__(self, store):
        self.store = store

    def create(
        self,
        *,
        tenant_id: str,
        name: str,
        effect: str,
        actions: list[str],
        resource_kinds: list[str],
        conditions: dict | None = None,
        requires_approval: bool = False,
        version: str = "1.0.0",
    ) -> dict:
        if effect not in {"allow", "deny"}:
            raise ValueError("policy effect must be allow or deny")
        policy_id = f"policy_{uuid4().hex}"
        from .models import utc_now
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_policies
                (id,tenant_id,name,version,effect,actions,resource_kinds,conditions,
                 requires_approval,enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (policy_id, tenant_id, name, version, effect, json.dumps(actions),
                 json.dumps(resource_kinds), json.dumps(conditions or {}),
                 int(requires_approval), 1, utc_now()),
            )
        return {"id": policy_id, "tenant_id": tenant_id, "name": name, "version": version}

    def bind(self, tenant_id: str, policy_id: str, subject_type: str, subject_id: str) -> str:
        if subject_type not in {"identity", "role", "group", "agent"}:
            raise ValueError("unsupported policy subject type")
        from .models import utc_now
        binding_id = f"binding_{uuid4().hex}"
        with self.store.connect() as conn:
            policy = conn.execute(
                "SELECT id FROM kernel_policies WHERE id=? AND tenant_id=? AND enabled=1",
                (policy_id, tenant_id),
            ).fetchone()
            if not policy:
                raise ValueError("policy not found in tenant")
            conn.execute(
                """INSERT INTO kernel_policy_bindings
                (id,tenant_id,policy_id,subject_type,subject_id,created_at)
                VALUES(?,?,?,?,?,?)""",
                (binding_id, tenant_id, policy_id, subject_type, subject_id, utc_now()),
            )
        return binding_id
```

### nexus_core/kernel/postgres_store.py — 68 líneas

```python
"""PostgreSQL implementation of the NEXUS durable control store."""

from __future__ import annotations

import re

from .control_store import SCHEMA, ControlStore
from .models import utc_now


class _PostgresConnection:
    def __init__(self, connection):
        self.connection = connection

    @staticmethod
    def _query(sql: str) -> str:
        sql = sql.replace("BEGIN IMMEDIATE", "BEGIN")
        ignored = bool(re.search(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", sql, re.IGNORECASE))
        sql = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", sql, flags=re.IGNORECASE)
        sql = sql.replace("?", "%s")
        if ignored:
            sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
        return sql

    def execute(self, sql: str, params=()):
        return self.connection.execute(self._query(sql), params)

    def executescript(self, sql: str):
        return self.connection.execute(sql)

    def __enter__(self):
        self.connection.__enter__()
        return self

    def __exit__(self, exc_type, exc, traceback):
        return self.connection.__exit__(exc_type, exc, traceback)


class PostgresControlStore(ControlStore):
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.path = None

    def connect(self) -> _PostgresConnection:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("psycopg is required for PostgreSQL control store") from exc
        return _PostgresConnection(
            psycopg.connect(self.database_url, row_factory=dict_row)
        )

    def initialize(self) -> None:
        schema = SCHEMA.replace(
            "sequence INTEGER PRIMARY KEY AUTOINCREMENT",
            "sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY",
        )
        with self.connect() as conn:
            conn.executescript(schema)
            conn.execute(
                """INSERT INTO kernel_tenants(id,name,created_at) VALUES(?,?,?)
                ON CONFLICT(id) DO NOTHING""",
                ("system", "NEXUS System", utc_now()),
            )

    def migrate_legacy_users(self) -> int:
        return 0
```

### nexus_core/kernel/runtime.py — 337 líneas

```python
"""Durable, provider-neutral execution runtime for NEXUS Sovereign."""

from __future__ import annotations

import inspect
import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict

from nexus_core.llm.abstraction import LLMFactory, LLMMessage

from .models import utc_now
from .telemetry import metrics, telemetry

Executor = Callable[[dict, "ExecutionContext"], dict | Awaitable[dict]]


@dataclass(frozen=True)
class ExecutionContext:
    store: Any
    task: dict
    worker_id: str

    @property
    def tenant_id(self) -> str:
        return str(self.task["tenant_id"])

    @property
    def run_id(self) -> str:
        return str(self.task["run_id"])

    def event(self, event_type: str, **payload: Any) -> None:
        self.store.append_run_event(self.tenant_id, self.run_id, event_type, payload)


class ExecutorRegistry:
    def __init__(self) -> None:
        self._executors: Dict[str, Executor] = {}

    def register(self, task_type: str, executor: Executor) -> None:
        if task_type in self._executors:
            raise ValueError(f"executor already registered: {task_type}")
        self._executors[task_type] = executor

    @property
    def task_types(self) -> tuple[str, ...]:
        return tuple(sorted(self._executors))

    async def execute(self, task: dict, context: ExecutionContext) -> dict:
        executor = self._executors.get(task["task_type"])
        if not executor:
            raise ValueError(f"unsupported durable task type: {task['task_type']}")
        context.event("task.started", task_id=task["id"], task_type=task["task_type"])
        with telemetry.span("nexus.runtime.execute", {
            "nexus.tenant.id": context.tenant_id,
            "nexus.run.id": context.run_id,
            "nexus.task.id": task["id"],
            "nexus.task.type": task["task_type"],
        }):
            result = executor(task["payload"], context)
            if inspect.isawaitable(result):
                result = await result
        if not isinstance(result, dict):
            raise TypeError("durable executor results must be objects")
        context.event("task.completed", task_id=task["id"], result=result)
        metrics.increment("nexus_runtime_tasks_total", tenant_id=context.tenant_id,
                          task_type=task["task_type"], status="completed")
        return result


def _select_client(route: str | None = None):
    clients = LLMFactory.create_from_env()
    requested = (route or os.getenv("LLM_PROVIDER") or "fake").lower()
    if requested in clients:
        return clients[requested]
    if requested != "fake" and os.getenv("NEXUS_ALLOW_MODEL_FALLBACK", "false").lower() != "true":
        raise RuntimeError(f"configured model provider is unavailable: {requested}")
    return clients["fake"]


async def execute_llm(payload: dict, context: ExecutionContext) -> dict:
    messages = payload.get("messages")
    if not messages and "message" in payload:
        messages = [{"role": "user", "content": str(payload["message"])}]
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a non-empty array")
    normalized = [LLMMessage(role=str(item["role"]), content=str(item["content"]))
                  for item in messages]
    client = _select_client(payload.get("model_route"))
    response = await client.complete(normalized, scenario=payload.get("scenario", "echo"))
    context.store.record_usage(context.tenant_id, context.run_id, "model",
                               response.model, "tokens", response.total_tokens,
                               {"provider": response.provider.value})
    return {"content": response.content, "model": response.model,
            "provider": response.provider.value, "tokens_input": response.tokens_input,
            "tokens_output": response.tokens_output, "duration_ms": response.duration_ms}


async def execute_agent(payload: dict, context: ExecutionContext) -> dict:
    agent_id = str(payload.get("agent_id") or "nexus")
    definitions = context.store.list_definitions("kernel_agents", context.tenant_id)
    agent = next((item for item in definitions if item.get("agent_id") == agent_id), None)
    if agent_id != "nexus" and not agent:
        raise ValueError("agent is not registered in this tenant")
    objective = str(payload.get("objective") or "").strip()
    if not objective:
        raise ValueError("agent objective is required")
    system = (agent or {}).get("system_prompt") or (
        "Eres NEXUS, un operador soberano. Responde con hechos, declara límites, "
        "no inventes acceso a herramientas y propone acciones verificables."
    )
    llm_result = await execute_llm({
        "model_route": (agent or {}).get("model_route", payload.get("model_route")),
        "scenario": payload.get("scenario", "echo"),
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": objective}],
    }, context)
    return {"agent_id": agent_id, **llm_result}


async def execute_chat(payload: dict, context: ExecutionContext) -> dict:
    conversation_id = str(payload["conversation_id"])
    conversation = context.store.get_conversation(context.tenant_id, conversation_id)
    if not conversation:
        raise ValueError("conversation not found")
    history = context.store.list_messages(context.tenant_id, conversation_id, limit=40)
    model_route = payload.get("model_route")
    client = _select_client(model_route)
    messages = [LLMMessage(role=item["role"], content=item["content"])
                for item in history if item["role"] in {"system", "user", "assistant"}]
    if not messages:
        raise ValueError("conversation has no messages")
    context.event("model.started", provider=client.config.provider.value,
                  model=client.config.model)
    response = await client.complete(messages, scenario=payload.get("scenario", "echo"))
    message = context.store.append_message(
        context.tenant_id, conversation_id, "assistant", response.content,
        run_id=context.run_id,
        metadata={"provider": response.provider.value, "model": response.model,
                  "tokens_input": response.tokens_input,
                  "tokens_output": response.tokens_output,
                  "duration_ms": response.duration_ms},
        classification=conversation["classification"],
    )
    context.store.record_usage(context.tenant_id, context.run_id, "model",
                               response.model, "tokens", response.total_tokens,
                               {"provider": response.provider.value})
    context.event("message.created", message_id=message["id"], role="assistant")
    return {"conversation_id": conversation_id, "message": message,
            "provider": response.provider.value, "model": response.model}


async def execute_memory(payload: dict, context: ExecutionContext) -> dict:
    content = str(payload.get("content") or "").strip()
    if not content:
        raise ValueError("memory content is required")
    from .memory import MemoryStore
    memory = MemoryStore(context.store)
    result = memory.save_message(
        tenant_id=context.tenant_id, agent_id=str(payload.get("agent_id", "nexus")),
        agent_name=str(payload.get("agent_name", "NEXUS")),
        role=str(payload.get("role", "system")), content=content,
        session_id=payload.get("session_id"),
        classification=str(payload.get("classification", "internal")),
    )
    return {"memory_id": result, "indexed_at": utc_now()}


async def execute_evaluation(payload: dict, context: ExecutionContext) -> dict:
    expected = payload.get("expected")
    actual = payload.get("actual")
    checks = {"non_empty": bool(actual), "matches_expected": expected is None or actual == expected}
    return {"passed": all(checks.values()), "checks": checks}


async def execute_tool(payload: dict, context: ExecutionContext) -> dict:
    """Invoke only first-party tools through the policy-enforced gateway."""
    from .approvals import ApprovalService
    from .audit import AuditWriter
    from .models import Identity, RiskLevel, RunContext, ToolDefinition, ToolResult
    from .policy import PolicyEngine
    from .sandbox import sandbox_for_environment
    from .tool_gateway import ToolGateway

    tool_id = str(payload.get("tool_id") or "")
    arguments = payload.get("arguments") or {}
    actor = payload.get("identity") or {}
    identity = Identity(
        subject_id=str(actor.get("subject_id") or "nexus-worker"),
        tenant_id=context.tenant_id,
        kind=str(actor.get("kind") or "workload"),
        roles=tuple(actor.get("roles") or ("operator",)),
    )
    run_context = RunContext(tenant_id=context.tenant_id, identity=identity,
                             run_id=context.run_id,
                             trace_id=str(payload.get("trace_id") or context.run_id))
    gateway = ToolGateway(PolicyEngine(context.store), AuditWriter(context.store),
                          ApprovalService(context.store))

    async def system_status(_arguments: dict, _run_context: RunContext) -> ToolResult:
        with context.store.connect() as conn:
            queued = conn.execute(
                "SELECT COUNT(*) AS value FROM kernel_tasks WHERE tenant_id=? AND status='queued'",
                (context.tenant_id,),
            ).fetchone()["value"]
        output = {"status": "healthy", "queued_tasks": queued,
                  "worker_id": context.worker_id}
        return ToolResult(
            output=output,
            verified=True,
            verification_method="control_store_query",
            evidence={"queued_tasks": queued, "worker_id": context.worker_id},
        )

    async def workspace_search(tool_arguments: dict, _run_context: RunContext) -> ToolResult:
        query = str(tool_arguments["query"])
        sandbox = sandbox_for_environment(os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd()))
        result = await sandbox.run(["rg", "-n", "--max-count", "100", "--", query, "."],
                                   timeout_seconds=20)
        return ToolResult(
            output={"matches": result.stdout},
            verified=result.exit_code in {0, 1} and not result.timed_out,
            verification_method="sandbox_exit_code",
            evidence={"query": query, "exit_code": result.exit_code,
                      "timed_out": result.timed_out},
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),  # rg uses 1 for a verified empty result
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
        )

    definitions = {
        "nexus.system.status": (ToolDefinition(
            tool_id="nexus.system.status", name="System status", tenant_id=context.tenant_id,
            input_schema={"type": "object", "additionalProperties": False},
            risk=RiskLevel.READ_ONLY, required_permissions=["execute:tool"]), system_status),
        "nexus.workspace.search": (ToolDefinition(
            tool_id="nexus.workspace.search", name="Workspace search",
            tenant_id=context.tenant_id,
            input_schema={"type": "object", "properties": {"query": {"type": "string"}},
                          "required": ["query"], "additionalProperties": False},
            risk=RiskLevel.READ_ONLY, required_permissions=["execute:tool"]), workspace_search),
    }
    if tool_id not in definitions:
        raise ValueError("tool is not in the first-party runtime catalog")
    definition, handler = definitions[tool_id]
    gateway.register(definition, handler)
    result = await gateway.invoke(tool_id, arguments, run_context,
                                  permissions=tuple(payload.get("permissions") or ()),
                                  approval_id=payload.get("approval_id"))
    return {"tool_id": tool_id, "output": result}


async def execute_brain(payload: dict, context: ExecutionContext) -> dict:
    """Durable intake → verified action(s) → evaluate pipeline.

    ``steps`` is deliberately data, not executable model output: each item is
    routed through ``execute_tool`` and therefore through policy, approval,
    sandboxing and the ToolResult post-condition gate.  A future planner may
    propose these steps, but only this persisted loop is allowed to advance
    them.
    """
    objective = str(payload.get("objective") or "").strip()
    if not objective:
        raise ValueError("brain objective is required")
    context.event("brain.intake", objective_length=len(objective))
    requested_steps = payload.get("steps", [])
    if not isinstance(requested_steps, list):
        raise ValueError("brain steps must be an array")
    if len(requested_steps) > 8:
        raise ValueError("brain supports at most 8 verified steps per run")
    plan = [{"step": "understand", "status": "completed"}]
    plan.extend({"step": f"tool:{item.get('tool_id', 'unknown')}", "status": "pending"}
                for item in requested_steps)
    plan.extend([
        {"step": "respond", "status": "pending"},
        {"step": "evaluate", "status": "pending"},
    ])
    context.event("brain.plan", steps=plan)
    observations = []
    for index, step in enumerate(requested_steps, start=1):
        if not isinstance(step, dict) or not step.get("tool_id"):
            raise ValueError("each brain step requires tool_id")
        plan[index]["status"] = "running"
        context.event("brain.step.started", index=index, tool_id=step["tool_id"])
        invocation = await execute_tool({
            "tool_id": step["tool_id"],
            "arguments": step.get("arguments", {}),
            "identity": payload.get("identity", {}),
            "permissions": payload.get("permissions", ()),
            "approval_id": step.get("approval_id"),
            "trace_id": payload.get("trace_id"),
        }, context)
        evidence = invocation["output"]
        if not evidence.get("success") or not evidence.get("verified"):
            raise RuntimeError(f"brain step {index} did not satisfy its post-condition")
        observations.append(invocation)
        plan[index]["status"] = "completed"
        context.event("brain.step.verified", index=index, tool_id=step["tool_id"],
                      verification_method=evidence["verification_method"],
                      evidence=evidence["evidence"])

    response_index = len(requested_steps) + 1
    plan[response_index]["status"] = "running"
    answer = await execute_agent({"agent_id": payload.get("agent_id", "nexus"),
                                  "objective": objective,
                                  "model_route": payload.get("model_route"),
                                  "scenario": payload.get("scenario", "echo")}, context)
    plan[response_index]["status"] = "completed"
    evaluation = await execute_evaluation({
        "actual": answer.get("content"),
        "expected": payload.get("expected_response"),
    }, context)
    evaluation["tool_postconditions_verified"] = all(
        item["output"].get("verified") for item in observations
    )
    evaluation["passed"] = evaluation["passed"] and evaluation["tool_postconditions_verified"]
    plan[response_index + 1]["status"] = "completed" if evaluation["passed"] else "failed"
    if not evaluation["passed"]:
        raise RuntimeError("brain evaluation failed")
    context.event("brain.evaluated", **evaluation)
    return {"objective": objective, "plan": plan, "answer": answer,
            "observations": observations, "evaluation": evaluation}


def build_default_registry() -> ExecutorRegistry:
    registry = ExecutorRegistry()
    registry.register("debug.fake_llm", execute_llm)
    registry.register("llm.complete", execute_llm)
    registry.register("agent.run", execute_agent)
    registry.register("conversation.respond", execute_chat)
    registry.register("tool.invoke", execute_tool)
    registry.register("brain.run", execute_brain)
    registry.register("memory.index", execute_memory)
    registry.register("evaluation.run", execute_evaluation)
    return registry
```

### nexus_core/kernel/sandbox.py — 161 líneas

```python
"""Constrained local process runner for development.

Production deployments should replace this implementation with an OCI or
microVM runtime. Shell parsing is deliberately unsupported.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence
from uuid import uuid4


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class LocalSandbox:
    def __init__(
        self,
        workspace_root: str | Path,
        allowed_programs: Iterable[str] = ("python3", "git", "rg"),
        max_output_bytes: int = 1_000_000,
    ):
        self.workspace_root = Path(workspace_root).resolve()
        self.allowed_programs = frozenset(allowed_programs)
        self.max_output_bytes = max_output_bytes

    def resolve_workspace(self, relative: str = ".") -> Path:
        candidate = (self.workspace_root / relative).resolve()
        if candidate != self.workspace_root and self.workspace_root not in candidate.parents:
            raise PermissionError("sandbox path escapes workspace")
        return candidate

    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str = ".",
        timeout_seconds: float = 30,
    ) -> SandboxResult:
        if not argv or argv[0] not in self.allowed_programs:
            raise PermissionError("program is not allowed in this sandbox")
        working_directory = self.resolve_workspace(cwd)
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(working_directory),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "NEXUS_SANDBOX": "1"},
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout_seconds
            )
            timed_out = False
        except asyncio.TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
            timed_out = True
        return SandboxResult(
            exit_code=process.returncode if process.returncode is not None else -1,
            stdout=stdout[:self.max_output_bytes].decode("utf-8", errors="replace"),
            stderr=stderr[:self.max_output_bytes].decode("utf-8", errors="replace"),
            timed_out=timed_out,
        )


class OCISandbox:
    """Ephemeral Docker/Podman sandbox for untrusted agent commands."""

    def __init__(
        self,
        workspace_root: str | Path,
        allowed_images: Iterable[str],
        runtime: str = "docker",
        memory: str = "512m",
        cpus: str = "1.0",
        pids_limit: int = 128,
    ):
        if runtime not in {"docker", "podman"}:
            raise ValueError("OCI runtime must be docker or podman")
        self.workspace_root = Path(workspace_root).resolve()
        self.allowed_images = frozenset(allowed_images)
        self.runtime = runtime
        self.memory = memory
        self.cpus = cpus
        self.pids_limit = pids_limit

    def build_argv(self, image: str, command: Sequence[str]) -> list[str]:
        if image not in self.allowed_images:
            raise PermissionError("sandbox image is not allowlisted")
        if not command:
            raise ValueError("sandbox command is required")
        name = f"nexus-sandbox-{uuid4().hex[:12]}"
        return [
            self.runtime, "run", "--rm", "--name", name,
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(self.pids_limit),
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--user", "65532:65532",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--mount", f"type=bind,src={self.workspace_root},dst=/workspace,rw",
            "--workdir", "/workspace",
            image,
            *command,
        ]

    async def run(
        self,
        image: str,
        command: Sequence[str],
        timeout_seconds: float = 120,
    ) -> SandboxResult:
        argv = self.build_argv(image, command)
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout_seconds
            )
            timed_out = False
        except asyncio.TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
            timed_out = True
        return SandboxResult(
            process.returncode if process.returncode is not None else -1,
            stdout.decode("utf-8", errors="replace")[:1_000_000],
            stderr.decode("utf-8", errors="replace")[:1_000_000],
            timed_out,
        )


def sandbox_for_environment(workspace_root: str | Path):
    environment = os.getenv("NEXUS_ENV", "development").lower()
    if environment == "production":
        images = [item.strip() for item in os.getenv(
            "NEXUS_SANDBOX_IMAGES", "python:3.12-alpine"
        ).split(",") if item.strip()]
        return OCISandbox(
            workspace_root, images, runtime=os.getenv("NEXUS_OCI_RUNTIME", "docker")
        )
    return LocalSandbox(workspace_root)
```

### nexus_core/kernel/schema_validation.py — 48 líneas

```python
"""Small dependency-free validator for the JSON Schema subset used by tools."""

from __future__ import annotations

from typing import Any, Dict


class SchemaValidationError(ValueError):
    pass


TYPE_MAP: dict[str, type | tuple[type, ...]] = {
    "object": dict, "array": list, "string": str, "integer": int,
    "number": (int, float), "boolean": bool, "null": type(None),
}


def validate(instance: Any, schema: Dict[str, Any], path: str = "$") -> None:
    expected = schema.get("type")
    if expected:
        accepted = TYPE_MAP.get(expected)
        if not accepted:
            raise SchemaValidationError(f"{path}: unsupported schema type {expected}")
        if not isinstance(instance, accepted) or (expected in {"integer", "number"} and isinstance(instance, bool)):
            raise SchemaValidationError(f"{path}: expected {expected}")
    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaValidationError(f"{path}: value is not in enum")
    if isinstance(instance, dict):
        required = schema.get("required", [])
        missing = [name for name in required if name not in instance]
        if missing:
            raise SchemaValidationError(f"{path}: missing required fields {missing}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extras = set(instance) - set(properties)
            if extras:
                raise SchemaValidationError(f"{path}: unexpected fields {sorted(extras)}")
        for name, value in instance.items():
            if name in properties:
                validate(value, properties[name], f"{path}.{name}")
    if isinstance(instance, list) and "items" in schema:
        for index, value in enumerate(instance):
            validate(value, schema["items"], f"{path}[{index}]")
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            raise SchemaValidationError(f"{path}: string is too short")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            raise SchemaValidationError(f"{path}: string is too long")
```

### nexus_core/kernel/store_factory.py — 35 líneas

```python
"""Control-store backend selection.

SQLite is intentionally limited to offline development and single-node tests.
Production requires PostgreSQL.
"""

from __future__ import annotations

import os
from pathlib import Path

from .control_store import ControlStore


def get_control_store(
    sqlite_path: str | Path | None = None,
    database_url: str | None = None,
):
    url = database_url if database_url is not None else os.getenv("DATABASE_URL", "")
    if url.startswith(("postgresql://", "postgres://")):
        from .postgres_store import PostgresControlStore

        return PostgresControlStore(url)
    if url and not url.startswith("sqlite://"):
        raise ValueError("DATABASE_URL must use postgresql:// or sqlite://")
    if url.startswith("sqlite:///"):
        sqlite_path = url.removeprefix("sqlite:///")
    if sqlite_path is None:
        from nexus_core.config import NEXUS_DB_PATH

        sqlite_path = NEXUS_DB_PATH
    environment = os.getenv("NEXUS_ENV", "development").lower()
    if environment == "production" and not os.getenv("NEXUS_ALLOW_SQLITE_PRODUCTION"):
        raise RuntimeError("PostgreSQL DATABASE_URL is required in production")
    return ControlStore(sqlite_path)
```

### nexus_core/kernel/telemetry.py — 87 líneas

```python
"""OpenTelemetry integration with a dependency-free no-op fallback."""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterator

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
    OTEL_AVAILABLE = True
except ImportError:
    trace = None
    Status = StatusCode = None
    OTEL_AVAILABLE = False


class Telemetry:
    def __init__(self, service_name: str = "nexus-kernel"):
        self.service_name = service_name
        self.tracer = trace.get_tracer(service_name) if OTEL_AVAILABLE else None

    @contextmanager
    def span(self, name: str, attributes: Dict[str, Any] | None = None) -> Iterator[Any]:
        if not self.tracer:
            yield None
            return
        with self.tracer.start_as_current_span(name, attributes=attributes or {}) as span:
            try:
                yield span
                span.set_status(Status(StatusCode.OK))
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                raise


telemetry = Telemetry()


class Metrics:
    """Small in-process metrics registry; exporters can scrape a safe snapshot."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: Dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}

    def increment(self, name: str, value: float = 1, **labels: str) -> None:
        key = (name, tuple(sorted((str(k), str(v)) for k, v in labels.items())))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + value

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [
                {"name": name, "labels": dict(labels), "value": value}
                for (name, labels), value in sorted(self._counters.items())
            ]


metrics = Metrics()


def configure_telemetry() -> bool:
    """Configure OTLP export when an endpoint is provided."""
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint or not OTEL_AVAILABLE:
        return False
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=Resource.create({
            "service.name": os.getenv("OTEL_SERVICE_NAME", "nexus")
        }))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
        telemetry.tracer = trace.get_tracer(telemetry.service_name)
        return True
    except Exception:
        return False
```

### nexus_core/kernel/tool_gateway.py — 142 líneas

```python
"""Policy-enforced tool invocation shared by every gateway."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import time
from typing import Any, Awaitable, Callable, Dict

from .approvals import ApprovalService
from .audit import AuditWriter
from .models import Resource, RunContext, ToolDefinition, ToolResult
from .policy import PolicyEngine
from .schema_validation import validate
from .telemetry import metrics, telemetry

ToolHandler = Callable[[Dict[str, Any], RunContext], ToolResult | Awaitable[ToolResult]]


class ToolGateway:
    def __init__(
        self,
        policy: PolicyEngine,
        audit: AuditWriter,
        approvals: ApprovalService | None = None,
    ):
        self.policy = policy
        self.audit = audit
        self.approvals = approvals
        self._definitions: Dict[str, ToolDefinition] = {}
        self._handlers: Dict[str, ToolHandler] = {}

    def register(self, definition: ToolDefinition, handler: ToolHandler) -> None:
        if definition.tool_id in self._definitions:
            raise ValueError(f"tool already registered: {definition.tool_id}")
        if os.getenv("NEXUS_ENV", "development").lower() == "production" and not inspect.iscoroutinefunction(handler):
            raise TypeError("production tool handlers must be async and sandbox-backed")
        self._definitions[definition.tool_id] = definition
        self._handlers[definition.tool_id] = handler

    async def invoke(
        self,
        tool_id: str,
        arguments: Dict[str, Any],
        context: RunContext,
        permissions: tuple[str, ...] = (),
        approval_id: str | None = None,
    ) -> Any:
        with telemetry.span("nexus.tool.invoke", {
            "nexus.tenant.id": context.tenant_id,
            "nexus.run.id": context.run_id,
            "nexus.trace.id": context.trace_id,
            "nexus.tool.id": tool_id,
        }):
            definition = self._definitions.get(tool_id)
            if not definition or not definition.enabled:
                raise KeyError("tool is unavailable")
            validate(arguments, definition.input_schema or {"type": "object"})
            decision = self.policy.decide(
                context.identity,
                "execute:tool",
                Resource(tool_id, definition.tenant_id, "tool"),
                permissions,
                definition,
            )
            self.audit.append(
                tenant_id=context.tenant_id,
                trace_id=context.trace_id,
                actor_id=context.identity.subject_id,
                action="tool.invoke",
                resource_type="tool",
                resource_id=tool_id,
                payload={"argument_keys": sorted(arguments)},
                decision="allow" if decision.allowed else "deny",
            )
            if not decision.allowed:
                raise PermissionError(decision.reason)
            action = f"execute:tool:{tool_id}"
            if decision.requires_approval:
                if not self.approvals or not approval_id:
                    raise PermissionError("durable human approval is required")
                if not self.approvals.verify(approval_id, context, action):
                    raise PermissionError("approval does not authorize this tool invocation")

            store = self.audit.store
            store.record_usage(
                context.tenant_id, context.run_id, "tool", tool_id, "calls", 1,
                {"trace_id": context.trace_id},
            )
            handler = self._handlers[tool_id]
            started = time.monotonic()
            try:
                if inspect.iscoroutinefunction(handler):
                    result = await asyncio.wait_for(
                        handler(arguments, context), timeout=definition.timeout_seconds
                    )
                else:
                    result = handler(arguments, context)
                if not isinstance(result, ToolResult):
                    raise TypeError("tool handlers must return ToolResult with deterministic evidence")
                if not result.success:
                    raise RuntimeError(
                        "tool post-condition was not verified "
                        f"(method={result.verification_method})"
                    )
                result_value = result.to_dict()
                encoded = json.dumps(result_value, default=str).encode("utf-8")
                if len(encoded) > definition.max_output_bytes:
                    raise ValueError("tool output exceeds configured limit")
                self.audit.append(
                    tenant_id=context.tenant_id, trace_id=context.trace_id,
                    actor_id=context.identity.subject_id, action="tool.complete",
                    resource_type="tool", resource_id=tool_id,
                    payload={"duration_ms": round((time.monotonic() - started) * 1000, 3),
                             "output_bytes": len(encoded), "run_id": context.run_id},
                    decision="allow",
                )
                metrics.increment(
                    "nexus_tool_calls_total", tool_id=tool_id, status="success",
                    tenant_id=context.tenant_id,
                )
                metrics.increment(
                    "nexus_tool_duration_ms_total",
                    (time.monotonic() - started) * 1000,
                    tool_id=tool_id, tenant_id=context.tenant_id,
                )
                return result_value
            except Exception as exc:
                self.audit.append(
                    tenant_id=context.tenant_id, trace_id=context.trace_id,
                    actor_id=context.identity.subject_id, action="tool.failed",
                    resource_type="tool", resource_id=tool_id,
                    payload={"error_type": type(exc).__name__, "run_id": context.run_id},
                    decision="error",
                )
                metrics.increment(
                    "nexus_tool_calls_total", tool_id=tool_id, status="error",
                    tenant_id=context.tenant_id,
                )
                raise
```

### nexus_core/kernel/workflows.py — 207 líneas

```python
"""Durable, resumable DAG workflows backed by the NEXUS control store."""

from __future__ import annotations

import json
from typing import Any, Dict, List
from uuid import uuid4

from .control_store import ControlStore
from .models import utc_now

TERMINAL_TASKS = {"completed", "failed", "cancelled", "dead_letter"}


class WorkflowValidationError(ValueError):
    pass


class DurableWorkflowEngine:
    def __init__(self, store: ControlStore):
        self.store = store

    @staticmethod
    def validate(definition: Dict[str, Any]) -> None:
        steps = definition.get("steps")
        if not isinstance(steps, list) or not steps:
            raise WorkflowValidationError("workflow requires a non-empty steps list")
        keys = [step.get("key") for step in steps]
        if any(not key for key in keys) or len(keys) != len(set(keys)):
            raise WorkflowValidationError("step keys must be present and unique")
        known = set(keys)
        for step in steps:
            if not step.get("task_type"):
                raise WorkflowValidationError(f"step {step['key']} requires task_type")
            if not set(step.get("depends_on", [])).issubset(known):
                raise WorkflowValidationError(f"step {step['key']} has unknown dependency")
        graph = {step["key"]: set(step.get("depends_on", [])) for step in steps}
        remaining = set(graph)
        while remaining:
            ready = {key for key in remaining if not (graph[key] & remaining)}
            if not ready:
                raise WorkflowValidationError("workflow contains a cycle")
            remaining -= ready

    def register(self, tenant_id: str, name: str, version: str,
                 definition: Dict[str, Any]) -> Dict[str, Any]:
        self.validate(definition)
        workflow_id = f"workflow_{uuid4().hex}"
        now = utc_now()
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_workflows
                (id,tenant_id,name,version,definition,status,created_at)
                VALUES(?,?,?,?,?,'active',?)""",
                (workflow_id, tenant_id, name, version, json.dumps(definition), now),
            )
        return {"id": workflow_id, "tenant_id": tenant_id, "name": name, "version": version}

    def start(self, tenant_id: str, workflow_id: str, context: Dict[str, Any],
              idempotency_key: str) -> Dict[str, Any]:
        run = self.store.create_run(tenant_id, context, idempotency_key, workflow_id)
        now = utc_now()
        with self.store.connect() as conn:
            workflow = conn.execute(
                "SELECT definition FROM kernel_workflows WHERE id=? AND tenant_id=? AND status='active'",
                (workflow_id, tenant_id),
            ).fetchone()
            if not workflow:
                raise KeyError("workflow not found")
            definition = json.loads(workflow["definition"])
            for step in definition["steps"]:
                conn.execute(
                    """INSERT OR IGNORE INTO kernel_workflow_steps
                    (id,run_id,step_key,status,depends_on,compensation_type,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?)""",
                    (f"step_{uuid4().hex}", run["id"], step["key"], "pending",
                     json.dumps(step.get("depends_on", [])), step.get("compensation_type"), now, now),
                )
        self.reconcile(run["id"], tenant_id)
        return self.store.get_run(run["id"], tenant_id) or run

    def reconcile(self, run_id: str, tenant_id: str) -> Dict[str, Any]:
        """Persist task results and enqueue all newly-unblocked steps exactly once."""
        now = utc_now()
        with self.store.connect() as conn:
            run = conn.execute(
                "SELECT * FROM kernel_runs WHERE id=? AND tenant_id=?", (run_id, tenant_id)
            ).fetchone()
            if not run:
                raise KeyError("run not found")
            workflow = conn.execute(
                "SELECT definition FROM kernel_workflows WHERE id=? AND tenant_id=?",
                (run["workflow_id"], tenant_id),
            ).fetchone()
            definition = json.loads(workflow["definition"])
            by_key = {step["key"]: step for step in definition["steps"]}
            rows = conn.execute(
                """SELECT s.*,t.status AS task_status,t.result AS task_result,t.error AS task_error,
                c.status AS compensation_status
                FROM kernel_workflow_steps s LEFT JOIN kernel_tasks t ON t.id=s.task_id
                LEFT JOIN kernel_tasks c ON c.id=s.compensation_task_id
                WHERE s.run_id=?""", (run_id,)
            ).fetchall()
            states = {row["step_key"]: dict(row) for row in rows}

            for key, state in states.items():
                task_status = state.get("task_status")
                if (task_status in TERMINAL_TASKS
                        and state["status"] not in {
                            task_status, "compensating", "compensated", "compensation_failed"
                        }):
                    conn.execute(
                        "UPDATE kernel_workflow_steps SET status=?,result=?,updated_at=? WHERE id=?",
                        (task_status, state.get("task_result"), now, state["id"]),
                    )
                    state["status"] = task_status

            failed = any(
                state["status"] in {"failed", "dead_letter", "cancelled"}
                for state in states.values()
            )
            if failed:
                for key, state in states.items():
                    if state.get("compensation_status") in TERMINAL_TASKS:
                        final = (
                            "compensated" if state["compensation_status"] == "completed"
                            else "compensation_failed"
                        )
                        conn.execute(
                            "UPDATE kernel_workflow_steps SET status=?,updated_at=? WHERE id=?",
                            (final, now, state["id"]),
                        )
                    elif (state["status"] == "completed" and state["compensation_type"]
                          and not state["compensation_task_id"]):
                        task_id = f"task_{uuid4().hex}"
                        payload = {
                            "compensates_step": key,
                            "original_result": json.loads(state["task_result"] or "null"),
                            "workflow_context": json.loads(run["context"]),
                        }
                        conn.execute(
                            """INSERT INTO kernel_tasks
                            (id,tenant_id,run_id,task_type,status,priority,payload,max_attempts,
                             timeout_seconds,available_at,created_at,updated_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (task_id, tenant_id, run_id, state["compensation_type"], "queued",
                             1, json.dumps(payload), 3, 300, now, now, now),
                        )
                        conn.execute(
                            """UPDATE kernel_workflow_steps SET compensation_task_id=?,
                            status='compensating',updated_at=? WHERE id=?""",
                            (task_id, now, state["id"]),
                        )
                        self.store._transition(
                            conn, task_id, None, "queued", "workflow compensation", "workflow-engine"
                        )
                        self.store._outbox(
                            conn, tenant_id, "task", task_id, "task.compensation.queued",
                            {"run_id": run_id, "step": key},
                        )
                conn.execute(
                    "UPDATE kernel_runs SET status='failed',error='workflow step failed',updated_at=? WHERE id=?",
                    (now, run_id),
                )
            else:
                for key, state in states.items():
                    dependencies = json.loads(state["depends_on"])
                    if state["status"] == "pending" and all(states[item]["status"] == "completed" for item in dependencies):
                        step = by_key[key]
                        task_id = f"task_{uuid4().hex}"
                        payload = dict(step.get("payload", {}))
                        payload["workflow_context"] = json.loads(run["context"])
                        conn.execute(
                            """INSERT INTO kernel_tasks
                            (id,tenant_id,run_id,task_type,status,priority,payload,max_attempts,
                             timeout_seconds,available_at,created_at,updated_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (task_id, tenant_id, run_id, step["task_type"], "queued",
                             step.get("priority", 5), json.dumps(payload), step.get("max_attempts", 3),
                             step.get("timeout_seconds", 300), now, now, now),
                        )
                        conn.execute(
                            "UPDATE kernel_workflow_steps SET task_id=?,status='queued',updated_at=? WHERE id=? AND task_id IS NULL",
                            (task_id, now, state["id"]),
                        )
                        self.store._transition(conn, task_id, None, "queued", "workflow step ready", "workflow-engine")
                        self.store._outbox(conn, tenant_id, "task", task_id, "task.queued", {"run_id": run_id, "step": key})
                refreshed = conn.execute(
                    "SELECT status FROM kernel_workflow_steps WHERE run_id=?", (run_id,)
                ).fetchall()
                statuses = [row["status"] for row in refreshed]
                run_status = "completed" if statuses and all(item == "completed" for item in statuses) else "running"
                conn.execute(
                    "UPDATE kernel_runs SET status=?,updated_at=? WHERE id=?", (run_status, now, run_id)
                )
        return self.store.get_run(run_id, tenant_id) or {}

    def history(self, run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        with self.store.connect() as conn:
            valid = conn.execute(
                "SELECT id FROM kernel_runs WHERE id=? AND tenant_id=?", (run_id, tenant_id)
            ).fetchone()
            if not valid:
                return []
            return [dict(row) for row in conn.execute(
                "SELECT * FROM kernel_workflow_steps WHERE run_id=? ORDER BY created_at", (run_id,)
            ).fetchall()]
```

### LLM

### nexus_core/llm/__init__.py — 0 líneas

```python

```

### nexus_core/llm/abstraction.py — 656 líneas

```python
# nexus_core/llm/abstraction.py

"""
Provides a provider-agnostic abstraction layer for interacting with LLMs.

This module defines a unified interface for various LLM providers like OpenAI,
Google Gemini, and local Ollama instances. It includes:
- Data classes for configuration, messages, and standardized responses.
- An abstract base class `BaseLLMClient` to enforce a common contract.
- Concrete client implementations for different providers.
- A `LLMFactory` for easy instantiation of clients.
- A `NexusLLM` wrapper that provides high-level features like automatic
  provider fallback and performance tracking.
"""

import abc
import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    httpx = None
    HTTPX_AVAILABLE = False

# Conditional imports for provider-specific libraries
try:
    import openai
    from openai import AsyncOpenAI
    from openai.types.chat import ChatCompletion
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    from google import genai
    from google.genai import types as genai_types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

# Assuming a logger utility exists. If not, a standard logger is used.
try:
    from nexus_core.utils.logger import get_logger
except ImportError:
    def get_logger(name: str) -> logging.Logger:
        """Provides a basic logger instance."""
        logger = logging.getLogger(name)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

# --- Custom Exception ---

class NexusLLMError(Exception):
    """Custom exception for errors within the NexusLLM layer."""
    pass

# --- Data Classes and Enums ---

class LLMProvider(str, Enum):
    """Enumerates the supported LLM providers."""
    OPENAI = "openai"
    GEMINI = "gemini"
    OLLAMA = "ollama"
    FAKE = "fake"
    GROQ = "groq"
    OPENAI_COMPATIBLE = "openai_compatible"

@dataclass
class LLMConfig:
    """
    Configuration for an LLM client.

    Attributes:
        provider: The LLM provider to use.
        model: The specific model name for the provider.
        api_key: The API key for authentication (if required).
        base_url: The base URL for the API, primarily for Ollama.
        temperature: The sampling temperature for generation.
        max_tokens: The maximum number of tokens to generate.
        timeout: The request timeout in seconds.
        system_prompt: A default system prompt to prepend to conversations.
    """
    provider: LLMProvider
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: int = 60
    system_prompt: Optional[str] = None

@dataclass
class LLMMessage:
    """Represents a single message in a conversation history."""
    role: str  # "system", "user", or "assistant"
    content: str

@dataclass
class LLMResponse:
    """
    A standardized response object from an LLM completion call.
    """
    content: str
    model: str
    provider: LLMProvider
    tokens_input: int = 0
    tokens_output: int = 0
    duration_ms: float = 0.0
    raw_response: Optional[Dict[str, Any]] = field(default=None, repr=False)

    @property
    def total_tokens(self) -> int:
        """The sum of input and output tokens."""
        return self.tokens_input + self.tokens_output

# --- Abstract Base Client ---

class BaseLLMClient(abc.ABC):
    """
    Abstract base class for all LLM clients.
    """
    def __init__(self, config: LLMConfig):
        self.config = config
        self._logger = get_logger(f"LLMClient.{self.config.provider.value}")

    @abc.abstractmethod
    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        """
        Generates a completion for a given conversation history.

        Args:
            messages: A list of LLMMessage objects representing the conversation.
            **kwargs: Provider-specific arguments to override config.

        Returns:
            An LLMResponse object with the completion details.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def is_available(self) -> bool:
        """
        Checks if the client is configured and ready to use.

        Returns:
            True if the client is available, False otherwise.
        """
        raise NotImplementedError

    async def ask(
        self, system_prompt: str, user_message: str, **kwargs: Any
    ) -> str:
        """
        A shortcut method for a simple two-turn conversation.

        Args:
            system_prompt: The system message to guide the model.
            user_message: The user's query.
            **kwargs: Provider-specific arguments.

        Returns:
            The string content of the model's response.
        """
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_message),
        ]
        response = await self.complete(messages, **kwargs)
        return response.content

# --- Concrete Client Implementations ---

class OpenAIClient(BaseLLMClient):
    """LLM client for OpenAI models."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        if not OPENAI_AVAILABLE:
            raise ImportError("The 'openai' library is not installed. Please install it with 'pip install openai'.")
        if not self.config.api_key:
            raise ValueError("OpenAI API key is required for OpenAIClient.")
        
        client_options = {
            "api_key": self.config.api_key,
            "timeout": self.config.timeout,
        }
        if self.config.base_url:
            client_options["base_url"] = self.config.base_url
        self.client = AsyncOpenAI(**client_options)

    def is_available(self) -> bool:
        return bool(self.config.api_key)

    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        start_time = time.perf_counter()
        
        # Prepare messages for OpenAI API
        api_messages = [{"role": m.role, "content": m.content} for m in messages]
        if self.config.system_prompt and api_messages[0]["role"] != "system":
            api_messages.insert(0, {"role": "system", "content": self.config.system_prompt})

        request_params = {
            "model": self.config.model,
            "messages": api_messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }

        max_retries = 3
        backoff_factor = 2.0
        for attempt in range(max_retries):
            try:
                response: ChatCompletion = await self.client.chat.completions.create(**request_params)
                duration_ms = (time.perf_counter() - start_time) * 1000

                usage = response.usage
                return LLMResponse(
                    content=response.choices[0].message.content or "",
                    model=self.config.model,
                    provider=self.config.provider,
                    tokens_input=usage.prompt_tokens if usage else 0,
                    tokens_output=usage.completion_tokens if usage else 0,
                    duration_ms=duration_ms,
                    raw_response=response.model_dump(),
                )
            except openai.RateLimitError as e:
                if attempt + 1 == max_retries:
                    self._logger.error("OpenAI rate limit exceeded after max retries.")
                    raise NexusLLMError("OpenAI rate limit exceeded") from e
                
                wait_time = backoff_factor * (2 ** attempt)
                self._logger.warning(f"OpenAI rate limit hit. Retrying in {wait_time:.2f}s...")
                await asyncio.sleep(wait_time)
            except openai.APIError as e:
                self._logger.error(f"OpenAI API error: {e}")
                raise NexusLLMError(f"OpenAI API error: {e}") from e
        
        # This line should not be reachable
        raise NexusLLMError("OpenAI request failed after all retries.")


class GeminiClient(BaseLLMClient):
    """LLM client for Google Gemini models."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        if not GEMINI_AVAILABLE:
            raise ImportError("The 'google-genai' library is required for GeminiClient")
        if not self.config.api_key:
            raise ValueError("Gemini API key is required for GeminiClient.")
        
        self.client = genai.Client(api_key=self.config.api_key)

    def is_available(self) -> bool:
        return bool(self.config.api_key)

    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        start_time = time.perf_counter()
        
        system_messages = [msg.content for msg in messages if msg.role == "system"]
        contents = [
            genai_types.Content(
                role="model" if msg.role == "assistant" else "user",
                parts=[genai_types.Part.from_text(text=msg.content)],
            )
            for msg in messages if msg.role != "system"
        ]
        config = genai_types.GenerateContentConfig(
            temperature=kwargs.get("temperature", self.config.temperature),
            max_output_tokens=kwargs.get("max_tokens", self.config.max_tokens),
            system_instruction="\n".join(filter(None, [self.config.system_prompt, *system_messages])) or None,
        )

        try:
            response = await self.client.aio.models.generate_content(
                model=self.config.model, contents=contents, config=config,
            )
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            usage = response.usage_metadata

            return LLMResponse(
                content=response.text or "",
                model=self.config.model,
                provider=self.config.provider,
                tokens_input=getattr(usage, "prompt_token_count", 0) or 0,
                tokens_output=getattr(usage, "candidates_token_count", 0) or 0,
                duration_ms=duration_ms,
                raw_response=response.model_dump(mode="json", exclude_none=True),
            )
        except Exception as e:
            self._logger.error(f"Gemini API error: {e}")
            raise NexusLLMError(f"Gemini API error: {e}") from e


class OllamaClient(BaseLLMClient):
    """LLM client for local Ollama instances."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        if not HTTPX_AVAILABLE:
            raise ImportError("The 'httpx' library is required for OllamaClient")
        self.base_url = self.config.base_url or "http://localhost:11434"
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=self.config.timeout)

    async def is_available(self) -> bool:
        try:
            response = await self.client.get("/api/tags", timeout=5)
            return response.status_code == 200
        except httpx.RequestError:
            return False

    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        start_time = time.perf_counter()
        
        api_messages = [{"role": m.role, "content": m.content} for m in messages]
        if self.config.system_prompt and api_messages[0]["role"] != "system":
            api_messages.insert(0, {"role": "system", "content": self.config.system_prompt})

        payload = {
            "model": self.config.model,
            "messages": api_messages,
            "stream": False, # Keep it simple, no streaming for now
            "options": {
                "temperature": kwargs.get("temperature", self.config.temperature),
                "num_predict": kwargs.get("max_tokens", self.config.max_tokens),
            }
        }

        try:
            response = await self.client.post("/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
            duration_ms = (time.perf_counter() - start_time) * 1000

            return LLMResponse(
                content=data["message"]["content"],
                model=self.config.model,
                provider=self.config.provider,
                tokens_input=data.get("prompt_eval_count", 0),
                tokens_output=data.get("eval_count", 0),
                duration_ms=duration_ms,
                raw_response=data,
            )
        except httpx.RequestError as e:
            self._logger.error(f"Ollama connection error: {e}")
            raise NexusLLMError(f"Could not connect to Ollama at {self.base_url}") from e
        except httpx.HTTPStatusError as e:
            self._logger.error(f"Ollama API error: {e.response.status_code} - {e.response.text}")
            raise NexusLLMError(f"Ollama API error: {e.response.status_code}") from e


class FakeLLMClient(BaseLLMClient):
    """Deterministic provider for development, CI and offline evaluation."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        fixture_path = config.base_url or os.getenv(
            "NEXUS_LLM_FIXTURES",
            str(Path(__file__).with_name("fixtures") / "responses.json"),
        )
        self.fixture_path = Path(fixture_path)
        self._fixtures = self._load_fixtures()

    def _load_fixtures(self) -> Dict[str, Any]:
        if not self.fixture_path.exists():
            return {"default": {"content": "Fake LLM response"}}
        with self.fixture_path.open("r", encoding="utf-8") as fixture_file:
            data = json.load(fixture_file)
        if not isinstance(data, dict):
            raise ValueError("Fake LLM fixture file must contain a JSON object")
        return data

    def is_available(self) -> bool:
        return True

    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        started = time.perf_counter()
        scenario = str(kwargs.get("scenario", "default"))
        fixture = self._fixtures.get(scenario, self._fixtures.get("default", {}))
        if not isinstance(fixture, dict):
            raise NexusLLMError(f"Invalid fake fixture for scenario '{scenario}'")

        delay_ms = int(fixture.get("delay_ms", 0))
        if delay_ms:
            await asyncio.sleep(delay_ms / 1000)

        error = fixture.get("error")
        if error:
            raise NexusLLMError(str(error))

        content = fixture.get("content", "Fake LLM response")
        if fixture.get("echo_last_message") and messages:
            content = messages[-1].content

        input_tokens = sum(max(1, len(message.content.split())) for message in messages)
        output_tokens = max(1, len(str(content).split()))
        return LLMResponse(
            content=str(content),
            model=self.config.model,
            provider=LLMProvider.FAKE,
            tokens_input=input_tokens,
            tokens_output=output_tokens,
            duration_ms=(time.perf_counter() - started) * 1000,
            raw_response={"scenario": scenario, "fixture": True},
        )

# --- Factory and High-Level Wrapper ---

class LLMFactory:
    """Factory for creating LLM clients."""

    @staticmethod
    def create(config: LLMConfig) -> BaseLLMClient:
        """
        Creates an LLM client based on the provided configuration.

        Args:
            config: The LLMConfig object.

        Returns:
            An instance of a BaseLLMClient subclass.
        
        Raises:
            ValueError: If an unsupported provider is specified.
        """
        provider_map = {
            LLMProvider.OPENAI: OpenAIClient,
            LLMProvider.GEMINI: GeminiClient,
            LLMProvider.OLLAMA: OllamaClient,
            LLMProvider.FAKE: FakeLLMClient,
            LLMProvider.GROQ: OpenAIClient,
            LLMProvider.OPENAI_COMPATIBLE: OpenAIClient,
        }
        client_class = provider_map.get(config.provider)
        if not client_class:
            raise ValueError(f"Unsupported LLM provider: {config.provider}")
        return client_class(config)

    @staticmethod
    def create_from_env() -> Dict[str, BaseLLMClient]:
        """
        Creates all available LLM clients based on environment variables.

        Returns:
            A dictionary of available client names to their instances.
        """
        clients: Dict[str, BaseLLMClient] = {}
        logger = get_logger("LLMFactory")

        fake_config = LLMConfig(
            provider=LLMProvider.FAKE,
            model=os.getenv("FAKE_LLM_MODEL", "nexus-fake-v1"),
            base_url=os.getenv("NEXUS_LLM_FIXTURES"),
        )
        clients["fake"] = FakeLLMClient(fake_config)

        # OpenAI
        if os.getenv("OPENAI_API_KEY"):
            try:
                config = LLMConfig(
                    provider=LLMProvider.OPENAI,
                    model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                    api_key=os.getenv("OPENAI_API_KEY")
                )
                clients["openai"] = OpenAIClient(config)
                logger.info("OpenAI client created from environment variables.")
            except Exception as e:
                logger.warning(f"Failed to create OpenAI client from env: {e}")

        # Gemini
        if os.getenv("GEMINI_API_KEY"):
            try:
                config = LLMConfig(
                    provider=LLMProvider.GEMINI,
                    model=os.getenv("GEMINI_MODEL", "gemini-1.5-flash"),
                    api_key=os.getenv("GEMINI_API_KEY")
                )
                clients["gemini"] = GeminiClient(config)
                logger.info("Gemini client created from environment variables.")
            except Exception as e:
                logger.warning(f"Failed to create Gemini client from env: {e}")

        # Groq / OpenAI-compatible endpoint
        if os.getenv("GROQ_API_KEY"):
            try:
                config = LLMConfig(
                    provider=LLMProvider.GROQ,
                    model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
                    api_key=os.getenv("GROQ_API_KEY"),
                    base_url=os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
                )
                clients["groq"] = OpenAIClient(config)
                logger.info("Groq client created from environment variables.")
            except Exception as e:
                logger.warning(f"Failed to create Groq client from env: {e}")

        # Ollama
        if os.getenv("OLLAMA_BASE_URL"):
            try:
                config = LLMConfig(
                    provider=LLMProvider.OLLAMA,
                    model=os.getenv("OLLAMA_MODEL", "llama3"),
                    base_url=os.getenv("OLLAMA_BASE_URL")
                )
                clients["ollama"] = OllamaClient(config)
                logger.info("Ollama client created from environment variables.")
            except Exception as e:
                logger.warning(f"Failed to create Ollama client from env: {e}")
        
        return clients


class NexusLLM:
    """
    A high-level wrapper for LLM clients that provides resilience and stats.
    """
    def __init__(
        self,
        primary: BaseLLMClient,
        fallback: Optional[BaseLLMClient] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initializes the NexusLLM wrapper.

        Args:
            primary: The main LLM client to use.
            fallback: An optional secondary client to use if the primary fails.
            logger: An optional logger instance.
        """
        self.primary = primary
        self.fallback = fallback
        self._logger = logger or get_logger("NexusLLM")
        
        # Stats tracking
        self._calls_total = 0
        self._calls_primary = 0
        self._calls_fallback = 0
        self._total_tokens = 0
        self._total_latency_ms = 0.0

    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        """
        Executes a completion request with optional fallback.

        Tries the primary client first. If it fails, and a fallback client
        is configured, it retries the request with the fallback.

        Args:
            messages: The conversation history.
            **kwargs: Provider-specific arguments.

        Returns:
            The LLMResponse from the successful client.

        Raises:
            NexusLLMError: If both primary and fallback clients fail.
        """
        self._calls_total += 1
        try:
            self._logger.info(f"Attempting completion with primary provider: {self.primary.config.provider.value}")
            self._calls_primary += 1
            response = await self.primary.complete(messages, **kwargs)
            self._update_stats(response)
            return response
        except Exception as primary_error:
            self._logger.warning(
                f"Primary provider '{self.primary.config.provider.value}' failed: {primary_error}"
            )
            if self.fallback:
                self._logger.info(f"Attempting completion with fallback provider: {self.fallback.config.provider.value}")
                self._calls_fallback += 1
                try:
                    response = await self.fallback.complete(messages, **kwargs)
                    self._update_stats(response)
                    return response
                except Exception as fallback_error:
                    self._logger.error(
                        f"Fallback provider '{self.fallback.config.provider.value}' also failed: {fallback_error}"
                    )
                    raise NexusLLMError("Both primary and fallback LLM providers failed.") from fallback_error
            else:
                raise NexusLLMError("Primary LLM provider failed and no fallback is configured.") from primary_error

    async def ask(self, system_prompt: str, user_message: str) -> str:
        """
        A shortcut for simple queries.

        Args:
            system_prompt: The system message.
            user_message: The user's message.

        Returns:
            The string content of the response.
        """
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_message),
        ]
        response = await self.complete(messages)
        return response.content

    def _update_stats(self, response: LLMResponse) -> None:
        """Updates internal performance statistics."""
        self._total_tokens += response.total_tokens
        self._total_latency_ms += response.duration_ms
        self._logger.info(
            f"LLM call successful via {response.provider.value}. "
            f"Duration: {response.duration_ms:.2f}ms, "
            f"Tokens: {response.total_tokens}."
        )

    def get_stats(self) -> Dict[str, Any]:
        """
        Retrieves the current performance statistics.

        Returns:
            A dictionary of performance metrics.
        """
        avg_latency = (self._total_latency_ms / self._calls_total) if self._calls_total > 0 else 0
        return {
            "calls_total": self._calls_total,
            "calls_primary_success": self._calls_primary - self._calls_fallback,
            "calls_fallback_success": self._calls_fallback,
            "total_tokens_processed": self._total_tokens,
            "avg_latency_ms": avg_latency,
        }
```

### nexus_core/llm/fixtures/responses.json — 26 líneas

```json
{
  "default": {
    "content": "Respuesta determinista de NEXUS Fake LLM."
  },
  "planner.simple_success": {
    "content": "{\"goal\":\"fixture\",\"steps\":[{\"id\":\"step-1\",\"tool\":\"echo\",\"arguments\":{\"text\":\"ok\"}}]}"
  },
  "planner.invalid_json": {
    "content": "esto no es JSON"
  },
  "tool_call.safe": {
    "content": "{\"tool\":\"file_read\",\"arguments\":{\"path\":\"README.md\"}}"
  },
  "tool_call.forbidden": {
    "content": "{\"tool\":\"shell\",\"arguments\":{\"command\":\"forbidden\"}}"
  },
  "provider.timeout": {
    "error": "simulated provider timeout"
  },
  "provider.rate_limited": {
    "error": "simulated provider rate limit"
  },
  "echo": {
    "echo_last_message": true
  }
}
```

### nexus_core/llm/gemini_provider.py — 19 líneas

```python
import os
from dotenv import load_dotenv
from google import genai

load_dotenv()  # carga el archivo .env

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


class GeminiProvider:
    def __init__(self, api_key):
        self.client = genai.Client(api_key=api_key)
        self.model = "gemini-2.5-pro"

    async def generate_code(self, prompt):
        response = await self.client.aio.models.generate_content(
            model=self.model, contents=prompt
        )
        return response.text
```

### nexus_core/llm/openai_provider.py — 22 líneas

```python
import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()  # carga el archivo .env

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

class OpenAIProvider:
    def __init__(self, api_key):
        self.client = OpenAI(api_key=api_key)

    async def generate_code(self, prompt):
        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You generate Python AI agents."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        return response.choices[0].message.content
```

### Agentes

### nexus_core/agent_team_manager.py — 638 líneas

```python
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  BAJIOWARE NEXUS — AGENT TEAM MANAGER                                        ║
║  Orquesta equipos dinámicos de agentes para proyectos reales                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Supera a CrewAI: equipos dinámicos con roles configurables en runtime       ║
║  Supera a AutoGen: workflows condicionales con lógica if/else real           ║
║  Supera a LangGraph: integración nativa con herramientas del sistema         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from nexus_core.config import PROJECTS_DIR

logger = logging.getLogger("nexus.agent_team_manager")


# ── Tipos de roles disponibles ────────────────────────────────────────────────

class AgentRole(str, Enum):
    PLANNER    = "planner"      # Diseña la arquitectura y divide tareas
    CODER      = "coder"        # Escribe código
    TESTER     = "tester"       # Ejecuta pruebas
    REVIEWER   = "reviewer"     # Revisa calidad y seguridad
    DEPLOYER   = "deployer"     # Despliega y ejecuta scripts
    RESEARCHER = "researcher"   # Investiga y analiza
    SECURITY   = "security"     # Audita seguridad
    DOCUMENTER = "documenter"   # Genera documentación


# ── Resultado de una tarea de agente ─────────────────────────────────────────

@dataclass
class AgentTaskResult:
    task_id: str
    role: AgentRole
    success: bool
    output: Any
    error: Optional[str] = None
    duration_ms: float = 0.0
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "task_id": self.task_id,
            "role": self.role,
            "success": self.success,
            "output": str(self.output)[:2000] if self.output else None,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


# ── Definición de un miembro del equipo ──────────────────────────────────────

@dataclass
class TeamMember:
    role: AgentRole
    name: str
    capability: str           # capability para el dispatcher
    system_prompt: str        # instrucciones específicas del rol
    tools: List[str] = field(default_factory=list)
    max_retries: int = 2


# ── Estado del equipo ─────────────────────────────────────────────────────────

class TeamStatus(str, Enum):
    IDLE      = "idle"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    WAITING   = "waiting_approval"  # punto de revisión humana


@dataclass
class TeamExecution:
    execution_id: str
    project_name: str
    objective: str
    status: TeamStatus
    members: List[TeamMember]
    results: Dict[str, AgentTaskResult] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    human_approval_required: bool = False
    human_approval_message: str = ""

    def to_dict(self) -> Dict:
        return {
            "execution_id": self.execution_id,
            "project_name": self.project_name,
            "objective": self.objective,
            "status": self.status,
            "members": [{"role": m.role, "name": m.name} for m in self.members],
            "results": {k: v.to_dict() for k, v in self.results.items()},
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "human_approval_required": self.human_approval_required,
            "human_approval_message": self.human_approval_message,
        }


# ── Agent Team Manager ────────────────────────────────────────────────────────

class AgentTeamManager:
    """
    Orquesta equipos dinámicos de agentes para ejecutar proyectos completos.
    
    Capacidades:
    - Crear equipos con roles dinámicos según el objetivo
    - Ejecutar tareas en paralelo o secuencial según dependencias
    - Lógica condicional: si test falla → volver a coder con el error
    - Puntos de aprobación humana (el 20%)
    - Memoria compartida entre miembros del equipo
    """

    # ── Templates de equipos predefinidos ────────────────────────────────────

    TEAM_TEMPLATES = {
        "software_development": [
            TeamMember(
                role=AgentRole.PLANNER,
                name="PlannerAgent",
                capability="code_generation",
                system_prompt="Eres un arquitecto de software. Analiza el objetivo y crea un plan técnico detallado con los archivos a crear y su estructura.",
                tools=["file_read", "file_search"],
            ),
            TeamMember(
                role=AgentRole.CODER,
                name="CoderAgent",
                capability="code_generation",
                system_prompt="Eres un desarrollador senior. Implementa el código siguiendo el plan del arquitecto. Escribe código limpio, documentado y con manejo de errores.",
                tools=["file_write", "file_read", "bash_exec"],
            ),
            TeamMember(
                role=AgentRole.TESTER,
                name="TesterAgent",
                capability="code_generation",
                system_prompt="Eres un QA engineer. Ejecuta las pruebas del código y reporta si pasan o fallan con detalles específicos.",
                tools=["bash_exec", "file_read"],
            ),
            TeamMember(
                role=AgentRole.REVIEWER,
                name="ReviewerAgent",
                capability="code_generation",
                system_prompt="Eres un senior reviewer. Revisa el código en busca de bugs, problemas de seguridad y mejoras de calidad.",
                tools=["file_read", "file_search"],
            ),
        ],
        "security_audit": [
            TeamMember(
                role=AgentRole.RESEARCHER,
                name="ReconAgent",
                capability="code_generation",
                system_prompt="Eres un investigador de seguridad. Mapea la superficie de ataque del sistema objetivo.",
                tools=["bash_exec", "file_read"],
            ),
            TeamMember(
                role=AgentRole.SECURITY,
                name="SecurityAgent",
                capability="code_generation",
                system_prompt="Eres un auditor de seguridad. Identifica vulnerabilidades críticas y propone mitigaciones con código.",
                tools=["bash_exec", "file_read", "file_search"],
            ),
            TeamMember(
                role=AgentRole.DOCUMENTER,
                name="ReportAgent",
                capability="code_generation",
                system_prompt="Eres un redactor técnico. Genera reportes de seguridad claros y accionables basados en los hallazgos.",
                tools=["file_write", "file_read"],
            ),
        ],
        "feature_sprint": [
            TeamMember(
                role=AgentRole.PLANNER,
                name="SprintPlanner",
                capability="code_generation",
                system_prompt="Eres un Scrum Master técnico. Divide el feature en tareas específicas y define el orden de implementación.",
                tools=["file_read"],
            ),
            TeamMember(
                role=AgentRole.CODER,
                name="BackendDev",
                capability="code_generation",
                system_prompt="Eres un desarrollador backend. Implementa los endpoints, modelos y lógica de negocio.",
                tools=["file_write", "file_read", "bash_exec"],
            ),
            TeamMember(
                role=AgentRole.TESTER,
                name="QAAgent",
                capability="code_generation",
                system_prompt="Ejecuta pytest y reporta resultados con detalles de fallos.",
                tools=["bash_exec"],
            ),
        ],
    }

    def __init__(self):
        self._executions: Dict[str, TeamExecution] = {}
        self._approval_events: Dict[str, asyncio.Event] = {}
        self._approval_decisions: Dict[str, bool] = {}
        logger.info("AgentTeamManager iniciado")

    def create_team(
        self,
        project_name: str,
        objective: str,
        template: str = "software_development",
        custom_members: Optional[List[TeamMember]] = None,
    ) -> TeamExecution:
        """
        Crea un equipo de agentes para un proyecto.
        
        Args:
            project_name: nombre del proyecto (ej: "ecommerce_zapateria")
            objective: qué debe lograr el equipo
            template: "software_development" | "security_audit" | "feature_sprint"
            custom_members: lista custom de miembros (override del template)
        """
        members = custom_members or self.TEAM_TEMPLATES.get(template, self.TEAM_TEMPLATES["software_development"])
        
        execution = TeamExecution(
            execution_id=f"team_{uuid.uuid4().hex[:8]}",
            project_name=project_name,
            objective=objective,
            status=TeamStatus.IDLE,
            members=members,
        )
        self._executions[execution.execution_id] = execution
        logger.info(f"Equipo creado: {project_name} | {len(members)} miembros | Template: {template}")
        return execution

    async def run_team(
        self,
        execution_id: str,
        require_human_approval: bool = True,
        timeout: float = 300.0,
    ) -> TeamExecution:
        """
        Ejecuta el equipo completo con lógica condicional.
        
        Flujo:
        1. Planner → crea el plan
        2. Coder → implementa (en paralelo si hay varios)
        3. Tester → ejecuta pruebas
           → SI falla: vuelve a Coder con el error (max 2 reintentos)
           → SI pasa: continúa
        4. Reviewer → revisa calidad
        5. [Aprobación humana si require_human_approval=True]
        6. Deployer/Documenter → entrega final
        """
        execution = self._executions.get(execution_id)
        if not execution:
            raise ValueError(f"Execution {execution_id} no encontrada")

        execution.status = TeamStatus.RUNNING
        logger.info(f"Iniciando equipo {execution_id} para: {execution.objective[:50]}")

        try:
            # Fase 1: Planner
            planner = self._get_member(execution, AgentRole.PLANNER)
            if planner:
                logger.info(f"[{execution_id}] Fase 1: Planning...")
                plan_result = await self._execute_member_task(
                    execution, planner,
                    f"OBJETIVO: {execution.objective}\n\nCrea un plan técnico detallado.",
                )
                execution.context["plan"] = plan_result.output
                if not plan_result.success:
                    logger.warning(f"[{execution_id}] Planner falló, continuando sin plan...")

            # Fase 2: Coder (con reintentos si tester falla)
            coder = self._get_member(execution, AgentRole.CODER)
            tester = self._get_member(execution, AgentRole.TESTER)
            
            if coder:
                for attempt in range(3):  # max 3 intentos
                    logger.info(f"[{execution_id}] Fase 2: Coding (intento {attempt+1})...")
                    
                    plan_context = execution.context.get("plan", "")
                    test_error = execution.context.get("last_test_error", "")
                    
                    prompt = f"OBJETIVO: {execution.objective}\n\n"
                    if plan_context:
                        prompt += f"PLAN:\n{str(plan_context)[:1000]}\n\n"
                    if test_error:
                        prompt += f"⚠️ CORRECCIÓN REQUERIDA — El tester reportó este error:\n{test_error}\n\nCorrige el problema específico.\n\n"
                    prompt += "Implementa el código ahora."
                    
                    code_result = await self._execute_member_task(execution, coder, prompt)
                    execution.context["code"] = code_result.output

                    # Materializar archivos en disco
                    if code_result.success and code_result.output:
                        pdir = str(PROJECTS_DIR / execution.project_name / "backend")
                        mat = await self._materialize_code(execution, code_result.output, pdir)
                        logger.info(f"[{execution.execution_id}] Materializados: {mat['files_written']} archivos")

                    
                    # Fase 3: Tester — lógica condicional
                    if tester and code_result.success:
                        logger.info(f"[{execution_id}] Fase 3: Testing...")
                        test_result = await self._execute_member_task(
                            execution, tester,
                            f"Ejecuta las pruebas para el código implementado.\n\nContexto: {execution.objective}",
                        )
                        
                        if test_result.success:
                            logger.info(f"[{execution_id}] ✅ Tests pasaron en intento {attempt+1}")
                            execution.context.pop("last_test_error", None)
                            break  # Tests OK — salir del loop
                        else:
                            # Tests fallaron — guardar error y reintentar con Coder
                            execution.context["last_test_error"] = test_result.error or str(test_result.output)[:500]
                            logger.warning(f"[{execution_id}] ❌ Tests fallaron, reintentando con Coder...")
                            if attempt == 2:
                                logger.error(f"[{execution_id}] Máximo reintentos alcanzado")
                    else:
                        break  # Sin tester, continuar

            # Fase 4: Reviewer
            reviewer = self._get_member(execution, AgentRole.REVIEWER)
            if reviewer:
                logger.info(f"[{execution_id}] Fase 4: Code Review...")
                review_result = await self._execute_member_task(
                    execution, reviewer,
                    f"Revisa el código implementado para: {execution.objective}\n\nBusca bugs, vulnerabilidades y mejoras.",
                )
                execution.context["review"] = review_result.output

            # Fase 5: Aprobación humana
            if require_human_approval:
                logger.info(f"[{execution_id}] ⏸ Esperando aprobación humana...")
                execution.status = TeamStatus.WAITING
                execution.human_approval_required = True
                
                summary = self._generate_summary(execution)
                execution.human_approval_message = summary
                
                # Esperar aprobación con timeout
                event = asyncio.Event()
                self._approval_events[execution_id] = event
                
                try:
                    await asyncio.wait_for(event.wait(), timeout=timeout)
                    approved = self._approval_decisions.get(execution_id, False)
                    
                    if not approved:
                        execution.status = TeamStatus.FAILED
                        logger.info(f"[{execution_id}] ❌ Rechazado por humano")
                        return execution
                    
                    logger.info(f"[{execution_id}] ✅ Aprobado por humano")
                except asyncio.TimeoutError:
                    logger.warning(f"[{execution_id}] Timeout esperando aprobación")

            # Fase 6: Deployer/Documenter en paralelo
            deployer   = self._get_member(execution, AgentRole.DEPLOYER)
            documenter = self._get_member(execution, AgentRole.DOCUMENTER)
            
            final_tasks = []
            if deployer:
                final_tasks.append(self._execute_member_task(
                    execution, deployer,
                    f"Despliega o finaliza: {execution.objective}"
                ))
            if documenter:
                final_tasks.append(self._execute_member_task(
                    execution, documenter,
                    f"Documenta el trabajo realizado para: {execution.objective}"
                ))
            
            if final_tasks:
                logger.info(f"[{execution_id}] Fase 6: Deploy/Docs en paralelo...")
                await asyncio.gather(*final_tasks)

            execution.status = TeamStatus.COMPLETED
            execution.completed_at = datetime.now().isoformat()
            logger.info(f"[{execution_id}] ✅ Equipo completado exitosamente")

            # Guardar automáticamente en Memory Bank
            try:
                from nexus_core.memory.manager import MemoryManager
                mm = MemoryManager()
                mm.remember_task(execution_id, {
                    "project": execution.project_name,
                    "objective": execution.objective[:300],
                    "status": "completed",
                    "members": [m.name for m in execution.members],
                    "timestamp": execution.completed_at,
                })
                # Guardar resultados de cada agente como knowledge
                for role, result in execution.results.items():
                    if result.success and result.output:
                        mm.remember_knowledge(
                            f"team_{execution_id}_{role}",
                            {
                                "project": execution.project_name,
                                "role": str(role),
                                "output": str(result.output)[:500],
                                "timestamp": execution.completed_at,
                            }
                        )
                logger.info(f"[{execution_id}] 🧠 Resultados guardados en Memory Bank")
            except Exception as e:
                logger.warning(f"[{execution_id}] No se pudo guardar en memoria: {e}")

        except Exception as e:
            execution.status = TeamStatus.FAILED
            logger.error(f"[{execution_id}] Error en equipo: {e}", exc_info=True)

        return execution

    async def approve(self, execution_id: str, approved: bool = True) -> bool:
        """Aprobación/rechazo humano de una ejecución en espera."""
        self._approval_decisions[execution_id] = approved
        event = self._approval_events.get(execution_id)
        if event:
            event.set()
            return True
        return False

    def get_execution(self, execution_id: str) -> Optional[TeamExecution]:
        return self._executions.get(execution_id)

    def get_all_executions(self) -> List[Dict]:
        return [e.to_dict() for e in self._executions.values()]

    def get_pending_approvals(self) -> List[Dict]:
        return [
            e.to_dict() for e in self._executions.values()
            if e.status == TeamStatus.WAITING
        ]

    # ── Métodos internos ──────────────────────────────────────────────────────

    def _get_member(self, execution: TeamExecution, role: AgentRole) -> Optional[TeamMember]:
        return next((m for m in execution.members if m.role == role), None)



    async def _materialize_code(self, execution, code_output, project_dir):
        import re
        from pathlib import Path
        if not code_output:
            return {"files_written": 0}
        base = Path(project_dir)
        base.mkdir(parents=True, exist_ok=True)
        files_written = []
        pat = re.compile(
            r'[`*]{1,3}([\w/\-.]+\.\w+)[`*]{0,3}\s*\n```\w*\n(.*?)```',
            re.DOTALL
        )
        for m in pat.finditer(code_output):
            rel = m.group(1).strip()
            code = m.group(2)
            if rel.startswith("/") or ".." in rel:
                continue
            target = base / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                target.write_text(code, encoding="utf-8")
                files_written.append(rel)
                logger.info(f"Materializado: {rel}")
            except Exception as e:
                logger.warning(f"Error {rel}: {e}")
        if not files_written:
            exts = {
                "python": "main.py", "py": "main.py",
                "javascript": "app.js", "js": "app.js",
                "typescript": "app.ts", "ts": "app.ts",
                "bash": "script.sh", "sql": "schema.sql",
                "json": "data.json", "html": "index.html",
            }
            pat2 = re.compile(r"```(\w+)\n(.*?)```", re.DOTALL)
            for i, m in enumerate(pat2.finditer(code_output)):
                lang = m.group(1).lower()
                code = m.group(2)
                fname = exts.get(lang, f"file_{i}.txt")
                if i > 0:
                    fname = f"file_{i}_{fname}"
                target = base / fname
                try:
                    target.write_text(code, encoding="utf-8")
                    files_written.append(fname)
                    logger.info(f"Bloque: {fname}")
                except Exception as e:
                    logger.warning(f"Error bloque {i}: {e}")
        execution.context["materialized_files"] = files_written
        execution.context["project_dir"] = str(base)
        logger.info(f"[{execution.execution_id}] {len(files_written)} archivos en {base}")
        return {"files_written": len(files_written), "files": files_written}


    async def _execute_member_task(
        self,
        execution: TeamExecution,
        member: TeamMember,
        prompt: str,
    ) -> AgentTaskResult:
        """Ejecuta la tarea de un miembro del equipo via JuniorAgent."""
        import time
        task_id = f"{execution.execution_id}_{member.role}_{uuid.uuid4().hex[:4]}"
        t0 = time.time()
        
        try:
            from nexus_core.agents.junior_agent import JuniorAgent
            agent = JuniorAgent()
            
            # Construir payload con contexto del equipo
            full_prompt = f"""ROL: {member.system_prompt}

PROYECTO: {execution.project_name}
CONTEXTO DEL EQUIPO: {str(execution.context)[:800]}

TAREA:
{prompt}"""
            
            result = await agent.run(task_id, {
                "type": "llm_query",
                "system_prompt": member.system_prompt,
                "prompt": full_prompt,
            })
            
            duration_ms = (time.time() - t0) * 1000
            response = result.get("result", {}).get("response", "") or result.get("result", {}).get("output", "")
            
            task_result = AgentTaskResult(
                task_id=task_id,
                role=member.role,
                success=result.get("success", False),
                output=response,
                duration_ms=duration_ms,
            )
            
            execution.results[member.role] = task_result
            logger.info(f"[{execution.execution_id}] {member.role}: {'✅' if task_result.success else '❌'} ({duration_ms:.0f}ms)")
            return task_result
            
        except Exception as e:
            duration_ms = (time.time() - t0) * 1000
            task_result = AgentTaskResult(
                task_id=task_id,
                role=member.role,
                success=False,
                output=None,
                error=str(e),
                duration_ms=duration_ms,
            )
            execution.results[member.role] = task_result
            logger.error(f"[{execution.execution_id}] {member.role} ERROR: {e}")
            return task_result

    def _generate_summary(self, execution: TeamExecution) -> str:
        """Genera resumen para aprobación humana."""
        lines = [
            f"📋 RESUMEN: {execution.project_name}",
            f"🎯 Objetivo: {execution.objective[:200]}",
            f"👥 Equipo: {', '.join(m.name for m in execution.members)}",
            "",
            "RESULTADOS:",
        ]
        for role, result in execution.results.items():
            status = "✅" if result.success else "❌"
            lines.append(f"  {status} {role}: {str(result.output)[:200] if result.output else result.error or 'sin output'}")
        return "\n".join(lines)


# ── Endpoints FastAPI ─────────────────────────────────────────────────────────

def create_team_router():
    from fastapi import APIRouter
    router = APIRouter(prefix="/teams", tags=["AgentTeams"])
    
    _manager = AgentTeamManager()

    @router.post("/create")
    async def create_team(req: dict):
        """Crea un equipo de agentes para un proyecto."""
        execution = _manager.create_team(
            project_name=req.get("project_name", "proyecto"),
            objective=req.get("objective", ""),
            template=req.get("template", "software_development"),
        )
        return execution.to_dict()

    @router.post("/{execution_id}/run")
    async def run_team(execution_id: str, req: dict = {}):
        """Inicia la ejecución del equipo."""
        require_approval = req.get("require_human_approval", True)
        asyncio.ensure_future(
            _manager.run_team(execution_id, require_human_approval=require_approval)
        )
        return {"started": True, "execution_id": execution_id}

    @router.get("/{execution_id}/status")
    async def team_status(execution_id: str):
        execution = _manager.get_execution(execution_id)
        if not execution:
            from fastapi import HTTPException
            raise HTTPException(404, "Execution no encontrada")
        return execution.to_dict()

    @router.post("/{execution_id}/approve")
    async def approve_team(execution_id: str, req: dict = {}):
        """Aprobación/rechazo humano."""
        approved = req.get("approved", True)
        ok = await _manager.approve(execution_id, approved)
        return {"approved": approved, "ok": ok}

    @router.get("/")
    async def list_teams():
        return {"executions": _manager.get_all_executions()}

    @router.get("/pending-approvals")
    async def pending_approvals():
        return {"pending": _manager.get_pending_approvals()}

    return router


# ── Singleton ─────────────────────────────────────────────────────────────────

_team_manager: Optional[AgentTeamManager] = None

def get_team_manager() -> AgentTeamManager:
    global _team_manager
    if _team_manager is None:
        _team_manager = AgentTeamManager()
    return _team_manager
```

### nexus_core/agents/__init__.py — 0 líneas

```python

```

### nexus_core/agents/base.py — 353 líneas

```python
# nexus_core/agents/base.py

"""
Defines the foundational abstract base class for all agents in the NEXUS system.

This module provides the core components for agent creation, including:
- AgentCapability: An enumeration of skills an agent can possess.
- AgentMetadata: A dataclass for an agent's static configuration.
- AgentStats: A class for tracking an agent's performance metrics.
- BaseAgent: An abstract class that all concrete agents must inherit from,
  defining the common interface and execution lifecycle.
"""

import abc
import asyncio
import logging
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

# Assuming a logger utility exists. If not, a standard logger is used.
try:
    from nexus_core.utils.logger import get_logger
except ImportError:
    # Fallback to standard logging if the custom logger is not available
    def get_logger(name: str) -> logging.Logger:
        """Provides a basic logger instance."""
        logger = logging.getLogger(name)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger


class AgentCapability(str, Enum):
    """Enumerates the potential capabilities of an agent."""
    CODE_GENERATION = "code_generation"
    DATA_ANALYSIS = "data_analysis"
    WEB_SEARCH = "web_search"
    FILE_OPERATIONS = "file_operations"
    API_CALLS = "api_calls"
    DATABASE_QUERIES = "database_queries"
    SECURITY_AUDIT = "security_audit"
    REPORT_GENERATION = "report_generation"
    ORCHESTRATION = "orchestration"
    LLM_INTERACTION = "llm_interaction"


@dataclass
class AgentMetadata:
    """
    Holds the static configuration and metadata for an agent.

    Attributes:
        agent_id: A unique identifier for the agent instance.
        name: The human-readable name of the agent.
        version: The version of the agent's implementation.
        capabilities: A list of skills the agent possesses.
        model: The underlying model used by the agent (e.g., an LLM).
        max_concurrent: The maximum number of tasks the agent can run in parallel.
        timeout_seconds: The default timeout for a single task.
        tags: A list of arbitrary tags for grouping or filtering agents.
        created_at: The timestamp when the agent instance was created.
    """
    name: str
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: str = "1.0.0"
    capabilities: List[AgentCapability] = field(default_factory=list)
    model: str = "openai/gpt-4o-mini"
    max_concurrent: int = 3
    timeout_seconds: int = 120
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def has_capability(self, cap: AgentCapability) -> bool:
        """
        Checks if the agent possesses a specific capability.

        Args:
            cap: The capability to check for.

        Returns:
            True if the agent has the capability, False otherwise.
        """
        return cap in self.capabilities

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes the metadata to a dictionary.

        Returns:
            A dictionary representation of the agent's metadata.
        """
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "version": self.version,
            "capabilities": [c.value for c in self.capabilities],
            "model": self.model,
            "max_concurrent": self.max_concurrent,
            "timeout_seconds": self.timeout_seconds,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
        }


class AgentStats:
    """
    Tracks runtime statistics for an agent's performance.
    """
    def __init__(self) -> None:
        self.total_tasks: int = 0
        self.completed_tasks: int = 0
        self.failed_tasks: int = 0
        self.total_retries: int = 0
        self.avg_duration_ms: float = 0.0
        self.last_active: Optional[datetime] = None

    def update(self, success: bool, duration_ms: float) -> None:
        """
        Updates the statistics after a task is completed.

        Args:
            success: Whether the task succeeded or failed.
            duration_ms: The duration of the task in milliseconds.
        """
        self.total_tasks += 1
        if success:
            self.completed_tasks += 1
        else:
            self.failed_tasks += 1

        # Update average duration using a weighted average
        if self.completed_tasks == 1 and success:
             self.avg_duration_ms = duration_ms
        elif success:
            total_duration = self.avg_duration_ms * (self.completed_tasks - 1)
            self.avg_duration_ms = (total_duration + duration_ms) / self.completed_tasks

        self.last_active = datetime.utcnow()

    def success_rate(self) -> float:
        """
        Calculates the success rate of the agent.

        Returns:
            The success rate as a float between 0.0 and 1.0. Returns 0.0 if
            no tasks have been processed.
        """
        if self.total_tasks == 0:
            return 0.0
        return self.completed_tasks / self.total_tasks


class BaseAgent(abc.ABC):
    """
    Abstract base class for all agents in the NEXUS system.

    This class defines the common interface and lifecycle for agent operations,
    including task execution, state management, and statistics tracking.
    """

    def __init__(self, metadata: AgentMetadata, event_bus: Any = None, logger: Optional[logging.Logger] = None):
        """
        Initializes the BaseAgent.

        Args:
            metadata: The static configuration for the agent.
            event_bus: An optional event bus for emitting system-wide events.
            logger: An optional logger instance. If not provided, a default
                    logger will be created.
        """
        self.metadata = metadata
        self._event_bus = event_bus
        self._logger = logger or get_logger(f"Agent.{self.metadata.name}")
        self._stats = AgentStats()
        self._current_tasks: int = 0
        self._lock = asyncio.Lock()

    @abc.abstractmethod
    async def execute(self, task_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        The core logic of the agent's task execution.

        This method must be implemented by all concrete agent subclasses. It
        contains the specific logic for handling a given task.

        Args:
            task_id: A unique identifier for the task.
            payload: A dictionary containing the data required to execute the task.

        Returns:
            A dictionary containing the result of the task execution.
        """
        raise NotImplementedError

    async def run(self, task_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orchestrates the full lifecycle of a task execution.

        This method wraps the `execute` call with pre-execution setup,
        post-execution cleanup, error handling, and timeout management.

        Args:
            task_id: A unique identifier for the task.
            payload: The data for the task.

        Returns:
            A dictionary containing the outcome of the task, including success
            status, result, error message, and duration.
        """
        start_time = time.perf_counter()
        try:
            await self._pre_execute(task_id, payload)
            
            result = await asyncio.wait_for(
                self.execute(task_id, payload),
                timeout=self.metadata.timeout_seconds
            )
            # Legacy agents often encode tool failures in a result dictionary
            # instead of raising.  Treating those values as success lets an
            # orchestrator persist a false claim of completion.
            if isinstance(result, dict) and result.get("status") in {
                "error", "failed", "hitl_denied", "completed_with_errors",
            }:
                raise RuntimeError(result.get("error") or result.get("message") or
                                   f"agent returned status={result['status']}")
            
            duration_ms = (time.perf_counter() - start_time) * 1000
            await self._post_execute(task_id, result, duration_ms)
            
            return {
                "success": True,
                "result": result,
                "error": None,
                "duration_ms": duration_ms
            }
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            await self._handle_failure(task_id, e, duration_ms)
            return {
                "success": False,
                "result": {},
                "error": f"{type(e).__name__}: {e}",
                "duration_ms": duration_ms
            }

    async def _pre_execute(self, task_id: str, payload: Dict[str, Any]) -> None:
        """
        Handles pre-task execution logic.
        """
        async with self._lock:
            self._current_tasks += 1
        self._logger.info(f"Starting task {task_id} on agent {self.name}.")
        if self._event_bus:
            await self._event_bus.publish(
                "agent.task.started",
                {"agent_id": self.agent_id, "task_id": task_id, "payload": payload}
            )

    async def _post_execute(self, task_id: str, result: Dict[str, Any], duration_ms: float) -> None:
        """
        Handles successful post-task execution logic.
        """
        async with self._lock:
            self._current_tasks -= 1
            self._stats.update(success=True, duration_ms=duration_ms)
        self._logger.info(f"Task {task_id} completed successfully in {duration_ms:.2f}ms.")
        if self._event_bus:
            await self._event_bus.publish(
                "agent.task.completed",
                {"agent_id": self.agent_id, "task_id": task_id, "result": result, "duration_ms": duration_ms}
            )

    async def _handle_failure(self, task_id: str, error: Exception, duration_ms: float) -> None:
        """
        Handles task execution failures.
        """
        async with self._lock:
            self._current_tasks -= 1
            self._stats.update(success=False, duration_ms=duration_ms)
        
        error_type = type(error).__name__
        self._logger.error(
            f"Task {task_id} failed on agent {self.name} after {duration_ms:.2f}ms. "
            f"Error: {error_type}: {error}",
            exc_info=True
        )
        
        if self._event_bus:
            await self._event_bus.publish(
                "agent.task.failed",
                {
                    "agent_id": self.agent_id,
                    "task_id": task_id,
                    "error": f"{error_type}: {error}",
                    "traceback": traceback.format_exc(),
                    "duration_ms": duration_ms
                }
            )

    @property
    def is_available(self) -> bool:
        """
        Checks if the agent can accept new tasks.

        Returns:
            True if the number of current tasks is less than the maximum
            concurrent limit, False otherwise.
        """
        return self._current_tasks < self.metadata.max_concurrent

    @property
    def agent_id(self) -> str:
        """Returns the agent's unique ID."""
        return self.metadata.agent_id

    @property
    def name(self) -> str:
        """Returns the agent's name."""
        return self.metadata.name

    def get_stats(self) -> Dict[str, Any]:
        """
        Retrieves the current statistics and basic metadata of the agent.

        Returns:
            A dictionary containing performance metrics and identifying info.
        """
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "is_available": self.is_available,
            "current_tasks": self._current_tasks,
            "max_concurrent": self.metadata.max_concurrent,
            "stats": {
                "total_tasks": self._stats.total_tasks,
                "completed_tasks": self._stats.completed_tasks,
                "failed_tasks": self._stats.failed_tasks,
                "success_rate": self._stats.success_rate(),
                "avg_duration_ms": self._stats.avg_duration_ms,
                "last_active": self._stats.last_active.isoformat() if self._stats.last_active else None,
            }
        }
```

### nexus_core/agents/data_analyst.py — 13 líneas

```python
from nexus_core.agents.base import BaseAgent

class DataAnalystAgent(BaseAgent):

    async def execute(self, task_id, payload):

        data = payload.get("data", [])

        result = {
            "summary": f"Processed {len(data)} records"
        }

        return result
```

### nexus_core/agents/dynamic_agent.py — 576 líneas

```python
"""
NEXUS PRO — DynamicAgent v2.0
Agente genérico con razonamiento LLM real (GPT-4o / Claude).

Flujo de ejecución:
  1. Recibe tarea con payload
  2. Si tiene LLM → GPT-4o razona y decide qué tool usar + cómo
  3. ToolExecutor ejecuta la tool decidida
  4. Resultado real del servidor
"""
import asyncio
import json
import os
import logging
from pathlib import Path
from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
from nexus_core.config import NEXUS_ROOT, REPORTS_DIR
from nexus_core.kernel.legacy import legacy_execution_enabled

logger = logging.getLogger("nexus.dynamic_agent")

# ── Mapeo role → capability ───────────────────────────────────
CAPABILITY_MAP = {
    "security":   AgentCapability.SECURITY_AUDIT,
    "devops":     AgentCapability.FILE_OPERATIONS,
    "data":       AgentCapability.DATA_ANALYSIS,
    "cloud":      AgentCapability.API_CALLS,
    "compliance": AgentCapability.REPORT_GENERATION,
    "red_team":   AgentCapability.SECURITY_AUDIT,
    "general":    AgentCapability.CODE_GENERATION,
    "code":       AgentCapability.CODE_GENERATION,
    "file":       AgentCapability.FILE_OPERATIONS,
    "bash":       AgentCapability.FILE_OPERATIONS,
}


# ══════════════════════════════════════════════════════════════
# TOOL EXECUTOR — ejecuta herramientas reales
# ══════════════════════════════════════════════════════════════
class ToolExecutor:

    @staticmethod
    async def bash_exec(payload: dict) -> dict:
        cmd = payload.get("command", payload.get("cmd", "echo hello"))
        cwd = payload.get("cwd", str(NEXUS_ROOT))
        timeout = int(payload.get("timeout", 60))
        blocked = ["rm -rf /", "mkfs", "dd if=", ":(){", "fork bomb"]
        if any(b in cmd for b in blocked):
            return {"status": "error", "error": "Comando bloqueado por seguridad"}
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, cwd=cwd,
                env={**os.environ}
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out = stdout.decode("utf-8", errors="replace").strip()
            err = stderr.decode("utf-8", errors="replace").strip()
            return {
                "status": "ok" if proc.returncode == 0 else "error",
                "output": out[:3000],
                "stderr": err[:500] if err else None,
                "returncode": proc.returncode,
                "command": cmd,
            }
        except asyncio.TimeoutError:
            return {"status": "error", "error": f"Timeout {timeout}s", "command": cmd}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def file_read(payload: dict) -> dict:
        path = payload.get("path", payload.get("filepath", ""))
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
            return {"status": "ok", "path": path,
                    "content": content[:5000], "lines": content.count("\n") + 1,
                    "size": len(content)}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def file_write(payload: dict) -> dict:
        path = payload.get("path", payload.get("filepath", ""))
        content = payload.get("content", "")
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(content, encoding="utf-8")
            return {"status": "ok", "path": path, "bytes": len(content)}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def file_list(payload: dict) -> dict:
        path = payload.get("path", str(NEXUS_ROOT))
        try:
            items = [
                {"name": f.name, "type": "dir" if f.is_dir() else "file",
                 "size": f.stat().st_size if f.is_file() else 0}
                for f in sorted(Path(path).iterdir())
                if not f.name.startswith(".")
            ]
            return {"status": "ok", "path": path, "items": items[:50], "total": len(items)}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def http_request(payload: dict) -> dict:
        import httpx
        url = payload.get("url", "")
        method = payload.get("method", "GET").upper()
        headers = payload.get("headers", {})
        body = payload.get("body", None)
        timeout = int(payload.get("timeout", 15))
        if not url:
            return {"status": "error", "error": "URL requerida"}
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.request(method, url, headers=headers, json=body)
                return {
                    "status": "ok", "status_code": resp.status_code,
                    "url": url, "body": resp.text[:3000],
                }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def code_exec(payload: dict) -> dict:
        code = payload.get("code", "print('NEXUS OK')")
        timeout = int(payload.get("timeout", 30))
        try:
            proc = await asyncio.create_subprocess_exec(
                "python3", "-c", code,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "status": "ok" if proc.returncode == 0 else "error",
                "output": stdout.decode("utf-8", errors="replace").strip()[:3000],
                "stderr": stderr.decode("utf-8", errors="replace").strip()[:500],
                "returncode": proc.returncode,
            }
        except asyncio.TimeoutError:
            return {"status": "error", "error": f"Timeout {timeout}s"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def nmap_scan(payload: dict) -> dict:
        target = payload.get("target", "localhost")
        flags = payload.get("flags", "-sV --top-ports 20 -T4")
        try:
            proc = await asyncio.create_subprocess_shell(
                f"nmap {flags} {target}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            return {"status": "ok", "target": target,
                    "output": stdout.decode("utf-8", errors="replace")[:4000]}
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Nmap timeout (120s)"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def report_gen(payload: dict) -> dict:
        import datetime
        title = payload.get("title", "Reporte NEXUS PRO")
        content = payload.get("content", "Sin contenido")
        agent_name = payload.get("agent", "NEXUS")
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        output_path = payload.get("output",
            str(REPORTS_DIR / f"{title.replace(' ','_').replace('/','_')}.md"))
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        report = f"""# {title}

**Generado por:** {agent_name}
**Fecha:** {ts}
**Plataforma:** NEXUS PRO v2.0

---

{content}

---
*Reporte generado automáticamente por NEXUS PRO*
"""
        Path(output_path).write_text(report, encoding="utf-8")
        return {"status": "ok", "path": output_path,
                "title": title, "size": len(report), "lines": report.count("\n")}

    @staticmethod
    async def llm_call(payload: dict, llm=None) -> dict:
        if not llm:
            return {"status": "error",
                    "error": "LLM no disponible — agrega una API key en Modelos & APIs"}
        system = payload.get("system", "Eres un asistente experto de NEXUS PRO.")
        user = payload.get("prompt", payload.get("user", ""))
        if not user:
            return {"status": "error", "error": "prompt requerido"}
        try:
            response = await llm.ask(system, user)
            return {"status": "ok", "response": response,
                    "tokens_approx": len(response.split())}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def git_ops(payload: dict) -> dict:
        git_cmd = payload.get("git_cmd", "status")
        cwd = payload.get("cwd", str(NEXUS_ROOT))
        return await ToolExecutor.bash_exec({"command": f"git {git_cmd}", "cwd": cwd})

    @staticmethod
    async def docker_ops(payload: dict) -> dict:
        docker_cmd = payload.get("docker_cmd", "ps")
        return await ToolExecutor.bash_exec({"command": f"docker {docker_cmd}"})

    @staticmethod
    async def sast_scan(payload: dict) -> dict:
        filepath = payload.get("filepath", payload.get("path", ""))
        if not filepath:
            return {"status": "error", "error": "filepath requerido"}
        result = await ToolExecutor.bash_exec({
            "command": f"python3 -m py_compile '{filepath}' && echo 'SYNTAX_OK' || echo 'SYNTAX_ERROR'"
        })
        # También buscar patrones peligrosos
        try:
            content = Path(filepath).read_text(errors="replace")
            issues = []
            patterns = [
                ("eval(", "Uso de eval() — riesgo de code injection"),
                ("exec(", "Uso de exec() — riesgo de code injection"),
                ("password =", "Posible contraseña hardcodeada"),
                ("secret =", "Posible secreto hardcodeado"),
                ("api_key =", "Posible API key hardcodeada"),
                ("subprocess.call(shell=True", "shell=True en subprocess — riesgo"),
            ]
            for pattern, msg in patterns:
                if pattern.lower() in content.lower():
                    issues.append(msg)
            result["security_issues"] = issues
            result["issues_count"] = len(issues)
        except Exception:
            pass
        return result

    @staticmethod
    async def stride_model(payload: dict) -> dict:
        target = payload.get("target", "sistema")
        context = payload.get("context", "")
        report = f"""# STRIDE Threat Model — {target}

## Spoofing (Suplantación de identidad)
- Verificar autenticación de {target}
- Implementar MFA donde sea posible

## Tampering (Manipulación de datos)
- Validar integridad de inputs/outputs
- Usar firmas digitales en datos críticos

## Repudiation (Repudio)
- Audit trail completo e inmutable
- Logs con timestamps firmados

## Information Disclosure (Divulgación)
- Cifrado en tránsito (TLS 1.3)
- Cifrado en reposo (AES-256)

## Denial of Service (Denegación de servicio)
- Rate limiting en APIs
- Circuit breakers

## Elevation of Privilege (Escalada de privilegios)
- Principio de mínimo privilegio
- RBAC estricto (Zero Trust)

**Contexto adicional:** {context or 'N/A'}
"""
        return await ToolExecutor.report_gen({
            "title": f"STRIDE_{target}",
            "content": report,
            "agent": "ThreatModeler"
        })

    @classmethod
    async def execute_tool(cls, tool_name: str, payload: dict, llm=None) -> dict:
        """Dispatcher central de herramientas."""
        if not legacy_execution_enabled():
            return {
                "status": "error",
                "error": "Legacy ToolExecutor is disabled; use the policy-enforced ToolGateway",
                "tool": tool_name,
            }
        tool_map = {
            "bash_exec":    lambda p: cls.bash_exec(p),
            "file_read":    lambda p: cls.file_read(p),
            "file_write":   lambda p: cls.file_write(p),
            "file_delete":  lambda p: cls.bash_exec({"command": f"rm '{p.get('path','')}'"}) if p.get("path") else {"status":"error","error":"path requerido"},
            "file_list":    lambda p: cls.file_list(p),
            "http_request": lambda p: cls.http_request(p),
            "code_exec":    lambda p: cls.code_exec(p),
            "nmap_scan":    lambda p: cls.nmap_scan(p),
            "report_gen":   lambda p: cls.report_gen(p),
            "llm_call":     lambda p: cls.llm_call(p, llm),
            "git_ops":      lambda p: cls.git_ops(p),
            "docker_ops":   lambda p: cls.docker_ops(p),
            "sast_scan":    lambda p: cls.sast_scan(p),
            "stride_model": lambda p: cls.stride_model(p),
            "api_test":     lambda p: cls.http_request(p),
            "web_search":   lambda p: {"status":"ok","note":"Requiere integración SerpAPI/Tavily"},
            "sql_query":    lambda p: {"status":"ok","note":"Requiere conexión DB configurada"},
            "memory_search":lambda p: {"status":"ok","note":"ChromaDB query pendiente"},
            "memory_write": lambda p: {"status":"ok","note":"ChromaDB write pendiente"},
            "nuclei_scan":  lambda p: cls.bash_exec({"command":f"nuclei -u {p.get('target','localhost')} -severity medium,high,critical"}) if p.get("target") else {"status":"error","error":"target requerido"},
        }
        executor = tool_map.get(tool_name)
        if not executor:
            return {"status": "error", "error": f"Tool '{tool_name}' no encontrada en el catálogo"}
        try:
            return await executor(payload)
        except Exception as e:
            return {"status": "error", "error": str(e), "tool": tool_name}


# ══════════════════════════════════════════════════════════════
# LLM REASONING ENGINE — GPT-4o planifica antes de ejecutar
# ══════════════════════════════════════════════════════════════
class LLMReasoningEngine:
    """
    Usa GPT-4o para razonar sobre la tarea y decidir:
    1. Qué tool usar
    2. Qué parámetros exactos pasar
    3. Cómo interpretar el resultado
    """

    PLANNER_SYSTEM = """Eres el motor de razonamiento de NEXUS PRO, un orquestador de agentes IA de grado militar.

Tu trabajo: analizar una tarea y decidir EXACTAMENTE qué herramienta usar y con qué parámetros.

Herramientas disponibles:
- bash_exec: ejecutar comandos shell. params: {command, cwd, timeout}
- file_read: leer archivo. params: {path}
- file_write: escribir archivo. params: {path, content}
- file_list: listar directorio. params: {path}
- http_request: petición HTTP. params: {url, method, headers, body}
- code_exec: ejecutar Python. params: {code, timeout}
- nmap_scan: escaneo de puertos. params: {target, flags}
- sast_scan: análisis seguridad código. params: {filepath}
- stride_model: modelado amenazas. params: {target, context}
- report_gen: generar reporte. params: {title, content}
- llm_call: consulta LLM adicional. params: {system, prompt}
- git_ops: operaciones git. params: {git_cmd, cwd}
- docker_ops: operaciones docker. params: {docker_cmd}

RESPONDE ÚNICAMENTE con JSON válido, sin markdown, sin explicaciones:
{
  "tool": "nombre_tool",
  "params": { ... },
  "reasoning": "una línea explicando por qué"
}"""

    INTERPRETER_SYSTEM = """Eres el intérprete de resultados de NEXUS PRO.
Recibes el output raw de una herramienta y debes:
1. Resumir qué encontraste
2. Destacar hallazgos importantes
3. Dar recomendaciones si aplica

Sé conciso, técnico y preciso. Máximo 200 palabras."""

    @classmethod
    async def plan(cls, llm, task_name: str, task_desc: str,
                   payload: dict, agent_tools: list, system_prompt: str) -> dict:
        """GPT-4o decide qué tool usar y con qué params."""
        user_msg = f"""Tarea: {task_name}
Descripción: {task_desc}
Payload proporcionado: {json.dumps(payload, ensure_ascii=False)}
Herramientas disponibles para este agente: {', '.join(agent_tools) if agent_tools else 'todas'}
System prompt del agente: {system_prompt[:200] if system_prompt else 'N/A'}

Decide la mejor herramienta y parámetros para completar esta tarea."""

        try:
            response = await llm.ask(cls.PLANNER_SYSTEM, user_msg)
            # Limpiar respuesta
            response = response.strip()
            if response.startswith("```"):
                response = response.split("```")[1]
                if response.startswith("json"):
                    response = response[4:]
            plan = json.loads(response.strip())
            return plan
        except json.JSONDecodeError as e:
            logger.warning(f"[LLM Planner] JSON inválido: {e} | response: {response[:200]}")
            return None
        except Exception as e:
            logger.warning(f"[LLM Planner] Error: {e}")
            return None

    @classmethod
    async def interpret(cls, llm, tool: str, result: dict,
                        task_name: str) -> str:
        """GPT-4o interpreta el resultado de la tool."""
        user_msg = f"""Tarea: {task_name}
Herramienta ejecutada: {tool}
Resultado: {json.dumps(result, ensure_ascii=False)[:2000]}

Interpreta este resultado."""
        try:
            return await llm.ask(cls.INTERPRETER_SYSTEM, user_msg)
        except Exception as e:
            return f"Interpretación no disponible: {e}"


# ══════════════════════════════════════════════════════════════
# DYNAMIC AGENT v2.0
# ══════════════════════════════════════════════════════════════
class DynamicAgent(BaseAgent):
    """
    Agente genérico instanciado desde DB con razonamiento LLM real.

    Flujo:
      1. Recibe tarea
      2. Si tiene LLM → GPT-4o planifica (tool + params)
      3. Ejecuta la tool planificada
      4. GPT-4o interpreta el resultado
      5. Retorna resultado estructurado
    """

    def __init__(self, agent_config: dict, llm=None):
        role = agent_config.get("role", "general")
        # Todas las capabilities para que el Orchestrator siempre encuentre este agente
        all_caps = list(AgentCapability)

        metadata = AgentMetadata(
            name=agent_config["name"],
            capabilities=all_caps,
            model=agent_config.get("model", "gpt-4o"),
            timeout_seconds=300,
            max_concurrent=3,
            tags=[role, "dynamic", agent_config.get("provider", "openai")],
        )
        super().__init__(metadata=metadata)
        self._config = agent_config
        self._llm = llm
        self._tools = agent_config.get("tools", [])
        self._system_prompt = agent_config.get("system_prompt", "")
        self._role = role

    async def execute(self, task_id: str, payload: dict) -> dict:
        """
        Ejecuta la tarea con razonamiento LLM + interceptor HITL.
        Si la acción requiere aprobación, pausa y espera al humano.
        """
        task_name = payload.get("_task_name", f"task_{task_id[:8]}")
        task_desc = payload.get("_task_desc", "")

        # Limpiar metadatos del payload antes de pasar a tools
        clean_payload = {k: v for k, v in payload.items()
                        if not k.startswith("_")}

        # ── Modo 1: Tool especificada directamente ────────────
        tool_name = clean_payload.get("tool") or clean_payload.get("type")

        # Inferir tool del payload si no está especificada
        if not tool_name:
            if "command" in clean_payload or "cmd" in clean_payload:
                tool_name = "bash_exec"
            elif "url" in clean_payload:
                tool_name = "http_request"
            elif "code" in clean_payload:
                tool_name = "code_exec"
            elif "filepath" in clean_payload or ("path" in clean_payload and clean_payload.get("path")):
                tool_name = "file_read"

        # ── Modo 2: LLM planifica si no hay tool explícita ───
        llm_plan = None
        if not tool_name and self._llm:
            logger.info(f"[{self.name}] 🧠 GPT-4o planificando tarea: {task_name}")
            llm_plan = await LLMReasoningEngine.plan(
                llm=self._llm,
                task_name=task_name,
                task_desc=task_desc,
                payload=clean_payload,
                agent_tools=self._tools,
                system_prompt=self._system_prompt,
            )
            if llm_plan:
                tool_name = llm_plan.get("tool", "bash_exec")
                # Merge params del LLM con el payload original
                llm_params = llm_plan.get("params", {})
                clean_payload = {**clean_payload, **llm_params}
                logger.info(f"[{self.name}] 🧠 Plan: {tool_name} | {llm_plan.get('reasoning','')}")

        # Fallback final
        if not tool_name:
            if self._tools:
                tool_name = self._tools[0]
            else:
                tool_name = "bash_exec"
                clean_payload["command"] = (
                    f"echo 'NEXUS Agent {self.name} ejecutado' && "
                    f"date && echo 'Role: {self._role}'"
                )

        logger.info(f"[{self.name}] ⚡ Ejecutando: {tool_name} | task: {task_id}")

        # ── HITL Check — ¿requiere aprobación humana? ─────────
        hitl_mode = self._config.get("hitl_mode", "destructive")
        if hitl_mode != "never":
            try:
                from nexus_core.hitl.manager import get_hitl_manager, HITLManager
                hitl = get_hitl_manager()
                risk = HITLManager.evaluate_risk(tool_name, clean_payload, hitl_mode)
                if risk is not None:
                    context = (
                        f"Agente {self.name} ({self._role}) quiere ejecutar '{tool_name}'.\n"
                        f"Tarea: {task_name}\n"
                        f"Params: {str(clean_payload)[:300]}"
                    )
                    logger.warning(
                        f"[{self.name}] ⏸ HITL requerido [{risk}] para {tool_name}"
                    )
                    status = await hitl.request(
                        agent_name=self.name,
                        agent_id=self.metadata.agent_id,
                        action=f"{task_name} → {tool_name}",
                        tool=tool_name,
                        params=clean_payload,
                        risk=risk,
                        context=context,
                        timeout=300,
                    )
                    from nexus_core.hitl.manager import HITLStatus
                    if status != HITLStatus.APPROVED:
                        return {
                            "agent": self.name,
                            "tool_used": tool_name,
                            "task_id": task_id,
                            "status": "hitl_denied",
                            "hitl_status": str(status),
                            "message": f"Acción bloqueada por HITL: {status}",
                        }
            except Exception as hitl_err:
                logger.warning(f"[{self.name}] HITL error (continuando): {hitl_err}")

        # ── Ejecutar la tool ──────────────────────────────────
        tool_result = await ToolExecutor.execute_tool(
            tool_name, clean_payload, self._llm
        )

        # ── Interpretar resultado con LLM ─────────────────────
        interpretation = None
        if self._llm and tool_result.get("status") == "ok":
            try:
                interpretation = await LLMReasoningEngine.interpret(
                    llm=self._llm,
                    tool=tool_name,
                    result=tool_result,
                    task_name=task_name,
                )
            except Exception as e:
                logger.warning(f"[{self.name}] Interpretación fallida: {e}")

        return {
            "agent": self.name,
            "role": self._role,
            "model": self._config.get("model", "gpt-4o"),
            "tool_used": tool_name,
            "task_id": task_id,
            "llm_reasoning": llm_plan.get("reasoning") if llm_plan else None,
            "llm_interpretation": interpretation,
            **tool_result,
        }
```

### nexus_core/agents/generated/__init__.py — 0 líneas

```python

```

### nexus_core/agents/generated/bashagent.py — 86 líneas

```python
"""
BAJIOWARE NEXUS — BashAgent
Agente especializado en ejecución de comandos bash reales.
Junior lo usa para instalar paquetes, gestionar servicios, correr scripts.
"""
from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
import asyncio
import os
import re
from pathlib import Path
from nexus_core.config import NEXUS_ROOT

BASE_DIR = NEXUS_ROOT

HARD_BLOCKED = [
    r"rm\s+-rf\s+/\s*$",
    r"mkfs\.",
    r"dd\s+if=.*of=/dev/[sh]d",
    r":\(\)\{.*\}",   # fork bomb
]


class BashAgent(BaseAgent):
    """
    Agente de ejecución bash.
    
    Payload esperado:
    - command: comando bash a ejecutar
    - cwd: directorio de trabajo (default: NEXUS_ROOT)
    - timeout: segundos máximos (default: 60)
    - sudo: bool — usar sudo (default: False)
    """
    capability = AgentCapability.FILE_OPERATIONS

    async def execute(self, task_id: str, payload: dict) -> dict:
        from nexus_core.kernel.legacy import legacy_execution_enabled
        if not legacy_execution_enabled():
            return {
                "status": "failed",
                "error": "Legacy BashAgent is disabled; use ToolGateway with an OCI sandbox",
                "task_id": task_id,
            }
        command = payload.get("command", "").strip()
        cwd     = payload.get("cwd", str(BASE_DIR))
        timeout = payload.get("timeout", 60)
        use_sudo = payload.get("sudo", False)

        if not command:
            return {"status": "failed", "error": "command requerido", "task_id": task_id}

        # Bloquear comandos destructivos
        for pattern in HARD_BLOCKED:
            if re.search(pattern, command, re.IGNORECASE):
                return {"status": "failed",
                        "error": f"Comando bloqueado por seguridad: {pattern}",
                        "task_id": task_id}

        if use_sudo:
            command = f"sudo {command}"

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env={**os.environ, "HOME": str(Path.home()), "USER": os.getenv("USER", "operator")},
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out = stdout.decode("utf-8", errors="replace").strip()
            err = stderr.decode("utf-8", errors="replace").strip()
            success = proc.returncode == 0

            return {
                "status": "completed" if success else "failed",
                "task_id": task_id,
                "returncode": proc.returncode,
                "output": out,
                "stderr": err if err else None,
                "command": command[:100],
            }

        except asyncio.TimeoutError:
            return {"status": "failed", "error": f"Timeout {timeout}s", "task_id": task_id}
        except Exception as e:
            return {"status": "failed", "error": str(e), "task_id": task_id}
```

### nexus_core/agents/generated/codeagent.py — 158 líneas

```python
"""
BAJIOWARE NEXUS — CodeAgent
Agente especializado en análisis, modificación y validación de código Python.
Junior lo usa para refactorizar, agregar features y validar sintaxis antes de escribir.
"""
from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
import asyncio
import ast
import os
from pathlib import Path
from nexus_core.config import NEXUS_ROOT

BASE_DIR = NEXUS_ROOT


class CodeAgent(BaseAgent):
    """
    Agente de operaciones de código.
    
    Payload esperado:
    - action: "validate" | "analyze" | "patch" | "search" | "generate"
    - filepath: ruta del archivo Python
    - code: código a validar/patchear
    - old_text: texto a reemplazar (para patch)
    - new_text: texto nuevo (para patch)
    - query: búsqueda en código (para search)
    - prompt: instrucción para generate (usa LLM)
    """
    capability = AgentCapability.CODE_GENERATION

    async def execute(self, task_id: str, payload: dict) -> dict:
        from nexus_core.kernel.legacy import require_legacy_execution
        require_legacy_execution()
        action   = payload.get("action", "validate")
        filepath = payload.get("filepath", "")
        code     = payload.get("code", "")

        try:
            if action == "validate":
                # Validar sintaxis Python
                target = code or (Path(filepath).read_text() if filepath else "")
                if not target:
                    return {"status": "failed", "error": "Se requiere code o filepath", "task_id": task_id}
                try:
                    ast.parse(target)
                    return {"status": "completed", "task_id": task_id,
                            "valid": True, "result": "Sintaxis OK"}
                except SyntaxError as e:
                    return {"status": "completed", "task_id": task_id,
                            "valid": False, "error": str(e)}

            elif action == "patch":
                # Reemplazar texto en archivo
                old_text = payload.get("old_text", "")
                new_text = payload.get("new_text", "")
                path = Path(filepath) if Path(filepath).is_absolute() else BASE_DIR / filepath
                if not path.exists():
                    return {"status": "failed", "error": f"No existe: {path}", "task_id": task_id}
                content = path.read_text(encoding="utf-8")
                if old_text not in content:
                    return {"status": "failed", "error": "old_text no encontrado en archivo",
                            "task_id": task_id}
                new_content = content.replace(old_text, new_text, 1)
                # Validar sintaxis si es .py
                if path.suffix == ".py":
                    try:
                        ast.parse(new_content)
                    except SyntaxError as e:
                        return {"status": "failed", "error": f"Sintaxis inválida tras patch: {e}",
                                "task_id": task_id}
                path.write_text(new_content, encoding="utf-8")
                # PEV — verificación post-patch
                verified = path.read_text(encoding="utf-8")
                if new_text in verified and old_text not in verified:
                    return {"status": "completed", "task_id": task_id,
                            "result": f"Patch aplicado y verificado en {path}",
                            "lines_before": len(content.splitlines()),
                            "lines_after": len(new_content.splitlines())}
                else:
                    return {"status": "failed", "task_id": task_id,
                            "error": f"PEV: patch no verificado en {path}"}

            elif action == "search":
                # Buscar en código
                import subprocess
                query   = payload.get("query", "")
                pattern = payload.get("file_pattern", "*.py")
                search_path = payload.get("search_path", str(BASE_DIR))
                if not query:
                    return {"status": "failed", "error": "query requerido", "task_id": task_id}
                proc = await asyncio.create_subprocess_shell(
                    f"grep -rn --include='{pattern}' '{query}' {search_path} 2>/dev/null | head -30",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode("utf-8", errors="replace").strip()
                output = output.replace(str(BASE_DIR) + "/", "")
                return {"status": "completed", "task_id": task_id,
                        "result": output or "(sin resultados)", "query": query}

            elif action == "analyze":
                # Leer archivo y analizarlo con LLM
                path = Path(filepath) if Path(filepath).is_absolute() else BASE_DIR / filepath
                if not path.exists():
                    return {"status": "failed", "error": f"No existe: {path}", "task_id": task_id}
                content = path.read_text(encoding="utf-8", errors="replace")
                prompt  = payload.get("prompt", "Analiza este código e identifica mejoras y bugs:")
                # Usar Gemini via JuniorAgent
                from nexus_core.agents.junior_agent import JuniorAgent
                agent = JuniorAgent()
                result = await agent.run(task_id + "_llm", {
                    "type": "llm_query",
                    "prompt": f"{prompt}\n\nArchivo: {filepath}\n\n```python\n{content[:6000]}\n```"
                })
                return {"status": "completed", "task_id": task_id,
                        "filepath": str(path),
                        "analysis": result.get("result", {}).get("response", ""),
                        "lines_analyzed": len(content.splitlines())}

            elif action == "generate":
                # Generar código nuevo con LLM
                prompt = payload.get("prompt", "")
                if not prompt:
                    return {"status": "failed", "error": "prompt requerido", "task_id": task_id}
                from nexus_core.agents.junior_agent import JuniorAgent
                agent = JuniorAgent()
                result = await agent.run(task_id + "_gen", {
                    "type": "llm_query",
                    "system_prompt": "Eres un experto en Python y FastAPI. Genera SOLO código, sin explicaciones. El código debe ser funcional y estar listo para usar.",
                    "prompt": prompt,
                })
                generated = result.get("result", {}).get("response", "")
                # Si hay filepath, escribir el archivo
                if filepath and generated:
                    path = Path(filepath) if Path(filepath).is_absolute() else BASE_DIR / filepath
                    # Limpiar markdown si viene con ```python
                    import re
                    clean = re.sub(r"```(?:python)?\s*|\s*```", "", generated).strip()
                    # Validar sintaxis
                    try:
                        ast.parse(clean)
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(clean, encoding="utf-8")
                        return {"status": "completed", "task_id": task_id,
                                "result": f"Código generado y guardado en {path}",
                                "lines": len(clean.splitlines())}
                    except SyntaxError as e:
                        return {"status": "failed", "task_id": task_id,
                                "error": f"Código generado tiene errores de sintaxis: {e}",
                                "generated_code": generated[:500]}
                return {"status": "completed", "task_id": task_id,
                        "result": generated}

            else:
                return {"status": "failed", "error": f"Acción desconocida: {action}", "task_id": task_id}

        except Exception as e:
            return {"status": "failed", "error": str(e), "task_id": task_id}
```

### nexus_core/agents/generated/dataanalysisagent.py — 70 líneas

```python
from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
import asyncio
import json

class DataAnalysisAgent(BaseAgent):
    """
    An AI agent specialized in performing various data analysis tasks on structured data.
    """
    capability = AgentCapability.DATA_ANALYSIS

    async def execute(self, task_id: str, payload: dict) -> dict:
        """
        Executes a data analysis task based on the provided payload.

        The payload must contain:
        - 'data': A list of dictionaries or a dictionary of lists (pandas DataFrame compatible).
        - 'analysis_type': The type of analysis to perform. Supported types are:
            - 'summary': Computes descriptive statistics (mean, std, etc.).
            - 'correlation': Computes the pairwise correlation of columns.
            - 'value_counts': Computes frequency counts for a specified column.
                              Requires an additional 'column' key in the payload.

        Args:
            task_id: The unique identifier for the task.
            payload: A dictionary containing the data and analysis parameters.

        Returns:
            A dictionary with the status and results of the analysis.
        """
        try:
            # Assuming necessary libraries like pandas and asyncio are available in the environment
            import pandas as pd
            import asyncio

            if 'data' not in payload or 'analysis_type' not in payload:
                raise ValueError("Payload must contain 'data' and 'analysis_type' keys.")

            df = pd.DataFrame(payload['data'])
            analysis_type = payload['analysis_type']

            if df.empty:
                raise ValueError("Input data cannot be empty.")

            # Simulate I/O or CPU-bound work for an async agent
            await asyncio.sleep(0.1)

            analysis_result = None
            if analysis_type == 'summary':
                analysis_result = df.describe().to_dict()
            elif analysis_type == 'correlation':
                # Ensure we only try to correlate numeric columns
                numeric_df = df.select_dtypes(include='number')
                if numeric_df.shape[1] < 2:
                    analysis_result = {"message": "Correlation requires at least two numeric columns."}
                else:
                    analysis_result = numeric_df.corr().to_dict()
            elif analysis_type == 'value_counts':
                if 'column' not in payload:
                    raise ValueError("Payload must specify a 'column' for 'value_counts' analysis.")
                column = payload['column']
                if column not in df.columns:
                    raise ValueError(f"Column '{column}' not found in the provided data.")
                analysis_result = df[column].value_counts().to_dict()
            else:
                raise ValueError(f"Unsupported analysis type: '{analysis_type}'.")

            return {"status": "completed", "results": analysis_result, "task_id": task_id}

        except Exception as e:
            return {"status": "failed", "results": str(e), "task_id": task_id}
```

### nexus_core/agents/generated/doc_agent.py — 252 líneas

```python
"""
DocAgent v1.0 — Memoria Técnica de BajioWare
Documenta incidentes, soluciones y lecciones en ChromaDB y SQLite.
El DocAgent es la memoria viva del sistema.
"""
import sqlite3
import json
import uuid
import subprocess
from datetime import datetime
from pathlib import Path
from nexus_core.config import NEXUS_ROOT, NEXUS_DATA_PATH, CHROMA_PATH as CONFIG_CHROMA_PATH, LEGACY_DATABASE_PATH

BASE_DIR = NEXUS_ROOT
DB_PATH = LEGACY_DATABASE_PATH
DOCS_DIR = NEXUS_DATA_PATH / "docs"
CHROMA_PATH = str(CONFIG_CHROMA_PATH)
DOCS_DIR.mkdir(parents=True, exist_ok=True)


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS technical_docs (
            doc_id TEXT PRIMARY KEY,
            doc_type TEXT,
            title TEXT,
            content TEXT,
            tags TEXT,
            project_id TEXT,
            related_incident TEXT,
            related_commit TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incident_reports (
            report_id TEXT PRIMARY KEY,
            incident_id TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            root_cause TEXT,
            solution TEXT,
            prevention TEXT,
            status TEXT DEFAULT 'open',
            assigned_to TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def document_incident(incident_id: str, title: str, description: str,
                      severity: str = "medium", root_cause: str = "",
                      solution: str = "", prevention: str = "") -> dict:
    """Documenta un incidente de seguridad o error del sistema."""
    _init_db()
    report_id = f"rpt_{uuid.uuid4().hex[:8]}"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO incident_reports
           (report_id, incident_id, severity, title, description, root_cause, solution, prevention)
           VALUES (?,?,?,?,?,?,?,?)""",
        (report_id, incident_id, severity, title, description, root_cause, solution, prevention)
    )
    conn.commit()
    conn.close()

    # Guardar también como archivo markdown
    doc_path = DOCS_DIR / f"incident_{report_id}.md"
    doc_content = f"""# Reporte de Incidente: {title}
**ID:** {report_id}
**Severidad:** {severity}
**Fecha:** {datetime.utcnow().isoformat()}

## Descripción
{description}

## Causa Raíz
{root_cause or "En investigación"}

## Solución Aplicada
{solution or "Pendiente"}

## Prevención Futura
{prevention or "Por definir"}
"""
    doc_path.write_text(doc_content)

    # Indexar en ChromaDB para búsqueda semántica
    _index_in_memory(report_id, f"Incidente: {title}\n{description}\n{solution}",
                     {"type": "incident", "severity": severity, "id": report_id})

    return {
        "report_id": report_id,
        "saved": True,
        "doc_path": str(doc_path),
        "indexed_in_memory": True,
    }


def document_solution(title: str, problem: str, solution: str,
                      tags: list = None, project_id: str = "general",
                      related_commit: str = "") -> dict:
    """Documenta una solución para reutilización futura."""
    _init_db()
    doc_id = f"doc_{uuid.uuid4().hex[:8]}"
    tags_str = json.dumps(tags or [])
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO technical_docs
           (doc_id, doc_type, title, content, tags, project_id, related_commit)
           VALUES (?,?,?,?,?,?,?)""",
        (doc_id, "solution", title, f"PROBLEMA:\n{problem}\n\nSOLUCION:\n{solution}",
         tags_str, project_id, related_commit)
    )
    conn.commit()
    conn.close()

    # Guardar markdown
    doc_path = DOCS_DIR / f"solution_{doc_id}.md"
    doc_path.write_text(f"""# Solución: {title}
**ID:** {doc_id}
**Tags:** {", ".join(tags or [])}
**Commit:** {related_commit}
**Fecha:** {datetime.utcnow().isoformat()}

## Problema
{problem}

## Solución
{solution}
""")

    # Indexar en ChromaDB
    _index_in_memory(doc_id, f"Solución: {title}\nProblema: {problem}\nSolución: {solution}",
                     {"type": "solution", "tags": tags_str, "id": doc_id})

    return {"doc_id": doc_id, "saved": True, "doc_path": str(doc_path)}


def analyze_incidents_with_llm(limit: int = 14) -> dict:
    """Analiza los incidentes recientes y genera un reporte ejecutivo."""
    _init_db()
    # Obtener incidentes de seguridad
    conn = sqlite3.connect(DB_PATH)
    incidents = conn.execute(
        """SELECT id, severity, title, description, file_path, created_at
           FROM security_incidents ORDER BY created_at DESC LIMIT ?""",
        (limit,)
    ).fetchall()
    conn.close()

    if not incidents:
        return {"message": "No hay incidentes registrados", "total": 0}

    # Clasificar por severidad
    high = [i for i in incidents if i[1] == "HIGH"]
    medium = [i for i in incidents if i[1] == "MEDIUM"]
    low = [i for i in incidents if i[1] == "LOW"]

    # Agrupar por tipo
    by_type = {}
    for inc in incidents:
        t = inc[2]
        if t not in by_type:
            by_type[t] = []
        by_type[t].append({"id": inc[0], "file": inc[3] if len(inc) > 3 else "", "date": inc[4] if len(inc) > 4 else ""})

    # Generar reporte
    report = {
        "total": len(incidents),
        "by_severity": {"HIGH": len(high), "MEDIUM": len(medium), "LOW": len(low)},
        "by_type": {k: len(v) for k, v in by_type.items()},
        "top_affected_files": list(set([i[4] for i in incidents if i[4]])),
        "recommendations": [],
        "incidents": [{"id": i[0], "severity": i[1], "title": i[2],
                       "file": i[4], "date": i[5]} for i in incidents],
    }

    # Agregar recomendaciones basadas en patrones
    if len(high) > 0:
        report["recommendations"].append({
            "priority": "CRÍTICA",
            "action": f"Resolver {len(high)} incidentes de severidad HIGH inmediatamente",
            "affected": list(set([i[3] if len(i) > 3 else "" for i in high])),
        })
    if "Hardcoded secret_key" in by_type:
        report["recommendations"].append({
            "priority": "ALTA",
            "action": "Mover todas las SECRET_KEY a variables de entorno (.env)",
            "affected": list(set([i.get("file","") for i in by_type.get("Hardcoded secret_key", [])])),
        })

    # Guardar reporte
    doc_id = f"rpt_{uuid.uuid4().hex[:8]}"
    report_path = DOCS_DIR / f"incident_analysis_{doc_id}.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    report["report_saved"] = str(report_path)

    return report


def search_similar_solutions(query: str, limit: int = 5) -> list:
    """Busca soluciones similares en la memoria técnica."""
    try:
        import chromadb
        client = chromadb.PersistentClient(path=CHROMA_PATH)
        try:
            col = client.get_collection("technical_knowledge")
            results = col.query(query_texts=[query], n_results=limit)
            docs = results.get("documents", [[]])[0]
            metas = results.get("metadatas", [[]])[0]
            return [{"content": d[:500], "meta": m} for d, m in zip(docs, metas)]
        except Exception:
            return []
    except Exception as e:
        return [{"error": str(e)}]


def _index_in_memory(doc_id: str, content: str, metadata: dict):
    """Indexa documento en ChromaDB."""
    try:
        import chromadb
        client = chromadb.PersistentClient(path=CHROMA_PATH)
        col = client.get_or_create_collection("technical_knowledge")
        col.add(documents=[content], metadatas=[metadata], ids=[doc_id])
    except Exception:
        pass


def get_recent_docs(doc_type: str = None, limit: int = 10) -> list:
    """Obtiene documentos técnicos recientes."""
    _init_db()
    conn = sqlite3.connect(DB_PATH)
    if doc_type:
        rows = conn.execute(
            "SELECT doc_id, doc_type, title, tags, project_id, created_at FROM technical_docs WHERE doc_type=? ORDER BY created_at DESC LIMIT ?",
            (doc_type, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT doc_id, doc_type, title, tags, project_id, created_at FROM technical_docs ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    return [{"doc_id": r[0], "type": r[1], "title": r[2], "tags": json.loads(r[3] or "[]"),
             "project_id": r[4], "created_at": r[5]} for r in rows]
```

### nexus_core/agents/generated/fileagent.py — 92 líneas

```python
"""
BAJIOWARE NEXUS — FileAgent
Agente especializado en operaciones de archivos del sistema.
Junior lo usa para escribir, leer, editar y borrar archivos reales.
"""
from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
import asyncio
from pathlib import Path
from nexus_core.config import NEXUS_ROOT


class FileAgent(BaseAgent):
    """
    Agente de operaciones de archivos.
    
    Payload esperado:
    - action: "write" | "read" | "append" | "delete" | "chmod" | "mkdir" | "exists"
    - filepath: ruta absoluta o relativa al archivo
    - content: contenido a escribir (para write/append)
    - mode: permisos chmod (ej: "755")
    """
    capability = AgentCapability.FILE_OPERATIONS

    async def execute(self, task_id: str, payload: dict) -> dict:
        from nexus_core.kernel.legacy import require_legacy_execution
        require_legacy_execution()
        action   = payload.get("action", "write")
        filepath = payload.get("filepath", "")
        content  = payload.get("content", "")
        mode     = payload.get("mode", "644")

        if not filepath:
            return {"status": "failed", "error": "filepath requerido", "task_id": task_id}

        try:
            path = Path(filepath) if Path(filepath).is_absolute() else NEXUS_ROOT / filepath

            if action == "write":
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                # PEV — verificación post-escritura
                written = path.read_text(encoding="utf-8")
                if written == content:
                    return {"status": "completed", "task_id": task_id,
                            "result": f"Archivo escrito y verificado: {path} ({len(content)} bytes)"}
                else:
                    return {"status": "failed", "task_id": task_id,
                            "error": f"PEV: contenido no coincide tras escritura en {path}"}

            elif action == "read":
                if not path.exists():
                    return {"status": "failed", "error": f"No existe: {path}", "task_id": task_id}
                text = path.read_text(encoding="utf-8", errors="replace")
                return {"status": "completed", "task_id": task_id,
                        "result": text[:5000], "lines": len(text.splitlines())}

            elif action == "append":
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "a", encoding="utf-8") as f:
                    f.write(content)
                return {"status": "completed", "task_id": task_id,
                        "result": f"Contenido añadido a {path}"}

            elif action == "delete":
                if path.exists():
                    path.unlink()
                    return {"status": "completed", "task_id": task_id,
                            "result": f"Eliminado: {path}"}
                return {"status": "completed", "task_id": task_id,
                        "result": f"No existía: {path}"}

            elif action == "chmod":
                import stat, os
                perm = int(mode, 8)
                os.chmod(path, perm)
                return {"status": "completed", "task_id": task_id,
                        "result": f"Permisos {mode} aplicados a {path}"}

            elif action == "mkdir":
                path.mkdir(parents=True, exist_ok=True)
                return {"status": "completed", "task_id": task_id,
                        "result": f"Directorio creado: {path}"}

            elif action == "exists":
                return {"status": "completed", "task_id": task_id,
                        "exists": path.exists(), "path": str(path)}

            else:
                return {"status": "failed", "error": f"Acción desconocida: {action}", "task_id": task_id}

        except Exception as e:
            return {"status": "failed", "error": str(e), "task_id": task_id}
```

### nexus_core/agents/generated/guardian_agent.py — 138 líneas

```python
"""
GuardianAgent v1.0 — Seguridad continua BajioWare
"""
import subprocess, sqlite3, json, os, re, uuid
from datetime import datetime
from pathlib import Path
from nexus_core.config import NEXUS_ROOT, LEGACY_DATABASE_PATH

BASE_DIR = NEXUS_ROOT
DB_PATH = LEGACY_DATABASE_PATH

HARDCODED_PATTERNS = [
    (r"password\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded password"),
    (r"secret_key\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded secret_key"),
    (r"api_key\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded API key"),
]


def init_incidents_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_incidents (
            id TEXT PRIMARY KEY,
            severity TEXT,
            title TEXT,
            description TEXT,
            file_path TEXT,
            line_number INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'open'
        )
    """)
    conn.commit()
    conn.close()


def save_incident(severity, title, description, file_path="", line_number=0):
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR IGNORE INTO security_incidents (id, severity, title, description, file_path, line_number) VALUES (?,?,?,?,?,?)",
        (incident_id, severity, title, description, file_path, line_number)
    )
    conn.commit()
    conn.close()
    return incident_id


def scan_for_secrets(directory=None):
    directory = Path(directory or BASE_DIR)
    skip = {"venv", "__pycache__", ".git", "node_modules"}
    incidents = []
    for f in directory.rglob("*.py"):
        if any(s in str(f) for s in skip):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            for pattern, title in HARDCODED_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    # Ignorar si usa getenv
                    if "getenv" in match.group() or "os.environ" in match.group():
                        continue
                    line_num = content[:match.start()].count("\n") + 1
                    rel_path = str(f).replace(str(BASE_DIR) + "/", "")
                    inc_id = save_incident("HIGH", title, f"Posible secreto: {match.group()[:50]}", rel_path, line_num)
                    incidents.append({"id": inc_id, "file": rel_path, "line": line_num, "type": title})
        except Exception:
            pass
    return incidents


def run_bandit_scan(directory=None):
    target = str(directory or BASE_DIR / "nexus_api")
    try:
        result = subprocess.run(
            f"bandit -r {target} -f json -q",
            shell=True, capture_output=True, text=True, timeout=60
        )
        try:
            data = json.loads(result.stdout)
            results_list = data.get("results", [])
            high = [r for r in results_list if r.get("issue_severity") == "HIGH"]
            for issue in high[:10]:
                save_incident("HIGH", issue.get("test_name", "Bandit"), issue.get("issue_text", ""),
                             issue.get("filename", "").replace(str(BASE_DIR) + "/", ""), issue.get("line_number", 0))
            return {"high": len(high), "medium": len([r for r in results_list if r.get("issue_severity") == "MEDIUM"]), "total": len(results_list)}
        except json.JSONDecodeError:
            return {"error": "bandit output invalid", "raw": result.stdout[:200]}
    except Exception as e:
        return {"error": str(e)}


def scan_recent_commits(n_commits=5):
    try:
        result = subprocess.run(
            f"git -C {BASE_DIR} log --oneline -{n_commits} --name-only",
            shell=True, capture_output=True, text=True
        )
        changed_files = [l.strip() for l in result.stdout.split("\n") if l.strip().endswith(".py")]
        incidents = []
        for f in set(changed_files):
            full_path = BASE_DIR / f
            if full_path.exists():
                content = full_path.read_text(encoding="utf-8", errors="replace")
                for pattern, title in HARDCODED_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        inc_id = save_incident("HIGH", f"[GIT] {title}", f"En commit reciente: {f}", f)
                        incidents.append({"id": inc_id, "file": f, "type": title})
        return {"files_scanned": len(set(changed_files)), "incidents": incidents}
    except Exception as e:
        return {"error": str(e)}


def get_open_incidents():
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            "SELECT id, severity, title, file_path, line_number, created_at FROM security_incidents WHERE status='open' ORDER BY created_at DESC LIMIT 20"
        ).fetchall()
        conn.close()
        return [{"id": r[0], "severity": r[1], "title": r[2], "file": r[3], "line": r[4], "date": r[5]} for r in rows]
    except Exception:
        return []


def full_security_scan():
    init_incidents_table()
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "secrets": scan_for_secrets(),
        "bandit": run_bandit_scan(),
        "commits": scan_recent_commits(),
        "open_incidents": len(get_open_incidents()),
    }


if __name__ == "__main__":
    print(json.dumps(full_security_scan(), indent=2, ensure_ascii=False))
```

### nexus_core/agents/generated/kill_switch_agent.py — 166 líneas

```python
"""
KillSwitchAgent v1.0 — Caja de Seguridad de BajioWare
Intercepta operaciones críticas y requiere aprobación humana.
"""
import sqlite3
import json
import uuid
from datetime import datetime
from pathlib import Path
from nexus_core.config import NEXUS_ROOT, LEGACY_DATABASE_PATH

BASE_DIR = NEXUS_ROOT
DB_PATH = LEGACY_DATABASE_PATH

# Operaciones que SIEMPRE requieren aprobación humana
CRITICAL_OPERATIONS = {
    "modify_core": ["fase8b_junior.py", "fase8c_junior_tools.py", "nexus_api/main.py"],
    "modify_auth": ["auth/security.py", "auth/dependencies.py"],
    "deploy_production": ["systemctl", "gunicorn", "nginx"],
    "delete_data": ["DROP TABLE", "DELETE FROM", "rm -rf"],
    "modify_agents": ["nexus_core/agents", "nexus_core/llm"],
    "financial": ["payment", "billing", "stripe"],
}

# Operaciones que NUNCA se pueden ejecutar aunque se aprueben
BLACKLIST = [
    "rm -rf /",
    "DROP DATABASE",
    "DELETE FROM users",
    "mkfs",
    "dd if=",
]

_kill_switch_active = False


def is_blacklisted(operation: str) -> bool:
    """Verifica si una operación está en la lista negra."""
    op_lower = operation.lower()
    return any(b.lower() in op_lower for b in BLACKLIST)


def is_critical(operation_type: str, target: str = "") -> dict:
    """Determina si una operación es crítica y requiere aprobación."""
    if is_blacklisted(target):
        return {"critical": True, "blocked": True, "reason": "Operación en lista negra"}

    for category, patterns in CRITICAL_OPERATIONS.items():
        for pattern in patterns:
            if pattern.lower() in target.lower():
                return {
                    "critical": True,
                    "blocked": False,
                    "category": category,
                    "reason": f"Afecta componente crítico: {pattern}",
                }

    return {"critical": False, "blocked": False}


def request_approval(operation_type: str, description: str, payload: dict,
                     risk_level: str = "high") -> dict:
    """Registra una operación crítica para aprobación humana."""
    op_id = f"op_{uuid.uuid4().hex[:8]}"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO critical_operations
           (op_id, operation_type, description, payload, risk_level)
           VALUES (?,?,?,?,?)""",
        (op_id, operation_type, description, json.dumps(payload), risk_level)
    )
    conn.commit()
    conn.close()
    return {
        "op_id": op_id,
        "status": "pending_approval",
        "message": f"⚠️ Operación crítica registrada. Marcos debe aprobar con POST /killswitch/approve/{op_id}",
        "risk_level": risk_level,
    }


def approve_operation(op_id: str, approved_by: str = "marcos") -> dict:
    """Aprueba una operación crítica pendiente."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT * FROM critical_operations WHERE op_id=?", (op_id,)
    ).fetchone()
    if not row:
        conn.close()
        return {"success": False, "error": "Operación no encontrada"}
    if row[5] != "pending_approval":
        conn.close()
        return {"success": False, "error": f"Estado actual: {row[5]}"}
    conn.execute(
        "UPDATE critical_operations SET status='approved', approved_at=?, approved_by=? WHERE op_id=?",
        (datetime.utcnow().isoformat(), approved_by, op_id)
    )
    conn.commit()
    conn.close()
    return {"success": True, "op_id": op_id, "status": "approved", "approved_by": approved_by}


def reject_operation(op_id: str, reason: str = "") -> dict:
    """Rechaza una operación crítica."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE critical_operations SET status='rejected', result=? WHERE op_id=?",
        (reason, op_id)
    )
    conn.commit()
    conn.close()
    return {"success": True, "op_id": op_id, "status": "rejected"}


def get_pending_operations() -> list:
    """Obtiene operaciones pendientes de aprobación."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        """SELECT op_id, operation_type, description, risk_level, created_at
           FROM critical_operations WHERE status='pending_approval'
           ORDER BY created_at DESC"""
    ).fetchall()
    conn.close()
    return [{"op_id": r[0], "type": r[1], "description": r[2],
             "risk": r[3], "created_at": r[4]} for r in rows]


def activate_emergency_stop(reason: str, triggered_by: str = "system") -> dict:
    """Activa el Kill Switch de emergencia — detiene todas las operaciones."""
    global _kill_switch_active
    _kill_switch_active = True
    log_id = f"ks_{uuid.uuid4().hex[:8]}"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO kill_switch_log (id, action, triggered_by, reason) VALUES (?,?,?,?)",
        (log_id, "EMERGENCY_STOP", triggered_by, reason)
    )
    conn.execute(
        "UPDATE critical_operations SET status='cancelled' WHERE status='pending_approval'"
    )
    conn.commit()
    conn.close()
    return {
        "kill_switch": "ACTIVATED",
        "log_id": log_id,
        "reason": reason,
        "message": "🚨 KILL SWITCH ACTIVADO — Todas las operaciones detenidas",
    }


def deactivate_emergency_stop(authorized_by: str = "marcos") -> dict:
    """Desactiva el Kill Switch."""
    global _kill_switch_active
    _kill_switch_active = False
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO kill_switch_log (id, action, triggered_by, reason) VALUES (?,?,?,?)",
        (f"ks_{uuid.uuid4().hex[:8]}", "DEACTIVATE", authorized_by, "Manual deactivation")
    )
    conn.commit()
    conn.close()
    return {"kill_switch": "DEACTIVATED", "authorized_by": authorized_by}


def is_active() -> bool:
    return _kill_switch_active
```

### nexus_core/agents/generated/loganalyzeragent.py — 18 líneas

```python

import asyncio
from nexus_core.agents.base import BaseAgent


class LogAnalyzerAgent(BaseAgent):

    async def execute(self, task_id, payload):

        # Simulación de procesamiento
        await asyncio.sleep(1)

        return {
            "agent": "LogAnalyzerAgent",
            "task_id": task_id,
            "status": "completed",
            "result": "dynamic agent executed"
        }
```

### nexus_core/agents/generated/plan_agent.py — 214 líneas

```python
"""
PlanAgent v1.0 — Junior propone planes, Marcos aprueba UNA vez, Junior ejecuta todo.
Este es el núcleo de la libertad controlada.
"""
import sqlite3
import json
import uuid
import asyncio
import httpx
from datetime import datetime
from pathlib import Path
from nexus_core.config import NEXUS_ROOT, LEGACY_DATABASE_PATH

BASE_DIR = NEXUS_ROOT
DB_PATH = LEGACY_DATABASE_PATH


def create_plan(title: str, objective: str, steps: list,
                risk_level: str = "low", affects_core: bool = False) -> dict:
    """Junior crea un plan completo para aprobación."""
    plan_id = f"plan_{uuid.uuid4().hex[:8]}"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO junior_plans
           (plan_id, title, objective, steps, risk_level, affects_core)
           VALUES (?,?,?,?,?,?)""",
        (plan_id, title, objective, json.dumps(steps),
         risk_level, 1 if affects_core else 0)
    )
    conn.commit()
    conn.close()

    # Si afecta core, también registrar en kill switch
    if affects_core:
        try:
            import httpx as _httpx
            _httpx.post(
                "http://127.0.0.1:8000/killswitch/request",
                json={"operation_type": "plan_execution",
                      "description": f"Plan: {title}",
                      "payload": {"plan_id": plan_id},
                      "risk_level": risk_level},
                timeout=5.0
            )
        except Exception:
            pass

    return {
        "plan_id": plan_id,
        "title": title,
        "objective": objective,
        "steps": steps,
        "risk_level": risk_level,
        "affects_core": affects_core,
        "status": "pending_review",
        "message": f"Plan registrado. Marcos debe aprobar: POST /plans/approve/{plan_id}",
        "preview_url": f"GET /plans/{plan_id}",
    }


def approve_plan(plan_id: str, approved_by: str = "marcos") -> dict:
    """Marcos aprueba un plan — Junior ejecutará todos los pasos."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT * FROM junior_plans WHERE plan_id=?", (plan_id,)
    ).fetchone()
    if not row:
        conn.close()
        return {"success": False, "error": "Plan no encontrado"}
    if row[7] != "pending_review":
        conn.close()
        return {"success": False, "error": f"Estado actual: {row[7]}"}
    conn.execute(
        "UPDATE junior_plans SET status='approved', reviewed_at=?, approved_by=? WHERE plan_id=?",
        (datetime.utcnow().isoformat(), approved_by, plan_id)
    )
    conn.commit()
    conn.close()
    return {
        "success": True,
        "plan_id": plan_id,
        "status": "approved",
        "message": "Plan aprobado. Junior puede ejecutar todos los pasos.",
    }


def reject_plan(plan_id: str, reason: str = "") -> dict:
    """Marcos rechaza un plan."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE junior_plans SET status='rejected', execution_log=? WHERE plan_id=?",
        (f"Rechazado: {reason}", plan_id)
    )
    conn.commit()
    conn.close()
    return {"success": True, "plan_id": plan_id, "status": "rejected"}


def get_plan(plan_id: str) -> dict:
    """Obtiene detalles de un plan."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT * FROM junior_plans WHERE plan_id=?", (plan_id,)
    ).fetchone()
    conn.close()
    if not row:
        return {"error": "Plan no encontrado"}
    steps = json.loads(row[3] or "[]")
    return {
        "plan_id": row[0], "title": row[1], "objective": row[2],
        "steps": steps, "risk_level": row[4],
        "affects_core": bool(row[5]), "status": row[6],
        "created_at": row[7], "approved_by": row[9],
        "execution_log": row[10],
        "total_steps": len(steps),
    }


def get_pending_plans() -> list:
    """Obtiene planes pendientes de aprobación."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        """SELECT plan_id, title, objective, risk_level, affects_core, created_at
           FROM junior_plans WHERE status='pending_review'
           ORDER BY created_at DESC"""
    ).fetchall()
    conn.close()
    return [{
        "plan_id": r[0], "title": r[1], "objective": r[2],
        "risk": r[3], "affects_core": bool(r[4]), "created_at": r[5]
    } for r in rows]


async def execute_approved_plan(plan_id: str) -> dict:
    """Ejecuta un plan aprobado paso a paso."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT * FROM junior_plans WHERE plan_id=?", (plan_id,)
    ).fetchone()
    if not row or row[6] != "approved":
        conn.close()
        return {"success": False, "error": f"Plan no aprobado o no encontrado"}

    steps = json.loads(row[3] or "[]")
    conn.execute(
        "UPDATE junior_plans SET status='executing' WHERE plan_id=?", (plan_id,)
    )
    conn.commit()
    conn.close()

    execution_log = []
    success_count = 0
    fail_count = 0

    async with httpx.AsyncClient(timeout=60.0) as client:
        for i, step in enumerate(steps):
            step_name = step.get("name", f"Step {i+1}")
            capability = step.get("capability", "file_operations")
            payload = step.get("payload", {})

            try:
                resp = await client.post(
                    "http://127.0.0.1:8000/junior/dispatch",
                    json={"task_name": step_name, "payload": payload,
                          "capability": capability}
                )
                result = resp.json()
                success = result.get("success", False)
                if success:
                    success_count += 1
                else:
                    fail_count += 1
                execution_log.append({
                    "step": step_name, "status": "ok" if success else "fail",
                    "result": str(result.get("result", ""))[:200]
                })
            except Exception as e:
                fail_count += 1
                execution_log.append({"step": step_name, "status": "error", "error": str(e)})

    final_status = "completed" if fail_count == 0 else "completed_with_errors"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE junior_plans SET status=?, execution_log=? WHERE plan_id=?",
        (final_status, json.dumps(execution_log), plan_id)
    )
    conn.commit()
    conn.close()

    return {
        "plan_id": plan_id,
        "status": final_status,
        "steps_total": len(steps),
        "steps_ok": success_count,
        "steps_failed": fail_count,
        "execution_log": execution_log,
    }


def list_plans(status: str = None) -> list:
    """Lista todos los planes."""
    conn = sqlite3.connect(DB_PATH)
    if status:
        rows = conn.execute(
            "SELECT plan_id, title, risk_level, affects_core, status, created_at FROM junior_plans WHERE status=? ORDER BY created_at DESC",
            (status,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT plan_id, title, risk_level, affects_core, status, created_at FROM junior_plans ORDER BY created_at DESC LIMIT 20"
        ).fetchall()
    conn.close()
    return [{"plan_id": r[0], "title": r[1], "risk": r[2],
             "affects_core": bool(r[3]), "status": r[4], "created_at": r[5]} for r in rows]
```

### nexus_core/agents/generated/project_manager_agent.py — 17 líneas

```python
import sqlite3
import uuid
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'nexus_api', 'database.db')

class ProjectManagerAgent:
    def __init__(self):
        self.db_path = DB_PATH

    def create_project(self, name, repo_path=None):
        project_id = f'proj_{uuid.uuid4().hex[:12]}'
        conn = sqlite3.connect(self.db_path)
        conn.execute('INSERT INTO projects (project_id, name, status, repo_path) VALUES (?,?,?,?)', (project_id, name, 'PLANEACION', repo_path))
        conn.commit()
        conn.close()
        return {'success': True, 'project_id': project_id, 'name': name, 'status': 'PLANEACION'}
```

### nexus_core/agents/generated/reportgenerationagent.py — 56 líneas

```python
from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
import asyncio
import json

class ReportGenerationAgent(BaseAgent):
    """
    An AI agent specialized in generating reports from structured data.
    """
    capability = "AgentCapability.REPORT_GENERATION"

    async def execute(self, task_id: str, payload: dict) -> dict:
        """
        Executes the report generation task.

        Args:
            task_id: The unique identifier for the task.
            payload: A dictionary containing the data and parameters for the report.
                     Expected keys:
                     - 'data_points' (list): A list of data points to include.
                     - 'report_title' (str): The title of the report.
                     - 'summary_prompt' (str): A prompt to guide the summary generation.

        Returns:
            A dictionary containing the status and the generated report content.
        """
        data_points = payload.get("data_points", [])
        title = payload.get("report_title", "Untitled Report")
        summary_prompt = payload.get("summary_prompt", "Summarize the following data:")

        if not data_points:
            return {"status": "failed", "result": "No data points provided for report generation.", "task_id": task_id}

        try:
            # Simulate complex analysis and summary generation
            header = f"# {title}\n\n"
            summary = f"## Executive Summary\n\n{summary_prompt}\nBased on the {len(data_points)} data points provided, the analysis indicates a clear trend. Key findings have been compiled and detailed below.\n\n"

            details = "## Detailed Analysis\n\n"
            for i, point in enumerate(data_points, 1):
                details += f"- Point {i}: {str(point)}\n"

            footer = "\n-- End of Report --"

            report_content = header + summary + details + footer

            return {
                "status": "completed",
                "result": {
                    "report_content": report_content,
                    "title": title,
                    "data_points_analyzed": len(data_points)
                },
                "task_id": task_id
            }
        except Exception as e:
            return {"status": "failed", "result": f"An error occurred during report generation: {str(e)}", "task_id": task_id}
```

### nexus_core/agents/generated/test_agent.py — 218 líneas

```python
"""
TestAgent v1.0 — Filtro de calidad BajioWare
Valida código en sandbox antes de pasar a producción.
Flujo: CodeAgent escribe → TestAgent valida → JUNIOR aprueba → DevOps despliega
"""
import subprocess
import sqlite3
import json
import uuid
import shutil
from datetime import datetime
from pathlib import Path
from nexus_core.config import NEXUS_ROOT, NEXUS_DATA_PATH, LEGACY_DATABASE_PATH

BASE_DIR = NEXUS_ROOT
DB_PATH = LEGACY_DATABASE_PATH
SANDBOX_DIR = NEXUS_DATA_PATH / "test_sandbox"


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS test_results (
            test_id TEXT PRIMARY KEY,
            project_id TEXT,
            filepath TEXT,
            test_type TEXT,
            status TEXT,
            passed INTEGER DEFAULT 0,
            failed INTEGER DEFAULT 0,
            output TEXT,
            duration_ms REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def _save_result(project_id, filepath, test_type, status, passed, failed, output, duration_ms):
    test_id = f"test_{uuid.uuid4().hex[:8]}"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO test_results
           (test_id, project_id, filepath, test_type, status, passed, failed, output, duration_ms)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (test_id, project_id, filepath, test_type, status, passed, failed, output[:2000], duration_ms)
    )
    conn.commit()
    conn.close()
    return test_id


def run_syntax_check(filepath: str, project_id: str = "general") -> dict:
    """Verifica sintaxis Python/JS antes de ejecutar."""
    import time
    t0 = time.time()
    _init_db()
    p = Path(filepath)
    if not p.exists():
        return {"status": "error", "error": f"Archivo no encontrado: {filepath}"}

    if p.suffix == ".py":
        result = subprocess.run(
            ["python3", "-c", f"import ast; ast.parse(open('{filepath}').read()); print('OK')"],
            capture_output=True, text=True, timeout=10
        )
        success = result.returncode == 0
        output = result.stdout if success else result.stderr
    else:
        return {"status": "skipped", "reason": f"No syntax check for {p.suffix}"}

    duration = (time.time() - t0) * 1000
    test_id = _save_result(project_id, filepath, "syntax", "passed" if success else "failed",
                           1 if success else 0, 0 if success else 1, output, duration)
    return {
        "test_id": test_id,
        "status": "passed" if success else "failed",
        "filepath": filepath,
        "output": output,
        "duration_ms": duration,
    }


def run_lint_check(filepath: str, project_id: str = "general") -> dict:
    """Ejecuta flake8 y verifica calidad del código."""
    import time
    t0 = time.time()
    _init_db()
    result = subprocess.run(
        ["flake8", filepath, "--max-line-length=120", "--count"],
        capture_output=True, text=True, timeout=30
    )
    issues = int(result.stdout.strip().split()[-1]) if result.stdout.strip() else 0
    status = "passed" if issues == 0 else "warning" if issues < 10 else "failed"
    duration = (time.time() - t0) * 1000
    test_id = _save_result(project_id, filepath, "lint", status, 1 if issues == 0 else 0, issues,
                           result.stdout[:500], duration)
    return {
        "test_id": test_id,
        "status": status,
        "issues": issues,
        "output": result.stdout[:500],
        "duration_ms": duration,
    }


def run_security_check(filepath: str, project_id: str = "general") -> dict:
    """Ejecuta bandit para verificar seguridad del código."""
    import time
    t0 = time.time()
    _init_db()
    result = subprocess.run(
        ["bandit", "-r", filepath, "-f", "json", "-q"],
        capture_output=True, text=True, timeout=60
    )
    try:
        data = json.loads(result.stdout)
        results = data.get("results", [])
        high = len([r for r in results if r.get("issue_severity") == "HIGH"])
        medium = len([r for r in results if r.get("issue_severity") == "MEDIUM"])
        status = "failed" if high > 0 else "warning" if medium > 0 else "passed"
    except Exception:
        high, medium, status = 0, 0, "passed"

    duration = (time.time() - t0) * 1000
    test_id = _save_result(project_id, filepath, "security", status, 1 if high == 0 else 0,
                           high, f"HIGH:{high} MEDIUM:{medium}", duration)
    return {
        "test_id": test_id,
        "status": status,
        "high_severity": high,
        "medium_severity": medium,
        "duration_ms": duration,
    }


def run_in_docker_sandbox(project_path: str, test_command: str = "pytest",
                          project_id: str = "general") -> dict:
    """Ejecuta pruebas en contenedor Docker aislado."""
    import time
    t0 = time.time()
    _init_db()
    docker_cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--memory=256m",
        "--cpus=0.5",
        "-v", f"{project_path}:/workspace",
        "-w", "/workspace",
        "python:3.12-slim",
        "sh", "-c", f"pip install -r requirements.txt -q 2>/dev/null; {test_command}"
    ]
    try:
        result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=120)
        success = result.returncode == 0
        output = (result.stdout + result.stderr)[:2000]
        passed = output.count(" passed")
        failed = output.count(" failed")
        status = "passed" if success else "failed"
        duration = (time.time() - t0) * 1000
        test_id = _save_result(project_id, project_path, "docker_sandbox", status,
                               passed, failed, output, duration)
        return {
            "test_id": test_id,
            "status": status,
            "passed": passed,
            "failed": failed,
            "output": output,
            "duration_ms": duration,
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": "Docker sandbox timeout 120s"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def full_quality_check(filepath: str, project_id: str = "general") -> dict:
    """Ejecuta todos los checks de calidad en secuencia."""
    results = {
        "filepath": filepath,
        "project_id": project_id,
        "timestamp": datetime.utcnow().isoformat(),
        "syntax": run_syntax_check(filepath, project_id),
        "lint": run_lint_check(filepath, project_id),
        "security": run_security_check(filepath, project_id),
    }
    # Determinar estado general
    statuses = [r.get("status") for r in results.values() if isinstance(r, dict)]
    if "failed" in statuses:
        results["overall"] = "failed"
        results["approved_for_production"] = False
    elif "warning" in statuses:
        results["overall"] = "warning"
        results["approved_for_production"] = True
    else:
        results["overall"] = "passed"
        results["approved_for_production"] = True

    return results


def get_test_history(project_id: str = None, limit: int = 20) -> list:
    """Historial de pruebas ejecutadas."""
    conn = sqlite3.connect(DB_PATH)
    if project_id:
        rows = conn.execute(
            "SELECT test_id, filepath, test_type, status, passed, failed, created_at FROM test_results WHERE project_id=? ORDER BY created_at DESC LIMIT ?",
            (project_id, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT test_id, filepath, test_type, status, passed, failed, created_at FROM test_results ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    return [{"test_id": r[0], "filepath": r[1], "type": r[2], "status": r[3],
             "passed": r[4], "failed": r[5], "at": r[6]} for r in rows]
```

### nexus_core/agents/junior_agent.py — 416 líneas

```python
"""
NEXUS PRO — Junior Agent v1.0
El agente autónomo estrella de NEXUS.

Junior es diferente a todos los demás agentes:
- Recibe un OBJETIVO en lenguaje natural
- GPT-4o genera un PLAN de N pasos
- Ejecuta cada paso encadenando resultados
- Cada paso puede usar cualquier tool
- El resultado de un paso alimenta el siguiente
- Genera un reporte final completo

Ejemplos de lo que Junior puede hacer solo:
  "Construye una API REST para una zapatería"
  "Audita la seguridad del proyecto NEXUS"
  "Analiza el código y genera documentación"
  "Crea un pipeline CI/CD seguro"
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
from nexus_core.agents.dynamic_agent import ToolExecutor
from nexus_core.config import NEXUS_ROOT, JUNIOR_WORKSPACE

logger = logging.getLogger("nexus.junior")

WORKSPACE = JUNIOR_WORKSPACE
WORKSPACE.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════
# JUNIOR PLANNER — GPT-4o genera plan de N pasos
# ══════════════════════════════════════════════════════════════
class JuniorPlanner:

    SYSTEM = """Eres el planificador de JUNIOR, el agente autónomo de NEXUS PRO.

Tu trabajo: dado un objetivo, genera un plan de pasos concretos y ejecutables.

Herramientas disponibles:
- bash_exec:    {command, cwd, timeout}
- file_read:    {path}
- file_write:   {path, content}
- file_list:    {path}
- http_request: {url, method, headers, body}
- code_exec:    {code, timeout}
- nmap_scan:    {target, flags}
- sast_scan:    {filepath}
- stride_model: {target, context}
- report_gen:   {title, content}
- llm_call:     {system, prompt}

REGLAS CRÍTICAS:
1. Máximo 8 pasos por plan
2. Cada paso debe ser atómico y verificable
3. Usa {prev_result} en params para referenciar el resultado anterior
4. El último paso SIEMPRE debe ser report_gen con el resumen completo
5. Sé específico con los parámetros — nada genérico

RESPONDE ÚNICAMENTE con JSON válido:
{
  "objective": "descripción del objetivo",
  "estimated_duration": "X minutos",
  "steps": [
    {
      "step": 1,
      "name": "nombre descriptivo",
      "tool": "nombre_tool",
      "params": { ... },
      "description": "qué hace este paso",
      "depends_on_prev": false
    }
  ]
}"""

    @classmethod
    async def create_plan(cls, llm, objective: str, context: dict = None) -> dict:
        """GPT-4o genera el plan completo de ejecución."""
        ctx = ""
        if context:
            ctx = f"\nContexto adicional: {json.dumps(context, ensure_ascii=False)[:500]}"

        user_msg = f"""Objetivo: {objective}{ctx}

Workspace de Junior: {WORKSPACE}
Proyecto NEXUS en: {NEXUS_ROOT}

Genera el plan de pasos para completar este objetivo."""

        try:
            response = await llm.ask(cls.SYSTEM, user_msg)
            # Limpiar respuesta
            response = response.strip()
            if "```" in response:
                parts = response.split("```")
                for part in parts:
                    if "{" in part:
                        response = part.replace("json", "").strip()
                        break
            plan = json.loads(response)
            logger.info(f"[Junior Planner] Plan generado: {len(plan.get('steps',[]))} pasos")
            return plan
        except json.JSONDecodeError as e:
            logger.error(f"[Junior Planner] JSON inválido: {e}")
            # Plan de fallback
            return {
                "objective": objective,
                "estimated_duration": "2 minutos",
                "steps": [
                    {
                        "step": 1,
                        "name": "Explorar proyecto",
                        "tool": "file_list",
                        "params": {"path": str(NEXUS_ROOT)},
                        "description": "Listar estructura del proyecto",
                        "depends_on_prev": False
                    },
                    {
                        "step": 2,
                        "name": "Análisis con LLM",
                        "tool": "llm_call",
                        "params": {
                            "system": "Eres Junior, agente de NEXUS PRO.",
                            "prompt": f"Completa este objetivo: {objective}"
                        },
                        "description": "GPT-4o analiza y responde",
                        "depends_on_prev": False
                    },
                    {
                        "step": 3,
                        "name": "Reporte final",
                        "tool": "report_gen",
                        "params": {
                            "title": f"Junior_{objective[:30].replace(' ','_')}",
                            "content": "Reporte generado por Junior Agent"
                        },
                        "description": "Generar reporte de resultados",
                        "depends_on_prev": False
                    }
                ]
            }
        except Exception as e:
            logger.error(f"[Junior Planner] Error: {e}")
            raise


# ══════════════════════════════════════════════════════════════
# JUNIOR AGENT
# ══════════════════════════════════════════════════════════════
class JuniorAgent(BaseAgent):
    """
    El agente autónomo estrella de NEXUS PRO.

    Recibe un objetivo → planifica → ejecuta N pasos → entrega resultado.
    """

    JUNIOR_SYSTEM = """Eres JUNIOR, el agente autónomo más avanzado de NEXUS PRO.

Características:
- Trabajas de forma completamente autónoma
- Encadenas múltiples herramientas para completar objetivos complejos
- Piensas antes de actuar y verificas tus resultados
- Generas reportes detallados de todo lo que haces
- Eres preciso, eficiente y seguro

Especialidades:
- Desarrollo de software (APIs, scripts, automatización)
- Ciberseguridad (análisis, pentesting, documentación)
- DevOps (CI/CD, Docker, infraestructura)
- Análisis de código y generación de documentación"""

    def __init__(self, llm=None):
        metadata = AgentMetadata(
            name="Junior",
            capabilities=list(AgentCapability),  # todas
            model="gpt-4o",
            timeout_seconds=600,  # 10 min para tareas complejas
            max_concurrent=2,
            tags=["autonomous", "junior", "star_agent"],
        )
        super().__init__(metadata=metadata)
        self._llm = llm
        self._execution_log: List[dict] = []

    def _log_step(self, step: int, name: str, status: str,
                  tool: str = None, result: Any = None, error: str = None):
        """Registra cada paso de la ejecución."""
        entry = {
            "step": step,
            "name": name,
            "status": status,
            "tool": tool,
            "timestamp": datetime.utcnow().isoformat(),
            "result_preview": str(result)[:200] if result else None,
            "error": error,
        }
        self._execution_log.append(entry)
        emoji = "✓" if status == "completed" else "✗" if status == "failed" else "→"
        logger.info(f"[Junior] {emoji} Paso {step}: {name} [{status}]")

    def _inject_context(self, params: dict, prev_result: Any,
                        step_results: dict) -> dict:
        """
        Inyecta resultados previos en los parámetros del paso actual.
        Reemplaza {prev_result} y {step_N} con valores reales.
        """
        params_str = json.dumps(params, ensure_ascii=False)

        # Inyectar resultado previo
        if prev_result and "{prev_result}" in params_str:
            prev_str = str(prev_result)[:500] if prev_result else ""
            params_str = params_str.replace("{prev_result}", prev_str)

        # Inyectar resultados de pasos específicos
        for step_num, result in step_results.items():
            placeholder = f"{{step_{step_num}}}"
            if placeholder in params_str:
                params_str = params_str.replace(
                    placeholder, str(result)[:300]
                )

        try:
            return json.loads(params_str)
        except Exception:
            return params

    async def _enrich_params_with_llm(
        self, llm, step: dict, prev_result: Any,
        step_results: dict, objective: str
    ) -> dict:
        """
        Si el paso depende del anterior y tiene placeholders,
        GPT-4o decide cómo enriquecer los parámetros.
        """
        if not step.get("depends_on_prev") or not prev_result:
            return step.get("params", {})

        params = step.get("params", {})
        params_str = json.dumps(params, ensure_ascii=False)

        if "{prev_result}" not in params_str and not step.get("depends_on_prev"):
            return params

        prompt = f"""Objetivo general: {objective}
Paso actual: {step.get('name')} usando {step.get('tool')}
Resultado del paso anterior: {json.dumps(prev_result, ensure_ascii=False, default=str)[:800]}
Parámetros base del paso: {params_str}

Actualiza los parámetros para usar la información del paso anterior.
Responde SOLO con el JSON de parámetros actualizado."""

        try:
            response = await llm.ask(
                "Eres el motor de parámetros de Junior Agent. Actualiza parámetros JSON.",
                prompt
            )
            response = response.strip()
            if "```" in response:
                for part in response.split("```"):
                    if "{" in part:
                        response = part.replace("json", "").strip()
                        break
            return json.loads(response)
        except Exception:
            return params

    async def execute(self, task_id: str, payload: dict) -> dict:
        """
        Ejecuta el objetivo autónomamente.

        Payload esperado:
        - objective: string con el objetivo en lenguaje natural
        - context: dict opcional con contexto adicional
        - max_steps: int opcional (default: 8)
        """
        objective = payload.get(
            "objective",
            payload.get("prompt",
            payload.get("_task_name", "Analizar el proyecto NEXUS"))
        )
        context = payload.get("context", {})
        max_steps = int(payload.get("max_steps", 8))

        self._execution_log = []
        session_id = f"junior_{uuid.uuid4().hex[:8]}"

        logger.info(f"[Junior] 🚀 Iniciando sesión {session_id}")
        logger.info(f"[Junior] 🎯 Objetivo: {objective}")

        if not self._llm:
            return {
                "status": "error",
                "error": "Junior requiere LLM — configura una API key en Modelos & APIs",
                "objective": objective,
            }

        # ── FASE 1: Planificación ─────────────────────────────
        logger.info(f"[Junior] 🧠 GPT-4o generando plan...")
        try:
            plan = await JuniorPlanner.create_plan(
                self._llm, objective, context
            )
        except Exception as e:
            return {"status": "error", "error": f"Error en planificación: {e}"}

        steps = plan.get("steps", [])[:max_steps]
        logger.info(
            f"[Junior] 📋 Plan: {len(steps)} pasos | "
            f"ETA: {plan.get('estimated_duration','?')}"
        )

        # ── FASE 2: Ejecución paso a paso ─────────────────────
        step_results = {}
        prev_result = None
        failed_steps = []
        final_report = None

        for i, step in enumerate(steps):
            step_num = step.get("step", i + 1)
            step_name = step.get("name", f"Paso {step_num}")
            tool_name = step.get("tool", "llm_call")

            self._log_step(step_num, step_name, "running", tool_name)

            try:
                # Enriquecer params con contexto previo
                params = step.get("params", {})
                if step.get("depends_on_prev") and prev_result:
                    params = await self._enrich_params_with_llm(
                        self._llm, step, prev_result, step_results, objective
                    )
                else:
                    params = self._inject_context(params, prev_result, step_results)

                # Ejecutar la tool
                result = await ToolExecutor.execute_tool(
                    tool_name, params, self._llm
                )

                # Guardar resultado
                step_results[step_num] = result
                prev_result = result

                status = "completed" if result.get("status") != "error" else "failed"
                self._log_step(step_num, step_name, status, tool_name, result)

                if status == "failed":
                    failed_steps.append({
                        "step": step_num,
                        "name": step_name,
                        "error": result.get("error", "Unknown error"),
                    })
                    logger.warning(
                        f"[Junior] ⚠ Paso {step_num} falló: "
                        f"{result.get('error','?')} — continuando..."
                    )

                # Si es report_gen, guardar como reporte final
                if tool_name == "report_gen" and result.get("status") == "ok":
                    final_report = result

            except Exception as e:
                error_msg = f"{type(e).__name__}: {e}"
                self._log_step(step_num, step_name, "failed", tool_name, error=error_msg)
                failed_steps.append({"step": step_num, "name": step_name, "error": error_msg})
                logger.error(f"[Junior] ✗ Paso {step_num} excepción: {error_msg}")
                prev_result = {"status": "error", "error": error_msg}

        # ── FASE 3: Resumen final ─────────────────────────────
        completed = len(steps) - len(failed_steps)
        success_rate = (completed / len(steps) * 100) if steps else 0

        logger.info(
            f"[Junior] ✅ Sesión completada | "
            f"{completed}/{len(steps)} pasos OK | "
            f"{success_rate:.0f}% éxito"
        )

        # Guardar log de sesión
        log_path = WORKSPACE / f"{session_id}_log.json"
        log_path.write_text(
            json.dumps({
                "session_id": session_id,
                "objective": objective,
                "plan": plan,
                "execution_log": self._execution_log,
                "step_results": {
                    k: str(v)[:500] for k, v in step_results.items()
                },
                "timestamp": datetime.utcnow().isoformat(),
            }, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8"
        )

        return {
            "agent": "Junior",
            "session_id": session_id,
            "objective": objective,
            "status": "completed" if not failed_steps else "completed_with_errors",
            "steps_total": len(steps),
            "steps_completed": completed,
            "steps_failed": len(failed_steps),
            "success_rate": round(success_rate, 1),
            "estimated_duration": plan.get("estimated_duration"),
            "execution_log": self._execution_log,
            "failed_steps": failed_steps,
            "final_report": final_report,
            "log_path": str(log_path),
            "last_result": str(prev_result)[:1000] if prev_result else None,
        }
```

### nexus_core/agents/pentest_agent.py — 535 líneas

```python
"""
NEXUS PRO — PentestAgent v1.0
Agente especializado en pentesting y análisis de seguridad.

Fases de ejecución:
  1. Reconocimiento    → nmap, fingerprinting
  2. Análisis SAST     → bandit, safety, secrets
  3. Modelado STRIDE   → GPT-4o genera threat model
  4. Análisis LLM      → correlación de hallazgos
  5. Reporte ejecutivo → BanBajío style
"""
import asyncio
import json
import os
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
from nexus_core.agents.dynamic_agent import ToolExecutor
from nexus_core.config import NEXUS_ROOT, PENTEST_DIR, REPORTS_DIR

PENTEST_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class SecurityScanner:
    """Ejecutores especializados de seguridad."""

    @staticmethod
    async def nmap_scan(target: str, flags: str = "-sV -sC --top-ports 1000 -T4") -> dict:
        """Escaneo completo con nmap."""
        try:
            proc = await asyncio.create_subprocess_shell(
                f"nmap {flags} {target}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
            output = stdout.decode("utf-8", errors="replace")
            # Parsear puertos abiertos
            open_ports = []
            for line in output.split("\n"):
                if "/tcp" in line and "open" in line:
                    open_ports.append(line.strip())
            return {
                "status": "ok",
                "target": target,
                "open_ports": open_ports,
                "raw_output": output[:4000],
                "ports_count": len(open_ports),
            }
        except asyncio.TimeoutError:
            return {"status": "error", "error": "nmap timeout (180s)", "target": target}
        except FileNotFoundError:
            # nmap no instalado — simular resultado
            return {
                "status": "simulated",
                "target": target,
                "open_ports": ["22/tcp open ssh", "8000/tcp open uvicorn/FastAPI", "80/tcp filtered http"],
                "raw_output": f"Nmap scan simulation for {target}\n22/tcp open ssh OpenSSH 8.9\n8000/tcp open http uvicorn\n80/tcp filtered http",
                "ports_count": 3,
                "note": "nmap no instalado — resultado simulado para demo",
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def bandit_scan(path: str) -> dict:
        """Análisis SAST con bandit."""
        try:
            result = subprocess.run(
                ["python3", "-m", "bandit", "-r", path, "-f", "json", "-q"],
                capture_output=True, text=True, timeout=60
            )
            try:
                data = json.loads(result.stdout)
                results = data.get("results", [])
                metrics = data.get("metrics", {})
                high = [r for r in results if r.get("issue_severity") == "HIGH"]
                medium = [r for r in results if r.get("issue_severity") == "MEDIUM"]
                low = [r for r in results if r.get("issue_severity") == "LOW"]
                return {
                    "status": "ok",
                    "path": path,
                    "total_issues": len(results),
                    "high": len(high),
                    "medium": len(medium),
                    "low": len(low),
                    "top_issues": [
                        {
                            "severity": r.get("issue_severity"),
                            "issue": r.get("issue_text", "")[:100],
                            "file": r.get("filename", "").replace(path, ""),
                            "line": r.get("line_number"),
                            "cwe": r.get("issue_cwe", {}).get("id", "N/A"),
                        }
                        for r in (high + medium)[:10]
                    ],
                    "metrics": metrics,
                }
            except json.JSONDecodeError:
                return {
                    "status": "ok",
                    "path": path,
                    "raw": result.stdout[:2000] or result.stderr[:1000],
                    "note": "bandit completado — parseo JSON falló",
                }
        except FileNotFoundError:
            return {"status": "error", "error": "bandit no instalado — pip install bandit"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def safety_check(requirements_path: str = None) -> dict:
        """Verifica dependencias con safety."""
        try:
            if requirements_path:
                cmd = f"python3 -m safety check -r {requirements_path} --json"
            else:
                cmd = "python3 -m safety check --json"
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=60
            )
            try:
                data = json.loads(result.stdout)
                vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
                return {
                    "status": "ok",
                    "vulnerabilities_count": len(vulns),
                    "vulnerabilities": [
                        {
                            "package": v[0] if isinstance(v, list) else v.get("package_name"),
                            "installed": v[2] if isinstance(v, list) else v.get("analyzed_version"),
                            "vuln_id": v[4] if isinstance(v, list) else v.get("vulnerability_id"),
                            "advisory": (v[3] if isinstance(v, list) else v.get("advisory", ""))[:100],
                        }
                        for v in vulns[:10]
                    ],
                }
            except Exception:
                return {
                    "status": "ok",
                    "raw": result.stdout[:1000] or result.stderr[:500],
                    "note": "safety completado",
                }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def scan_secrets(path: str) -> dict:
        """Busca secrets hardcodeados en el código."""
        import re
        patterns = [
            (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
            (r'(?i)(secret_?key|secret)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret"),
            (r'(?i)(api_?key|apikey)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded API key"),
            (r'(?i)(token)\s*=\s*["\'][^"\']{10,}["\']', "Hardcoded token"),
            (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API key pattern"),
            (r'sk-ant-[a-zA-Z0-9]{20,}', "Anthropic API key pattern"),
        ]
        skip_dirs = {"venv", "__pycache__", ".git", "node_modules", ".backups"}
        findings = []
        files_scanned = 0
        try:
            for f in Path(path).rglob("*.py"):
                if any(s in str(f) for s in skip_dirs):
                    continue
                try:
                    content = f.read_text(encoding="utf-8", errors="replace")
                    files_scanned += 1
                    for pattern, desc in patterns:
                        for match in re.finditer(pattern, content):
                            if "getenv" in content[max(0, match.start()-20):match.start()+50]:
                                continue
                            line = content[:match.start()].count("\n") + 1
                            findings.append({
                                "type": desc,
                                "file": str(f).replace(path, ""),
                                "line": line,
                                "snippet": match.group()[:60],
                            })
                except Exception:
                    pass
            return {
                "status": "ok",
                "files_scanned": files_scanned,
                "secrets_found": len(findings),
                "findings": findings[:15],
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @staticmethod
    async def http_fingerprint(target: str) -> dict:
        """Fingerprinting de la API/web."""
        import httpx
        findings = []
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                resp = await client.get(target)
                headers = dict(resp.headers)
                # Verificar headers de seguridad
                security_headers = {
                    "strict-transport-security": "HSTS",
                    "x-frame-options": "Clickjacking protection",
                    "x-content-type-options": "MIME sniffing protection",
                    "content-security-policy": "CSP",
                    "x-xss-protection": "XSS Protection",
                }
                missing = []
                present = []
                for h, desc in security_headers.items():
                    if h in headers:
                        present.append(f"✓ {desc}")
                    else:
                        missing.append(f"✗ {desc} MISSING")
                        findings.append({"type": "missing_header", "header": h, "desc": desc})
                return {
                    "status": "ok",
                    "target": target,
                    "status_code": resp.status_code,
                    "server": headers.get("server", "hidden"),
                    "security_headers_present": present,
                    "security_headers_missing": missing,
                    "findings": findings,
                    "response_headers": {
                        k: v for k, v in headers.items()
                        if k in ["server", "x-powered-by", "via", "content-type"]
                    },
                }
        except Exception as e:
            return {"status": "error", "error": str(e), "target": target}


class PentestAgent(BaseAgent):
    """
    Agente especializado en pentesting y análisis de seguridad.
    Ejecuta las 5 fases completas y genera reporte ejecutivo.
    """

    REPORT_TEMPLATE = """# {title}

**Clasificación:** CONFIDENCIAL
**Fecha:** {date}
**Ejecutado por:** NEXUS PRO PentestAgent v1.0
**Target:** {target}
**Metodología:** OWASP + STRIDE + NIST

---

## Resumen Ejecutivo

{executive_summary}

---

## Hallazgos de Reconocimiento (Nmap)

**Puertos abiertos:** {ports_count}

```
{nmap_output}
```

**Análisis:** {nmap_analysis}

---

## Análisis SAST (Bandit)

| Severidad | Cantidad |
|-----------|----------|
| 🔴 HIGH   | {bandit_high} |
| 🟡 MEDIUM | {bandit_medium} |
| 🟢 LOW    | {bandit_low} |

**Top Issues:**
{bandit_issues}

---

## Dependencias Vulnerables (Safety)

**Vulnerabilidades encontradas:** {safety_count}

{safety_details}

---

## Secrets Hardcodeados

**Archivos escaneados:** {files_scanned}
**Secrets encontrados:** {secrets_count}

{secrets_details}

---

## Headers de Seguridad HTTP

**Presentes:** {headers_present}
**Faltantes:** {headers_missing}

---

## Modelado de Amenazas (STRIDE)

{stride_report}

---

## Análisis de Riesgo (GPT-4o)

{llm_analysis}

---

## Recomendaciones Prioritarias

{recommendations}

---

## Conclusión

{conclusion}

---
*Reporte generado automáticamente por NEXUS PRO PentestAgent*
*Usar solo para fines autorizados — Zero Trust · Defense in Depth*
"""

    def __init__(self, llm=None):
        metadata = AgentMetadata(
            name="PentestAgent",
            capabilities=list(AgentCapability),
            model="gpt-4o",
            timeout_seconds=600,
            max_concurrent=1,
            tags=["security", "pentest", "red_team", "stride"],
        )
        super().__init__(metadata=metadata)
        self._llm = llm

    async def execute(self, task_id: str, payload: dict) -> dict:
        target = payload.get("target", "localhost:8000")
        target_path = payload.get("path", str(NEXUS_ROOT))
        target_name = payload.get("name", "NEXUS PRO")
        session_id = f"pentest_{uuid.uuid4().hex[:8]}"
        results = {}

        self._logger.info(f"[PentestAgent] 🔴 Iniciando pentesting de {target_name}")

        # ── FASE 1: Reconocimiento ────────────────────────────
        self._logger.info("[PentestAgent] Fase 1: Reconocimiento (nmap)")
        results["nmap"] = await SecurityScanner.nmap_scan(target)

        # ── FASE 1B: Fingerprinting HTTP ─────────────────────
        self._logger.info("[PentestAgent] Fase 1B: Fingerprinting HTTP")
        http_target = f"http://{target}" if not target.startswith("http") else target
        results["http"] = await SecurityScanner.http_fingerprint(http_target)

        # ── FASE 2A: SAST con Bandit ──────────────────────────
        self._logger.info("[PentestAgent] Fase 2A: SAST con Bandit")
        results["bandit"] = await SecurityScanner.bandit_scan(target_path)

        # ── FASE 2B: Dependencias con Safety ─────────────────
        self._logger.info("[PentestAgent] Fase 2B: Dependencias con Safety")
        req_path = f"{target_path}/nexus_api/requirements.txt"
        results["safety"] = await SecurityScanner.safety_check(
            req_path if Path(req_path).exists() else None
        )

        # ── FASE 2C: Secrets scan ─────────────────────────────
        self._logger.info("[PentestAgent] Fase 2C: Secrets scan")
        results["secrets"] = await SecurityScanner.scan_secrets(target_path)

        # ── FASE 3: STRIDE con GPT-4o ─────────────────────────
        stride_report = "N/A — LLM no disponible"
        llm_analysis = "N/A — LLM no disponible"
        recommendations = "Ver hallazgos arriba"
        executive_summary = "Análisis completado"
        conclusion = "Ver reporte completo"

        if self._llm:
            self._logger.info("[PentestAgent] Fase 3: STRIDE con GPT-4o")
            stride_prompt = f"""Aplica metodología STRIDE a {target_name}.
Sistema analizado: Orquestador de agentes IA con API FastAPI, SQLite, WebSockets y LLM integrado.
Puertos encontrados: {results['nmap'].get('open_ports', [])}
Issues SAST encontrados: {results['bandit'].get('high', 0)} HIGH, {results['bandit'].get('medium', 0)} MEDIUM
Headers faltantes: {results['http'].get('security_headers_missing', [])}

Para cada categoría STRIDE identifica amenazas específicas y contramedidas concretas."""

            try:
                stride_report = await self._llm.ask(
                    "Eres un arquitecto de seguridad experto en STRIDE y Zero Trust.",
                    stride_prompt
                )
            except Exception as e:
                stride_report = f"Error generando STRIDE: {e}"

            # ── FASE 4: Análisis correlacionado ───────────────
            self._logger.info("[PentestAgent] Fase 4: Análisis correlacionado GPT-4o")
            analysis_prompt = f"""Analiza estos hallazgos de seguridad de {target_name}:

RECONOCIMIENTO:
- Puertos abiertos: {results['nmap'].get('ports_count', 0)}
- {chr(10).join(results['nmap'].get('open_ports', [])[:5])}

SAST (Bandit):
- HIGH: {results['bandit'].get('high', 0)}
- MEDIUM: {results['bandit'].get('medium', 0)}
- Top issues: {json.dumps(results['bandit'].get('top_issues', [])[:3], ensure_ascii=False)}

DEPENDENCIAS VULNERABLES: {results['safety'].get('vulnerabilities_count', 0)}

SECRETS HARDCODEADOS: {results['secrets'].get('secrets_found', 0)}

HEADERS HTTP FALTANTES: {len(results['http'].get('security_headers_missing', []))}

Proporciona:
1. Score de riesgo general (0-100, donde 100 = crítico)
2. Top 3 vulnerabilidades más críticas con impacto real
3. Vector de ataque más probable
4. 5 recomendaciones prioritarias ordenadas por impacto"""

            try:
                llm_analysis = await self._llm.ask(
                    "Eres un Red Team Lead experto en análisis de riesgo CVSS y MITRE ATT&CK.",
                    analysis_prompt
                )
            except Exception as e:
                llm_analysis = f"Error en análisis: {e}"

            # ── Resumen ejecutivo ─────────────────────────────
            try:
                executive_summary = await self._llm.ask(
                    "Eres un CISO escribiendo para la junta directiva. Sé conciso y ejecutivo.",
                    f"""Resume en 3 párrafos el estado de seguridad de {target_name}:
- {results['bandit'].get('total_issues', 0)} issues de código ({results['bandit'].get('high', 0)} críticos)
- {results['safety'].get('vulnerabilities_count', 0)} dependencias vulnerables
- {results['secrets'].get('secrets_found', 0)} posibles secrets expuestos
- {len(results['http'].get('security_headers_missing', []))} headers de seguridad faltantes
- {results['nmap'].get('ports_count', 0)} puertos expuestos"""
                )
            except Exception:
                executive_summary = "Ver hallazgos detallados en el reporte."

            recommendations = llm_analysis
            conclusion = f"Análisis completado. Score estimado por GPT-4o incluido en sección de análisis."

        # ── FASE 5: Generar reporte ───────────────────────────
        self._logger.info("[PentestAgent] Fase 5: Generando reporte ejecutivo")
        date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        report_name = f"PentestReport_{target_name.replace(' ','_')}_{session_id}"

        # Formatear issues de bandit
        bandit_issues_str = "\n".join([
            f"- [{i.get('severity')}] {i.get('issue','')[:80]} | {i.get('file','')}:{i.get('line','')}"
            for i in results['bandit'].get('top_issues', [])[:5]
        ]) or "Sin issues críticos detectados"

        # Formatear safety
        safety_str = "\n".join([
            f"- {v.get('package','?')} {v.get('installed','?')} → {v.get('advisory','')[:80]}"
            for v in results['safety'].get('vulnerabilities', [])[:5]
        ]) or "Sin vulnerabilidades de dependencias detectadas"

        # Formatear secrets
        secrets_str = "\n".join([
            f"- [{s.get('type')}] {s.get('file','')}:{s.get('line','')} → {s.get('snippet','')[:40]}"
            for s in results['secrets'].get('findings', [])[:5]
        ]) or "Sin secrets hardcodeados detectados"

        report_content = self.REPORT_TEMPLATE.format(
            title=f"Reporte de Seguridad — {target_name}",
            date=date_str,
            target=target,
            executive_summary=executive_summary,
            ports_count=results['nmap'].get('ports_count', 0),
            nmap_output="\n".join(results['nmap'].get('open_ports', [])[:10]),
            nmap_analysis=f"{results['nmap'].get('ports_count',0)} puertos encontrados. "
                          + ("Ver detalles arriba." if results['nmap'].get('status') != 'simulated'
                             else "⚠ Nmap no instalado — instala con: sudo apt install nmap"),
            bandit_high=results['bandit'].get('high', 0),
            bandit_medium=results['bandit'].get('medium', 0),
            bandit_low=results['bandit'].get('low', 0),
            bandit_issues=bandit_issues_str,
            safety_count=results['safety'].get('vulnerabilities_count', 0),
            safety_details=safety_str,
            files_scanned=results['secrets'].get('files_scanned', 0),
            secrets_count=results['secrets'].get('secrets_found', 0),
            secrets_details=secrets_str,
            headers_present="\n".join(results['http'].get('security_headers_present', [])[:5]),
            headers_missing="\n".join(results['http'].get('security_headers_missing', [])[:5]),
            stride_report=stride_report[:2000],
            llm_analysis=llm_analysis[:2000],
            recommendations=recommendations[:1500],
            conclusion=conclusion,
        )

        # Guardar reporte
        report_path = REPORTS_DIR / f"{report_name}.md"
        report_path.write_text(report_content, encoding="utf-8")

        # Guardar JSON de resultados raw
        raw_path = PENTEST_DIR / f"{session_id}_raw.json"
        raw_path.write_text(
            json.dumps(results, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8"
        )

        self._logger.info(f"[PentestAgent] ✅ Reporte generado: {report_path}")

        return {
            "agent": "PentestAgent",
            "session_id": session_id,
            "target": target,
            "target_name": target_name,
            "report_path": str(report_path),
            "raw_results_path": str(raw_path),
            "summary": {
                "ports_open": results['nmap'].get('ports_count', 0),
                "sast_high": results['bandit'].get('high', 0),
                "sast_medium": results['bandit'].get('medium', 0),
                "deps_vulns": results['safety'].get('vulnerabilities_count', 0),
                "secrets_found": results['secrets'].get('secrets_found', 0),
                "missing_headers": len(results['http'].get('security_headers_missing', [])),
            },
            "report_preview": report_content[:1000],
        }
```

### nexus_core/agents/registry.py — 240 líneas

```python
# nexus_core/agents/registry.py

"""
Provides a central registry for managing the lifecycle and discovery of agents.

The AgentRegistry is responsible for:
- Registering and unregistering agents in the system.
- Discovering agents based on their capabilities.
- Selecting the most suitable agent for a task based on load.
- Providing health checks and aggregated statistics for all registered agents.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from nexus_core.agents.base import AgentCapability, BaseAgent

# Assuming a logger utility exists. If not, a standard logger is used.
try:
    from nexus_core.utils.logger import get_logger
except ImportError:
    # Fallback to standard logging if the custom logger is not available
    def get_logger(name: str) -> logging.Logger:
        """Provides a basic logger instance."""
        logger = logging.getLogger(name)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger


class AgentRegistry:
    """
    Manages the collection of active agents in the NEXUS system.

    This class acts as a service locator for agents, allowing other parts of
    the system to find and interact with agents based on their capabilities
    and current workload.
    """

    def __init__(self, event_bus: Any = None, state_manager: Any = None, logger: Optional[logging.Logger] = None):
        """
        Initializes the AgentRegistry.

        Args:
            event_bus: An optional event bus for emitting system-wide events.
            state_manager: An optional state manager for persisting registry state.
            logger: An optional logger instance.
        """
        self._agents: Dict[str, BaseAgent] = {}
        self._lock = asyncio.Lock()
        self._event_bus = event_bus
        self._state_manager = state_manager
        self._logger = logger or get_logger("AgentRegistry")

    async def register(self, agent: BaseAgent) -> None:
        """
        Registers a new agent with the registry.

        If an agent with the same ID already exists, it will be overwritten.

        Args:
            agent: The agent instance to register.
        """
        async with self._lock:
            if agent.agent_id in self._agents:
                self._logger.warning(f"Overwriting existing agent registration for ID: {agent.agent_id}")
            self._agents[agent.agent_id] = agent
            self._logger.info(f"Agent '{agent.name}' (ID: {agent.agent_id}) registered.")

        # state_manager sync omitido — update_agent_state no implementado aún

        if self._event_bus:
            try:
                from nexus_core.core.event_bus import Event, EventType
                await self._event_bus.publish(Event(
                    type=EventType.AGENT_REGISTERED,
                    payload={"agent_id": agent.agent_id, "metadata": agent.metadata.to_dict()},
                    source="AgentRegistry"
                ))
            except Exception:
                pass

    async def unregister(self, agent_id: str) -> None:
        """
        Removes an agent from the registry.

        Args:
            agent_id: The ID of the agent to unregister.
        """
        async with self._lock:
            agent = self._agents.pop(agent_id, None)

        if agent:
            self._logger.info(f"Agent '{agent.name}' (ID: {agent_id}) unregistered.")
            if self._event_bus:
                await self._event_bus.publish("agent.unregistered", {"agent_id": agent_id})
        else:
            self._logger.warning(f"Attempted to unregister non-existent agent with ID: {agent_id}")

    async def discover(self, capability: AgentCapability) -> List[BaseAgent]:
        """
        Finds all agents that possess a specific capability.

        The returned list is sorted by the current load, with the least
        busy agents appearing first.

        Args:
            capability: The capability to search for.

        Returns:
            A list of agent instances that have the specified capability.
        """
        async with self._lock:
            # Create a snapshot to work with
            agents_snapshot = list(self._agents.values())

        capable_agents = [
            agent for agent in agents_snapshot
            if agent.metadata.has_capability(capability)
        ]

        # Sort by current load (_current_tasks) ascending
        capable_agents.sort(key=lambda a: a._current_tasks)
        return capable_agents

    async def get_best_agent(self, capability: AgentCapability) -> Optional[BaseAgent]:
        """
        Finds the most suitable agent for a task requiring a specific capability.

        The "best" agent is defined as the one that is currently available and
        has the lowest load ratio (current tasks / max concurrent tasks).

        Args:
            capability: The required capability.

        Returns:
            The best available agent instance, or None if no suitable agent is found.
        """
        async with self._lock:
            agents_snapshot = list(self._agents.values())

        available_agents = [
            agent for agent in agents_snapshot
            if agent.is_available and agent.metadata.has_capability(capability)
        ]

        if not available_agents:
            return None

        # Calculate load ratio and find the agent with the minimum
        best_agent = min(
            available_agents,
            key=lambda a: a._current_tasks / a.metadata.max_concurrent
        )
        return best_agent

    def get(self, agent_id: str) -> Optional[BaseAgent]:
        """
        Retrieves a specific agent by its ID.

        Args:
            agent_id: The ID of the agent to retrieve.

        Returns:
            The agent instance, or None if not found.
        """
        return self._agents.get(agent_id)

    async def get_all(self) -> Dict[str, BaseAgent]:
        """
        Retrieves all registered agents.

        Returns:
            A dictionary mapping agent IDs to agent instances.
        """
        async with self._lock:
            return dict(self._agents)

    async def health_check(self) -> Dict[str, bool]:
        """
        Performs a simple health check on all registered agents.

        The current implementation checks the `is_available` property.

        Returns:
            A dictionary mapping agent IDs to their availability status (bool).
        """
        async with self._lock:
            return {
                agent_id: agent.is_available
                for agent_id, agent in self._agents.items()
            }

    def get_agents_by_capability(self, capability):
        """
        Devuelve los agentes que soportan una capacidad específica
        """

        result = []

        for agent in self._agents.values():

            for cap in agent.metadata.capabilities:
                if cap.value == capability:
                    result.append(agent)

        return result

    def get_stats(self) -> Dict[str, Any]:
        """
        Provides aggregated statistics about the agents in the registry.

        Returns:
            A dictionary with statistics, including total agents, agents by
            capability, and currently available agents.
        """
        total_agents = len(self._agents)
        available_now = sum(1 for agent in self._agents.values() if agent.is_available)

        agents_by_capability: Dict[str, int] = {}
        for capability in AgentCapability:
            count = sum(
                1 for agent in self._agents.values()
                if agent.metadata.has_capability(capability)
            )
            if count > 0:
                agents_by_capability[capability.value] = count

        return {
            "total_agents": total_agents,
            "available_agents": available_now,
            "agents_by_capability": agents_by_capability,
        }
```

### API

#### nexus_api/main.py

```python
"""
nexus_api/main.py — NEXUS Sovereign 3.0
Orquestador de Agentes IA · Zero Trust · Military Grade
"""
import asyncio
import logging
import sys
import time
import uuid
import warnings
from collections import defaultdict, deque

logging.getLogger('passlib').setLevel(logging.ERROR)
warnings.filterwarnings('ignore', message='.*bcrypt.*')
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "nexus_core"))

# Load process-level settings before importing auth/provider modules that use
# os.getenv at import time. Pydantic's env_file does not populate os.environ.
from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ── Security Headers Middleware ────────────────────────────────
from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Frame-Options"] = "DENY"
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
                headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
                headers["Content-Security-Policy"] = (
                    "default-src 'self'; connect-src 'self' ws: wss:; "
                    "script-src 'self'; style-src 'self'; object-src 'none'; "
                    "base-uri 'self'; frame-ancestors 'none';"
                )
                if scope.get("scheme") == "https":
                    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestContextMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        supplied = Headers(scope=scope).get("X-Request-ID", "")
        try:
            trace_id = str(uuid.UUID(supplied)) if supplied else str(uuid.uuid4())
        except ValueError:
            trace_id = str(uuid.uuid4())
        scope.setdefault("state", {})["trace_id"] = trace_id
        started = time.monotonic()
        status_code = 500

        async def send_with_id(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                MutableHeaders(scope=message)["X-Request-ID"] = trace_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            from nexus_core.kernel.telemetry import metrics

            labels = {
                "method": scope.get("method", ""),
                "path": scope.get("route", {}).path
                if getattr(scope.get("route"), "path", None) else scope.get("path", ""),
                "status": str(status_code),
            }
            metrics.increment("nexus_http_requests_total", **labels)
            metrics.increment(
                "nexus_http_duration_ms_total", (time.monotonic() - started) * 1000,
                **labels,
            )


class RateLimitMiddleware:
    def __init__(self, app, requests_per_minute: int, burst: int):
        self.app = app
        self.limit = max(1, requests_per_minute + burst)
        self.requests = defaultdict(deque)
        self.lock = asyncio.Lock()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") == "/health":
            return await self.app(scope, receive, send)
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        now = time.monotonic()
        async with self.lock:
            history = self.requests[client_ip]
            while history and now - history[0] >= 60:
                history.popleft()
            if len(history) >= self.limit:
                response = JSONResponse(
                    {"detail": "rate limit exceeded"}, status_code=429,
                    headers={"Retry-After": "60"},
                )
                return await response(scope, receive, send)
            history.append(now)
        await self.app(scope, receive, send)


from nexus_api.auth.deps import require_admin
from nexus_api.config import settings

logger = logging.getLogger("nexus.api")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s"
)

# ══════════════════════════════════════════════════════════════
# LIFESPAN
# ══════════════════════════════════════════════════════════════
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)

    from nexus_core.kernel.telemetry import configure_telemetry
    app.state.telemetry_enabled = configure_telemetry()
    logger.info("  NEXUS Sovereign 3.0 — Iniciando...")
    logger.info("=" * 60)

    import os
    if int(os.getenv("WEB_CONCURRENCY", "1")) > 1:
        import logging
        logging.getLogger("nexus").warning(
            "WARNING: Multiple workers detected. In-memory state (AgentRegistry, HITLManager, StateManager) is NOT shared between workers. Set WEB_CONCURRENCY=1 until Redis is integrated."
        )

    # ── NEXUS PRO DB ──────────────────────────────────────────
    try:
        from nexus_api.config import NEXUS_DB_PATH
        from nexus_core.kernel.store_factory import get_control_store
        app.state.control_store = get_control_store(NEXUS_DB_PATH)
        app.state.control_store.initialize()
        if not settings.is_production:
            from nexus_api.db.database import init_nexus_db
            init_nexus_db()
        logger.info("[NEXUS-DB] ✓ Control plane inicializado")
    except Exception as e:
        logger.error(f"[NEXUS-DB] ✗ {e}")
        raise

    # Production runs only the durable control plane. Legacy in-memory agents,
    # schedulers and orchestrators are development compatibility components.
    if settings.is_production or not settings.NEXUS_ENABLE_LEGACY_RUNTIME:
        app.state.orchestrator = None
        app.state.event_bus = None
        app.state.state_manager = None
        app.state.registry = None
        app.state.llm = None
        app.state.memory = None
        app.state.workflow_manager = None
        app.state.junior_bridge = None
        logger.info("[NEXUS] Control plane durable listo; workers son servicios separados")
        yield
        logger.info("[NEXUS] Control plane detenido")
        return

    # ── Scheduler ─────────────────────────────────────────────
    try:
        from nexus_api.scheduler.manager import start_scheduler
        start_scheduler()
        logger.info("[SCHEDULER] ✓ Iniciado")
    except Exception as e:
        logger.warning(f"[SCHEDULER] ⚠ {e}")

    # ── EventBus — base de todo, primero ─────────────────────
    try:
        from nexus_core.core.event_bus import EventBus
        app.state.event_bus = EventBus()
        logger.info("[EVENTBUS] ✓ Listo")
    except Exception as e:
        logger.warning(f"[EVENTBUS] ⚠ {e}")
        app.state.event_bus = None

    # ── StateManager ──────────────────────────────────────────
    try:
        from nexus_core.state.manager import StateManager
        app.state.state_manager = StateManager()
        logger.info("[STATE] ✓ Listo")
    except Exception as e:
        logger.warning(f"[STATE] ⚠ {e}")
        app.state.state_manager = None

    # ── AgentRegistry ─────────────────────────────────────────
    try:
        from nexus_core.agents.registry import AgentRegistry
        app.state.registry = AgentRegistry()
        logger.info("[REGISTRY] ✓ Listo")
    except Exception as e:
        logger.warning(f"[REGISTRY] ⚠ {e}")
        app.state.registry = None

    # ── NexusOrchestrator (requiere state + registry + event_bus) ──
    # FIX: clase se llama NexusOrchestrator, no Orchestrator
    # FIX: requiere config, state_manager, agent_registry, event_bus
    try:
        from nexus_core.core.orchestrator import NexusOrchestrator, OrchestratorConfig
        if all([app.state.state_manager, app.state.registry, app.state.event_bus]):
            cfg = OrchestratorConfig()
            app.state.orchestrator = NexusOrchestrator(
                config=cfg,
                state_manager=app.state.state_manager,
                agent_registry=app.state.registry,
                event_bus=app.state.event_bus,
            )
            import asyncio
            asyncio.create_task(app.state.orchestrator.start())
            logger.info("[ORCHESTRATOR] ✓ NexusOrchestrator arrancado")
        else:
            logger.warning("[ORCHESTRATOR] ⚠ Dependencias incompletas — state/registry/eventbus requeridos")
            app.state.orchestrator = None
    except Exception as e:
        logger.warning(f"[ORCHESTRATOR] ⚠ {e}")
        app.state.orchestrator = None

    # ── LLM — NexusLLM con factory desde .env ─────────────────
    # FIX: LLMProvider es un Enum, no se instancia directamente
    # FIX: usar LLMFactory.create_from_env() que detecta keys del .env
    try:
        from nexus_core.llm.abstraction import LLMFactory, NexusLLM
        clients = LLMFactory.create_from_env()
        if clients:
            providers = list(clients.keys())
            primary  = clients[providers[0]]
            fallback = clients[providers[1]] if len(providers) > 1 else None
            app.state.llm = NexusLLM(primary=primary, fallback=fallback)
            msg = f"primary: {providers[0]}"
            if fallback:
                msg += f" · fallback: {providers[1]}"
            logger.info(f"[LLM] ✓ NexusLLM listo — {msg}")
        else:
            app.state.llm = None
            logger.warning("[LLM] ⚠ Sin API keys en .env — agrega OPENAI_API_KEY o GEMINI_API_KEY")
    except Exception as e:
        logger.warning(f"[LLM] ⚠ {e}")
        app.state.llm = None

    # ── MemoryManager ─────────────────────────────────────────
    try:
        from nexus_core.memory.manager import MemoryManager
        app.state.memory = MemoryManager()
        logger.info("[MEMORY] ✓ Listo")
    except Exception as e:
        logger.warning(f"[MEMORY] ⚠ {e}")
        app.state.memory = None

    # ── WorkflowManager — FIX: requiere event_bus como arg ────
    try:
        from nexus_core.workflow_manager import WorkflowManager
        if app.state.event_bus:
            app.state.workflow_manager = WorkflowManager(
                event_bus=app.state.event_bus,
                orchestrator=app.state.orchestrator,  # puede ser None, tiene fallback interno
            )
            logger.info("[WORKFLOW] ✓ WorkflowManager listo")
        else:
            logger.warning("[WORKFLOW] ⚠ EventBus no disponible")
            app.state.workflow_manager = None
    except Exception as e:
        logger.warning(f"[WORKFLOW] ⚠ {e}")
        app.state.workflow_manager = None

    # ── AgentTeamManager ──────────────────────────────────────
    try:
        from nexus_core.agent_team_manager import create_team_router
        app.include_router(create_team_router())
        logger.info("[TEAMS] ✓ AgentTeamManager → /teams/*")
    except Exception as e:
        logger.warning(f"[TEAMS] ⚠ {e}")

    # ── Registrar agentes — FIX: metadata explícita ──────────
    try:
        import importlib

        from nexus_core.agents.base import AgentCapability, AgentMetadata
        _agents_with_meta = [
            ("nexus_core.agents.generated.bashagent", "BashAgent",
             AgentMetadata(name="BashAgent", capabilities=[AgentCapability.FILE_OPERATIONS])),
            ("nexus_core.agents.generated.codeagent", "CodeAgent",
             AgentMetadata(name="CodeAgent", capabilities=[AgentCapability.CODE_GENERATION])),
            ("nexus_core.agents.generated.fileagent", "FileAgent",
             AgentMetadata(name="FileAgent", capabilities=[AgentCapability.FILE_OPERATIONS])),
        ]
        registered = []
        for mod_path, cls_name, meta in _agents_with_meta:
            try:
                mod = importlib.import_module(mod_path)
                AgentClass = getattr(mod, cls_name)
                agent = AgentClass(metadata=meta)
                if app.state.registry:
                    await app.state.registry.register(agent)
                registered.append(cls_name)
            except Exception as ae:
                logger.warning(f"[AGENTS] ⚠ {cls_name}: {ae}")
        if registered:
            logger.info(f"[AGENTS] ✓ Registrados: {', '.join(registered)}")
    except Exception as e:
        logger.warning(f"[AGENTS] ⚠ {e}")

    # ── HITL Manager — inicializar singleton ────────────────
    try:
        from nexus_core.hitl.manager import get_hitl_manager
        hitl = get_hitl_manager()
        app.state.hitl = hitl
        logger.info("[HITL] ✓ HITLManager activo — interceptando acciones críticas")
    except Exception as e:
        logger.warning(f"[HITL] ⚠ {e}")
        app.state.hitl = None

    # ── Registrar Junior Agent (estrella) ───────────────────
    try:
        from nexus_core.agents.junior_agent import JuniorAgent
        llm = getattr(app.state, 'llm', None)
        registry = getattr(app.state, 'registry', None)
        if registry:
            junior = JuniorAgent(llm=llm)
            await registry.register(junior)
            app.state.junior = junior
            logger.info("[JUNIOR-AGENT] ✓ Junior Agent registrado — autónomo y listo")
    except Exception as e:
        logger.warning(f"[JUNIOR-AGENT] ⚠ {e}")
        app.state.junior = None

    # ── Cargar agentes de DB al Registry ────────────────────
    try:
        from nexus_api.db.database import db_list_agents
        from nexus_core.agents.dynamic_agent import DynamicAgent
        db_agents = db_list_agents()
        loaded = []
        llm = getattr(app.state, 'llm', None)
        registry = getattr(app.state, 'registry', None)
        if registry and db_agents:
            for agent_cfg in db_agents:
                try:
                    dyn_agent = DynamicAgent(agent_cfg, llm=llm)
                    await registry.register(dyn_agent)
                    loaded.append(agent_cfg['name'])
                except Exception as ae:
                    logger.warning(f"[DYNAMIC] ⚠ {agent_cfg['name']}: {ae}")
            if loaded:
                logger.info(f"[DYNAMIC] ✓ Agentes DB cargados: {', '.join(loaded)}")
    except Exception as e:
        logger.warning(f"[DYNAMIC] ⚠ Error cargando agentes DB: {e}")

    # ── JuniorBridge — FIX: módulo no existe, warning limpio ──
    try:
        from nexus_core.junior_bridge import get_junior_bridge, initialize_bridge
        bridge_ok = await initialize_bridge()
        app.state.junior_bridge = get_junior_bridge() if bridge_ok else None
        logger.info(f"[JUNIOR] {'✓ Activo' if bridge_ok else '⚠ Degradado'}")
    except ModuleNotFoundError:
        logger.warning("[JUNIOR] ⚠ nexus_core/junior_bridge.py no existe — se puede crear")
        app.state.junior_bridge = None
    except Exception as e:
        logger.warning(f"[JUNIOR] ⚠ {e}")
        app.state.junior_bridge = None

    logger.info("=" * 60)
    logger.info("  NEXUS Sovereign 3.0 — SISTEMA HEALTHY ✓")
    logger.info("  API Docs → http://0.0.0.0:8000/docs")
    logger.info("=" * 60)

    yield  # ← app corriendo

    # ── Shutdown ──────────────────────────────────────────────
    logger.info("[NEXUS] Apagando servicios...")
    try:
        if getattr(app.state, "orchestrator", None):
            await app.state.orchestrator.stop()
    except Exception:
        pass
    try:
        from nexus_api.scheduler.manager import stop_scheduler
        stop_scheduler()
    except Exception:
        pass
    logger.info("[NEXUS] ✓ Apagado limpio")


# ══════════════════════════════════════════════════════════════
# APP
# ══════════════════════════════════════════════════════════════
app = FastAPI(
    title="NEXUS Sovereign",
    version="3.0.0",
    description="Plataforma soberana de ejecución durable de agentes",
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(
    RateLimitMiddleware,
    requests_per_minute=settings.RATE_LIMIT_PER_MINUTE,
    burst=settings.RATE_LIMIT_BURST,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
)

# ══════════════════════════════════════════════════════════════
# ROUTERS
# ══════════════════════════════════════════════════════════════
# Auth — obligatorio
from nexus_api.routes.auth import router as auth_router
from nexus_api.routes.factory import router as factory_router
from nexus_api.routes.jarvis import router as jarvis_router
from nexus_api.routes.memory import router as memory_router

app.include_router(auth_router, prefix="/api/v1", tags=["Auth v1"])
app.include_router(memory_router, prefix="/api/v1")
if settings.NEXUS_ENABLE_LEGACY_RUNTIME and not settings.is_production:
    app.include_router(factory_router, prefix="/api/v1")
    app.include_router(jarvis_router, prefix="/api/v1")

# Los routers del producto son obligatorios: un import roto debe impedir el arranque.
import importlib

_routes = [
    ("nexus_api.routes.scheduler",       {},                              ["Scheduler"]),
    ("nexus_api.routes.agents",          {},                              ["Agents"]),
    ("nexus_api.routes.tasks",           {},                              ["Tasks"]),
    ("nexus_api.routes.nexus",           {},                              ["Nexus"]),
    ("nexus_api.routes.guardian",        {"prefix": "/guardian"},         ["Security"]),
    ("nexus_api.routes.teams_v2",        {"prefix": "/teams-v2"},         ["Teams"]),
    ("nexus_api.routes.project_manager", {"prefix": "/project-manager"},  ["ProjectMgr"]),
    ("nexus_api.routes.plans",           {"prefix": "/plans"},            ["Plans"]),
    ("nexus_api.routes.composite",       {"prefix": "/composite"},        ["Composite"]),
    ("nexus_api.routes.killswitch",      {"prefix": "/killswitch"},       ["KillSwitch"]),
    ("nexus_api.routes.testagent",       {"prefix": "/testagent"},        ["TestAgent"]),
    ("nexus_api.routes.docagent",        {"prefix": "/docagent"},         ["DocAgent"]),
    ("nexus_api.routes.ws_logs",         {},                              ["WebSocket"]),
    ("nexus_api.routes.projects",        {"prefix": "/projects"},         ["Projects"]),
    ("nexus_api.routes.tools",           {},                              ["Tools"]),
    ("nexus_api.routes.models",          {},                              ["Models"]),
    ("nexus_api.routes.junior",          {},                              ["Junior"]),
    ("nexus_api.routes.pentest",         {},                              ["Pentest"]),
    ("nexus_api.routes.hitl",            {},                              ["HITL"]),
    ("nexus_api.routes.directory",       {},                              ["Directory"]),
    ("nexus_api.routes.evolution",       {},                              ["Evolution"]),
    ("nexus_api.routes.connectors",      {},                              ["Connectors"]),
    ("nexus_api.routes.packages",        {},                              ["Packages"]),
    ("nexus_api.routes.a2a",             {},                              ["A2A"]),
    ("nexus_api.routes.approvals",       {},                              ["Approvals"]),
    ("nexus_api.routes.policies",        {},                              ["Policies"]),
    ("nexus_api.routes.workflows",       {},                              ["Workflows"]),
    ("nexus_api.routes.audit",           {},                              ["Audit"]),
    ("nexus_api.routes.sovereign",       {},                              ["Sovereign"]),
]

_legacy_route_modules = {
    "nexus_api.routes.scheduler", "nexus_api.routes.agents",
    "nexus_api.routes.tasks", "nexus_api.routes.nexus",
    "nexus_api.routes.guardian", "nexus_api.routes.teams_v2",
    "nexus_api.routes.project_manager", "nexus_api.routes.plans",
    "nexus_api.routes.composite", "nexus_api.routes.killswitch",
    "nexus_api.routes.testagent", "nexus_api.routes.docagent",
    "nexus_api.routes.ws_logs", "nexus_api.routes.projects",
    "nexus_api.routes.tools", "nexus_api.routes.models",
    "nexus_api.routes.junior", "nexus_api.routes.pentest",
    "nexus_api.routes.hitl",
}

for module_path, kwargs, tags in _routes:
    if module_path in _legacy_route_modules and (
        settings.is_production or not settings.NEXUS_ENABLE_LEGACY_RUNTIME
    ):
        continue
    mod = importlib.import_module(module_path)
    alias_kwargs = dict(kwargs)
    alias_kwargs["prefix"] = "/api/v1" + alias_kwargs.get("prefix", "")
    app.include_router(mod.router, tags=[f"{tag} v1" for tag in tags], **alias_kwargs)

# ══════════════════════════════════════════════════════════════
# ENDPOINTS BASE
# ══════════════════════════════════════════════════════════════
@app.get("/health", tags=["Health"])
async def health():
    from datetime import datetime

    def svc(key):
        return "ok" if getattr(app.state, key, None) is not None else "degraded"

    hitl_count = 0
    try:
        hitl = getattr(app.state, 'hitl', None)
        if hitl:
            hitl_count = hitl.count_pending()
    except Exception:
        pass

    services = {k: svc(k) for k in [
        "orchestrator", "llm", "memory", "registry",
        "event_bus", "junior_bridge", "workflow_manager", "state_manager"
    ]}

    durable_ready = getattr(app.state, "control_store", None) is not None
    core_ok = durable_ready and (
        settings.is_production or not settings.NEXUS_ENABLE_LEGACY_RUNTIME or
        all(services[k] == "ok" for k in ["event_bus", "state_manager", "registry"])
    )

    return {
        "status": "healthy" if core_ok else "degraded",
        "version": "3.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "platform": "NEXUS Sovereign — Durable Agent Platform",
        "services": services,
        "durable_control_plane": "ok" if durable_ready else "degraded",
        "hitl_pending": hitl_count,
    }


@app.get("/", tags=["Health"])
async def root():
    return {
        "name": "NEXUS Sovereign",
        "version": "3.0.0",
        "status": "online",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/system/metrics", tags=["System"])
async def system_metrics(_=Depends(require_admin)):
    from nexus_core.kernel.telemetry import metrics

    return {"metrics": metrics.snapshot()}
```

#### nexus_api/routes/pentest.py

```python
"""
NEXUS PRO — Pentest API
Endpoints para ejecutar pentesting completo con PentestAgent
"""
import uuid
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional

from nexus_api.auth.deps import get_current_user
from nexus_api.db.database import db_create_task, db_update_task, db_get_task
from nexus_api.config import NEXUS_ROOT, NEXUS_DATA_PATH

router = APIRouter(dependencies=[Depends(get_current_user)])

REPORTS_DIR = NEXUS_DATA_PATH / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class PentestRequest(BaseModel):
    target: str = "localhost:8000"
    target_path: str = str(NEXUS_ROOT)
    target_name: str = "NEXUS PRO"
    scope: str = "full"  # full | quick | sast_only | network_only


async def _run_pentest(task_id: str, req: dict, app):
    """Ejecuta el pentesting en background."""
    import datetime as dt
    db_update_task(task_id, status="running",
        started_at=dt.datetime.utcnow().isoformat(), progress=10)
    try:
        from nexus_core.agents.pentest_agent import PentestAgent
        llm = getattr(app.state, 'llm', None)
        agent = PentestAgent(llm=llm)

        db_update_task(task_id, progress=20)

        payload = {
            "target": req["target"],
            "path": req["target_path"],
            "name": req["target_name"],
        }
        result = await agent.run(task_id, payload)

        inner = result.get("result", {})
        db_update_task(task_id,
            status="completed" if result.get("success") else "failed",
            progress=100,
            result=str(inner)[:3000],
            completed_at=dt.datetime.utcnow().isoformat()
        )
    except Exception as e:
        db_update_task(task_id, status="failed",
            error=f"{type(e).__name__}: {e}", progress=0)


@router.post("/pentest/run", status_code=202)
async def run_pentest(body: PentestRequest,
                       background: BackgroundTasks,
                       request: Request,
                       current_user: dict = Depends(get_current_user)):
    """Ejecuta pentesting completo — retorna task_id para monitorear."""
    task_id = f"pentest_{uuid.uuid4().hex[:8]}"
    db_create_task({
        "id": task_id,
        "name": f"Pentest: {body.target_name}",
        "description": f"Target: {body.target} | Scope: {body.scope}",
        "task_type": "unique",
        "priority": "crítica",
        "payload": body.model_dump(),
    })
    background.add_task(_run_pentest, task_id, body.model_dump(), request.app)
    return {
        "task_id": task_id,
        "target": body.target,
        "target_name": body.target_name,
        "status": "running",
        "message": f"Pentesting iniciado — monitorea en GET /pentest/status/{task_id}",
        "phases": ["reconocimiento", "sast", "secrets", "stride", "reporte"],
    }


@router.get("/pentest/status/{task_id}")
def pentest_status(task_id: str):
    task = db_get_task(task_id)
    if not task:
        raise HTTPException(404, f"Tarea '{task_id}' no encontrada")
    return task


@router.get("/pentest/reports")
def list_reports():
    """Lista todos los reportes generados."""
    reports = []
    for f in sorted(REPORTS_DIR.glob("*.md"), reverse=True):
        stat = f.stat()
        reports.append({
            "filename": f.name,
            "path": str(f),
            "size_kb": round(stat.st_size / 1024, 1),
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        })
    return {"reports": reports, "total": len(reports)}


@router.get("/pentest/reports/{filename}")
def get_report(filename: str):
    """Lee un reporte específico."""
    path = REPORTS_DIR / filename
    if not path.exists():
        raise HTTPException(404, f"Reporte '{filename}' no encontrado")
    return {
        "filename": filename,
        "content": path.read_text(encoding="utf-8"),
        "size_kb": round(path.stat().st_size / 1024, 1),
    }


@router.post("/pentest/quick-scan")
async def quick_scan(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Scan rápido de la propia instancia NEXUS."""
    from nexus_core.agents.pentest_agent import SecurityScanner
    target = "localhost:8000"
    nmap = await SecurityScanner.nmap_scan(target, "-sV --top-ports 100 -T4")
    http = await SecurityScanner.http_fingerprint("http://localhost:8000")
    secrets = await SecurityScanner.scan_secrets(str(NEXUS_ROOT / "nexus_api"))
    return {
        "target": target,
        "nmap": nmap,
        "http_headers": http,
        "secrets": secrets,
        "timestamp": datetime.utcnow().isoformat(),
    }
```

#### nexus_api/routes/composite.py

```python
"""Composite Tools API — Capacidades de alto nivel para Junior."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from nexus_api.auth.deps import require_operator

router = APIRouter(dependencies=[Depends(require_operator)])

class ExploreRequest(BaseModel):
    query: str
    base_path: Optional[str] = None
    file_type: Optional[str] = "*.py"

class AnalyzeRequest(BaseModel):
    project_path: str

class PatchRequest(BaseModel):
    filepath: str
    description: str
    old_text: str
    new_text: str
    auto_test: Optional[bool] = True

@router.post("/explore")
async def explore_filesystem(req: ExploreRequest):
    """Explorar y encontrar archivos relevantes en UNA operación."""
    from nexus_core.composite_tools import explore_filesystem
    return await explore_filesystem(req.query, req.base_path, req.file_type)

@router.post("/analyze")
async def analyze_project(req: AnalyzeRequest):
    """Análisis completo de un proyecto."""
    from nexus_core.composite_tools import analyze_project
    return await analyze_project(req.project_path)

@router.post("/patch")
async def smart_patch(req: PatchRequest):
    """Patch quirúrgico con backup + verificación + test automático."""
    from nexus_core.composite_tools import smart_patch
    return await smart_patch(req.filepath, req.description,
                              req.old_text, req.new_text, req.auto_test)

@router.get("/health")
async def system_health():
    """Check completo del sistema en UNA llamada."""
    from nexus_core.composite_tools import system_health_check
    return await system_health_check()
```

#### nexus_api/routes/models.py

```python
"""
NEXUS PRO — Models & API Keys
Agrega API keys → detecta modelos disponibles automáticamente
"""
import uuid
import httpx
import asyncio
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from nexus_api.auth.deps import get_current_user, require_admin
from nexus_api.db.database import db_list_keys, db_create_key, db_update_key, db_delete_key
from nexus_api.config import NEXUS_DB_PATH

router = APIRouter(dependencies=[Depends(get_current_user)])

# Modelos conocidos por provider
PROVIDER_MODELS = {
    "openai": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo", "o1-preview", "o1-mini"],
    "anthropic": ["claude-opus-4-5", "claude-sonnet-4-5", "claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-haiku-20240307"],
    "google": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash", "gemini-pro"],
    "groq": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768", "gemma2-9b-it"],
    "together": ["meta-llama/Llama-3-70b-chat-hf", "mistralai/Mixtral-8x7B-Instruct-v0.1"],
    "ollama": ["llama3", "mistral", "codellama", "phi3", "gemma2"],
}

async def _detect_models_real(key_id: str, provider: str, api_key: str):
    """Detecta modelos reales haciendo una llamada de prueba al proveedor."""
    models = PROVIDER_MODELS.get(provider.lower(), [])
    status = "ok"

    try:
        if provider.lower() == "openai":
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get("https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"})
                if r.status_code == 200:
                    data = r.json()
                    gpt_models = sorted([m['id'] for m in data.get('data', []) if 'gpt' in m['id'] or 'o1' in m['id']])
                    models = gpt_models[:15] if gpt_models else models
                else:
                    status = "invalid_key"

        elif provider.lower() == "anthropic":
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get("https://api.anthropic.com/v1/models",
                    headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"})
                if r.status_code == 200:
                    data = r.json()
                    models = [m['id'] for m in data.get('data', [])]
                else:
                    status = "invalid_key"

        elif provider.lower() == "groq":
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get("https://api.groq.com/openai/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"})
                if r.status_code == 200:
                    data = r.json()
                    models = [m['id'] for m in data.get('data', [])]
                else:
                    status = "invalid_key"

        elif provider.lower() == "ollama":
            async with httpx.AsyncClient(timeout=5) as client:
                base = api_key if api_key.startswith("http") else "http://localhost:11434"
                r = await client.get(f"{base}/api/tags")
                if r.status_code == 200:
                    data = r.json()
                    models = [m['name'] for m in data.get('models', [])]
                else:
                    status = "unreachable"

    except Exception as e:
        status = "ok"  # usar modelos conocidos si falla la detección

    db_update_key(key_id, models=models, status=status)


class AddKeyRequest(BaseModel):
    alias: str
    provider: str   # openai | anthropic | google | groq | together | ollama
    api_key: str

@router.get("/models/keys")
def list_keys():
    """Lista todas las API keys configuradas (con key enmascarada)."""
    keys = db_list_keys()
    # Nunca exponer la key real
    for k in keys:
        k.pop('key_value', None)
    return keys

@router.get("/models/available")
def available_models():
    """Retorna todos los modelos disponibles según las keys configuradas."""
    keys = db_list_keys()
    all_models = []
    for k in keys:
        if k['status'] == 'ok':
            for m in k.get('models', []):
                all_models.append({
                    "model": m,
                    "provider": k['provider'],
                    "key_alias": k['alias'],
                    "key_id": k['id'],
                })
    return {"models": all_models, "total": len(all_models)}

@router.post("/models/keys", status_code=201)
async def add_key(
    body: AddKeyRequest,
    background: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
):
    """Agrega una API key y detecta modelos disponibles en background."""
    key_id = f"key_{uuid.uuid4().hex[:8]}"

    # Enmascarar la key para mostrar
    k = body.api_key
    if len(k) > 12:
        masked = k[:8] + "••••••••" + k[-4:]
    else:
        masked = "••••••••••••"

    data = {
        "id": key_id,
        "alias": body.alias,
        "provider": body.provider.lower(),
        "key_masked": masked,
        "key_value": body.api_key,
        "models": PROVIDER_MODELS.get(body.provider.lower(), []),
        "status": "detecting",
    }
    db_create_key(data)

    # Detectar modelos reales en background
    background.add_task(_detect_models_real, key_id, body.provider, body.api_key)

    data.pop('key_value')
    return {"id": key_id, "message": f"API key de {body.provider} agregada — detectando modelos...", **data}

@router.post("/models/keys/{key_id}/detect")
async def redetect_models(
    key_id: str,
    background: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
):
    """Re-detecta modelos para una key existente."""
    keys = db_list_keys()
    key = next((k for k in keys if k['id'] == key_id), None)
    if not key:
        raise HTTPException(404, "API key no encontrada")

    # Necesitamos la key real de la DB
    import sqlite3
    from pathlib import Path
    conn = sqlite3.connect(NEXUS_DB_PATH)
    row = conn.execute("SELECT key_value FROM api_keys WHERE id=?", (key_id,)).fetchone()
    conn.close()
    if row:
        background.add_task(_detect_models_real, key_id, key['provider'], row[0])

    return {"message": "Detección iniciada", "key_id": key_id}

@router.delete("/models/keys/{key_id}")
def delete_key(
    key_id: str,
    current_user: dict = Depends(require_admin),
):
    db_delete_key(key_id)
    return {"deleted": key_id}

@router.get("/models/catalog")
def model_catalog():
    """Catálogo completo de modelos conocidos por provider."""
    return PROVIDER_MODELS
```

#### nexus_api/routes/__init__.py

```python

```

#### Lista de todos los archivos en nexus_api/routes

| Archivo | Líneas |
|---|---|
| nexus_api/routes/__init__.py | 0 |
| nexus_api/routes/a2a.py | 98 |
| nexus_api/routes/agents.py | 158 |
| nexus_api/routes/approvals.py | 39 |
| nexus_api/routes/audit.py | 26 |
| nexus_api/routes/auth.py | 100 |
| nexus_api/routes/composite.py | 50 |
| nexus_api/routes/connectors.py | 93 |
| nexus_api/routes/directory.py | 253 |
| nexus_api/routes/docagent.py | 65 |
| nexus_api/routes/evolution.py | 101 |
| nexus_api/routes/factory.py | 398 |
| nexus_api/routes/guardian.py | 37 |
| nexus_api/routes/hitl.py | 160 |
| nexus_api/routes/jarvis.py | 412 |
| nexus_api/routes/junior.py | 231 |
| nexus_api/routes/killswitch.py | 77 |
| nexus_api/routes/memory.py | 95 |
| nexus_api/routes/models.py | 177 |
| nexus_api/routes/nexus.py | 25 |
| nexus_api/routes/packages.py | 43 |
| nexus_api/routes/pentest.py | 139 |
| nexus_api/routes/plans.py | 78 |
| nexus_api/routes/policies.py | 69 |
| nexus_api/routes/project_manager.py | 56 |
| nexus_api/routes/projects.py | 197 |
| nexus_api/routes/scheduler.py | 76 |
| nexus_api/routes/sovereign.py | 290 |
| nexus_api/routes/tasks.py | 164 |
| nexus_api/routes/teams_v2.py | 101 |
| nexus_api/routes/testagent.py | 52 |
| nexus_api/routes/tools.py | 58 |
| nexus_api/routes/workflows.py | 94 |
| nexus_api/routes/ws_logs.py | 142 |


### CLI y worker

#### nexus_cli.py

```python
"""Token-free administrative and debugging CLI for NEXUS."""

from __future__ import annotations

import argparse
import asyncio
import json

from nexus_core.config import NEXUS_DB_PATH
from nexus_core.kernel.store_factory import get_control_store
from nexus_core.llm.abstraction import LLMConfig, LLMFactory, LLMMessage, LLMProvider


def output(value) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(prog="nexus", description="BAJIOWARE NEXUS CLI")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    list_parser = commands.add_parser("list")
    list_parser.add_argument("resource", choices=("tenants", "agents", "tools"))
    list_parser.add_argument("--tenant", default="system")
    fake = commands.add_parser("fake-llm")
    fake.add_argument("message")
    fake.add_argument("--scenario", default="echo")
    goal = commands.add_parser("submit-goal")
    goal.add_argument("goal")
    goal.add_argument("--tenant", default="system")
    goal.add_argument("--idempotency-key", required=True)
    debug_task = commands.add_parser("enqueue-debug")
    debug_task.add_argument("message")
    debug_task.add_argument("--scenario", default="echo")
    debug_task.add_argument("--tenant", default="system")
    debug_task.add_argument("--idempotency-key", required=True)
    args = parser.parse_args()

    store = get_control_store(NEXUS_DB_PATH)
    store.initialize()
    if args.command == "status":
        output({"status": "ready", "database": str(NEXUS_DB_PATH), "offline_llm": True})
    elif args.command == "list":
        if args.resource == "tenants":
            output(store.list_tenants())
        else:
            table = "kernel_agents" if args.resource == "agents" else "kernel_tools"
            output(store.list_definitions(table, args.tenant))
    elif args.command == "fake-llm":
        client = LLMFactory.create(LLMConfig(provider=LLMProvider.FAKE, model="nexus-fake-v1"))
        response = asyncio.run(client.complete(
            [LLMMessage(role="user", content=args.message)], scenario=args.scenario
        ))
        output({"content": response.content, "provider": response.provider.value})
    elif args.command == "submit-goal":
        output(store.create_run(
            args.tenant, {"goal": args.goal, "source": "cli"}, args.idempotency_key
        ))
    elif args.command == "enqueue-debug":
        run = store.create_run(
            args.tenant, {"source": "cli"}, args.idempotency_key
        )
        output(store.enqueue_task(
            tenant_id=args.tenant,
            run_id=run["id"],
            task_type="debug.fake_llm",
            payload={"message": args.message, "scenario": args.scenario},
        ))


if __name__ == "__main__":
    main()
```

#### nexus_worker.py

```python
"""Durable NEXUS Sovereign worker."""

from __future__ import annotations

import argparse
import asyncio
import os
import socket
import time

from nexus_core.config import NEXUS_DB_PATH
from nexus_core.kernel.runtime import ExecutionContext, build_default_registry
from nexus_core.kernel.store_factory import get_control_store
from nexus_core.kernel.workflows import DurableWorkflowEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="NEXUS durable worker")
    parser.add_argument("--once", action="store_true", help="Claim at most one task")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    args = parser.parse_args()
    worker_id = os.getenv("NEXUS_WORKER_ID", f"{socket.gethostname()}-{os.getpid()}")
    store = get_control_store(NEXUS_DB_PATH)
    store.initialize()
    registry = build_default_registry()

    while True:
        task = store.claim_task(worker_id)
        if task:
            try:
                context = ExecutionContext(store=store, task=task, worker_id=worker_id)
                result = asyncio.run(asyncio.wait_for(
                    registry.execute(task, context), timeout=task["timeout_seconds"]
                ))
                store.complete_task(task["id"], worker_id, result=result)
            except Exception as exc:
                store.append_run_event(task["tenant_id"], task["run_id"], "task.failed",
                                       {"task_id": task["id"],
                                        "error_type": type(exc).__name__,
                                        "error": str(exc)[:1000]})
                store.fail_or_retry_task(task["id"], worker_id, str(exc))
            run = store.get_run(task["run_id"], task["tenant_id"])
            if run and run.get("workflow_id"):
                DurableWorkflowEngine(store).reconcile(task["run_id"], task["tenant_id"])
        if args.once:
            return
        if not task:
            time.sleep(max(0.1, args.poll_seconds))


if __name__ == "__main__":
    main()
```

#### nexus_core/main.py

```python
"""
NEXUS CORE ALPHA v1.0.0
BajioWare AI Orchestration Engine

Este script es un demo funcional de NEXUS, mostrando cómo integrar y ejecutar agentes
en un entorno orquestado. Para ejecutar este demo, simplemente ejecute este archivo
usando Python 3.11+.

Uso:
    python -m nexus_core.main
"""

import os
import asyncio
from dotenv import load_dotenv

from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
from nexus_core.core.event_bus import EventBus
from nexus_core.core.orchestrator import NexusOrchestrator, OrchestratorConfig
from nexus_core.state.manager import StateManager
from nexus_core.agents.registry import AgentRegistry
from nexus_core.utils.logger import NexusLogger
from nexus_core.core.agent_factory import AgentFactory
from nexus_core.core.planner import NexusPlanner
from nexus_core.llm.gemini_provider import GeminiProvider
from nexus_core.core.agent_generator import AgentGenerator

# 👇 imports de skills
from nexus_core.skills.registry import SkillRegistry
from nexus_core.skills.file_reader import FileReaderSkill
from nexus_core.skills.http_client import HttpClientSkill
from nexus_core.skills.nmap_scan import NmapScanSkill
from nexus_core.skills.nuclei_scan import NucleiScanSkill

# 👇 import de memoria
from nexus_core.memory.manager import MemoryManager
from nexus_core.vector.memory import VectorMemory

load_dotenv()

gemini_api_key = os.getenv("GEMINI_API_KEY")
openai_api_key = os.getenv("OPENAI_API_KEY")


class DataAnalystAgent(BaseAgent):
    async def execute(self, task_id, payload) -> dict:
        await asyncio.sleep(1.0)
        return {"analysis": "completed", "records": 1500, "anomalies": 3}


class ReportGeneratorAgent(BaseAgent):
    async def execute(self, task_id, payload) -> dict:
        await asyncio.sleep(0.5)
        return {"report_url": "/output/report.pdf", "pages": 12}


class SecurityAuditAgent(BaseAgent):
    _fail_count: int = 0

    async def execute(self, task_id, payload) -> dict:
        if self._fail_count == 0:
            self._fail_count += 1
            raise RuntimeError("Conexión rechazada — simulando fallo")
        return {"vulnerabilities": 0, "score": 98}


async def main():
    logger = NexusLogger("NEXUS")
    logger.info("EventBus started")
    event_bus = EventBus()
    state_manager = StateManager()
    logger.info("StateManager initialized (phase: 1)")
    agent_registry = AgentRegistry()

    # 👇 inicializamos memoria
    memory_manager = MemoryManager()
    logger.info("Memory system initialized")

    vector_memory = VectorMemory()
    logger.info("Vector memory initialized")

    # 👇 probamos memoria
    memory_manager.remember_task(
        "demo-task",
        {
            "goal": "scan example.com",
            "result": "ports 80,443"
        }
    )
    memory = memory_manager.recall_task("demo-task")
    print("Memory recall:", memory)

    vector_memory.add_memory(
        "scan example.com found ports 80 and 443",
        {"target": "example.com"}
    )

    vector_memory.add_memory(
        "scan internal server found port 22 open",
        {"target": "internal"}
    )

    results = vector_memory.search_memory(
        "ports discovered on example"
    )

    print("Vector search:", results)

    # 👇 inicializamos LLM provider y AgentGenerator
    llm_provider = GeminiProvider(api_key=gemini_api_key)
    agent_generator = AgentGenerator(llm_provider, logger)

    agent_factory = AgentFactory(agent_registry, logger, agent_generator)
    planner = NexusPlanner(agent_registry, agent_factory, logger)

    orchestrator_config = OrchestratorConfig()
    orchestrator = NexusOrchestrator(
        config=orchestrator_config,
        state_manager=state_manager,
        agent_registry=agent_registry,
        event_bus=event_bus,
        logger=logger
    )

    # 👇 inicializamos SkillRegistry y registramos skills
    skill_registry = SkillRegistry()
    skill_registry.register(FileReaderSkill())
    skill_registry.register(HttpClientSkill())
    skill_registry.register(NmapScanSkill())
    skill_registry.register(NucleiScanSkill())
    logger.info(f"Skills loaded: {skill_registry.list_skills()}")

    # 👇 probamos la skill Nmap
    nmap_skill = skill_registry.get("nmap_scan")
    result = await nmap_skill.execute("scanme.nmap.org")

    print("Nmap result:", result["scan_result"][:500])

    # 👇 guardamos el resultado en memoria vectorial
    vector_memory.add_memory(
        result["scan_result"],
        {"target": "scanme.nmap.org", "type": "port_scan"}
    )

    # 👇 probamos una skill
    file_skill = skill_registry.get("file_reader")
    result = await file_skill.execute(path="nexus_core/README.md")
    print("Skill result:", result)

    # Registro de agentes estáticos
    metadata = AgentMetadata(name="Data Analyst", capabilities=[AgentCapability.DATA_ANALYSIS])
    await agent_registry.register(DataAnalystAgent(metadata=metadata))
    logger.info("Agent registered: DataAnalystAgent")

    metadata = AgentMetadata(name="Report Generator", capabilities=[AgentCapability.REPORT_GENERATION])
    await agent_registry.register(ReportGeneratorAgent(metadata=metadata))
    logger.info("Agent registered: ReportGeneratorAgent")

    metadata = AgentMetadata(name="Security Audit", capabilities=[AgentCapability.SECURITY_AUDIT])
    await agent_registry.register(SecurityAuditAgent(metadata=metadata))
    logger.info("Agent registered: SecurityAuditAgent")

    # Agente dinámico
    dynamic_agent = await agent_factory.create_agent(
        "Log Analyzer",
        AgentCapability.DATA_ANALYSIS
    )
    logger.info("Dynamic agent created: Log Analyzer")

    await orchestrator.start()
    logger.info("Planner demo: ejecutando Goal...")

    goal = "analyze sales data and generate report"
    tasks = await planner.plan(goal)
    await planner.ensure_agents(tasks)

    task_ids = []
    for t in tasks:
        task_id = await orchestrator.dispatch(
            t["task"],
            t["payload"],
            t["capability"].value,
            priority=3
        )
        task_ids.append(task_id)

    for task_id in task_ids:
        await orchestrator.wait_for_task(task_id)

    logger.info("All tasks completed.")

    status = orchestrator.get_status()
    print("════════════════════════════════════════")
    print(f"status:           {status['status']}")
    print(f"queue_size:       {status['queue_size']}")
    print(f"active_tasks:     {status['active_tasks']}")
    print(f"completed_tasks:  {status['completed_count']}")
    print("════════════════════════════════════════")

    await orchestrator.stop()


if __name__ == "__main__":
    asyncio.run(main())
```

### MCP

```text
nexus_mcp/__init__.py
nexus_mcp/server.py
nexus_mcp/tests/__init__.py
nexus_mcp/tests/smoke.py
nexus_mcp/tests/test_remote_security.py
```

### nexus_mcp/server.py — 188 líneas

```python
"""Official-SDK MCP gateway for local development and approved clients.

Run over stdio:
    python -m nexus_mcp.server

Run Streamable HTTP locally:
    NEXUS_MCP_TRANSPORT=streamable-http python -m nexus_mcp.server
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl

from nexus_core.config import NEXUS_DB_PATH
from nexus_core.kernel.store_factory import get_control_store
from nexus_core.llm.abstraction import LLMConfig, LLMFactory, LLMMessage, LLMProvider

store = get_control_store(NEXUS_DB_PATH)
store.initialize()

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True,
    openWorldHint=False,
)
WRITE_IDEMPOTENT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True,
    openWorldHint=False,
)


def is_remote_transport() -> bool:
    return os.getenv("NEXUS_MCP_TRANSPORT", "stdio") == "streamable-http"


def validate_remote_configuration(host: str) -> None:
    """Fail closed before binding a remotely reachable MCP listener."""
    if host in {"127.0.0.1", "localhost", "::1"}:
        return
    environment = os.getenv("NEXUS_ENV", "development").strip().lower()
    local_container = (
        os.getenv("NEXUS_MCP_TRUST_LOCAL_CONTAINER", "false").lower() == "true"
    )
    if local_container:
        if environment == "production":
            raise SystemExit("NEXUS_MCP_TRUST_LOCAL_CONTAINER is forbidden in production")
        return
    issuer = os.getenv("OIDC_ISSUER", "").strip()
    public_url = os.getenv("NEXUS_MCP_PUBLIC_URL", "").strip()
    audience = os.getenv("OIDC_AUDIENCE", "").strip()
    for label, value in (("OIDC_ISSUER", issuer), ("NEXUS_MCP_PUBLIC_URL", public_url)):
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.fragment:
            raise SystemExit(f"{label} must be an HTTPS URL without credentials or fragments")
    if not audience:
        raise SystemExit("OIDC_AUDIENCE is required for remote MCP token audience binding")


class NexusOIDCTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            from nexus_api.auth.oidc import oidc_verifier
            claims = await oidc_verifier.verify(token)
            import jwt
            raw_claims = jwt.decode(token, options={"verify_signature": False})
            scopes = raw_claims.get("scope", "").split()
            return AccessToken(
                token=token, client_id=str(raw_claims.get("client_id", raw_claims["sub"])),
                scopes=scopes, subject=str(raw_claims["sub"]),
                expires_at=raw_claims.get("exp"), claims={**raw_claims, **claims},
            )
        except Exception:
            return None


def build_server() -> MCPServer:
    kwargs: dict[str, Any] = {}
    issuer = os.getenv("OIDC_ISSUER", "").strip()
    public_url = os.getenv("NEXUS_MCP_PUBLIC_URL", "").strip()
    if issuer or public_url:
        if not issuer or not public_url:
            raise RuntimeError("OIDC_ISSUER and NEXUS_MCP_PUBLIC_URL must be configured together")
        kwargs = {
            "token_verifier": NexusOIDCTokenVerifier(),
            "auth": AuthSettings(
                issuer_url=AnyHttpUrl(issuer), resource_server_url=AnyHttpUrl(public_url),
                required_scopes=["nexus:read"],
            ),
        }
    return MCPServer(
        "bajioware-nexus", title="BAJIOWARE NEXUS", version="0.5.0",
        instructions=(
        "NEXUS is an enterprise agent directory and execution control plane. "
        "Tools exposed here are tenant-scoped and read-only unless explicitly documented."
        ), **kwargs,
    )


mcp = build_server()


def tenant() -> str:
    access = get_access_token()
    if access and access.claims and access.claims.get("tenant_id"):
        return str(access.claims["tenant_id"])
    return os.getenv("NEXUS_MCP_TENANT", "system")


@mcp.tool(annotations=READ_ONLY)
async def nexus_status() -> dict[str, Any]:
    """Return the health and offline-development capabilities of NEXUS."""
    return {
        "status": "ready",
        "tenant_id": tenant(),
        "offline_llm": True,
        "gateways": ["mcp", "rest", "cli"],
    }


@mcp.tool(annotations=READ_ONLY)
async def list_nexus_agents() -> list[dict[str, Any]]:
    """List registered agent definitions for the configured tenant."""
    return store.list_definitions("kernel_agents", tenant())


@mcp.tool(annotations=READ_ONLY)
async def list_nexus_tools() -> list[dict[str, Any]]:
    """List registered tool definitions for the configured tenant."""
    return store.list_definitions("kernel_tools", tenant())


@mcp.tool(annotations=READ_ONLY)
async def debug_with_fake_llm(message: str, scenario: str = "echo") -> dict[str, Any]:
    """Exercise the NEXUS model contract without consuming API tokens."""
    client = LLMFactory.create(LLMConfig(provider=LLMProvider.FAKE, model="nexus-fake-v1"))
    response = await client.complete(
        [LLMMessage(role="user", content=message)], scenario=scenario
    )
    return {
        "content": response.content,
        "provider": response.provider.value,
        "tokens_are_estimated": True,
        "tokens": response.total_tokens,
    }


@mcp.tool(annotations=WRITE_IDEMPOTENT)
async def submit_nexus_goal(goal: str, idempotency_key: str) -> dict[str, Any]:
    """Create a durable pending run; workers execute it only after policy checks."""
    if is_remote_transport():
        if os.getenv("NEXUS_MCP_ENABLE_WRITE_TOOLS", "false").lower() != "true":
            raise PermissionError("remote MCP write tools are disabled")
        access = get_access_token()
        if not access or "nexus:write" not in access.scopes:
            raise PermissionError("nexus:write scope is required")
    if not goal.strip():
        raise ValueError("goal is required")
    return store.create_run(
        tenant(), {"goal": goal, "source": "mcp"}, idempotency_key=idempotency_key
    )


def main() -> None:
    transport = os.getenv("NEXUS_MCP_TRANSPORT", "stdio")
    if transport not in {"stdio", "streamable-http"}:
        raise SystemExit("NEXUS_MCP_TRANSPORT must be stdio or streamable-http")
    if transport == "streamable-http":
        host = os.getenv("NEXUS_MCP_HOST", "127.0.0.1")
        validate_remote_configuration(host)
        mcp.run(
            transport="streamable-http", host=host,
            port=int(os.getenv("NEXUS_MCP_PORT", "8000")),
            json_response=True, stateless_http=True, max_request_body_size=4 * 1024 * 1024,
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
```

### nexus_mcp/tests/test_remote_security.py — 42 líneas

```python
"""Remote MCP must fail closed unless its public identity is complete."""

import os
from unittest.mock import patch

import pytest

from nexus_mcp.server import validate_remote_configuration


def test_loopback_needs_no_remote_identity() -> None:
    validate_remote_configuration("127.0.0.1")


def test_remote_rejects_local_trust_in_production() -> None:
    with patch.dict(os.environ, {
        "NEXUS_ENV": "production",
        "NEXUS_MCP_TRUST_LOCAL_CONTAINER": "true",
    }, clear=True):
        with pytest.raises(SystemExit, match="forbidden"):
            validate_remote_configuration("0.0.0.0")


def test_remote_requires_https_and_audience() -> None:
    with patch.dict(os.environ, {
        "NEXUS_ENV": "production",
        "OIDC_ISSUER": "http://identity.example.test",
        "NEXUS_MCP_PUBLIC_URL": "https://mcp.example.test/mcp",
        "OIDC_AUDIENCE": "https://mcp.example.test/mcp",
    }, clear=True):
        with pytest.raises(SystemExit, match="OIDC_ISSUER must be an HTTPS URL"):
            validate_remote_configuration("0.0.0.0")


def test_remote_accepts_complete_public_identity() -> None:
    with patch.dict(os.environ, {
        "NEXUS_ENV": "production",
        "OIDC_ISSUER": "https://identity.example.test",
        "NEXUS_MCP_PUBLIC_URL": "https://mcp.example.test/mcp",
        "OIDC_AUDIENCE": "https://mcp.example.test/mcp",
    }, clear=True):
        validate_remote_configuration("0.0.0.0")
```

### nexus_mcp/tests/smoke.py — 34 líneas

```python
"""In-memory MCP protocol smoke without a network port or paid model."""

import asyncio
import os
import tempfile
from pathlib import Path


async def smoke() -> None:
    with tempfile.TemporaryDirectory() as directory:
        os.environ.update({
            "NEXUS_DB_PATH": str(Path(directory) / "mcp.db"),
            "NEXUS_ENV": "development",
            "NEXUS_MCP_TENANT": "system",
        })
        from mcp import Client

        from nexus_mcp.server import mcp, store

        store.initialize()
        async with Client(mcp) as client:
            tools = await client.list_tools()
            names = {tool.name for tool in tools.tools}
            assert {"nexus_status", "debug_with_fake_llm", "submit_nexus_goal"} <= names
            status = await client.call_tool("nexus_status", {})
            fake = await client.call_tool(
                "debug_with_fake_llm", {"message": "hola", "scenario": "echo"}
            )
            assert not status.is_error
            assert not fake.is_error


if __name__ == "__main__":
    asyncio.run(smoke())
```

### Configuración

#### .env.example

```
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Variables de Entorno                          ║
# ║  cp .env.example .env → editar con tus keys               ║
# ╚══════════════════════════════════════════════════════════════╝

# ── LLM API Keys ─────────────────────────────────────────────
# Las API keys son opcionales. El proveedor fake permite desarrollo offline.
OPENAI_API_KEY=
GEMINI_API_KEY=
ANTHROPIC_API_KEY=
GROQ_API_KEY=
GROQ_BASE_URL=https://api.groq.com/openai/v1
GROQ_MODEL=llama-3.3-70b-versatile

# Modelo por defecto para agentes
LLM_PROVIDER=fake
FAKE_LLM_MODEL=nexus-fake-v1
NEXUS_LLM_FIXTURES=nexus_core/llm/fixtures/responses.json
DEFAULT_LLM_MODEL=nexus-fake-v1
FALLBACK_LLM_MODEL=

# ── NEXUS Core ───────────────────────────────────────────────
# development | production
NEXUS_ENV=development
# Raíz del proyecto. Las rutas relativas de abajo se resuelven desde aquí.
NEXUS_ROOT=.
NEXUS_DATA_PATH=data
NEXUS_DB_PATH=data/nexus_pro.db
# PostgreSQL es obligatorio en producción para el nuevo control plane.
DATABASE_URL=
POSTGRES_PASSWORD=
# Compatibilidad con despliegues anteriores; preferir NEXUS_DATA_PATH.
NEXUS_DATA_DIR=data
# debug | info | warning | error
NEXUS_LOG_LEVEL=info
NEXUS_OCI_RUNTIME=docker
NEXUS_SANDBOX_IMAGES=python:3.12-alpine
# Solo para migración local temporal. Nunca funciona en production.
NEXUS_ENABLE_LEGACY_EXECUTION=false
NEXUS_ENABLE_LEGACY_RUNTIME=false
NEXUS_API_WORKERS=2
# Solo permite fallback explícito entre proveedores configurados.
NEXUS_ALLOW_MODEL_FALLBACK=false
NEXUS_WORKSPACE_ROOT=/nexus/data/workspaces
OTEL_SERVICE_NAME=nexus
OTEL_EXPORTER_OTLP_ENDPOINT=

# ── JWT Auth (Punto 7) ───────────────────────────────────────
JWT_SECRET_KEY=
JWT_ALGORITHM=HS256
JWT_ISSUER=nexus
JWT_AUDIENCE=nexus-api
# OIDC empresarial opcional. Vacío conserva identidad local.
OIDC_ISSUER=
OIDC_AUDIENCE=nexus-api
OIDC_TENANT_CLAIM=tenant_id
OIDC_ROLE_CLAIM=nexus_role
NEXUS_MCP_PUBLIC_URL=
NEXUS_MCP_HOST=127.0.0.1
NEXUS_MCP_PORT=8000
# Remoto: apagado por defecto. Requiere nexus:write además de esta bandera.
NEXUS_MCP_ENABLE_WRITE_TOOLS=false
# Gateway HTTPS para Claude web.
NEXUS_MCP_SERVER_NAME=mcp.example.com
NEXUS_MCP_TLS_PORT=8444
NEXUS_MCP_TLS_DIR=
# 8 horas
JWT_EXPIRE_MINUTES=480

# ── Admin por defecto ────────────────────────────────────────
NEXUS_ADMIN_EMAIL=
NEXUS_ADMIN_PASSWORD=
NEXUS_ADMIN_NAME=Admin

# ── Puertos ──────────────────────────────────────────────────
NEXUS_BACKEND_PORT=8000
NEXUS_PUBLIC_URL=http://localhost:8000
NEXUS_FRONTEND_PORT=3000
NEXUS_CONNECTOR_TLS_PORT=8443
NEXUS_CONNECTOR_PKI_DIR=
NEXUS_CONNECTOR_PROXY_SECRET=

# ── URLs para el frontend ────────────────────────────────────
# Producción: usar dominio real
# VITE_API_URL=https://nexus.tudominio.com/api
# VITE_WS_URL=wss://nexus.tudominio.com

# Desarrollo local
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
VITE_ENABLE_LEGACY_UI=false
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# ── Pentest ──────────────────────────────────────────────────
PENTEST_REPORTS_DIR=/nexus/data/reports
PENTEST_WORKSPACE=/nexus/data/pentest

# ── Rate Limiting ────────────────────────────────────────────
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_BURST=10

# ── Notificaciones (opcional) ────────────────────────────────
# SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
# TELEGRAM_BOT_TOKEN=...
# TELEGRAM_CHAT_ID=...
```

#### requirements-prod.in

```
-r nexus_api/requirements.txt
-r nexus_core/requirements.txt
```

#### requirements-dev.txt

```
-r nexus_api/requirements.txt
-r nexus_core/requirements.txt
ruff>=0.6,<1
mypy>=1.11,<2
pip-audit>=2.7,<3
```

#### ruff.toml

```toml
target-version = "py312"
line-length = 100

[lint.per-file-ignores]
"nexus_api/main.py" = ["E402"]
```

#### docker-compose.yml

```yaml
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — docker-compose.yml                            ║
# ║  Servicios: backend · frontend · chromadb                  ║
# ╚══════════════════════════════════════════════════════════════╝
version: "3.9"

x-logging: &default-logging
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"

services:

  # ── Backend FastAPI + nexus_core ─────────────────────────────
  backend:
    build:
      context: .
      dockerfile: Dockerfile.backend
    container_name: nexus-backend
    restart: unless-stopped
    env_file: .env
    environment:
      - NEXUS_DB_PATH=/nexus/data/nexus_pro.db
      - NEXUS_DATA_DIR=/nexus/data
      - DATABASE_URL=postgresql://nexus:${POSTGRES_PASSWORD}@postgres:5432/nexus
      - NEXUS_ENV=production
      - LOG_LEVEL=info
    volumes:
      # Datos persistentes — surviven rebuilds
      - nexus_data:/nexus/data
      # Hot-reload del código en desarrollo
      # Comentar en producción:
      # - ./nexus_api:/nexus/nexus_api
      # - ./nexus_core:/nexus/nexus_core
    ports:
      - "127.0.0.1:${NEXUS_BACKEND_PORT:-8000}:8000"
    depends_on:
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 40s
    logging: *default-logging
    networks:
      - nexus_net
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
    security_opt:
      - no-new-privileges:true
    cap_drop: ["ALL"]

  # ── Frontend React → nginx ────────────────────────────────────
  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend
      args:
        - VITE_API_URL=${VITE_API_URL:-http://localhost:8000}
        - VITE_WS_URL=${VITE_WS_URL:-ws://localhost:8000}
    container_name: nexus-frontend
    restart: unless-stopped
    ports:
      - "${NEXUS_FRONTEND_PORT:-3000}:80"
    depends_on:
      backend:
        condition: service_healthy
    logging: *default-logging
    networks:
      - nexus_net

  worker:
    build:
      context: .
      dockerfile: Dockerfile.backend
    restart: unless-stopped
    env_file: .env
    environment:
      - NEXUS_DB_PATH=/nexus/data/nexus_pro.db
      - NEXUS_DATA_DIR=/nexus/data
      - DATABASE_URL=postgresql://nexus:${POSTGRES_PASSWORD}@postgres:5432/nexus
      - NEXUS_ENV=production
    entrypoint: ["python", "/nexus/nexus_worker.py"]
    volumes:
      - nexus_data:/nexus/data
    depends_on:
      backend:
        condition: service_healthy
    logging: *default-logging
    networks:
      - nexus_net
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
    security_opt:
      - no-new-privileges:true
    cap_drop: ["ALL"]

  mcp:
    build:
      context: .
      dockerfile: Dockerfile.backend
    profiles: ["mcp-local"]
    restart: unless-stopped
    env_file: .env
    environment:
      - NEXUS_ENV=development
      - NEXUS_DB_PATH=/nexus/data/nexus_pro.db
      - NEXUS_MCP_TRANSPORT=streamable-http
      - NEXUS_MCP_HOST=0.0.0.0
      - NEXUS_MCP_PORT=8000
      - NEXUS_MCP_PUBLIC_URL=${NEXUS_MCP_PUBLIC_URL:-}
      # Safe only because the published host port below is bound to 127.0.0.1.
      - NEXUS_MCP_TRUST_LOCAL_CONTAINER=true
      - DATABASE_URL=postgresql://nexus:${POSTGRES_PASSWORD}@postgres:5432/nexus
    entrypoint: ["python", "-m", "nexus_mcp.server"]
    volumes:
      - nexus_data:/nexus/data
    ports:
      - "127.0.0.1:${NEXUS_MCP_PORT:-8002}:8000"
    logging: *default-logging
    networks:
      - nexus_net

  # MCP público: sin puertos directos y con OAuth/OIDC obligatorio.
  mcp-remote:
    build:
      context: .
      dockerfile: Dockerfile.backend
    profiles: ["mcp-remote"]
    restart: unless-stopped
    env_file: .env
    environment:
      - NEXUS_ENV=production
      - NEXUS_DB_PATH=/nexus/data/nexus_pro.db
      - NEXUS_MCP_TRANSPORT=streamable-http
      - NEXUS_MCP_HOST=0.0.0.0
      - NEXUS_MCP_PORT=8000
      - NEXUS_MCP_PUBLIC_URL=${NEXUS_MCP_PUBLIC_URL:?HTTPS public MCP URL is required}
      - OIDC_ISSUER=${OIDC_ISSUER:?OIDC issuer is required}
      - OIDC_AUDIENCE=${OIDC_AUDIENCE:?OIDC audience is required}
      - NEXUS_MCP_ENABLE_WRITE_TOOLS=${NEXUS_MCP_ENABLE_WRITE_TOOLS:-false}
      - DATABASE_URL=postgresql://nexus:${POSTGRES_PASSWORD}@postgres:5432/nexus
    entrypoint: ["python", "-m", "nexus_mcp.server"]
    volumes:
      - nexus_data:/nexus/data
    expose: ["8000"]
    depends_on:
      postgres:
        condition: service_healthy
    logging: *default-logging
    networks:
      - nexus_net
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=32m
    security_opt:
      - no-new-privileges:true
    cap_drop: ["ALL"]

  mcp-gateway:
    image: nginx:1.27-alpine
    profiles: ["mcp-remote"]
    restart: unless-stopped
    ports:
      - "${NEXUS_MCP_TLS_PORT:-8444}:8443"
    volumes:
      - ./docker/mcp-remote.conf.template:/etc/nginx/templates/default.conf.template:ro
      - ${NEXUS_MCP_TLS_DIR:?NEXUS_MCP_TLS_DIR is required}:/etc/nexus/tls:ro
    environment:
      - NEXUS_MCP_SERVER_NAME=${NEXUS_MCP_SERVER_NAME:?MCP domain is required}
    depends_on:
      - mcp-remote
    networks:
      - nexus_net
    read_only: true
    tmpfs:
      - /var/cache/nginx:rw,noexec,nosuid,size=16m
      - /var/run:rw,noexec,nosuid,size=4m
      - /tmp:rw,noexec,nosuid,size=4m
    security_opt:
      - no-new-privileges:true
    cap_drop: ["ALL"]
    cap_add: ["NET_BIND_SERVICE"]

  connector-gateway:
    image: nginx:1.27-alpine
    profiles: ["connector"]
    restart: unless-stopped
    ports:
      - "${NEXUS_CONNECTOR_TLS_PORT:-8443}:8443"
    volumes:
      - ./docker/connector-mtls.conf.template:/etc/nginx/templates/default.conf.template:ro
      - ${NEXUS_CONNECTOR_PKI_DIR:?NEXUS_CONNECTOR_PKI_DIR is required}:/etc/nexus/pki:ro
    environment:
      - NEXUS_CONNECTOR_PROXY_SECRET=${NEXUS_CONNECTOR_PROXY_SECRET:?NEXUS_CONNECTOR_PROXY_SECRET is required}
    depends_on:
      backend:
        condition: service_healthy
    networks:
      - nexus_net
    read_only: true
    tmpfs:
      - /var/cache/nginx:rw,noexec,nosuid,size=16m
      - /var/run:rw,noexec,nosuid,size=4m
    security_opt:
      - no-new-privileges:true
    cap_drop: ["ALL"]
    cap_add: ["NET_BIND_SERVICE"]

  postgres:
    image: postgres:17-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: nexus
      POSTGRES_USER: nexus
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U nexus -d nexus"]
      interval: 10s
      timeout: 5s
      retries: 10
    logging: *default-logging
    networks:
      - nexus_net

  # ── Watchtower — Auto-updates (opcional) ─────────────────────
  # watchtower:
  #   image: containrrr/watchtower
  #   volumes:
  #     - /var/run/docker.sock:/var/run/docker.sock
  #   command: --interval 86400 nexus-backend nexus-frontend
  #   restart: unless-stopped

volumes:
  nexus_data:
    driver: local
  postgres_data:
    driver: local

networks:
  nexus_net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.0.1/16
```

#### pyproject.toml

NO EXISTE

#### setup.py

NO EXISTE

#### requirements-prod.lock — primeras 100 líneas

```text
# This file was autogenerated by uv via the following command:
#    uv pip compile requirements-prod.in --generate-hashes --python-version 3.12 --output-file requirements-prod.lock
aiosqlite==0.22.1 \
    --hash=sha256:043e0bd78d32888c0a9ca90fc788b38796843360c855a7262a532813133a0650 \
    --hash=sha256:21c002eb13823fad740196c5a2e9d8e62f6243bd9e7e4a1f87fb5e44ecb4fceb
    # via -r nexus_api/requirements.txt
annotated-doc==0.0.5 \
    --hash=sha256:117bac03a25ede5df5440e855b32d556049ca169ead221505badf432fed4b101 \
    --hash=sha256:c7e58ce09192557605d8bbd92836d7e1d520ac9580096042c0bfd197efacf1bb
    # via
    #   fastapi
    #   typer
annotated-types==0.8.0 \
    --hash=sha256:13b2beaad985e05e2d6407ee4c4f35590b11f8d693a258a561055cac8f64cab7 \
    --hash=sha256:f072f4d804ea359e4eaf198b1af7a8b0943881a87f31bb764f8bf219bb9419e0
    # via pydantic
anyio==4.14.2 \
    --hash=sha256:9f505dda5ac9f0c8309b5e8bd445a8c2bf7246f3ce950121e45ea15bc41d1494 \
    --hash=sha256:cfa139f3ed1a23ee8f88a145ddb5ac7605b8bbfd8592baacd7ce3d8bb4313c7f
    # via
    #   google-genai
    #   httpx
    #   httpx2
    #   mcp
    #   openai
    #   sse-starlette
    #   starlette
    #   watchfiles
apscheduler==3.11.3 \
    --hash=sha256:bbeb2ec02d23d3c06a6c07ed7f0f3939ada6680eb121fae809a69bb42c537a30 \
    --hash=sha256:cd2fcc9330039a81a5893472ad49facf23a6d5604cbe1d918c835c6de7834d5a
    # via -r nexus_api/requirements.txt
attrs==26.1.0 \
    --hash=sha256:c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309 \
    --hash=sha256:d03ceb89cb322a8fd706d4fb91940737b6642aa36998fe130a9bc96c985eff32
    # via
    #   jsonschema
    #   referencing
bcrypt==3.2.2 \
    --hash=sha256:2b02d6bfc6336d1094276f3f588aa1225a598e27f8e3388f4db9948cb707b521 \
    --hash=sha256:433c410c2177057705da2a9f2cd01dd157493b2a7ac14c8593a16b3dab6b6bfb \
    --hash=sha256:4e029cef560967fb0cf4a802bcf4d562d3d6b4b1bf81de5ec1abbe0f1adb027e \
    --hash=sha256:61bae49580dce88095d669226d5076d0b9d927754cedbdf76c6c9f5099ad6f26 \
    --hash=sha256:6d2cb9d969bfca5bc08e45864137276e4c3d3d7de2b162171def3d188bf9d34a \
    --hash=sha256:7180d98a96f00b1050e93f5b0f556e658605dd9f524d0b0e68ae7944673f525e \
    --hash=sha256:7d9ba2e41e330d2af4af6b1b6ec9e6128e91343d0b4afb9282e54e5508f31baa \
    --hash=sha256:7ff2069240c6bbe49109fe84ca80508773a904f5a8cb960e02a977f7f519b129 \
    --hash=sha256:88273d806ab3a50d06bc6a2fc7c87d737dd669b76ad955f449c43095389bc8fb \
    --hash=sha256:a2c46100e315c3a5b90fdc53e429c006c5f962529bc27e1dfd656292c20ccc40 \
    --hash=sha256:cd43303d6b8a165c29ec6756afd169faba9396a9472cdff753fe9f19b96ce2fa
    # via
    #   -r nexus_api/requirements.txt
    #   passlib
certifi==2026.7.22 \
    --hash=sha256:62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775 \
    --hash=sha256:741e2c3b351ddf169a738da9f2c048608ff7f2c5cc02f1ebc6b118bb090d5d55
    # via
    #   httpcore
    #   httpx
    #   requests
cffi==2.1.1 \
    --hash=sha256:046bfc24911b37851ee1b51aab8bffe713d89c68c6a057b09484ce9fd5f69b4e \
    --hash=sha256:06c72bb76605a4b0cd0aad6930b69d4baf7dd5d806cfc409b824191099700e66 \
    --hash=sha256:0beceaabe56af686895136a2de78db54ecd8e4046b236b8fd6d6cb61389e9bf2 \
    --hash=sha256:154852545011f779917b11c78db2358d095da62a9a172b78ad0a583ee5adc0d0 \
    --hash=sha256:194cffa889098ced9976c3fc6340305e43f6303657d298da55366907c05c22d6 \
    --hash=sha256:19ee6127ee34de7d83ce3d371ebc5ed91addbdcc39f9ab15ce4eb35a4e534971 \
    --hash=sha256:1a18a57b58cfb21fc28d72e876acf10eaed67a1ed96226f92af4df681d571c4c \
    --hash=sha256:1aa5645c30469b09530c4ebca77ebf8f17618293c58f8549cb1a543a50236e7d \
    --hash=sha256:1dea0e4d7d4f11f619fe8c1d76caf49e24405b4b5743c0e3be16a500ecd930c9 \
    --hash=sha256:208f941bb9d18e768138677f0a6d2ce01f590df56043dda1df1535ac57c88517 \
    --hash=sha256:210019b6c7cf07f081b4c54635c8cf744377001350e29cc0f81c4377b4797735 \
    --hash=sha256:246fa40ce8645a614ff682e0b70f37134e460eaf93a775e0cbe3cca585a67a80 \
    --hash=sha256:25792eac27877609e7bb06d42ff88278a6624fff2ba9bbb523c09616b117e80f \
    --hash=sha256:27350daa11d4f10c540e6e89dada4c54feb7256ad03e9a4dc075ebad7ba360d1 \
    --hash=sha256:28907ab9bfb6aa13184cfc17c6b8e1023c5ab6fd7076d8c20a35e59fe04f8f29 \
    --hash=sha256:2ae64be792b8966f2c69538199728b290e34726562896df1e5dc8ffd8d8188e8 \
    --hash=sha256:31348097ff5bbe827ccc41795d4dd099d9f0625e7def00ee653c137a490c2a6c \
    --hash=sha256:3143d81e29e1e20a9ce10901ec369012947876596f75a222235965f2b7ae832e \
    --hash=sha256:3222ba5d678f80a030e6afbcc33dc1ae5cb45facabb61cee2c7016b8432fde48 \
    --hash=sha256:3311ed60d36f83378794e1009ac6258bafbf81f7888b4caa7b35a521e3f95813 \
    --hash=sha256:334644fbac4eff73d985a17a91226df55d0f394160c4cfb880e084c8f7161cac \
    --hash=sha256:34e261f78cb6ceaaa36f42f2613f4380d94d9c759a9c73c769ee6e0247364632 \
    --hash=sha256:363e05fa78e15116c3c32c210ee36884fd6b9afa6d440e47112c3bd511d64cb6 \
    --hash=sha256:398aff33cee2767e3e781d2554c54bd0dff386bb437581e0d8011fde1a942ec1 \
    --hash=sha256:3d22a20b1fb1632cc72c22f95f7b0d2961c3e1c235f245ba4c606c4771035659 \
    --hash=sha256:42a494cee34437f05546455144f2b5d9ac09b1face62bcfce597d2e521066688 \
    --hash=sha256:42e2f76b9455f5a9a844f770bf3e200ed3da0e15f5df3db9c31fe80b04b3d004 \
    --hash=sha256:42f6930c31dc7f50732c9ae793c2786c7b6b044195967bbdde40bb9be81c4cc0 \
    --hash=sha256:456a61fa52d579ebf9df2e9552ead5129855dbaff6c1e5a9b1bc408809bdc062 \
    --hash=sha256:471cee653ae88de62096552e6d24ccb4a5adb8c8c9f10b5054d0122c15bf2779 \
    --hash=sha256:49cbc70e6542d4ccccb936558d1064a8012541e78f821f955cff24e357776c94 \
    --hash=sha256:4a7c934f7360e8cd64fe9efadcbd10c7c6364f531e432b9a4bf5ccbc9e0e8b50 \
    --hash=sha256:4be96343e422f2dfcd12ab5c9f5aebe03f82f737c6bffeca6830b3875cb44aab \
    --hash=sha256:4f42141fc14250de6dde5ee7ea4432be017252d91f19c5ad043c084cea629cac \
    --hash=sha256:507a24c282e0f42f8ed737cf048572cbf580468da5555764a8331735e9c736b6 \
    --hash=sha256:51b31d1c98274844cfd7838ce00bfc27c7423a4dc00fc0772fc3331c2cc90676 \
    --hash=sha256:58acb8ab8e295e6c5ea12f888cbb13cf21511ef2a3303a23f4325c29d17fe5c1 \
    --hash=sha256:5a59cc1c4442bc3d5c703bf720b51138d0bfc173618807c9ee2490a7541dd3d9 \
    --hash=sha256:5bb4e7ea95dcd6a014a6fef62e62467d67d8e582326443f3d68e71d6320a9fcf \
```

#### nexus_frontend/package.json — dependencies y scripts

```json
{
  "dependencies": {
    "@tanstack/react-query": "^5.91.0",
    "axios": "^1.13.6",
    "date-fns": "^4.1.0",
    "lucide-react": "^0.577.0",
    "react": "^19.2.4",
    "react-dom": "^19.2.4",
    "recharts": "^3.8.0",
    "zustand": "^5.0.12"
  },
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "lint": "eslint .",
    "preview": "vite preview"
  }
}
```

## 4. Esquema de base de datos

| Tabla | Columnas | Tipo | Nullable | Default | Índices | Definición |
|---|---|---|---|---|---|---|
| jarvis_notifications | id INTEGER [NO]<br>message TEXT [SÍ]<br>tipo TEXT [SÍ]<br>detail TEXT [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | junior_jarvis.py:43 |
| junior_updates | id INTEGER [NO]<br>title TEXT [NO]<br>description TEXT [SÍ]<br>category TEXT [SÍ]<br>priority TEXT [SÍ]<br>impact TEXT [SÍ]<br>implementation TEXT [SÍ]<br>status TEXT [SÍ]<br>approved_by TEXT [SÍ]<br>approved_at TEXT [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | junior_jarvis.py:51 |
| junior_chats | id INTEGER [NO]<br>session_id TEXT [NO]<br>title TEXT [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | junior_jarvis.py:64 |
| junior_messages | id INTEGER [NO]<br>session_id TEXT [NO]<br>role TEXT [NO]<br>content TEXT [NO]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | junior_jarvis.py:71 |
| tools | id TEXT [NO]<br>name TEXT [NO]<br>category TEXT [NO]<br>description TEXT [SÍ]<br>config TEXT [SÍ]<br>is_builtin INTEGER [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/db/database.py:27 |
| agents | id TEXT [NO]<br>name TEXT [NO]<br>role TEXT [NO]<br>description TEXT [SÍ]<br>model TEXT [NO]<br>provider TEXT [NO]<br>temperature REAL [SÍ]<br>max_tokens INTEGER [SÍ]<br>system_prompt TEXT [SÍ]<br>tools TEXT [SÍ]<br>hitl_mode TEXT [SÍ]<br>status TEXT [SÍ]<br>tasks_count INTEGER [SÍ]<br>success_rate REAL [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/db/database.py:37 |
| teams | id TEXT [NO]<br>name TEXT [NO]<br>description TEXT [SÍ]<br>specialization TEXT [SÍ]<br>strategy TEXT [SÍ]<br>agents TEXT [SÍ]<br>hitl TEXT [SÍ]<br>status TEXT [SÍ]<br>tasks_count INTEGER [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/db/database.py:55 |
| tasks | id TEXT [NO]<br>name TEXT [NO]<br>description TEXT [SÍ]<br>task_type TEXT [NO]<br>status TEXT [SÍ]<br>priority TEXT [SÍ]<br>agent_id TEXT [SÍ]<br>team_id TEXT [SÍ]<br>payload TEXT [SÍ]<br>cron_expr TEXT [SÍ]<br>progress INTEGER [SÍ]<br>result TEXT [SÍ]<br>error TEXT [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/db/database.py:68 |
| api_keys | id TEXT [NO]<br>alias TEXT [NO]<br>provider TEXT [NO]<br>key_masked TEXT [NO]<br>key_value TEXT [NO]<br>models TEXT [SÍ]<br>status TEXT [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/db/database.py:87 |
| junior_updates | id INTEGER [NO]<br>title TEXT [NO]<br>description TEXT [SÍ]<br>category TEXT [SÍ]<br>priority TEXT [SÍ]<br>impact TEXT [SÍ]<br>implementation TEXT [SÍ]<br>status TEXT [SÍ]<br>approved_by TEXT [SÍ]<br>approved_at TEXT [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/db/database.py:98 |
| junior_chats | id INTEGER [NO]<br>session_id TEXT [NO]<br>title TEXT [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/db/database.py:112 |
| junior_messages | id INTEGER [NO]<br>session_id TEXT [NO]<br>role TEXT [NO]<br>content TEXT [NO]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/db/database.py:120 |
| jarvis_notifications | id INTEGER [NO]<br>message TEXT [SÍ]<br>tipo TEXT [SÍ]<br>detail TEXT [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/routes/jarvis.py:31 |
| factory_projects | id TEXT [NO]<br>nombre TEXT [NO]<br>cliente TEXT [NO]<br>tipo TEXT [NO]<br>status TEXT [NO]<br>requirements TEXT [SÍ]<br>plan_maestro TEXT [SÍ]<br>approved_by TEXT [SÍ]<br>approved_at TEXT [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/services/factory_service.py:17 |
| factory_phases | id TEXT [NO]<br>project_id TEXT [NO]<br>fase_num INTEGER [NO]<br>nombre TEXT [NO]<br>descripcion TEXT [SÍ]<br>status TEXT [SÍ]<br>agentes TEXT [SÍ]<br>tools TEXT [SÍ]<br>output_path TEXT [SÍ]<br>result TEXT [SÍ]<br>started_at TEXT [SÍ]<br>completed_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/services/factory_service.py:32 |
| pentest_engagements | id TEXT [NO]<br>nombre TEXT [NO]<br>cliente TEXT [NO]<br>tipo TEXT [NO]<br>status TEXT [SÍ]<br>scope TEXT [SÍ]<br>plan TEXT [SÍ]<br>approved_by TEXT [SÍ]<br>approved_at TEXT [SÍ]<br>findings TEXT [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/services/factory_service.py:49 |
| agent_memory | id INTEGER [NO]<br>agent_id TEXT [NO]<br>agent_name TEXT [NO]<br>session_id TEXT [SÍ]<br>role TEXT [NO]<br>content TEXT [NO]<br>summary TEXT [SÍ]<br>tokens_est INTEGER [SÍ]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/services/memory_service.py:20 |
| memory_summaries | id INTEGER [NO]<br>agent_id TEXT [NO]<br>session_id TEXT [SÍ]<br>summary TEXT [NO]<br>msg_count INTEGER [SÍ]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_api/services/memory_service.py:33 |
| technical_docs | doc_id TEXT [NO]<br>doc_type TEXT [SÍ]<br>title TEXT [SÍ]<br>content TEXT [SÍ]<br>tags TEXT [SÍ]<br>project_id TEXT [SÍ]<br>related_incident TEXT [SÍ]<br>related_commit TEXT [SÍ]<br>created_at TIMESTAMP [SÍ]<br>updated_at TIMESTAMP [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/agents/generated/doc_agent.py:24 |
| incident_reports | report_id TEXT [NO]<br>incident_id TEXT [SÍ]<br>severity TEXT [SÍ]<br>title TEXT [SÍ]<br>description TEXT [SÍ]<br>root_cause TEXT [SÍ]<br>solution TEXT [SÍ]<br>prevention TEXT [SÍ]<br>status TEXT [SÍ]<br>assigned_to TEXT [SÍ]<br>created_at TIMESTAMP [SÍ]<br>resolved_at TIMESTAMP [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/agents/generated/doc_agent.py:38 |
| security_incidents | id TEXT [NO]<br>severity TEXT [SÍ]<br>title TEXT [SÍ]<br>description TEXT [SÍ]<br>file_path TEXT [SÍ]<br>line_number INTEGER [SÍ]<br>created_at TIMESTAMP [SÍ]<br>status TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/agents/generated/guardian_agent.py:22 |
| test_results | test_id TEXT [NO]<br>project_id TEXT [SÍ]<br>filepath TEXT [SÍ]<br>test_type TEXT [SÍ]<br>status TEXT [SÍ]<br>passed INTEGER [SÍ]<br>failed INTEGER [SÍ]<br>output TEXT [SÍ]<br>duration_ms REAL [SÍ]<br>created_at TIMESTAMP [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/agents/generated/test_agent.py:23 |
| schema_migrations | version INTEGER [NO]<br>name TEXT [NO]<br>applied_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:19 |
| kernel_tenants | id TEXT [NO]<br>name TEXT [NO]<br>status TEXT [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:22 |
| kernel_organizations | id TEXT [NO]<br>name TEXT [NO]<br>status TEXT [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:26 |
| kernel_environments | id TEXT [NO]<br>tenant_id TEXT [NO]<br>name TEXT [NO]<br>classification TEXT [NO]<br>status TEXT [NO]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>name  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:30 |
| kernel_groups | id TEXT [NO]<br>tenant_id TEXT [NO]<br>name TEXT [NO]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>name  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:35 |
| kernel_group_memberships | id TEXT [NO]<br>tenant_id TEXT [NO]<br>group_id TEXT [NO]<br>subject_type TEXT [NO]<br>subject_id TEXT [NO]<br>created_at TEXT [NO]<br>UNIQUE(group_id  [SÍ]<br>subject_type  [SÍ]<br>subject_id  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:39 |
| kernel_service_accounts | id TEXT [NO]<br>tenant_id TEXT [NO]<br>name TEXT [NO]<br>credential_hash TEXT [NO]<br>roles TEXT [NO]<br>active INTEGER [NO]<br>expires_at TEXT [SÍ]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>name  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:44 |
| kernel_resources | id TEXT [NO]<br>tenant_id TEXT [NO]<br>environment_id TEXT [SÍ]<br>kind TEXT [NO]<br>name TEXT [NO]<br>classification TEXT [NO]<br>owner_id TEXT [SÍ]<br>attributes TEXT [NO]<br>status TEXT [NO]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>kind  [SÍ]<br>name  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:49 |
| kernel_capabilities | id TEXT [NO]<br>tenant_id TEXT [NO]<br>name TEXT [NO]<br>description TEXT [NO]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>name  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:55 |
| kernel_agent_capabilities | agent_id TEXT [NO]<br>capability_id TEXT [NO]<br>capability_id  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:59 |
| kernel_tool_resources | tool_id TEXT [NO]<br>resource_id TEXT [NO]<br>scopes TEXT [NO]<br>resource_id  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:63 |
| kernel_users | id TEXT [NO]<br>tenant_id TEXT [NO]<br>email TEXT [NO]<br>name TEXT [NO]<br>hashed_pw TEXT [NO]<br>role TEXT [NO]<br>active INTEGER [NO]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>email  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:67 |
| auth_refresh_sessions | jti TEXT [NO]<br>user_id TEXT [NO]<br>expires_at TEXT [NO]<br>revoked_at TEXT [SÍ]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:74 |
| auth_revoked_tokens | jti TEXT [NO]<br>expires_at TEXT [NO]<br>revoked_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:79 |
| kernel_departments | id TEXT [NO]<br>tenant_id TEXT [NO]<br>name TEXT [NO]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>name  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:82 |
| kernel_packages | id TEXT [NO]<br>tenant_id TEXT [NO]<br>package_name TEXT [NO]<br>version TEXT [NO]<br>manifest TEXT [NO]<br>status TEXT [NO]<br>installed_by TEXT [NO]<br>installed_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>package_name  [SÍ]<br>version  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:87 |
| kernel_policies | id TEXT [NO]<br>tenant_id TEXT [NO]<br>name TEXT [NO]<br>version TEXT [NO]<br>effect TEXT [NO]<br>actions TEXT [NO]<br>resource_kinds TEXT [NO]<br>conditions TEXT [NO]<br>requires_approval INTEGER [NO]<br>enabled INTEGER [NO]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>name  [SÍ]<br>version  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:94 |
| kernel_policy_bindings | id TEXT [NO]<br>tenant_id TEXT [NO]<br>policy_id TEXT [NO]<br>subject_type TEXT [NO]<br>subject_id TEXT [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:102 |
| kernel_agents | id TEXT [NO]<br>tenant_id TEXT [NO]<br>department_id TEXT [SÍ]<br>name TEXT [NO]<br>version TEXT [NO]<br>definition TEXT [NO]<br>status TEXT [NO]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>name  [SÍ]<br>version  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:107 |
| kernel_tools | id TEXT [NO]<br>tenant_id TEXT [NO]<br>name TEXT [NO]<br>version TEXT [NO]<br>definition TEXT [NO]<br>status TEXT [NO]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>name  [SÍ]<br>version  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:114 |
| kernel_runs | id TEXT [NO]<br>tenant_id TEXT [NO]<br>workflow_id TEXT [SÍ]<br>status TEXT [NO]<br>idempotency_key TEXT [SÍ]<br>context TEXT [NO]<br>result TEXT [SÍ]<br>error TEXT [SÍ]<br>created_at TEXT [NO]<br>updated_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>idempotency_key  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:121 |
| kernel_tasks | id TEXT [NO]<br>tenant_id TEXT [NO]<br>run_id TEXT [NO]<br>task_type TEXT [NO]<br>status TEXT [NO]<br>priority INTEGER [NO]<br>payload TEXT [NO]<br>result TEXT [SÍ]<br>error TEXT [SÍ]<br>attempts INTEGER [NO]<br>max_attempts INTEGER [NO]<br>timeout_seconds INTEGER [NO]<br>cancel_requested INTEGER [NO]<br>available_at TEXT [NO]<br>lease_owner TEXT [SÍ]<br>lease_until TEXT [SÍ]<br>created_at TEXT [NO]<br>updated_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:127 |
| kernel_task_transitions | sequence INTEGER [NO]<br>task_id TEXT [NO]<br>from_status TEXT [SÍ]<br>to_status TEXT [NO]<br>reason TEXT [SÍ]<br>actor_id TEXT [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:139 |
| kernel_dead_letters | id TEXT [NO]<br>tenant_id TEXT [NO]<br>task_id TEXT [NO]<br>payload TEXT [NO]<br>error TEXT [NO]<br>attempts INTEGER [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:145 |
| kernel_workflows | id TEXT [NO]<br>tenant_id TEXT [NO]<br>name TEXT [NO]<br>version TEXT [NO]<br>definition TEXT [NO]<br>status TEXT [NO]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>name  [SÍ]<br>version  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:150 |
| kernel_workflow_steps | id TEXT [NO]<br>run_id TEXT [NO]<br>step_key TEXT [NO]<br>task_id TEXT [SÍ]<br>status TEXT [NO]<br>depends_on TEXT [NO]<br>compensation_type TEXT [SÍ]<br>compensation_task_id TEXT [SÍ]<br>result TEXT [SÍ]<br>created_at TEXT [NO]<br>updated_at TEXT [NO]<br>UNIQUE(run_id  [SÍ]<br>step_key  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:155 |
| kernel_outbox | id TEXT [NO]<br>tenant_id TEXT [NO]<br>aggregate_type TEXT [NO]<br>aggregate_id TEXT [NO]<br>event_type TEXT [NO]<br>payload TEXT [NO]<br>published_at TEXT [SÍ]<br>attempts INTEGER [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:162 |
| kernel_run_events | sequence INTEGER [NO]<br>event_id TEXT [NO]<br>tenant_id TEXT [NO]<br>run_id TEXT [NO]<br>event_type TEXT [NO]<br>payload TEXT [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:167 |
| kernel_conversations | id TEXT [NO]<br>tenant_id TEXT [NO]<br>owner_id TEXT [NO]<br>title TEXT [NO]<br>agent_id TEXT [SÍ]<br>classification TEXT [NO]<br>status TEXT [NO]<br>created_at TEXT [NO]<br>updated_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:175 |
| kernel_messages | sequence INTEGER [NO]<br>id TEXT [NO]<br>tenant_id TEXT [NO]<br>conversation_id TEXT [NO]<br>run_id TEXT [SÍ]<br>role TEXT [NO]<br>content TEXT [NO]<br>metadata TEXT [NO]<br>classification TEXT [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:182 |
| kernel_artifacts | id TEXT [NO]<br>tenant_id TEXT [NO]<br>run_id TEXT [SÍ]<br>media_type TEXT [NO]<br>storage_uri TEXT [NO]<br>sha256 TEXT [NO]<br>size_bytes INTEGER [NO]<br>metadata TEXT [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:191 |
| kernel_memories | id TEXT [NO]<br>tenant_id TEXT [NO]<br>agent_id TEXT [NO]<br>agent_name TEXT [NO]<br>session_id TEXT [SÍ]<br>role TEXT [NO]<br>content TEXT [NO]<br>classification TEXT [NO]<br>tokens_est INTEGER [NO]<br>expires_at TEXT [SÍ]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:196 |
| kernel_memory_summaries | id TEXT [NO]<br>tenant_id TEXT [NO]<br>agent_id TEXT [NO]<br>session_id TEXT [SÍ]<br>summary TEXT [NO]<br>msg_count INTEGER [NO]<br>classification TEXT [NO]<br>expires_at TEXT [SÍ]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:204 |
| kernel_knowledge_documents | id TEXT [NO]<br>tenant_id TEXT [NO]<br>title TEXT [NO]<br>source_uri TEXT [NO]<br>content TEXT [NO]<br>sha256 TEXT [NO]<br>classification TEXT [NO]<br>metadata TEXT [NO]<br>created_by TEXT [NO]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>source_uri  [SÍ]<br>sha256  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:210 |
| kernel_usage_ledger | id TEXT [NO]<br>tenant_id TEXT [NO]<br>run_id TEXT [NO]<br>subject_type TEXT [NO]<br>subject_id TEXT [NO]<br>metric TEXT [NO]<br>amount REAL [NO]<br>metadata TEXT [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:219 |
| kernel_quotas | id TEXT [NO]<br>tenant_id TEXT [NO]<br>subject_type TEXT [NO]<br>subject_id TEXT [NO]<br>metric TEXT [NO]<br>limit_value REAL [NO]<br>enabled INTEGER [NO]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>subject_type  [SÍ]<br>subject_id  [SÍ]<br>metric  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:226 |
| kernel_approvals | id TEXT [NO]<br>tenant_id TEXT [NO]<br>run_id TEXT [NO]<br>action TEXT [NO]<br>status TEXT [NO]<br>requested_by TEXT [NO]<br>decided_by TEXT [SÍ]<br>reason TEXT [SÍ]<br>created_at TEXT [NO]<br>decided_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:232 |
| kernel_audit_events | sequence INTEGER [NO]<br>event_id TEXT [NO]<br>tenant_id TEXT [NO]<br>trace_id TEXT [NO]<br>actor_id TEXT [NO]<br>action TEXT [NO]<br>resource_type TEXT [NO]<br>resource_id TEXT [NO]<br>decision TEXT [SÍ]<br>payload TEXT [NO]<br>previous_hash TEXT [SÍ]<br>event_hash TEXT [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:238 |
| evolution_proposals | id TEXT [NO]<br>tenant_id TEXT [NO]<br>title TEXT [NO]<br>hypothesis TEXT [NO]<br>evidence TEXT [NO]<br>acceptance_criteria TEXT [NO]<br>risk TEXT [NO]<br>status TEXT [NO]<br>proposed_by TEXT [NO]<br>implementation_actor TEXT [SÍ]<br>evaluation_actor TEXT [SÍ]<br>approval_actor TEXT [SÍ]<br>baseline_version TEXT [NO]<br>candidate_version TEXT [SÍ]<br>created_at TEXT [NO]<br>updated_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:245 |
| evolution_evaluations | id TEXT [NO]<br>proposal_id TEXT [NO]<br>evaluator_id TEXT [NO]<br>passed INTEGER [NO]<br>metrics TEXT [NO]<br>report_uri TEXT [SÍ]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:253 |
| evolution_campaigns | proposal_id TEXT [NO]<br>max_iterations INTEGER [NO]<br>iterations_used INTEGER [NO]<br>token_budget INTEGER [NO]<br>tokens_used INTEGER [NO]<br>deadline TEXT [NO]<br>status TEXT [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:259 |
| evolution_canary_samples | id TEXT [NO]<br>proposal_id TEXT [NO]<br>success_rate REAL [NO]<br>error_rate REAL [NO]<br>latency_ms REAL [NO]<br>cost REAL [NO]<br>decision TEXT [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:266 |
| connector_enrollment_tokens | token_hash TEXT [NO]<br>tenant_id TEXT [NO]<br>expires_at TEXT [NO]<br>used_at TEXT [SÍ]<br>created_by TEXT [NO]<br>created_at TEXT [NO] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:272 |
| kernel_connectors | id TEXT [NO]<br>tenant_id TEXT [NO]<br>name TEXT [NO]<br>device_id TEXT [NO]<br>credential_hash TEXT [NO]<br>status TEXT [NO]<br>capabilities TEXT [NO]<br>allowed_roots TEXT [NO]<br>certificate_fingerprint TEXT [SÍ]<br>credential_rotated_at TEXT [SÍ]<br>last_seen_at TEXT [SÍ]<br>revoked_at TEXT [SÍ]<br>created_at TEXT [NO]<br>UNIQUE(tenant_id  [SÍ]<br>device_id  [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/kernel/control_store.py:276 |
| teams | team_id TEXT [NO]<br>team_type TEXT [SÍ]<br>name TEXT [SÍ]<br>status TEXT [SÍ]<br>project_id TEXT [SÍ]<br>config TEXT [SÍ]<br>created_at TIMESTAMP [SÍ]<br>updated_at TIMESTAMP [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/team_orchestrator.py:30 |
| team_agents | id TEXT [NO]<br>team_id TEXT [SÍ]<br>role TEXT [SÍ]<br>agent_name TEXT [SÍ]<br>status TEXT [SÍ]<br>container_id TEXT [SÍ]<br>created_at TIMESTAMP [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/team_orchestrator.py:35 |
| team_events | id TEXT [NO]<br>team_id TEXT [SÍ]<br>agent_role TEXT [SÍ]<br>event_type TEXT [SÍ]<br>payload TEXT [SÍ]<br>created_at TIMESTAMP [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/team_orchestrator.py:39 |
| team_lessons | id TEXT [NO]<br>project_id TEXT [SÍ]<br>team_id TEXT [SÍ]<br>lesson TEXT [SÍ]<br>category TEXT [SÍ]<br>created_at TIMESTAMP [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/team_orchestrator.py:43 |
| nexus_users | id INTEGER [NO]<br>email TEXT [SÍ]<br>name TEXT [SÍ]<br>hashed_pw TEXT [SÍ]<br>role TEXT [SÍ]<br>active INTEGER [SÍ]<br>created_at TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/tests/unit/test_kernel_offline.py:384 |
| migration_probe | id TEXT [SÍ] | SQLite SQL | ver columnas | No extraído | No declarado | nexus_core/tests/unit/test_kernel_offline.py:531 |


## 5. Catálogo de herramientas actual

| Nombre herramienta | Archivo:línea | Cómo se invoca | Inputs | Outputs | ¿Sandbox? | ¿Policy? | ¿Approval? |
|---|---|---|---|---|---|---|---|
| DURABLE nexus.system.status | nexus_core/kernel/runtime.py:233-237 | handler | {} | ToolResult | No | Sí | Policy |
| DURABLE nexus.workspace.search | nexus_core/kernel/runtime.py:238-243 | sandbox rg | query | matches/evidence | Sí | Sí | Policy |
| LEGADO bash_exec | nexus_core/agents/dynamic_agent.py:40-75 | shell | command,cwd,timeout | stdout/stderr | No | No | HITL opcional |
| LEGADO file_read | dynamic_agent.py:78-87 | Path read | path | content | No | No | No |
| LEGADO file_write | dynamic_agent.py:90-100 | Path write | path,content | path/bytes | No | No | No |
| LEGADO file_list | dynamic_agent.py:103-115 | Path list | path | items | No | No | No |
| LEGADO http_request/api_test | dynamic_agent.py:118-130 | httpx | url/method | body/status | No | No | No |
| LEGADO code_exec | dynamic_agent.py:133-150 | python3 -c | code | output | No | No | No |
| LEGADO nmap_scan | dynamic_agent.py:153-166 | shell nmap | target/flags | output | No | No | HITL opcional |
| LEGADO nuclei_scan | dynamic_agent.py:317 | shell nuclei | target | output | No | No | HITL opcional |
| LEGADO sast_scan | dynamic_agent.py:222-248 | bash | filepath | issues | No | No | HITL opcional |
| LEGADO stride_model | dynamic_agent.py:251-286 | report | target/context | report | No | No | HITL opcional |
| LEGADO report_gen | dynamic_agent.py:168-194 | write | title/content | path | No | No | No |
| LEGADO llm_call | dynamic_agent.py:196-218 | LLM | system/prompt | response | No | No | No |
| SKILL nmap_scan | skills/nmap_scan.py:5-35 | exec argv | target | scan result | No | No | No |
| SKILL nuclei_scan | skills/nuclei_scan.py:4-32 | subprocess | target | output | No | No | No |
| PENTEST bandit_scan | pentest_agent.py:76-115 | subprocess | path | findings | No | No | No |
| PENTEST safety_check | pentest_agent.py:117-150 | shell | requirements | vulns | No | No | No |
| PENTEST scan_secrets | pentest_agent.py:153-196 | regex | path | findings | No | No | No |
| PENTEST http_fingerprint | pentest_agent.py:198-235 | httpx | target | headers | No | No | No |


## 6. Flujo del bucle agéntico

### Runtime durable
1. API crea run/tarea: nexus_api/routes/sovereign.py:192-215.
2. Worker usa registry: nexus_worker.py; nexus_core/kernel/runtime.py:37-63.
3. brain.run procesa pasos declarados, máximo 8: runtime.py:255-297.
4. execute_tool limita catálogo: runtime.py:176-252.
5. Gateway valida schema/policy: tool_gateway.py:57-79; approval durable: 80-85.
6. Search usa sandbox: runtime.py:215-230, sandbox.py:21-159.
7. Resultado se audita y brain termina/aborta: tool_gateway.py:101-142, runtime.py:295-324.
8. No hay tool call LLM ni ReAct autónomo.


### Runtime legado
1. Rutas se incluyen solo en dev con flag: nexus_api/main.py:451-491.
2. Tarea/pentest: routes/tasks.py:113-145, routes/pentest.py:60-83.
3. DynamicAgent planifica/elige tool: dynamic_agent.py:464-505.
4. HITL en memoria: dynamic_agent.py:510-547, hitl/manager.py:137-172.
5. ToolExecutor ejecuta: dynamic_agent.py:288-325.
6. Interpreta una vez: dynamic_agent.py:554-575.
7. Pentest secuencial: pentest_agent.py:348-500.
8. No hay compactación, retries estratégicos ni ReAct.


## 7. Testing actual

| Archivo | Nº tests | Qué cubre | Cobertura estimada del módulo |
|---|---|---|---|
| nexus_api/routes/pentest.py | 0 | Ver código | No ejecutada |
| nexus_api/routes/testagent.py | 1 | Ver código | No ejecutada |
| nexus_api/tests/api_smoke.py | 0 | Ver código | No ejecutada |
| nexus_core/agents/generated/test_agent.py | 0 | Ver código | No ejecutada |
| nexus_core/agents/pentest_agent.py | 0 | Ver código | No ejecutada |
| nexus_core/tests/conftest.py | 0 | Ver código | No ejecutada |
| nexus_core/tests/integration/postgres_smoke.py | 0 | Ver código | No ejecutada |
| nexus_core/tests/unit/test_event_bus.py | 4 | Ver código | No ejecutada |
| nexus_core/tests/unit/test_kernel_offline.py | 28 | Ver código | No ejecutada |
| nexus_core/tests/unit/test_security.py | 4 | Ver código | No ejecutada |
| nexus_core/tests/unit/test_sovereign_runtime.py | 4 | Ver código | No ejecutada |
| nexus_core/tests/unit/test_state_manager.py | 4 | Ver código | No ejecutada |
| nexus_mcp/tests/__init__.py | 0 | Ver código | No ejecutada |
| nexus_mcp/tests/smoke.py | 0 | Ver código | No ejecutada |
| nexus_mcp/tests/test_remote_security.py | 4 | Ver código | No ejecutada |


- Kernel durable: sí, test_kernel_offline.py y test_sovereign_runtime.py.
- Sandbox: flags OCI; no prueba integral Docker.
- HITL legado: no se localizó test dedicado. Approvals durable: sí.
- LLM: fixture fake; no proveedores remotos.
- E2E de pentest: NO EXISTE.


## 8. Cómo se arranca hoy

| Objetivo | Comando | Fuente |
|---|---|---|
| Instalar prod | .venv/bin/pip install --require-hashes -r requirements.lock | README.md:26 |
| CLI | .venv/bin/python nexus_cli.py --help | README.md:66 |
| API | .venv/bin/uvicorn nexus_api.main:app --host 127.0.0.1 --port 8000 | README.md:42 |
| Worker | .venv/bin/python nexus_worker.py --once | README.md:36 |
| Frontend | npm run dev | nexus_frontend/package.json:scripts |
| Tests | python3 -m pytest nexus_core/tests -q | Makefile:7 |
| Ruff | ruff check --select E4,E7,E9,F,I | Makefile:19 |
| Mypy | mypy --ignore-missing-imports --follow-imports=skip | Makefile:29 |


## 9. Dependencias externas del sistema

| Herramienta | ¿Dónde se invoca? | ¿Cómo se verifica? | ¿Qué pasa si falta? |
|---|---|---|---|
| nmap | pentest_agent.py:36; skills/nmap_scan.py:11 | No explícitamente | simulación/error |
| nuclei | skills/nuclei_scan.py:11; dynamic_agent.py:317 | No | error |
| bandit | pentest_agent.py:76 | No | error |
| safety | pentest_agent.py:117 | No | error |
| python3 | dynamic_agent.py:133 | No | subproceso falla |
| git | dynamic_agent.py:211; sandbox.py:26 | allowlist | PermissionError/fallo |
| rg | runtime.py:218; sandbox.py:26 | allowlist | exit/evidence |
| docker/podman | sandbox.py:83-159 | runtime config | subproceso falla |
| grep/df/uptime/free | codeagent.py:91; composite_tools.py:192 | No | error/salida vacía |


## 10. Inventario de deuda técnica

| Archivo:línea | Tipo | Contenido |
|---|---|---|
| factory_runner.py:156 | TODO | - Código funcional completo, sin TODOs ni stubs |
| junior_jarvis.py:59 | texto | status TEXT DEFAULT 'pending', |
| junior_jarvis.py:351 | texto | "SELECT title FROM junior_updates WHERE status='pending'" |
| nexus_api/db/database.py:106 | texto | status         TEXT DEFAULT 'pending', |
| nexus_api/db/database.py:149 | TODO | ("tool_stride",   "stride_model",    "security",  "Modelado de amenazas con metodología STRIDE",           1), |
| nexus_api/main.py:195 | TODO | # ── EventBus — base de todo, primero ───────────────────── |
| nexus_api/main.py:524 | texto | hitl_count = hitl.count_pending() |
| nexus_api/main.py:546 | texto | "hitl_pending": hitl_count, |
| nexus_api/routes/a2a.py:84 | texto | "pending": "submitted", "queued": "submitted", "running": "working", |
| nexus_api/routes/agents.py:46 | TODO | """Lista todos los agentes — DB + Registry.""" |
| nexus_api/routes/factory.py:24 | NOTE | notes: Optional[str] = None |
| nexus_api/routes/factory.py:97 | texto | "status":        "pending_approval", |
| nexus_api/routes/factory.py:118 | texto | if project["status"] not in ("pending_approval", "analyzing"): |
| nexus_api/routes/factory.py:177 | TODO | - Genera código REAL y funcional, sin TODOs ni stubs |
| nexus_api/routes/factory.py:179 | TODO | - Guarda TODOS los archivos en {output_dir}/ |
| nexus_api/routes/factory.py:269 | TODO | 2. Metodología recomendada (OWASP/PTES/NIST) |
| nexus_api/routes/factory.py:296 | texto | "UPDATE pentest_engagements SET plan=?,status='pending_approval' WHERE id=?", |
| nexus_api/routes/factory.py:305 | texto | "status":        "pending_approval", |
| nexus_api/routes/factory.py:324 | texto | if engage["status"] not in ("pending_approval","analyzing"): |
| nexus_api/routes/hitl.py:33 | texto | @router.get("/hitl/pending") |
| nexus_api/routes/hitl.py:34 | texto | def get_pending(_: dict = Depends(get_current_user)): |
| nexus_api/routes/hitl.py:37 | texto | pending = hitl.get_pending() |
| nexus_api/routes/hitl.py:39 | texto | "pending": pending, |
| nexus_api/routes/hitl.py:40 | texto | "total": len(pending), |
| nexus_api/routes/hitl.py:57 | texto | return {"count": hitl.count_pending()} |
| nexus_api/routes/hitl.py:104 | texto | pending = hitl.get_pending() |
| nexus_api/routes/hitl.py:108 | texto | "data": {"pending": pending, "count": len(pending)}, |
| nexus_api/routes/hitl.py:154 | texto | "count": hitl.count_pending(), |
| nexus_api/routes/jarvis.py:97 | texto | async def get_updates(status: str = "pending"): |
| nexus_api/routes/jarvis.py:380 | texto | pending_updates = conn.execute( |
| nexus_api/routes/jarvis.py:381 | texto | "SELECT COUNT(*) as c FROM junior_updates WHERE status='pending'" |
| nexus_api/routes/jarvis.py:384 | texto | pending_updates = 0 |
| nexus_api/routes/jarvis.py:389 | texto | "pending_updates": pending_updates, |
| nexus_api/routes/killswitch.py:31 | texto | from nexus_core.agents.generated.kill_switch_agent import is_active, get_pending_operations |
| nexus_api/routes/killswitch.py:32 | texto | pending = get_pending_operations() |
| nexus_api/routes/killswitch.py:35 | texto | "pending_operations": len(pending), |
| nexus_api/routes/killswitch.py:36 | texto | "pending": pending[:5], |
| nexus_api/routes/killswitch.py:40 | texto | @router.get("/pending") |
| nexus_api/routes/killswitch.py:41 | texto | async def get_pending(): |
| nexus_api/routes/killswitch.py:43 | texto | from nexus_core.agents.generated.kill_switch_agent import get_pending_operations |
| nexus_api/routes/killswitch.py:44 | texto | ops = get_pending_operations() |
| nexus_api/routes/killswitch.py:45 | texto | return {"pending": ops, "total": len(ops)} |
| nexus_api/routes/memory.py:34 | TODO | """Lista todos los agentes que tienen memoria almacenada.""" |
| nexus_api/routes/models.py:96 | TODO | """Retorna todos los modelos disponibles según las keys configuradas.""" |
| nexus_api/routes/pentest.py:96 | TODO | """Lista todos los reportes generados.""" |
| nexus_api/routes/plans.py:38 | texto | @router.get("/pending") |
| nexus_api/routes/plans.py:39 | texto | async def pending_plans(): |
| nexus_api/routes/plans.py:41 | texto | from nexus_core.agents.generated.plan_agent import get_pending_plans |
| nexus_api/routes/plans.py:42 | texto | plans = get_pending_plans() |
| nexus_api/routes/plans.py:48 | TODO | """Lista todos los planes.""" |
| nexus_api/routes/plans.py:64 | TODO | """✅ Marcos aprueba el plan — Junior ejecutará todos los pasos.""" |
| nexus_api/routes/plans.py:76 | TODO | """🚀 Ejecutar un plan aprobado — Junior ejecuta todos los pasos automáticamente.""" |
| nexus_api/routes/projects.py:48 | texto | "status": "pending", |
| nexus_api/routes/sovereign.py:171 | texto | if run["status"] != "pending": |
| nexus_api/routes/sovereign.py:199 | texto | if run["status"] == "pending": |
| nexus_api/routes/sovereign.py:222 | texto | if run["status"] == "pending": |
| nexus_api/routes/testagent.py:38 | TODO | """Ejecuta todos los checks: sintaxis + lint + seguridad.""" |
| nexus_api/services/factory_service.py:38 | texto | status       TEXT DEFAULT 'pending', |
| nexus_api/services/factory_service.py:151 | TODO | {"num":5, "nombre":"API Endpoints + Validation","tools":["file_write","bash_exec"],"agentes":["CodeAgent"],"desc":"Todos los endpoints con validación"}, |
| nexus_api/services/factory_service.py:189 | texto | (json.dumps(plan), "pending_approval", project_id) |
| nexus_core/agent_team_manager.py:437 | texto | def get_pending_approvals(self) -> List[Dict]: |
| nexus_core/agent_team_manager.py:443 | TODO | # ── Métodos internos ────────────────────────────────────────────────────── |
| nexus_core/agent_team_manager.py:623 | texto | @router.get("/pending-approvals") |
| nexus_core/agent_team_manager.py:624 | texto | async def pending_approvals(): |
| nexus_core/agent_team_manager.py:625 | texto | return {"pending": _manager.get_pending_approvals()} |
| nexus_core/agents/dynamic_agent.py:313 | NOTE | "web_search":   lambda p: {"status":"ok","note":"Requiere integración SerpAPI/Tavily"}, |
| nexus_core/agents/dynamic_agent.py:314 | NOTE | "sql_query":    lambda p: {"status":"ok","note":"Requiere conexión DB configurada"}, |
| nexus_core/agents/dynamic_agent.py:315 | NOTE | "memory_search":lambda p: {"status":"ok","note":"ChromaDB query pendiente"}, |
| nexus_core/agents/dynamic_agent.py:316 | NOTE | "memory_write": lambda p: {"status":"ok","note":"ChromaDB write pendiente"}, |
| nexus_core/agents/generated/kill_switch_agent.py:76 | texto | "status": "pending_approval", |
| nexus_core/agents/generated/kill_switch_agent.py:91 | texto | if row[5] != "pending_approval": |
| nexus_core/agents/generated/kill_switch_agent.py:115 | texto | def get_pending_operations() -> list: |
| nexus_core/agents/generated/kill_switch_agent.py:120 | texto | FROM critical_operations WHERE status='pending_approval' |
| nexus_core/agents/generated/kill_switch_agent.py:139 | texto | "UPDATE critical_operations SET status='cancelled' WHERE status='pending_approval'" |
| nexus_core/agents/generated/plan_agent.py:2 | TODO | PlanAgent v1.0 — Junior propone planes, Marcos aprueba UNA vez, Junior ejecuta todo. |
| nexus_core/agents/generated/plan_agent.py:55 | texto | "status": "pending_review", |
| nexus_core/agents/generated/plan_agent.py:62 | TODO | """Marcos aprueba un plan — Junior ejecutará todos los pasos.""" |
| nexus_core/agents/generated/plan_agent.py:70 | texto | if row[7] != "pending_review": |
| nexus_core/agents/generated/plan_agent.py:83 | TODO | "message": "Plan aprobado. Junior puede ejecutar todos los pasos.", |
| nexus_core/agents/generated/plan_agent.py:119 | texto | def get_pending_plans() -> list: |
| nexus_core/agents/generated/plan_agent.py:124 | texto | FROM junior_plans WHERE status='pending_review' |
| nexus_core/agents/generated/plan_agent.py:201 | TODO | """Lista todos los planes.""" |
| nexus_core/agents/generated/test_agent.py:179 | TODO | """Ejecuta todos los checks de calidad en secuencia.""" |
| nexus_core/agents/junior_agent.py:5 | TODO | Junior es diferente a todos los demás agentes: |
| nexus_core/agents/junior_agent.py:169 | TODO | - Generas reportes detallados de todo lo que haces |
| nexus_core/agents/pentest_agent.py:65 | NOTE | "note": "nmap no instalado — resultado simulado para demo", |
| nexus_core/agents/pentest_agent.py:109 | NOTE | "note": "bandit completado — parseo JSON falló", |
| nexus_core/agents/pentest_agent.py:147 | NOTE | "note": "safety completado", |
| nexus_core/agents/pentest_agent.py:250 | TODO | **Metodología:** OWASP + STRIDE + NIST |
| nexus_core/agents/pentest_agent.py:390 | TODO | stride_prompt = f"""Aplica metodología STRIDE a {target_name}. |
| nexus_core/composite_tools.py:180 | texto | plans = (await client.get("http://127.0.0.1:8000/plans/pending")).json() |
| nexus_core/composite_tools.py:181 | texto | result["pending_plans"] = plans.get("total", 0) |
| nexus_core/core/orchestrator.py:77 | texto | status=TaskStatus.PENDING, |
| nexus_core/hitl/manager.py:36 | texto | PENDING  = "pending" |
| nexus_core/hitl/manager.py:77 | texto | self.status      = HITLStatus.PENDING |
| nexus_core/hitl/manager.py:108 | texto | self._pending:  Dict[str, HITLRequest] = {} |
| nexus_core/hitl/manager.py:123 | TODO | """Notifica a todos los WebSocket conectados.""" |
| nexus_core/hitl/manager.py:152 | TODO | # Modo 'always' — todo requiere aprobación |
| nexus_core/hitl/manager.py:187 | texto | self._pending[req.id] = req |
| nexus_core/hitl/manager.py:209 | texto | self._pending.pop(req.id, None) |
| nexus_core/hitl/manager.py:223 | texto | req = self._pending.get(hitl_id) |
| nexus_core/hitl/manager.py:236 | texto | req = self._pending.get(hitl_id) |
| nexus_core/hitl/manager.py:248 | texto | def get_pending(self) -> List[dict]: |
| nexus_core/hitl/manager.py:249 | texto | return [r.to_dict() for r in self._pending.values()] |
| nexus_core/hitl/manager.py:254 | texto | def count_pending(self) -> int: |
| nexus_core/hitl/manager.py:255 | texto | return len(self._pending) |
| nexus_core/hitl/manager.py:258 | texto | ids = list(self._pending.keys()) |
| nexus_core/hitl/manager.py:264 | texto | ids = list(self._pending.keys()) |
| nexus_core/junior_bridge.py:49 | TODO | """Conecta todos los módulos del core.""" |
| nexus_core/junior_bridge.py:127 | TODO | logger.info("[JuniorBridge] ✓ Todo listo — NEXUS operativo") |
| nexus_core/junior_bridge.py:132 | TODO | """Registra todos los agentes disponibles en el Registry.""" |
| nexus_core/kernel/approvals.py:23 | texto | (approval_id, context.tenant_id, context.run_id, action, "pending", |
| nexus_core/kernel/approvals.py:47 | texto | if approval["status"] != "pending": |
| nexus_core/kernel/approvals.py:55 | texto | WHERE id=? AND tenant_id=? AND status='pending'""", |
| nexus_core/kernel/control_store.py:234 | texto | action TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', |
| nexus_core/kernel/control_store.py:449 | texto | (run_id, tenant_id, workflow_id, "pending", idempotency_key, |
| nexus_core/kernel/control_store.py:452 | texto | return {"id": run_id, "tenant_id": tenant_id, "status": "pending", "context": context} |
| nexus_core/kernel/runtime.py:274 | texto | plan.extend({"step": f"tool:{item.get('tool_id', 'unknown')}", "status": "pending"} |
| nexus_core/kernel/runtime.py:277 | texto | {"step": "respond", "status": "pending"}, |
| nexus_core/kernel/runtime.py:278 | texto | {"step": "evaluate", "status": "pending"}, |
| nexus_core/kernel/workflows.py:76 | texto | (f"step_{uuid4().hex}", run["id"], step["key"], "pending", |
| nexus_core/kernel/workflows.py:168 | texto | if state["status"] == "pending" and all(states[item]["status"] == "completed" for item in dependencies): |
| nexus_core/state/manager.py:16 | texto | PENDING = "pending" |
| nexus_core/state/manager.py:179 | texto | async def get_pending_tasks(self) -> List[TaskState]: |
| nexus_core/state/manager.py:181 | texto | tasks = [TaskState.from_dict(task) for task in self._state.tasks.values() if task["status"] == TaskStatus.PENDING] |
| nexus_core/team_orchestrator.py:123 | TODO | """Lista todos los equipos.""" |
| nexus_core/tests/unit/test_kernel_offline.py:476 | texto | task_id="task-real", name="real", status=TaskStatus.PENDING, |
| nexus_core/tests/unit/test_state_manager.py:10 | texto | return TaskState(task_id, "test", TaskStatus.PENDING, "agent-1", {"id": task_id}, priority=priority) |
| nexus_core/tests/unit/test_state_manager.py:42 | texto | assert [item.task_id for item in await state_manager.get_pending_tasks()] == ["high"] |
| nexus_core/workflow_manager.py:29 | texto | PENDING   = "pending" |
| nexus_core/workflow_manager.py:37 | texto | PENDING   = "pending" |
| nexus_core/workflow_manager.py:52 | texto | status: NodeStatus = NodeStatus.PENDING |
| nexus_core/workflow_manager.py:66 | texto | status: WorkflowStatus = WorkflowStatus.PENDING |
| nexus_core/workflow_manager.py:211 | texto | if node.status != NodeStatus.PENDING: |
| nexus_frontend/src/api/client.js:128 | texto | hitlPending:   () => api.get('/hitl/pending'), |
| nexus_frontend/src/components/ui/index.jsx:114 | texto | pending:   { color: 'var(--yellow)', label: 'PENDING'  }, |
| nexus_frontend/src/hooks/useWebSocket.js:67 | texto | setHITL(d.data?.pending \|\| []) |
| nexus_frontend/src/pages/ControlPlane.jsx:53 | texto | <Btn onClick={()=>installMarketing.mutate()} style={{ opacity:installMarketing.isPending ? .7 : 1 }}>Instalar Marketing</Btn> |
| nexus_frontend/src/pages/Factory.jsx:8 | texto | draft:'var(--text-dim)', analyzing:'var(--cyan)', pending_approval:'var(--yellow)', |
| nexus_frontend/src/pages/Factory.jsx:12 | texto | draft:'○', analyzing:'⟳', pending_approval:'⏸', approved:'✓', |
| nexus_frontend/src/pages/Factory.jsx:126 | texto | {p.status === 'pending_approval' && ( |
| nexus_frontend/src/pages/Factory.jsx:128 | texto | style={{ width:'100%', opacity: approveMutation.isPending ? .6 : 1 }}> |
| nexus_frontend/src/pages/Factory.jsx:175 | texto | style={{ opacity: analyzeMutation.isPending ? .6 : 1 }}> |
| nexus_frontend/src/pages/Factory.jsx:176 | texto | {analyzeMutation.isPending ? '⟳ ANALIZANDO CON IA...' : '🧠 GENERAR PLAN MAESTRO'} |
| nexus_frontend/src/pages/Factory.jsx:249 | texto | style={{ width:'100%', opacity: approveMutation.isPending ? .6 : 1 }}> |
| nexus_frontend/src/pages/Factory.jsx:250 | texto | {approveMutation.isPending ? '⟳ APROBANDO...' : '🚀 APROBAR PLAN Y EJECUTAR FÁBRICA'} |
| nexus_frontend/src/pages/HITL.jsx:19 | texto | const { data: apiPending } = useQuery({ |
| nexus_frontend/src/pages/HITL.jsx:20 | texto | queryKey: ['hitl-pending'], |
| nexus_frontend/src/pages/HITL.jsx:21 | texto | queryFn: async () => { const { data } = await nexusApi.hitlPending(); return data.pending \|\| [] }, |
| nexus_frontend/src/pages/HITL.jsx:25 | texto | const items = hitlItems.length > 0 ? hitlItems : (apiPending \|\| []) |
| nexus_frontend/src/pages/HITL.jsx:26 | texto | const pending = items.filter(h => !resolved[h.id]) |
| nexus_frontend/src/pages/HITL.jsx:32 | texto | qc.invalidateQueries(['hitl-pending']) |
| nexus_frontend/src/pages/HITL.jsx:39 | texto | qc.invalidateQueries(['hitl-pending']) |
| nexus_frontend/src/pages/HITL.jsx:44 | texto | onSuccess: () => { pending.forEach(h => setResolved(r=>({...r,[h.id]:'approved'}))); qc.invalidateQueries(['hitl-pending']) }, |
| nexus_frontend/src/pages/HITL.jsx:48 | texto | onSuccess: () => { pending.forEach(h => setResolved(r=>({...r,[h.id]:'denied'}))); qc.invalidateQueries(['hitl-pending']) }, |
| nexus_frontend/src/pages/HITL.jsx:59 | texto | HUMAN IN THE LOOP · {pending.length} PENDIENTES |
| nexus_frontend/src/pages/HITL.jsx:64 | texto | {pending.length > 0 && ( |
| nexus_frontend/src/pages/HITL.jsx:66 | TODO | <Btn variant="primary" onClick={()=>approveAllMutation.mutate()}>✓ APROBAR TODOS</Btn> |
| nexus_frontend/src/pages/HITL.jsx:67 | TODO | <Btn variant="danger"  onClick={()=>denyAllMutation.mutate()}>✗ DENEGAR TODOS</Btn> |
| nexus_frontend/src/pages/HITL.jsx:72 | texto | {pending.length === 0 ? ( |
| nexus_frontend/src/pages/HITL.jsx:77 | TODO | Todos los agentes operando normalmente |
| nexus_frontend/src/pages/HITL.jsx:82 | texto | {pending.map(h => { |
| nexus_frontend/src/pages/HITL.jsx:85 | texto | const isApproving = approveMutation.isPending && approveMutation.variables?.id === h.id |
| nexus_frontend/src/pages/HITL.jsx:86 | texto | const isDenying   = denyMutation.isPending   && denyMutation.variables?.id === h.id |
| nexus_frontend/src/pages/Junior.jsx:47 | TODO | "Analiza todo el proyecto NEXUS PRO y dime qué archivos son basura", |
| nexus_frontend/src/pages/Junior.jsx:96 | texto | queryFn: () => jApi.updates('pending').then(r => r.data.updates \|\| []), |
| nexus_frontend/src/pages/Junior.jsx:189 | texto | {approveMut.isPending && approveMut.variables === u.id ? '⟳' : '✓ APROBAR'} |
| nexus_frontend/src/pages/Junior.jsx:324 | texto | queryFn: () => jApi.updates('pending').then(r => r.data), |
| nexus_frontend/src/pages/Junior.jsx:375 | texto | if (!input.trim() \|\| sendMut.isPending) return |
| nexus_frontend/src/pages/Junior.jsx:429 | texto | {statusData?.pending_updates > 0 && ( |
| nexus_frontend/src/pages/Junior.jsx:430 | texto | <span style={{ color:'var(--yellow)' }}>· {statusData.pending_updates} actualizaciones</span> |
| nexus_frontend/src/pages/Junior.jsx:507 | texto | {sendMut.isPending && ( |
| nexus_frontend/src/pages/Junior.jsx:544 | texto | disabled={!input.trim() \|\| sendMut.isPending} |
| nexus_frontend/src/pages/Junior.jsx:552 | texto | {sendMut.isPending ? '⟳' : '▶'} |
| nexus_frontend/src/pages/Junior.jsx:569 | TODO | placeholder="Ej: Analiza todo el proyecto NEXUS PRO, identifica archivos innecesarios y genera reporte con recomendaciones..." |
| nexus_frontend/src/pages/Junior.jsx:588 | texto | disabled={!runObj.trim() \|\| runMut.isPending} |
| nexus_frontend/src/pages/Junior.jsx:595 | texto | {runMut.isPending ? '⟳ INICIANDO...' : '🚀 EJECUTAR JUNIOR'} |
| nexus_frontend/src/pages/Memory.jsx:146 | texto | style={{ opacity: clearMutation.isPending ? .6 : 1 }}> |
| nexus_frontend/src/pages/Pentest.jsx:77 | texto | <Btn variant="danger" onClick={()=>runMutation.mutate()} style={{ opacity:runMutation.isPending?.6:1 }}> |
| nexus_frontend/src/pages/Pentest.jsx:78 | texto | {runMutation.isPending ? '⟳ INICIANDO...' : '🔴 PENTEST COMPLETO'} |
| nexus_frontend/src/pages/RBAC.jsx:47 | TODO | { role:'ADMIN',      color:'var(--red)',    desc:'Acceso total al sistema',         perms:['Todo'] }, |
| nexus_frontend/src/pages/RBAC.jsx:50 | TODO | { role:'VIEWER',     color:'var(--text-dim)',desc:'Solo lectura de dashboards',     perms:['Ver todo (read-only)'] }, |
| nexus_frontend/src/pages/Teams.jsx:10 | TODO | { value:'parallel',     label:'Paralela — todos simultáneo' }, |
| nexus_frontend/src/pages/Users.jsx:99 | texto | style={{ opacity: createMutation.isPending ? .6 : 1 }}> |
| nexus_frontend/src/pages/Users.jsx:100 | texto | {createMutation.isPending ? '⟳ CREANDO...' : '✓ CREAR USUARIO'} |
| nexus_frontend/src/pages/Users.jsx:179 | TODO | ['admin', 'var(--red)',    ['Todo el sistema', 'Crear/eliminar usuarios', 'Configurar modelos', 'Aprobar HITL', 'Pentest completo']], |
| nexus_healthcheck.sh:61 | texto | for ep in "/agents" "/tasks" "/teams-v2" "/hitl/pending" "/memory/agents" "/auth/users"; do |
| nexus_healthcheck.sh:78 | TODO | echo -e "${GREEN}${BOLD}✓ Todos los checks pasaron ($PASS/$TOTAL)${NC}" |
| nexus_junior_jarvis.sh:82 | texto | status TEXT DEFAULT 'pending', |
| nexus_junior_jarvis.sh:374 | texto | "SELECT title FROM junior_updates WHERE status='pending'" |
| nexus_junior_jarvis.sh:484 | texto | status TEXT DEFAULT 'pending', |
| nexus_junior_jarvis.sh:560 | texto | async def get_updates(status: str = "pending"): |
| nexus_junior_jarvis.sh:844 | texto | pending_updates = conn.execute( |
| nexus_junior_jarvis.sh:845 | texto | "SELECT COUNT(*) as c FROM junior_updates WHERE status='pending'" |
| nexus_junior_jarvis.sh:848 | texto | pending_updates = 0 |
| nexus_junior_jarvis.sh:853 | texto | "pending_updates": pending_updates, |
| nexus_junior_jarvis.sh:908 | texto | updates:     (status='pending') => nexusApi.api.get(`/jarvis/updates?status=${status}`), |
| nexus_junior_jarvis.sh:924 | TODO | "Analiza todo el proyecto NEXUS PRO y dime qué archivos son basura", |
| nexus_junior_jarvis.sh:973 | texto | queryFn: () => jApi.updates('pending').then(r => r.data.updates \|\| []), |
| nexus_junior_jarvis.sh:1066 | texto | {approveMut.isPending && approveMut.variables === u.id ? '⟳' : '✓ APROBAR'} |
| nexus_junior_jarvis.sh:1200 | texto | queryFn: () => jApi.updates('pending').then(r => r.data), |
| nexus_junior_jarvis.sh:1251 | texto | if (!input.trim() \|\| sendMut.isPending) return |
| nexus_junior_jarvis.sh:1305 | texto | {statusData?.pending_updates > 0 && ( |
| nexus_junior_jarvis.sh:1306 | texto | <span style={{ color:'var(--yellow)' }}>· {statusData.pending_updates} actualizaciones</span> |
| nexus_junior_jarvis.sh:1383 | texto | {sendMut.isPending && ( |
| nexus_junior_jarvis.sh:1420 | texto | disabled={!input.trim() \|\| sendMut.isPending} |
| nexus_junior_jarvis.sh:1428 | texto | {sendMut.isPending ? '⟳' : '▶'} |
| nexus_junior_jarvis.sh:1445 | TODO | placeholder="Ej: Analiza todo el proyecto NEXUS PRO, identifica archivos innecesarios y genera reporte con recomendaciones..." |
| nexus_junior_jarvis.sh:1464 | texto | disabled={!runObj.trim() \|\| runMut.isPending} |
| nexus_junior_jarvis.sh:1471 | texto | {runMut.isPending ? '⟳ INICIANDO...' : '🚀 EJECUTAR JUNIOR'} |
| nexus_mcp/server.py:157 | texto | """Create a durable pending run; workers execute it only after policy checks.""" |
| nexus_upgrade.sh:360 | TODO | print('  Todos los módulos importaron correctamente') |


## 11. Superficie de eliminación — runtime legado

### 11.1 Archivos completos que serán eliminados

| Ruta | Razón |
|---|---|
| nexus_core/agents/dynamic_agent.py | ToolExecutor/planner legado. |
| nexus_core/agents/pentest_agent.py | Pentest directo. |
| nexus_core/composite_tools.py | IO/shell legacy. |
| nexus_core/hitl/manager.py | HITL in-memory paralelo. |
| nexus_core/agents/generated/bashagent.py | Shell legacy. |
| nexus_core/agents/generated/codeagent.py | Shell/patch legacy. |
| nexus_core/skills/nmap_scan.py | Sin policy/sandbox. |
| nexus_core/skills/nuclei_scan.py | Sin policy/sandbox. |


### 11.2 Archivos que serán modificados

| Ruta | Líneas / acción |
|---|---|
| nexus_api/main.py | 151-184,451-491: retirar inicializaciones/rutas legacy. |
| nexus_api/config.py | 36-39: retirar flag. |
| nexus_core/kernel/legacy.py | 1-17: retirar gate. |
| nexus_api/routes/tasks.py | 72-96: retirar fallback shell. |
| nexus_api/routes/pentest.py | migrar o retirar. |
| nexus_api/routes/composite.py | migrar o retirar. |
| nexus_core/main.py | registro demo skills legacy. |


### 11.3 Puntos de entrada
- nexus_api/main.py:174-184,451-491
- nexus_api/routes/tasks.py:75-76
- nexus_core/agents/dynamic_agent.py:291
- nexus_api/routes/pentest.py:35

### 11.4 Flags

| Setting | Archivo:línea | Default |
|---|---|---|
| NEXUS_ENABLE_LEGACY_RUNTIME | nexus_api/config.py:36-39; .env.example | false |
| NEXUS_ENABLE_LEGACY_EXECUTION | nexus_core/kernel/legacy.py:6-10; .env.example | false |


### 11.5 Tests
- nexus_core/tests/unit/test_kernel_offline.py:test_legacy_execution_is_disabled_by_default depende del flag.
- No se localizaron tests directos de PentestAgent/DynamicAgent.

### 11.6 Dependencias

```text
nexus_api/main.py -> rutas legacy -> dynamic_agent/pentest_agent/composite_tools
routes/tasks.py -> kernel/legacy.py -> fallback shell
dynamic_agent.py -> hitl/manager.py + herramientas directas
pentest_agent.py -> nmap/bandit/safety/httpx + reportes
```

## 12. Código reutilizable del legado

| Pieza | Archivo:línea | Por qué vale la pena | Cómo migrarla |
|---|---|---|---|
| Parser nmap | pentest_agent.py:43-47 | puertos estructurados | handler durable argv/schema/evidence |
| Fingerprint HTTP | pentest_agent.py:198-235 | headers de seguridad | ToolDefinition con SSRF control |
| Scanner secrets | pentest_agent.py:153-196 | hallazgos estructurados | tool durable confinement |
| Reporte Markdown | pentest_agent.py:244-334,456+ | plantilla | ArtifactStore durable |
| LLM abstraction | llm/abstraction.py:75-656 | interfaz/fallback/uso | conservar runtime durable |
| OCI sandbox | kernel/sandbox.py:83-159 | aislamiento | ampliar catálogo |


## 13. Preguntas abiertas
- Hay dos runtimes; el activo depende de flags/entorno en nexus_api/main.py.
- No se determinó cómo se provisionan policies allow en producción.
- No existe flujo de pentest E2E en kernel durable.
- No se inspeccionaron datos reales de SQLite ni .env.
- Despliegue worker/frontend depende de variables externas no evaluadas.
