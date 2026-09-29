# Decisiones del cleanup de OmniAgentCS-CLI

Rama: chore/final-cleanup. Base: 4705cfa. Autorización total de esta misión;
se conservan el schema del ControlStore y las firmas públicas del runtime.
Cada archivo eliminado figura individualmente; los movimientos conservan historia.
La memoria durable es kernel/memory.py; memory/ y vector/ son implementaciones antiguas.

## Inventario y decisiones

| Path | Decisión | Razón | Referencias consultadas |
|---|---|---|---|
| `omni.py` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_worker.py` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_core/kernel/` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_core/scope/` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_core/agent/` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_core/tools/` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_core/cli/` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_core/config/` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_core/provisioner/` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_core/integrations/` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_core/llm/abstraction.py` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_core/llm/anthropic_client.py` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_core/utils/` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_core/tests/` | conservar | CLI, worker, servicios durables o pruebas vigentes | imports absolutos/relativos, registry y tests; inspección de consumidores |
| `nexus_frontend` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `bajioware_landing` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `departments` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `docker` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `junior_jarvis.py` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_junior_jarvis.sh` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `factory_runner.py` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_cli.py` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_connector.py` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_ops.py` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_backup.sh` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_restore.sh` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_start.sh` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_upgrade.sh` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_healthcheck.sh` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `install.sh` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `Dockerfile.backend` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `Dockerfile.frontend` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `docker-compose.yml` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_api` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_mcp` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `.dockerignore` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `.nvmrc` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `data/factory` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/agents` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/core` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/state` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/planner` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/evolution` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/hitl` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/vector` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/team_orchestrator.py` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/memory` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/workforce` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/Makefile` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/run_nexus.sh` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/setup_nexus.sh` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/nexus_state.json` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/llm/openai_provider.py` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/llm/gemini_provider.py` | LEGACY: eliminar en su fase | sin consumidores de runtime actual; referencias restantes son legacy o tests específicos | rg de imports en omni, worker y paquetes actuales; lectura de test_kernel_offline y conftest |
| `nexus_core/kernel/{packages,connectors,directory,memory,knowledge}.py` | conservar | facilidades del kernel y contratos probados; decisión conservadora sin cambiar schema | tests offline, runtime y ControlStore |
| `docs/` | archivar documentación de plataforma; conservar historia | las guías antiguas no deben presentarse como instrucciones vigentes | lectura de títulos y referencias a API/MCP/Compose |
| `nexus_frontend/.env` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/.gitignore` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/README.md` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/eslint.config.js` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/index.html` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/package-lock.json` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/package.json` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/public/favicon.svg` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/public/icons.svg` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/App.css` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/App.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/api/client.js` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/assets/hero.png` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/components/layout/Sidebar.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/components/layout/TopBar.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/components/ui/Form.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/components/ui/Modal.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/components/ui/index.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/hooks/useNexusData.js` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/hooks/useWebSocket.js` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/index.css` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/main.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Agents.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Audit.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/ControlPlane.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Factory.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Guardian.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/HITL.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Junior.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Login.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Memory.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Models.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Overview.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Pentest.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/RBAC.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Settings.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Tasks.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Teams.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Terminal.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Users.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/pages/Vault.jsx` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/store/authStore.js` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/src/store/nexusStore.js` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_frontend/vite.config.js` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `bajioware_landing/index.html` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `departments/marketing/evals/marketing.json` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `departments/marketing/manifest.json` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `docker/connector-mtls.conf.template` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `docker/entrypoint.sh` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `docker/mcp-remote.conf.template` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `docker/nginx.conf` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `junior_jarvis.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_junior_jarvis.sh` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `factory_runner.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_cli.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_connector.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_ops.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_backup.sh` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_restore.sh` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_start.sh` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_upgrade.sh` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_healthcheck.sh` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `install.sh` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `Dockerfile.backend` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `Dockerfile.frontend` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `docker-compose.yml` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/__init__.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/auth/__init__.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/auth/deps.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/auth/oidc.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/auth/service.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/config.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/core/config.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/db/__init__.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/db/database.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/main.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/requirements.txt` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/__init__.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/a2a.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/agents.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/approvals.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/audit.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/auth.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/connectors.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/directory.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/evolution.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/memory.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/models.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/packages.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/policies.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/projects.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/scheduler.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/sovereign.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/tasks.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/tools.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/workflows.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/routes/ws_logs.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/scheduler/__init__.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/scheduler/manager.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/services/__init__.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/services/factory_service.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/services/integration_guide.md` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/services/memory_service.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/services/project_service.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/services/workspace_manager.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_api/tests/api_smoke.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_mcp/__init__.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_mcp/server.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_mcp/tests/__init__.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_mcp/tests/smoke.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_mcp/tests/test_remote_security.py` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `.dockerignore` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `.nvmrc` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `data/factory/templates/pentest_scope.md` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `data/factory/templates/software_requirements.md` | borrar | plataforma FastAPI/React, despliegue o agentes legacy | rg nexus_api/nexus_mcp en rutas actuales: sin referencias; tests de connector/marketing revisados |
| `nexus_core/agents/__init__.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/agents/base.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/agents/data_analyst.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/agents/generated/__init__.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/agents/generated/dataanalysisagent.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/agents/generated/doc_agent.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/agents/generated/guardian_agent.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/agents/generated/kill_switch_agent.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/agents/generated/loganalyzeragent.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/agents/generated/plan_agent.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/agents/generated/project_manager_agent.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/agents/generated/reportgenerationagent.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/agents/generated/test_agent.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/agents/registry.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/core/__init__.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/core/agent_factory.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/core/agent_generator.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/core/event_bus.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/core/orchestrator.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/core/planner.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/state/__init__.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/state/manager.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/planner/__init__.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/evolution/__init__.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/evolution/lab.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/evolution/runner.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/hitl/__init__.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/vector/__init__.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/vector/embeddings.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/vector/memory.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/vector/store.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/team_orchestrator.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/memory/__init__.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/memory/manager.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/memory/models.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/memory/store.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/workforce/__init__.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/Makefile` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/run_nexus.sh` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/setup_nexus.sh` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/nexus_state.json` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/llm/openai_provider.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/llm/gemini_provider.py` | borrar | runtime legacy o wrapper LLM sin consumidores actuales | rg absoluto/relativo; test_event_bus, test_state_manager y cinco casos offline legacy identificados |
| `nexus_core/tests/unit/test_event_bus.py` | borrar | 4 tests por archivo prueban exclusivamente EventBus/StateManager eliminados | lectura completa de ambos archivos y fixtures conftest |
| `nexus_core/tests/unit/test_state_manager.py` | borrar | 4 tests por archivo prueban exclusivamente EventBus/StateManager eliminados | lectura completa de ambos archivos y fixtures conftest |
| `nexus_core/tests/unit/test_kernel_offline.py` | editar | retirar cinco tests legacy y sus imports; mantener todos los tests del kernel; PackageManager usa manifest temporal | AST de funciones y lectura de contratos; eliminados: test_connector_signed_update_and_rollback, test_evolution_lab_enforces_separation_of_duties, test_evolution_workspace_excludes_secrets_and_protects_baseline, test_real_event_bus_dispatches_and_stops_cleanly, test_real_state_manager_persists_without_deadlock |
| `nexus_core/tests/conftest.py` | editar | retirar fixtures tmp_state_file/state_manager/event_bus; mantener onboarding_env | consumidores de fixtures en los dos test files legacy eliminados |
| `nexus_core/tests/unit/test_sovereign_runtime.py` | editar | quitar dos asignaciones F841 conservando llamadas y efectos; conservar la asignación usada en línea 14 | ruff líneas 38/78 e inspección de los tres casos |
| `nexus_core/utils/logger.py` | editar | retirar import muerto contextlib | ruff F401; llm.abstraction conserva get_logger |
| `nexus_core/utils/security.py` | editar | retirar imports muertos typing/re/pathlib/json/functools | ruff F401; test_security conserva contratos |
| `AUDITORIA_NEXUS_2026-08-04.md` | mover a docs/missions/AUDITORIA_NEXUS_2026-08-04.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `CLEANUP_AUDIT.md` | mover a docs/missions/CLEANUP_AUDIT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `CLEANUP_RECON_V2.md` | mover a docs/missions/CLEANUP_RECON_V2.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `CLEANUP_RESULT.md` | mover a docs/missions/CLEANUP_RESULT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `CLEANUP_RESULT_V2.md` | mover a docs/missions/CLEANUP_RESULT_V2.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `CLI_RECON.md` | mover a docs/missions/CLI_RECON.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `CLI_RESULT.md` | mover a docs/missions/CLI_RESULT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `CODEBASE_MAP.md` | mover a docs/missions/CODEBASE_MAP.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `FIX_SANDBOX_RECON.md` | mover a docs/missions/FIX_SANDBOX_RECON.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `FIX_SANDBOX_RESULT.md` | mover a docs/missions/FIX_SANDBOX_RESULT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `INFORME_ARQUITECTONICO_NEXUS_2026-08-08.md` | mover a docs/missions/INFORME_ARQUITECTONICO_NEXUS_2026-08-08.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `MSF_DAEMON_DIAG.md` | mover a docs/missions/MSF_DAEMON_DIAG.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `MSF_DAEMON_RESULT.md` | mover a docs/missions/MSF_DAEMON_RESULT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `MSF_RESULT.md` | mover a docs/missions/MSF_RESULT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `NMAP_RECON.md` | mover a docs/missions/NMAP_RECON.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `NMAP_RESULT.md` | mover a docs/missions/NMAP_RESULT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `OMNIAGENT_CONTEXT.md` | mover a docs/missions/OMNIAGENT_CONTEXT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `ONBOARDING_RECON.md` | mover a docs/missions/ONBOARDING_RECON.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `ONBOARDING_RESULT.md` | mover a docs/missions/ONBOARDING_RESULT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `PLAN_IMPLEMENTACION_NEXUS.md` | mover a docs/missions/PLAN_IMPLEMENTACION_NEXUS.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `PLAN_MAESTRO_BAJIOWARE.md` | mover a docs/missions/PLAN_MAESTRO_BAJIOWARE.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `PRICING.md` | mover a docs/missions/PRICING.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `PURGE_RECON.md` | mover a docs/missions/PURGE_RECON.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `PURGE_RESULT.md` | mover a docs/missions/PURGE_RESULT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `REACT_RECON.md` | mover a docs/missions/REACT_RECON.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `REACT_RESULT.md` | mover a docs/missions/REACT_RESULT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `REPORTE_IMPLEMENTACION_NEXUS_2026-08-04.md` | mover a docs/missions/REPORTE_IMPLEMENTACION_NEXUS_2026-08-04.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `RESIDUALS_DIAG.md` | mover a docs/missions/RESIDUALS_DIAG.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `RESIDUALS_RESULT.md` | mover a docs/missions/RESIDUALS_RESULT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `SCOPE_RECON.md` | mover a docs/missions/SCOPE_RECON.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `SCOPE_RESULT.md` | mover a docs/missions/SCOPE_RESULT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `SCOPE_WIRE_RESULT.md` | mover a docs/missions/SCOPE_WIRE_RESULT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `TOOLKIT_RECON.md` | mover a docs/missions/TOOLKIT_RECON.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `TOOLKIT_RESULT.md` | mover a docs/missions/TOOLKIT_RESULT.md | reporte histórico; despejar raíz sin perder historia | git ls-files y clasificación por misión |
| `docs/CLEANUP_2026-08-04.md` | archivar en docs/missions/platform/CLEANUP_2026-08-04.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `docs/DEPLOYMENT_ON_PREM.md` | archivar en docs/missions/platform/DEPLOYMENT_ON_PREM.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `docs/NEXUS_SOVEREIGN.md` | archivar en docs/missions/platform/NEXUS_SOVEREIGN.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `docs/SCIM_PROVISIONING.md` | archivar en docs/missions/platform/SCIM_PROVISIONING.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `docs/adr/ADR-001-kernel-gateways.md` | archivar en docs/missions/platform/adr/ADR-001-kernel-gateways.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `docs/adr/ADR-002-zero-trust-execution.md` | archivar en docs/missions/platform/adr/ADR-002-zero-trust-execution.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `docs/adr/ADR-003-governed-evolution.md` | archivar en docs/missions/platform/adr/ADR-003-governed-evolution.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `docs/runbooks/BACKUP_RESTORE.md` | archivar en docs/missions/platform/runbooks/BACKUP_RESTORE.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `docs/runbooks/CLAUDE_MCP.md` | archivar en docs/missions/platform/runbooks/CLAUDE_MCP.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `docs/runbooks/CONNECTOR_MTLS.md` | archivar en docs/missions/platform/runbooks/CONNECTOR_MTLS.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `docs/runbooks/DATA_GOVERNANCE.md` | archivar en docs/missions/platform/runbooks/DATA_GOVERNANCE.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `docs/runbooks/DEVELOPMENT_OFFLINE.md` | archivar en docs/missions/platform/runbooks/DEVELOPMENT_OFFLINE.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `docs/runbooks/INCIDENT_RESPONSE.md` | archivar en docs/missions/platform/runbooks/INCIDENT_RESPONSE.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `docs/runbooks/SLO_SLI.md` | archivar en docs/missions/platform/runbooks/SLO_SLI.md | documentación NEXUS platform; conserva ADRs e historia fuera de guías vigentes | títulos y comandos API/MCP/Compose |
| `nexus_core/plan_maestro.md` | archivar en docs/missions/platform/plan_maestro_core.md | plan/guía/lock conjunto de plataforma retirada; no anunciarlo como instalación CLI | referencias a main.py inexistente y dependencias FastAPI/MCP/React; manifiestos CLI se ajustan en fase de build |
| `nexus_core/README.md` | archivar en docs/missions/platform/README_core.md | plan/guía/lock conjunto de plataforma retirada; no anunciarlo como instalación CLI | referencias a main.py inexistente y dependencias FastAPI/MCP/React; manifiestos CLI se ajustan en fase de build |
| `requirements.lock` | archivar en docs/missions/platform/requirements.lock | plan/guía/lock conjunto de plataforma retirada; no anunciarlo como instalación CLI | referencias a main.py inexistente y dependencias FastAPI/MCP/React; manifiestos CLI se ajustan en fase de build |
| `requirements-prod.lock` | archivar en docs/missions/platform/requirements-prod.lock | plan/guía/lock conjunto de plataforma retirada; no anunciarlo como instalación CLI | referencias a main.py inexistente y dependencias FastAPI/MCP/React; manifiestos CLI se ajustan en fase de build |
| `CHANGELOG.txt` | borrar | duplicado byte a byte de CHANGELOG.md | comparación binaria de ambos archivos |
| `react_e2e_manual.py` | mover a scripts/ y ajustar raíz | herramienta manual actual; debe resolver checkout tras moverla | lectura de imports, carga dotenv y rutas |
| `list_models.sh` | mover a scripts/ y ajustar raíz | herramienta manual actual; debe resolver checkout tras moverla | lectura de imports, carga dotenv y rutas |
| `.gitignore` | editar | ignorar caches, configuración local y sidecars SQLite sin versionar secretos | git status y patrones requeridos |
| `nexus_api/**/__pycache__/` | borrar local | solo bytecode de módulos legacy ya eliminados; no datos | inventario de archivos no-cache vacío |
| `nexus_mcp/**/__pycache__/` | borrar local | solo bytecode de módulos legacy ya eliminados; no datos | inventario de archivos no-cache vacío |
| `nexus_core/agents/**/__pycache__/` | borrar local | solo bytecode de módulos legacy ya eliminados; no datos | inventario de archivos no-cache vacío |
| `nexus_core/core/**/__pycache__/` | borrar local | solo bytecode de módulos legacy ya eliminados; no datos | inventario de archivos no-cache vacío |
| `nexus_core/state/**/__pycache__/` | borrar local | solo bytecode de módulos legacy ya eliminados; no datos | inventario de archivos no-cache vacío |
| `nexus_core/planner/**/__pycache__/` | borrar local | solo bytecode de módulos legacy ya eliminados; no datos | inventario de archivos no-cache vacío |
| `nexus_core/evolution/**/__pycache__/` | borrar local | solo bytecode de módulos legacy ya eliminados; no datos | inventario de archivos no-cache vacío |
| `nexus_core/hitl/**/__pycache__/` | borrar local | solo bytecode de módulos legacy ya eliminados; no datos | inventario de archivos no-cache vacío |
| `nexus_core/vector/**/__pycache__/` | borrar local | solo bytecode de módulos legacy ya eliminados; no datos | inventario de archivos no-cache vacío |
| `nexus_core/memory/**/__pycache__/` | borrar local | solo bytecode de módulos legacy ya eliminados; no datos | inventario de archivos no-cache vacío |
| `nexus_core/workforce/**/__pycache__/` | borrar local | solo bytecode de módulos legacy ya eliminados; no datos | inventario de archivos no-cache vacío |
| `nexus_core/skills/**/__pycache__/` | borrar local | solo bytecode de módulos legacy ya eliminados; no datos | inventario de archivos no-cache vacío |
| `nexus_frontend/{node_modules,dist}/` | borrar local | build y dependencias del frontend retirado | inventario local tras git rm: solo node_modules y dist |
| `data/nexus_pro.db` | migrar a /home/operator/.local/share/omni/control.db | backup SQLite consistente y dump idéntico; eng-scanme leído desde XDG; original en .backups/nexus_pro.db.pre-xdg | integrity_check, comparación de iterdump, doctor JSON y list-engagements antes de retirar origen |
| `.env (ignorado)` | editar solo NEXUS_DB_PATH | precedencia dotenv invalidaría la migración si mantiene data/nexus_pro.db; respaldo privado previo | dotenv_values sin mostrar claves; doctor tras migración |
| `/home/operator/.config/omni/config.toml` | crear config XDG 600 | ruta SQLite explícita; config anterior inexistente; sin copiar secretos de .env | load_config/save_config y stat; db_file XDG resuelto |
| `nexus_worker.py` | editar | usar config XDG y precedencia dotenv como CLI; evita recrear data/nexus_pro.db tras migración | import estático NEXUS_DB_PATH anterior; pruebas con DB global/override |
| `nexus_core/tests/unit/test_onboarding_cli.py` | añadir dos casos | worker respeta DB global y override; --once simulado sin trabajos reales | 7 tests del archivo pasan; store y dotenv simulados |
| `requirements-prod.in` | editar | alinear instalación, configuración y CI con CLI/worker; retirar referencias a componentes eliminados | inventario de imports y grep de referencias; MessagePack ya estaba instalado/usado; sin nuevas bibliotecas |
| `requirements-dev.txt` | editar | alinear instalación, configuración y CI con CLI/worker; retirar referencias a componentes eliminados | inventario de imports y grep de referencias; MessagePack ya estaba instalado/usado; sin nuevas bibliotecas |
| `nexus_core/requirements.txt` | editar | alinear instalación, configuración y CI con CLI/worker; retirar referencias a componentes eliminados | inventario de imports y grep de referencias; MessagePack ya estaba instalado/usado; sin nuevas bibliotecas |
| `Makefile` | editar | alinear instalación, configuración y CI con CLI/worker; retirar referencias a componentes eliminados | inventario de imports y grep de referencias; MessagePack ya estaba instalado/usado; sin nuevas bibliotecas |
| `.env.example` | editar | alinear instalación, configuración y CI con CLI/worker; retirar referencias a componentes eliminados | inventario de imports y grep de referencias; MessagePack ya estaba instalado/usado; sin nuevas bibliotecas |
| `ruff.toml` | editar | alinear instalación, configuración y CI con CLI/worker; retirar referencias a componentes eliminados | inventario de imports y grep de referencias; MessagePack ya estaba instalado/usado; sin nuevas bibliotecas |
| `.github/workflows/ci.yml` | editar | alinear instalación, configuración y CI con CLI/worker; retirar referencias a componentes eliminados | inventario de imports y grep de referencias; MessagePack ya estaba instalado/usado; sin nuevas bibliotecas |
| `requirements{,-prod}.lock` | archivados, sin locks nuevos | locks anteriores incluían todo FastAPI/MCP y paquetes ya retirados; instalación vigente por manifiestos; no se promete resolución reproducible | docs/missions/platform conserva los originales; no se instalaron dependencias |
| `README.md` | reescribir | guía actual de CLI/worker, 11 tools, XDG, instalación y pruebas; referencias de plataforma archivadas | --help, registry, config, provisioner, scripts y diagnóstico real |
| `nexus_core/cli/main.py` | editar descripción de argparse | nombre comercial vigente en --help; sin cambios de ejecución | omni --help |
