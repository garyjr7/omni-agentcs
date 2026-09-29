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
