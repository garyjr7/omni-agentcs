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
