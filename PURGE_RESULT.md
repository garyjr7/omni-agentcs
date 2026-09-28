# PURGE RESULT

## git status
```text
D  .env
 M .env.example
 M nexus_api/config.py
 M nexus_api/main.py
D  nexus_api/routes/composite.py
D  nexus_api/routes/docagent.py
D  nexus_api/routes/factory.py
D  nexus_api/routes/guardian.py
D  nexus_api/routes/hitl.py
D  nexus_api/routes/jarvis.py
D  nexus_api/routes/junior.py
D  nexus_api/routes/killswitch.py
D  nexus_api/routes/pentest.py
D  nexus_api/routes/plans.py
D  nexus_api/routes/project_manager.py
 M nexus_api/routes/tasks.py
D  nexus_api/routes/teams_v2.py
D  nexus_api/routes/testagent.py
D  nexus_core/agents/dynamic_agent.py
D  nexus_core/agents/generated/bashagent.py
D  nexus_core/agents/generated/codeagent.py
D  nexus_core/agents/generated/fileagent.py
D  nexus_core/agents/pentest_agent.py
D  nexus_core/composite_tools.py
D  nexus_core/hitl/manager.py
D  nexus_core/kernel/legacy.py
D  nexus_core/skills/__init__.py
D  nexus_core/skills/base.py
D  nexus_core/skills/file_reader.py
D  nexus_core/skills/http_client.py
D  nexus_core/skills/nmap_scan.py
D  nexus_core/skills/nuclei_scan.py
D  nexus_core/skills/registry.py
 M nexus_core/tests/unit/test_kernel_offline.py
?? .env
?? PURGE_RECON.md
?? PURGE_RESULT.md
```

## imports
```text
nexus_api.main: OK
nexus_core.kernel.runtime: OK
nexus_worker: OK
nexus_mcp.server: OK
```

## tests unit
```text

nexus_core/tests/unit/test_event_bus.py::test_publish_dispatch_and_stats PASSED [  2%]
nexus_core/tests/unit/test_event_bus.py::test_handlers_are_isolated_by_event_type PASSED [  4%]
nexus_core/tests/unit/test_event_bus.py::test_start_and_stop_are_idempotent PASSED [  6%]
nexus_core/tests/unit/test_event_bus.py::test_event_ids_are_unique PASSED [  9%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_artifact_store_is_tenant_scoped_and_detects_tampering PASSED [ 11%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_connector_enrollment_is_one_time_and_revocable PASSED [ 13%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_connector_signed_update_and_rollback PASSED [ 16%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_control_store_is_idempotent PASSED [ 18%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_directory_entities_are_tenant_scoped PASSED [ 20%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_durable_retry_dead_letter_and_history PASSED [ 23%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_durable_task_lease PASSED [ 25%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_durable_workflow_resumes_and_enqueues_dependencies PASSED [ 27%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_evolution_lab_enforces_separation_of_duties PASSED [ 30%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_evolution_workspace_excludes_secrets_and_protects_baseline PASSED [ 32%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_explicit_policy_deny_overrides_admin PASSED [ 34%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_failed_workflow_enqueues_compensation_once PASSED [ 37%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_fake_provider_uses_fixture PASSED [ 39%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_high_risk_tool_requires_approval PASSED [ 41%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_legacy_users_are_migrated PASSED [ 44%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_marketing_package_installs_without_kernel_changes PASSED [ 46%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_memory_store_is_durable_scoped_and_searchable PASSED [ 48%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_model_router_enforces_budget PASSED [ 51%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_oci_sandbox_has_mandatory_isolation_flags PASSED [ 53%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_policy_denies_cross_tenant PASSED [ 55%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_postgres_adapter_translates_placeholders_and_idempotent_insert PASSED [ 58%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_production_rejects_implicit_sqlite PASSED [ 60%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_real_event_bus_dispatches_and_stops_cleanly PASSED [ 62%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_real_state_manager_persists_without_deadlock PASSED [ 65%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_schema_migrations_upgrade_and_rollback PASSED [ 67%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_tool_gateway_requires_approval_and_audits PASSED [ 69%]
nexus_core/tests/unit/test_kernel_offline.py::OfflineKernelTests::test_tool_gateway_validates_schema_quota_and_output PASSED [ 72%]
nexus_core/tests/unit/test_security.py::test_path_containment_blocks_prefix_and_traversal PASSED [ 74%]
nexus_core/tests/unit/test_security.py::test_high_policy_blocks_dynamic_execution PASSED [ 76%]
nexus_core/tests/unit/test_security.py::test_url_validation_blocks_ssrf PASSED [ 79%]
nexus_core/tests/unit/test_security.py::test_rate_limit_and_blocked_attempt_are_audited PASSED [ 81%]
nexus_core/tests/unit/test_sovereign_runtime.py::test_conversation_is_tenant_scoped_and_runtime_appends_response PASSED [ 83%]
nexus_core/tests/unit/test_sovereign_runtime.py::test_runtime_rejects_unknown_executor PASSED [ 86%]
nexus_core/tests/unit/test_sovereign_runtime.py::test_first_party_tool_runs_through_gateway_and_is_audited PASSED [ 88%]
nexus_core/tests/unit/test_sovereign_runtime.py::test_brain_advances_only_after_a_verified_tool_observation PASSED [ 90%]
nexus_core/tests/unit/test_state_manager.py::test_initialize_creates_valid_state PASSED [ 93%]
nexus_core/tests/unit/test_state_manager.py::test_task_persists_across_instances PASSED [ 95%]
nexus_core/tests/unit/test_state_manager.py::test_update_checkpoint_and_priority_order PASSED [ 97%]
nexus_core/tests/unit/test_state_manager.py::test_checksum_corruption_is_detected PASSED [100%]

============================== 43 passed in 7.27s ==============================
```

## tests mcp
```text
....                                                                     [100%]
4 passed in 4.49s
```

## ruff
```text
All checks passed!
```

---

# RE-VERIFICACIÓN (HEAD 57205a7)

Re-ejecutado en el entorno actual con `.venv/bin/python`.

```text
import nexus_api.main           -> OK
import nexus_core.kernel.runtime -> OK
import nexus_worker              -> OK
import nexus_mcp.server          -> OK
pytest nexus_core/tests/unit -q       -> 43 passed
pytest .../test_kernel_offline.py -q  -> 27 passed
pytest nexus_mcp/tests -q             -> 4 passed
grep "NEXUS_ENABLE_LEGACY_RUNTIME|NEXUS_ENABLE_LEGACY_EXECUTION" --include=*.py -> sin resultados
nexus_core/kernel/ -> sin referencias a dynamic_agent|pentest_agent|composite_tools|hitl.manager|bashagent|codeagent|nmap_scan|nuclei_scan
```

Todos los CRITERIOS DE ÉXITO literales de la misión se cumplen. No se realizaron
más cambios de código.

## Residuales fuera del kernel — REQUIERE REFACTOR

Archivos NO legados-listados que aún referencian módulos eliminados. Ninguno es
importado por la app al arrancar (`nexus_api`, `nexus_worker`, `nexus_mcp`), por lo
que no rompen el arranque, pero contradicen "eliminar el runtime legado por completo".

| Archivo | Detalle | Estado |
|---|---|---|
| `nexus_core/agents/junior_agent.py:28` | `from nexus_core.agents.dynamic_agent import ToolExecutor` | **ROTO** (`ModuleNotFoundError` al importar) |
| `nexus_core/main.py:29-33` | importa `nexus_core.skills.*` (eliminados) | **ROTO** (`ModuleNotFoundError` al importar) |
| `nexus_core/junior_bridge.py:141-145` | import perezoso de `bashagent`/`codeagent`/`fileagent` (eliminados) | referencia muerta (capturada por `try/except`) |
| `nexus_core/agent_team_manager.py:515` | import perezoso de `nexus_core.agents.junior_agent` | referencia muerta en runtime |
| `nexus_core/workflow_manager.py:258` | import perezoso de `nexus_core.agents.junior_agent` | referencia muerta en runtime |
| `nexus_api/services/nexus_service.py:28-36` | import perezoso del stack `core.orchestrator` legado desde la ruta **superviviente** `nexus_api/routes/nexus.py` | **REQUIERE REFACTOR** (degrada a `offline` por `try/except`) |

### Otros hallazgos

- `nexus_api/config.py` y `.env.example` ya sin `NEXUS_ENABLE_LEGACY_RUNTIME`/`NEXUS_ENABLE_LEGACY_EXECUTION`. Queda `VITE_ENABLE_LEGACY_UI` en `.env.example` (frontend, fuera de alcance).
- `nexus_core/tests/unit/test_kernel_offline.py` fue modificado en la purga (commit anterior) para eliminar el import y el test del gate legado eliminado (`kernel/legacy.py`). Justificado: el módulo referenciado ya no existe.
- `.env` permanece sin trackear (`?? .env`) y no fue tocado.

## Decisión de alcance

Por indicación explícita, se deja el árbol como está (los criterios literales pasan)
y solo se documentan los residuales de arriba. No se eliminaron archivos fuera de la
lista de la FASE 2 ni se modificó código en esta re-verificación.
