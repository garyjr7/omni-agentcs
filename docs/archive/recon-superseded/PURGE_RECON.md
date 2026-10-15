# PURGE RECON

## Estado y referencia

Checkpoint creado: a8c2046 checkpoint: antes de purga legacy

## Kernel/LLM/worker/MCP → legado

```text
```

## Gate legacy

```text
nexus_core/tests/unit/test_kernel_offline.py:29:from nexus_core.kernel.legacy import legacy_execution_enabled
nexus_core/tests/unit/test_kernel_offline.py:412:        previous = os.environ.pop("NEXUS_ENABLE_LEGACY_EXECUTION", None)
nexus_core/tests/unit/test_kernel_offline.py:414:            self.assertFalse(legacy_execution_enabled())
nexus_core/tests/unit/test_kernel_offline.py:417:                os.environ["NEXUS_ENABLE_LEGACY_EXECUTION"] = previous
nexus_core/agents/generated/bashagent.py:36:        from nexus_core.kernel.legacy import legacy_execution_enabled
nexus_core/agents/generated/bashagent.py:37:        if not legacy_execution_enabled():
nexus_core/agents/generated/codeagent.py:32:        from nexus_core.kernel.legacy import require_legacy_execution
nexus_core/agents/generated/codeagent.py:33:        require_legacy_execution()
nexus_core/agents/generated/fileagent.py:25:        from nexus_core.kernel.legacy import require_legacy_execution
nexus_core/agents/generated/fileagent.py:26:        require_legacy_execution()
nexus_api/main.py:173:    if settings.is_production or not settings.NEXUS_ENABLE_LEGACY_RUNTIME:
nexus_api/main.py:448:if settings.NEXUS_ENABLE_LEGACY_RUNTIME and not settings.is_production:
nexus_api/main.py:502:        settings.is_production or not settings.NEXUS_ENABLE_LEGACY_RUNTIME
nexus_api/main.py:535:        settings.is_production or not settings.NEXUS_ENABLE_LEGACY_RUNTIME or
nexus_core/agents/dynamic_agent.py:18:from nexus_core.kernel.legacy import legacy_execution_enabled
nexus_core/agents/dynamic_agent.py:291:        if not legacy_execution_enabled():
nexus_api/config.py:39:    NEXUS_ENABLE_LEGACY_RUNTIME: bool = False
nexus_core/kernel/legacy.py:6:def legacy_execution_enabled() -> bool:
nexus_core/kernel/legacy.py:9:        and os.getenv("NEXUS_ENABLE_LEGACY_EXECUTION", "false").lower() == "true"
nexus_core/kernel/legacy.py:13:def require_legacy_execution() -> None:
nexus_core/kernel/legacy.py:14:    if not legacy_execution_enabled():
nexus_api/routes/tasks.py:75:                from nexus_core.kernel.legacy import require_legacy_execution
nexus_api/routes/tasks.py:76:                require_legacy_execution()
```

## Routers condicionales

```text
173:    if settings.is_production or not settings.NEXUS_ENABLE_LEGACY_RUNTIME:
448:if settings.NEXUS_ENABLE_LEGACY_RUNTIME and not settings.is_production:
487:_legacy_route_modules = {
501:    if module_path in _legacy_route_modules and (
502:        settings.is_production or not settings.NEXUS_ENABLE_LEGACY_RUNTIME
535:        settings.is_production or not settings.NEXUS_ENABLE_LEGACY_RUNTIME or
```
