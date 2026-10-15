# REACT_RECON.md — Reconocimiento para el bucle ReAct durable

Rama: `feat/react-loop` (creada desde `feat/nmap-tool`, HEAD `9121449`).
Estado de partida: 99 tests unitarios en verde, ruff limpio.

> Nota: el working tree **no** estaba limpio al empezar:
> `nexus_core/tests/integration/test_nmap_e2e.py` tiene una modificación sin
> commitear (añade `domains=("scanme.nmap.org",)` al scope de prueba) y existe
> un `list_models.sh` sin trackear (script local del operador con curl+jq).
> No forman parte de esta misión y **no** se commitean.

---

## 1. LLM: `nexus_core/llm/abstraction.py`

Confirmado. Todo lo que la misión asume existe:

| Símbolo | Firma / semántica real |
| --- | --- |
| `LLMConfig` | dataclass: `provider, model, api_key, base_url, temperature=0.1, max_tokens=4096, timeout=60, system_prompt=None` |
| `LLMMessage` | dataclass `(role, content)`. Roles usados por los clientes: `system`, `user`, `assistant` |
| `LLMResponse` | `content, model, provider, tokens_input, tokens_output, duration_ms, raw_response` + `total_tokens` |
| `BaseLLMClient` | `async complete(messages: List[LLMMessage], **kwargs) -> LLMResponse`, `is_available()`, `async ask(system, user)` |
| `LLMFactory.create_from_env()` | devuelve `Dict[str, BaseLLMClient]` **siempre con `"fake"` primero**; añade `openai` / `gemini` / `groq` / `ollama` sólo si su variable de entorno está presente |
| `NexusLLM` | **existe**: `NexusLLM(primary, fallback=None, logger=None)` con `async complete(...)`, fallback automático y `get_stats()` |
| `FakeLLMClient` | lee fixtures JSON; `scenario="echo"` devuelve el último mensaje del usuario. `NEXUS_LLM_FIXTURES` sobreescribe la ruta |

Consecuencia de diseño: como `"fake"` es siempre la primera clave de
`create_from_env()`, el `execute_react` del spec (`primary = providers[0]`)
elegiría *siempre* el provider fake. Ver "Decisiones" en `REACT_RESULT.md`.

## 2. Ejecutores durables: `nexus_core/kernel/runtime.py`

- `ExecutionContext(store, task, worker_id)` frozen; `tenant_id`/`run_id` salen
  de `task`; `event(type, **payload)` → `store.append_run_event`.
- `ExecutorRegistry.execute(task, context)`: dispatch por `task["task_type"]`,
  emite `task.started` / `task.completed`, exige que el resultado sea `dict`.
- `execute_tool(payload, context)`: construye `Identity` desde
  `payload["identity"]` (default `workload`/`operator`), carga el scope con
  `load_engagement_scope(store, tenant, payload["engagement_id"])`, construye
  `RunContext(..., scope=scope, store=store, worker_id=...)`, instancia
  `ToolGateway(PolicyEngine, AuditWriter, ApprovalService, scope_validator=make_scope_validator(...))`
  y registra **sólo** la tool pedida desde `durable_tool_definitions(tenant)`.
  Devuelve `{"tool_id": ..., "output": <ToolResult.to_dict()>}`.
  Claves aceptadas hoy: `tool_id`, `arguments`, `identity`, `engagement_id`,
  `permissions`, `approval_id`, `trace_id`.
- `execute_brain(payload, context)`: NO se toca (runner declarativo).
- `build_default_registry()`: registra `debug.fake_llm`, `llm.complete`,
  `agent.run`, `conversation.respond`, `tool.invoke`, `brain.run`,
  `memory.index`, `evaluation.run`. Punto de inserción de `react.run`.
- `registry.register()` lanza `ValueError` si el task_type ya existe.

Rutas de error relevantes para el bucle:

- Target fuera de scope → `ScopeViolation` **propagada** desde `ToolGateway.invoke`
  (tras auditar `scope.denied`).
- Tool sin scope pero `scope_required=True` → `PermissionError("scope is required but not provided")`.
- Tool no encontrada en el catálogo → `ValueError("tool is not in the first-party runtime catalog")` (lo lanza `execute_tool`, antes del gateway).
- Handler devuelve `ToolResult.success == False` → `RuntimeError("tool post-condition was not verified ...")`.
- `validate` de esquema / quota / output-too-large → excepción.

## 3. Persistencia: `nexus_core/kernel/control_store.py`

`SCHEMA` ya incluye `kernel_conversations` y `kernel_messages` → **no** hace
falta cambio de esquema (restricción 5 cumplida).

- `create_conversation(tenant_id, owner_id, title, agent_id=None, classification="internal")`
  → dict con `id` (`conversation_<hex>`), `title` truncado a 120, `status="active"`.
- `list_conversations(tenant_id, owner_id)` → orden `updated_at DESC`, excluye `deleted`.
- `get_conversation(tenant_id, conversation_id, owner_id=None)`.
- `append_message(tenant_id, conversation_id, role, content, *, run_id=None, metadata=None, classification="internal")`
  roles permitidos: `system | user | assistant | tool`; toca `updated_at` de la conversación.
- `list_messages(tenant_id, conversation_id, limit=100)` → **cronológico**
  (subquery `ORDER BY sequence DESC LIMIT n` + outer `ORDER BY sequence`);
  `limit` se clampa a `[1, 500]`; `metadata` se decodifica de JSON.
- `append_run_event(tenant_id, run_id, event_type, payload=None)` / `list_run_events(tenant_id, run_id, after=0)`
  → aquí vive el canal de cancelación cooperativa (`react.cancel_requested`).
- `record_usage(tenant_id, run_id, subject_type, subject_id, metric, amount, metadata)`
  (lo usa el gateway para `tool`/`calls`; el bucle puede registrar `tokens`).
- No existe `delete_message` ni `update_message`: `kernel_messages` es
  append-only. Ver decisión sobre resumen de historial en `REACT_RESULT.md`.

## 4. Auditoría: `nexus_core/kernel/audit.py`

`AuditWriter(store).append(*, tenant_id, trace_id, actor_id, action, resource_type, resource_id, payload, decision=None) -> event_id`.
Cadena de hashes (`previous_hash`/`event_hash`) + `_sanitize` que redacta
`password|secret|token|api_key|authorization`. `export(tenant_id, trace_id=None, run_id=None)`.
El bucle audita `action="react.step"` (payload ya sanitizado automáticamente).

## 5. Catálogo de tools: `nexus_core/tools/registry.py`

`durable_tool_definitions(tenant_id="system") -> dict[str, tuple[ToolDefinition, Handler]]`
con `nexus.system.status`, `nexus.workspace.search`, `nexus.recon.nmap`.
`ToolDefinition` expone `tool_id, name, description, risk (RiskLevel), input_schema,
required_permissions, timeout_seconds, max_output_bytes, scope_target_field, scope_required`.
`nmap_definition()`: riesgo MEDIUM, `scope_target_field="target"`, `scope_required=True`,
`timeout_seconds=600`, `max_output_bytes=4_000_000`, argumentos `target`/`flags`/`timeout_seconds`.

Es la fuente del `tool_catalog` que se renderiza en el prompt y la whitelist que
aplica la "regla de hierro".

## 6. Scope: `nexus_core/scope/{models,validator}.py` + `kernel/scope_loader.py`

- `ScopeViolation(target, reason, engagement_id="")`; subclases `ScopeExpired`,
  `ScopeSignatureInvalid`, `ScopeUnresolvable`, `ScopePrivateIP`.
- `make_scope_validator(signing_secret)` devuelve el callable
  `(context, definition, arguments)` que valida `arguments[scope_target_field]`.
- `load_engagement_scope(store, tenant_id, engagement_id)` → `None` si falsy,
  `PermissionError` si no existe. El scope se carga **dentro** de `execute_tool`,
  así que el bucle no necesita construirlo: sólo propagar `engagement_id`.

## 7. Sandbox: `nexus_core/kernel/sandbox.py`

`LocalSandbox(workspace_root, allowed_programs, max_output_bytes)` (dev) y
`OCISandbox` (prod, `--network none`). `sandbox_for_environment(root, allowed_programs=None)`.
El handler de nmap ya está mockeable sustituyendo
`nmap_module.sandbox_for_environment` (patrón de `test_nmap_handler.py`).

## 8. Convenciones de test

- `nexus_core/tests/pytest.ini`: `asyncio_mode = auto`, `testpaths = tests`.
- Patrón "durable de verdad": `store.create_run` → `enqueue_task` →
  `claim_task("worker-test")` → `registry.execute(claimed, ExecutionContext(store, claimed, "worker-test"))`.
- Para aislar el bucle sin tocar la red: `mock.patch("nexus_core.kernel.runtime.execute_tool", fake)`
  (ya usado en `test_scope_wiring.py`).
- Fixtures en `nexus_core/tests/fixtures/<dominio>/`; hay que crear `react/`.
- `tmp_path / "control.db"` + `store.initialize()` en cada test.
- Entorno: `.venv/bin/python` (3.12.3), pytest 9.1.1, ruff 0.16.1; `nmap`, `rg`
  y `python` global ausentes. `.env` existe pero **todas** las API keys están
  vacías → cualquier E2E que requiera un LLM real debe auto-saltarse.

## 9. Riesgos / decisiones abiertas

1. `create_from_env()` siempre devuelve `"fake"` → hay que decidir el orden de
   providers en `execute_react` (ver `REACT_RESULT.md`).
2. Historial append-only → el resumen es sustitutivo **lógico** al leer
   (marcador `react.history_summary`), no un borrado físico.
3. `run_react_loop` no recibe `identity` en su firma → se deriva de
   `context.task["payload"]` para que las tools sigan pasando por
   policy/approval con la identidad original de la task.
4. Cancelación cooperativa: `list_run_events` + `append_run_event`, ya
   soportado por el store; se chequea antes de cada iteración.
5. La cancelación de task (`request_task_cancel`) es otro canal (flag
   `cancel_requested` en `kernel_tasks`); el bucle no lo lee porque el evento de
   run es el contrato pedido por la misión.
