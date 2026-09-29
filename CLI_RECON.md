# CLI_RECON.md — Reconocimiento para el CLI `omni` (misión 5)

Rama: `feat/cli-omni` (creada desde `feat/react-loop` @ `0b2caab`).
Estado del árbol al empezar: limpio salvo WIP previo no relacionado
(`nexus_core/tests/integration/test_nmap_e2e.py` modificado, `list_models.sh` y
`react_e2e_manual.py` sin trackear) → **no se arrastran a este commit**.

## 1. Cómo se construye un cliente LLM

`nexus_core/llm/abstraction.py`:

* `BaseLLMClient.complete(messages: list[LLMMessage], **kwargs) -> LLMResponse`
  (método abstracto; los clientes reales aceptan `temperature`, `max_tokens`;
  `FakeLLMClient` acepta `scenario`).
* `LLMMessage(role: str, content: str)` — dataclass simple.
* `LLMResponse(content, model, provider, tokens_input, tokens_output, duration_ms, raw_response)`.
* `LLMFactory.create_from_env() -> dict[str, BaseLLMClient]`, con claves
  `fake` (siempre presente), `openai`, `gemini`, `groq`, `ollama` (solo si la
  env var correspondiente existe). **`fake` siempre está**, por eso el orden de
  preferencia importa.
* `NexusLLM(primary, fallback=None).complete(messages, **kwargs)` reintenta con
  el fallback y acumula stats (`get_stats()`).

En el repo real: `GROQ_API_KEY` está definido en `.env` y `openai/gemini`
vacíos → el único proveedor real es `groq`. `nmap` **está** instalado
(`/usr/bin/nmap`), así que el E2E opt-in sí puede ejecutarse.

## 2. Bucle ReAct existente (`nexus_core/agent/react.py`)

* `run_react_loop(*, context, objective, engagement_id, llm_client, config=ReActConfig(), tool_catalog=None) -> ReActResult`.
* `ReActConfig` es `@dataclass(frozen=True)` con `max_iterations=12`,
  `timeout_per_tool_seconds=600`, `enable_summarization=True`,
  `max_history_messages=40`.
* Por cada iteración: chequea cancelación → compacta historial → renderiza el
  system prompt → `llm_client.complete` → `parse_react_response` → persiste la
  acción (`memory.append_step`) → ejecuta `runtime.execute_tool` (vía
  `asyncio.wait_for`) → inyecta la observación → audita `react.step`.
* Ya emite run events: `react.action`, `react.parse_error`,
  `react.scope_violation`, `react.clarification_requested`, `react.cancelled`,
  `react.finished`. **No hace falta emitir nuevos** y la misión lo prohíbe.
* El payload de cada tool call se arma con
  `{"tool_id", "arguments", "identity", "engagement_id", "permissions", "approval_id", "trace_id"}`
  tomando `identity`/`permissions`/`approval_id` de `context.task["payload"]`.
  **Ese es el punto de extensión natural para `approval_id` aprobado por el humano.**

## 3. Policy + approvals (`nexus_core/kernel/{policy,approvals,tool_gateway}.py`)

* `PolicyEngine(store).decide(identity, action, resource, permissions=(), tool=None) -> PolicyDecision`.
  Con `tool.risk in {HIGH, DESTRUCTIVE}` y allow → `requires_approval=True`
  (política `role-and-permission`), y también para un allow explícito.
* `Resource(resource_id, tenant_id, kind, ...)`; el gateway usa
  `Resource(tool_id, definition.tenant_id, "tool")` y `action="execute:tool"`.
* `ToolGateway.invoke(...)`: schema → **scope gate** → `policy.decide` → audit
  `tool.invoke` → si `decision.requires_approval`: `approvals.verify(approval_id, context, f"execute:tool:{tool_id}")`
  (si no hay `approvals` o `approval_id` → `PermissionError("durable human approval is required")`).
* `ApprovalService.request(context: RunContext, action) -> dict` crea la fila
  `pending` en `kernel_approvals` (requested_by = `context.identity.subject_id`).
* `ApprovalService.decide(approval_id, tenant_id, actor_id, approved, reason)`
  **rechaza la autoaprobación** (`requested_by == actor_id` → `PermissionError`).
* `ApprovalService.verify(approval_id, context, expected_action)` comprueba
  `run_id == context.run_id`, `action == expected_action` y `status == "approved"`.
* No existe un listado de aprobaciones: se añade `list_pending(tenant_id)`
  (método **aditivo**, sin cambiar firmas existentes) para el comando `/approvals`.

## 4. Persistencia (`nexus_core/kernel/control_store.py`)

* `create_conversation(tenant_id, owner_id, title, agent_id=None, classification="internal")`,
  `list_conversations(tenant_id, owner_id)`, `get_conversation(tenant_id, id, owner_id=None)`.
* `append_message(tenant_id, conversation_id, role, content, *, run_id=None, metadata=None, classification="internal")`,
  `list_messages(tenant_id, conversation_id, limit=100)` (cronológico, cap 500).
* `memory.ensure_conversation(store, tenant_id, run_id, owner_id)` es
  **idempotente** (título determinista `react:<run_id>`), así que el CLI puede
  pre-crear la conversación para saber su id y suscribirse a los mensajes.
* `create_run(tenant_id, context, idempotency_key=None)`,
  `enqueue_task(...)`, `claim_task(worker_id, lease_seconds=60)`,
  `append_run_event(tenant_id, run_id, event_type, payload)`,
  `list_run_events(tenant_id, run_id, after=0)` (filtra por `sequence`).
* `ExecutionContext(store, task, worker_id)` es un dataclass frozen con
  propiedades `tenant_id`/`run_id` y `event(...)`. El CLI puede construir uno
  directamente con el dict de la task **sin** encolar nada en la DB.
* `AuditWriter(store).append(...)` keyword-only, encadenado por hash; `export(tenant_id)`.

## 5. Config / arranque

* `nexus_core.kernel.store_factory.get_control_store(sqlite_path, database_url=None)`
  elige SQLite o Postgres según `DATABASE_URL`; `nexus_core.config.NEXUS_DB_PATH`
  da la ruta por defecto. Es el mismo arranque que usa `nexus_cli.py`.
* No hay constante de versión en el proyecto: el CLI define la suya (`__version__`).
* `python-dotenv` está instalado en el `.venv` (lo usa `react_e2e_manual.py`).
* Test runner: `.venv/bin/python -m pytest nexus_core/tests/unit -q` desde la
  raíz; `nexus_core/tests/pytest.ini` con `asyncio_mode=auto`.

## 6. Restricciones relevantes confirmadas

* No se puede tocar el schema: `kernel_approvals`, `kernel_conversations`,
  `kernel_messages` y `kernel_run_events` ya existen y se reutilizan.
* No se pueden cambiar las firmas públicas de `execute_tool`, `execute_brain`,
  `ToolGateway` ni `execute_agent`; `execute_react` y `run_react_loop` solo se
  **extienden** con un parámetro/campo opcional.
* La CLI no ejecuta herramientas: siempre `run_react_loop` → `execute_tool`.
