# Auditoría arquitectónica de NEXUS

**Fecha:** 2026-08-08  
**Alcance:** código fuente versionado y presente en el workspace (`nexus_api`, `nexus_core`, `nexus_mcp`, `nexus_worker.py`, conectores, Docker y frontend). Se excluyen dependencias compiladas (`node_modules`, `.venv`), artefactos generados y datos operativos.  
**Naturaleza:** lectura estática; no se ha ejecutado una acción de agente contra el sistema anfitrión.

## Dictamen ejecutivo

NEXUS está en una transición arquitectónica incompleta entre dos plataformas que coexisten en el mismo repositorio:

1. **Legacy / NEXUS PRO:** API FastAPI que crea agentes en memoria, planifica con LLM y ejecuta herramientas locales directamente. Su bucle autónomo principal es `JuniorAgent`; la coordinación por tareas usa `NexusOrchestrator`, `EventBus` y un JSON local.
2. **Sovereign / durable:** plano de control reciente, multi-tenant y persistente. Encola trabajos en `kernel_tasks`, los reclama `nexus_worker.py`, aplica RBAC/políticas/aprobaciones mediante `ToolGateway`, conserva eventos y auditoría encadenada, y ofrece REST, MCP y un gateway A2A.

El segundo es la base adecuada para una migración descentralizada. Sin embargo, su agente durable actual **no tiene un bucle de tool-calling autónomo**: `brain.run` hace una única consulta LLM y una evaluación de “no vacío”; sólo expone dos herramientas first-party, ambas de lectura. El primero sí puede ejecutar shell y modificar archivos, pero no tiene aislamiento fuerte, sus controles son en parte opcionales y la semántica de éxito puede divergir del resultado real. No debe considerarse un runtime distribuible ni confiable para ejecución no supervisada.

## 1. Estructura y stack

```text
NEXUS/
├── nexus_api/                 # FastAPI: auth, rutas REST y compatibilidad legacy
│   ├── main.py                # composición de runtime y routers
│   ├── routes/                # sovereign, workflows, policies, approvals, legacy, etc.
│   ├── auth/                  # JWT/OIDC y dependencias RBAC
│   ├── db/                    # SQLite del producto legacy
│   └── services/ scheduler/
├── nexus_core/
│   ├── kernel/                # control plane durable: store, runtime, policy, sandbox, audit
│   ├── agents/                # BaseAgent, registro, Junior, Dynamic y agentes generados
│   ├── core/                  # orquestador legacy y EventBus en memoria
│   ├── state/                 # estado legacy JSON con checksum
│   ├── llm/                   # abstracción OpenAI/Gemini/fake
│   ├── hitl/                  # aprobaciones legacy en memoria
│   ├── memory/, vector/, skills/, evolution/
│   └── tests/                 # pruebas unitarias e integración del kernel
├── nexus_worker.py            # worker durable, proceso separado
├── nexus_mcp/                 # servidor MCP (stdio / Streamable HTTP)
├── nexus_connector.py         # conector de borde/desktop
├── nexus_frontend/            # React 19 + Vite + Zustand + React Query
├── docker-compose.yml         # backend, worker, PostgreSQL, frontend, MCP y gateways
├── Dockerfile.backend         # Python 3.12, usuario sin privilegios, FS read-only
└── docs/, departments/, data/ # documentación, paquetes/departamentos y datos runtime
```

| Capa | Tecnologías y responsabilidad |
|---|---|
| API/control plane | Python 3.12, FastAPI, Pydantic v2, Uvicorn, JWT/OIDC, rate limiting propio y CORS. |
| Persistencia | `ControlStore` con SQLite/PostgreSQL según factory; tablas para runs, tasks, workflow, outbox, auditoría, aprobaciones y definiciones. El legado usa SQLite/JSON local. |
| Ejecución durable | Worker Python independiente, leasing, reintentos/backoff, DLQ y DAG persistente. |
| LLM | Abstracción provider-neutral para OpenAI, Gemini y fake/offline; `NexusLLM` admite fallback. |
| Integración | REST, MCP SDK, A2A JSON-RPC, enrolamiento de conectores con mTLS en producción. |
| Frontend | React 19, Vite 8, Axios, TanStack Query, Zustand, Recharts y WebSocket. |
| Despliegue | Docker Compose; backend/worker con `read_only`, `cap_drop: ALL`, `no-new-privileges`; PostgreSQL 17. |

### Selección de runtime efectiva

`nexus_api/config.py` declara `NEXUS_ENABLE_LEGACY_RUNTIME=False`. En producción `main.py` fuerza el plano durable y no monta los routers legacy. Además, la ejecución legacy directa exige explícitamente `NEXUS_ENABLE_LEGACY_EXECUTION=true` y nunca se permite en producción:

```python
# nexus_core/kernel/legacy.py
def legacy_execution_enabled() -> bool:
    return (
        os.getenv("NEXUS_ENV", "development").lower() != "production"
        and os.getenv("NEXUS_ENABLE_LEGACY_EXECUTION", "false").lower() == "true"
    )
```

Esto es un buen cortafuego de migración, pero el código legacy sigue distribuido en módulos y rutas. Su activación simultánea con `NEXUS_ENABLE_LEGACY_RUNTIME=true` reabre capacidad de shell local.

## 2. Comunicación y planos de orquestación

```text
                         ┌───────────────────────────────────┐
REST / MCP / A2A ───────▶│ ControlStore: run + task + outbox   │
                         └──────────────┬────────────────────┘
                                        │ lease / claim
                                 nexus_worker.py
                                        │
                                        ▼
                         ExecutorRegistry / kernel.runtime
                              │ LLM │ tool.invoke │ workflow
                              ▼     ▼
                         ToolGateway → Policy → Approval → Audit
                                      → Sandbox → resultado persistido

Legacy (sólo desarrollo, opt-in):
REST BackgroundTask → DynamicAgent o JuniorAgent → ToolExecutor → shell/files/HTTP
                         │                         ↕ resultado raw
                         └─ NexusOrchestrator → EventBus + StateManager(JSON)
```

### Plano durable (objetivo de migración)

`POST /api/v1/sovereign/runs`, conversaciones, tools y workflows crean un `run` y encolan una tarea. El worker es la única pieza que ejecuta:

```python
# nexus_worker.py
task = store.claim_task(worker_id)
if task:
    try:
        context = ExecutionContext(store=store, task=task, worker_id=worker_id)
        result = asyncio.run(asyncio.wait_for(
            registry.execute(task, context), timeout=task["timeout_seconds"]
        ))
        store.complete_task(task["id"], worker_id, result=result)
    except Exception as exc:
        store.append_run_event(..., "task.failed", {...})
        store.fail_or_retry_task(task["id"], worker_id, str(exc))
```

El `ControlStore` reclama de forma transaccional (`BEGIN IMMEDIATE`), asigna `lease_owner`, incrementa intentos y usa un lease de 60 s. `fail_or_retry_task` vuelve a encolar con backoff exponencial o mueve a `kernel_dead_letters`; `DurableWorkflowEngine` desbloquea los nodos de un DAG una sola vez y persiste su estado. Runs y eventos se consultan/streamean por SSE. Es una buena separación API/worker y puede horizontalizarse mediante una base compartida.

### Plano legacy

`NexusOrchestrator` es un planificador de cola, no un agente de razonamiento: selecciona el agente menos cargado por capability, llama a `agent.run`, actualiza el estado y reintenta hasta tres veces.

```python
# nexus_core/core/orchestrator.py
async def _execute_task(self, task_id, agent):
    await self._state.update_task(task_id, status=TaskStatus.RUNNING)
    try:
        result = await asyncio.wait_for(agent.run(task_id, task_state.payload),
                                        timeout=self._config.task_timeout_seconds)
        if result["success"]:
            await self._state.update_task(task_id, status=TaskStatus.COMPLETED,
                result=result["result"], completed_at=datetime.datetime.utcnow())
            await self._bus.publish(Event(type=EventType.TASK_COMPLETED, ...))
        else:
            await self._retry_or_fail(task_id, result["error"])
```

La comunicación es un `asyncio.Queue` local (`EventBus`) y el estado es `nexus_state.json` protegido por lock, reemplazo atómico y checksum SHA-256. No es compartido entre procesos. `main.py` incluso advierte que múltiples workers no comparten registry, HITL, EventBus ni StateManager. Para descentralización debe retirarse de la ruta crítica, no replicarse.

## 3. Motor de orquestación / agent loop

### Loop autónomo real: `JuniorAgent`

El loop que implementa pensamiento → decisión → ejecución → feedback es el de `nexus_core/agents/junior_agent.py`:

```python
# resumido fielmente de JuniorAgent.execute()
plan = await JuniorPlanner.create_plan(self._llm, objective, context)
steps = plan.get("steps", [])[:max_steps]
for i, step in enumerate(steps):
    tool_name = step.get("tool", "llm_call")
    self._log_step(step_num, step_name, "running", tool_name)
    params = await self._enrich_params_with_llm(...) if step.get("depends_on_prev") else \
             self._inject_context(step.get("params", {}), prev_result, step_results)
    result = await ToolExecutor.execute_tool(tool_name, params, self._llm)
    step_results[step_num] = result
    prev_result = result
    status = "completed" if result.get("status") != "error" else "failed"
    self._log_step(step_num, step_name, status, tool_name, result)
```

- **Pensamiento/plan:** el LLM produce JSON de hasta 8 pasos.
- **Decisión:** cada paso especifica herramienta y parámetros; puede depender de un resultado anterior y pide al LLM que los reescriba.
- **Ejecución:** despacha `ToolExecutor`.
- **Feedback:** conserva `step_results` y lo inyecta en los pasos siguientes; registra un log JSON de sesión.
- **Pausa:** `JuniorAgent` no posee una pausa durable propia. `DynamicAgent` sí consulta el HITL legacy antes de ejecutar, bloqueando en un `asyncio.Event` hasta 300 s.

`DynamicAgent` tiene un loop de una sola acción: LLM Planner → herramienta → LLM Interpreter. No replanifica tras un fallo ni itera hasta una condición de término.

### Bucle Sovereign actual

El equivalente durable se llama `execute_brain`, pero no es aún un agent loop general:

```python
# nexus_core/kernel/runtime.py
plan = [
    {"step": "understand", "status": "completed"},
    {"step": "respond", "status": "running"},
    {"step": "evaluate", "status": "pending"},
]
answer = await execute_agent({...}, context)       # una llamada LLM
plan[1]["status"] = "completed"
evaluation = await execute_evaluation({"actual": answer.get("content")}, context)
plan[2]["status"] = "completed"
```

`execute_evaluation` sólo comprueba `bool(actual)` y, opcionalmente, igualdad literal con `expected`. Por tanto, no prueba objetivo, efectos externos ni coherencia de una acción. Esta es la principal brecha funcional del nuevo runtime.

## 4. Tool calling e interacción con el sistema anfitrión

### Camino seguro y durable

El catálogo runtime de `execute_tool` contiene hoy únicamente:

- `nexus.system.status`: consulta el número de tareas en cola.
- `nexus.workspace.search`: ejecuta `rg` de solo lectura dentro de `LocalSandbox` u OCI sandbox.

`ToolGateway.invoke` valida JSON Schema, decide política/tenant/permisos, exige aprobación para riesgo alto/destructivo, limita timeout y tamaño de salida, y audita inicio, fin o error. `LocalSandbox` evita shell y restringe binarios:

```python
# nexus_core/kernel/sandbox.py
if not argv or argv[0] not in self.allowed_programs:
    raise PermissionError("program is not allowed in this sandbox")
working_directory = self.resolve_workspace(cwd)
process = await asyncio.create_subprocess_exec(
    *argv, cwd=str(working_directory), stdin=asyncio.subprocess.DEVNULL,
    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    env={"PATH": "/usr/local/bin:/usr/bin:/bin", "NEXUS_SANDBOX": "1"},
)
stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
return SandboxResult(exit_code=process.returncode, stdout=..., stderr=...)
```

En producción `OCISandbox` construye `docker|podman run` con red deshabilitada, rootfs read-only, capabilities eliminadas, `no-new-privileges`, usuario 65532, límites de CPU/memoria/PIDs y mount del workspace. Es una base de contención correcta, con una salvedad: el workspace se monta `rw`, por lo que para herramientas de escritura se debe aplicar allowlist de paths y verificación postcondición.

### Camino legacy directo

`ToolExecutor` en `dynamic_agent.py` implementa `bash_exec`, `code_exec`, `file_read/write/list`, HTTP, git, Docker, nmap/nuclei, SAST y generación de reportes. Su despacho está tras `legacy_execution_enabled()`, pero cuando se habilita usa directamente `asyncio.create_subprocess_shell`, rutas suministradas y el entorno completo del proceso:

```python
# nexus_core/agents/dynamic_agent.py
proc = await asyncio.create_subprocess_shell(
    cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    cwd=cwd, env={**os.environ}
)
stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
return {"status": "ok" if proc.returncode == 0 else "error",
        "output": ..., "stderr": ..., "returncode": proc.returncode}
```

El filtro sólo bloquea unas pocas cadenas (`rm -rf /`, `mkfs`, `dd if=`, fork bomb); no constituye sandbox, allowlist, validación de path, control de red ni prevención de inyección. `BashAgent`, `CodeAgent`, `FileAgent`, `PentestAgent`, `composite_tools` y el fallback de `routes/tasks.py` contienen más ejecuciones de shell/files. Los endpoints legacy están aislados por configuración, pero su exposición debe seguir considerándose de alto riesgo si se activa.

## 5. Estado, feedback y prevención de alucinaciones

### Qué evidencia se captura

| Mecanismo | Evidencia observada | Valor |
|---|---|---|
| Shell legacy (`bash_exec`, `BashAgent`) | `returncode`, stdout, stderr y timeout. | Confirma terminación del proceso, no que el efecto pedido sea correcto. |
| Lectura/escritura de archivo legacy | `FileAgent.write` relee y compara contenido; `CodeAgent.patch` relee, valida presencia y usa `ast.parse`; `smart_patch` hace backup y revierte si falla sintaxis/verificación. | PEV razonable, pero puntual e inconsistente. |
| Otras mutaciones legacy | `file_write` del `ToolExecutor`, append/delete/chmod/mkdir, generación de código/reporte y muchos agentes devuelven éxito sin relectura ni hash. | Sin postcondición verificable. |
| Sandbox durable | `SandboxResult(exit_code, stdout, stderr, timed_out)` llega al handler `workspace_search`. | Telemetría factual para una lectura. |
| ToolGateway durable | Auditoría de decisión, duración, bytes y errores; límite de salida. | No guarda output, exit code ni una prueba de postcondición por defecto. |
| Worker durable | Resultado del executor se persiste en `kernel_tasks.result`, run events y transición. | Durable y trazable, pero depende de que la herramienta devuelva evidencia suficiente. |

Ejemplo de PEV existente:

```python
# nexus_core/agents/generated/fileagent.py
path.write_text(content, encoding="utf-8")
written = path.read_text(encoding="utf-8")
if written == content:
    return {"status": "completed", "result": "Archivo escrito y verificado..."}
return {"status": "failed", "error": "PEV: contenido no coincide..."}
```

### Riesgos críticos detectados

1. **Éxito de infraestructura ≠ éxito de misión (alto).** `BaseAgent.run()` devuelve `success=True` siempre que `execute()` no lance excepción. Los agentes suelen representar fallos dentro de un dict (`{"status": "failed"}` o `{"status": "error"}`), que el wrapper no interpreta. Así, `NexusOrchestrator` puede marcar completada una ejecución cuya herramienta falló.
2. **Feedback de Junior incompleto (alto).** Sólo clasifica como fallo `status == "error"`; un resultado `"failed"` cuenta como completado. Sigue además con los siguientes pasos tras fallar, y el reporte final puede declarar un plan completado con evidencias fallidas.
3. **Validación post-acción no es uniforme (alto).** El exit code y consola se capturan en varios comandos, pero no se convierten en un contrato común de evidencia ni se validan contra una postcondición declarada. Para escritura, borrado, despliegue, HTTP mutante o Docker no hay verificación genérica del estado final.
4. **El bucle durable no llama herramientas de forma autónoma (alto funcional).** `brain.run` no interpreta tool calls del modelo ni realimenta observaciones; su evaluación de no-vacío no mitiga alucinación.
5. **HITL legacy fail-open (alto).** `DynamicAgent.execute()` captura cualquier error del HITL y continúa: `except Exception as hitl_err: ... "continuando"`. Además, solicitudes/aprobaciones viven en RAM: un reinicio las pierde y no hay separación de deberes. El servicio durable `ApprovalService` sí la aplica.
6. **Cancelación/cooperación limitada (medio-alto).** El control store marca `cancel_requested`, pero el worker no revisa esa marca mientras ejecuta ni renueva lease para trabajos largos. Cancelar una tarea activa no mata el subprocess ni la interrupción LLM.
7. **EventBus legacy no inicializado en la composición observada (medio).** `main.py` y `JuniorBridge` instancian `EventBus`, pero no llaman `await event_bus.start()` ni `StateManager.initialize()`. La cola puede aceptar eventos sin despacharlos y el estado no se restaura/crea de manera explícita. También existen dos grafos legacy distintos: el de `app.state` y el `JuniorBridge`.
8. **Datos sensibles / trazabilidad (medio).** La auditoría durable redacciona claves conocidas y encadena hashes, pero almacena sólo metadatos de salida. Los logs legacy y `payload`/salidas pueden contener datos no redactados; la relectura y stdout se truncan de manera no uniforme.

## 6. Prompts maestros e instrucciones de sistema

| Ubicación | Rol e instrucciones dominantes |
|---|---|
| `agents/junior_agent.py::JuniorPlanner.SYSTEM` | Pide máximo 8 pasos, acciones atómicas/verificables, propagación de `{prev_result}` y `report_gen` final; fuerza JSON. |
| `agents/junior_agent.py::JuniorAgent.JUNIOR_SYSTEM` | Personalidad autónoma: “piensa antes de actuar y verifica”, desarrollo, ciberseguridad y DevOps. **No se pasa directamente al LLM en el loop actual**; es declarativo. |
| `agents/dynamic_agent.py::LLMReasoningEngine.PLANNER_SYSTEM` | Decide una sola herramienta/parámetros del catálogo legacy y fuerza JSON. |
| `agents/dynamic_agent.py::LLMReasoningEngine.INTERPRETER_SYSTEM` | Resume raw tool output y recomendaciones en 200 palabras. Es interpretación, no validador. |
| `kernel/runtime.py::execute_agent` | Prompt soberano por defecto: responder con hechos, declarar límites, no inventar acceso a herramientas y proponer acciones verificables. |
| `routes/junior.py::junior_chat` | Prompt de chat técnico conciso para software, seguridad, DevOps y automatización; no ejecuta tools. |
| `agent_team_manager.py` y `routes/factory.py` | Prompts por rol (arquitecto, desarrollador, QA, reviewer, seguridad, Scrum) y generación de entregables. |
| Base de datos legacy (`agents.system_prompt`) | Prompts configurables desde API y cargados por `DynamicAgent`; se insertan tanto en el planificador como en la ejecución de LLMs auxiliares. |

Hay una contradicción importante: los prompts piden verificar resultados, pero esa garantía no se implementa sistemáticamente como contrato de herramientas, evaluación ni gate de completitud. Un prompt no sustituye observabilidad y postcondiciones.

## 7. Implicaciones para una migración descentralizada

El núcleo a conservar es `kernel/` + `nexus_worker.py`: ya separa API y ejecutor, tiene idempotencia, leases, outbox, workflow, políticas, auditoría, RBAC multi-tenant, MCP/A2A y contenedorización restrictiva. El sistema legacy debe tratarse como adaptador temporal de desarrollo.

Prioridades arquitectónicas antes de habilitar agentes autónomos distribuidos:

1. Definir un contrato único `ToolResult`: `status`, `exit_code`, `stdout/stderr` con hashes/artifacts, `timed_out`, `observations`, `postcondition`, `verified_at` y `retryable`.
2. Implementar un loop durable explícito: plan persistido → autorización → tool invocation → observación persistida → evaluación de postcondición → replanificación/pausa/fin. El LLM nunca debe declarar éxito por sí solo.
3. Registrar herramientas en el catálogo durable, con schemas, riesgo, permisos, timeout, compensación e implementación exclusivamente sandboxed. Eliminar bypasses `create_subprocess_shell` y paths arbitrarios de la ruta productiva.
4. Promover HITL a `ApprovalService` durable para cualquier mutación; fail-closed si no puede crear o verificar una aprobación. Asociar aprobación a hash de argumentos y artefacto/versión de herramienta.
5. Persistir output de herramienta como artifact inmutable y enlazarlo a evento/auditoría; verificar por tipo de efecto (hash/versión de fichero, `stat`, consulta HTTP de lectura, healthcheck, diff, test).
6. Añadir heartbeats/renovación de lease y cancelación cooperativa de workers/sandboxes. Decidir semántica de recuperación para efectos no idempotentes.
7. Sustituir EventBus/StateManager/HITL en memoria por broker/outbox compartido o mantenerlos fuera del control plane. No escalar el legacy horizontalmente.

## 8. Conclusión

NEXUS posee los componentes correctos para evolucionar a un ecosistema descentralizado gobernado, pero todavía no una única arquitectura operativa. El **control plane Sovereign** es el candidato de consolidación; el **agent loop Legacy** es el candidato funcional de referencia, no de despliegue. La migración debe concentrarse en trasladar su planificación y feedback a ejecutores durable/policy-enforced, elevando la evidencia real de cada acción a condición obligatoria de avance del agente.
