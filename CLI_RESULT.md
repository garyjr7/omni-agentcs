# CLI_RESULT.md — CLI interactivo `omni` (misión 5)

Rama: `feat/cli-omni`. Sin push.

## Entregado

| Área | Archivo | Contenido |
| --- | --- | --- |
| Fase 1 | `nexus_core/agent/react.py` | `ApprovalDecision`, `ReActConfig.on_approval_needed`, `_operator_approval_gate()` |
| Fase 1 | `nexus_core/kernel/runtime.py` | `_build_run_context()` y `select_llm_client()` reutilizables; `execute_tool`/`execute_react` los usan |
| Fase 1 | `nexus_core/kernel/approvals.py` | `list_pending(tenant_id)` (método aditivo) |
| Fase 2 | `nexus_core/cli/{__init__,main,session,render,commands,approval}.py` | REPL, stream en vivo, render ANSI, comandos meta, callback humano |
| Fase 3 | `omni.py` | entry point ejecutable (`chmod +x`) con `load_dotenv` |
| Fase 4 | `nexus_core/cli/session.py` | `_stream_run_events` (thread daemon, poll cada 500 ms) |
| Fase 5 | 5 archivos de test | 35 tests nuevos (8 + 7 + 10 + 6 + 4) + 1 E2E opt-in |
| Fase 6 | `README.md` | sección «CLI interactivo omni» |

Firma pública intacta: `execute_tool`, `execute_brain`, `ToolGateway`, `execute_agent` y
`execute_react` no cambian (se añaden helpers y un campo opcional al final de
`ReActConfig`). `run_react_loop` solo recibe el callback vía `config`, así que sus 15
tests previos siguen pasando sin tocarlos. Cero dependencias nuevas (stdlib + lo que ya
usaba el proyecto: `python-dotenv`).

## Verificación

| Check | Resultado |
| --- | --- |
| 4 imports (`nexus_core.cli`, `.main`, `.session`, `omni`) | 4/4 OK |
| Los 8 imports de la misión 4 (api, kernel, react, parser, memory, registry, worker, mcp) | 8/8 OK |
| `.venv/bin/python -m pytest nexus_core/tests/unit -q` | **177 passed** (142 previos + 35 nuevos) |
| `ruff check nexus_core/cli omni.py tests/unit/test_cli_*.py tests/unit/test_react_approval.py --select F,E9` | All checks passed |
| residual `TODO/FIXME/XXX/HACK/NotImplementedError` en `nexus_core/cli/` + `runtime.py` | limpio (exit 1) |
| `NEXUS_E2E=1 pytest nexus_core/tests/integration/test_cli_e2e.py test_react_e2e.py -v` | **3 passed** (12.5 s) |
| `omni.py --help` / `--version` | OK (todos los flags listados, `omni 3.0.0`) |
| `omni.py` ejecutable | `-rwxrwxr-x` |
| Nota ruff | `test_sovereign_runtime.py` tiene 2 `F841` **preexistentes** (variables `task` sin usar); no se tocan por no pertenecer a esta misión |

Tests por archivo (spec → entregado):
`test_react_approval.py` 8/8, `test_cli_commands.py` 10/10, `test_cli_render.py` 6/6,
`test_cli_e2e.py` 1/1 opt-in. Extras: `test_cli_approval.py` (7, el gate humano real) y
`test_cli_session.py` (4, bucle del REPL).

## E2E opt-in — sí se ejecutó

Con `GROQ_API_KEY` en `.env` y `nmap` instalado (`/usr/bin/nmap`), el E2E corre de verdad:

```
nexus_core/tests/integration/test_cli_e2e.py::test_cli_one_shot_objective_completes PASSED [ 33%]
nexus_core/tests/integration/test_react_e2e.py::test_e2e_react_nmap_scanme          PASSED [ 66%]
nexus_core/tests/integration/test_react_e2e.py::test_e2e_react_denies_out_of_scope  PASSED [100%]
============================== 3 passed in 12.48s ==============================
```

Salida real del one-shot (`NEXUS_DB_PATH=/tmp/omni_manual.db omni.py --engagement eng-scanme
--objective "Escanea scanme.nmap.org en los puertos 22 y 80..."`, Groq real):

```
• run=run_0a061fef76694dc198e4d62fdecfa4eb engagement=eng-scanme max_iterations=6
💭 Ejecutar nmap contra el objetivo dentro del alcance para identificar los puertos 22 y 80 abiertos en scanme.nmap.org.
⚙️  nexus.recon.nmap
     target: scanme.nmap.org
     flags:  ['-p', '22,80']
     noise:  medium
✓ nexus.recon.nmap — ✓ 1 host(s) up | 2 puerto(s) abierto(s) | noise: low
┌────────────────────────────────────────────────────────────────────┐
│ RESULTADO                                                          │
├────────────────────────────────────────────────────────────────────┤
│ Escaneo completado exitosamente. Se detectaron los puertos solicit │
├────────────────────────────────────────────────────────────────────┤
│ [info] Puerto 22 abierto (SSH)                                     │
│ [info] Puerto 80 abierto (HTTP)                                    │
└────────────────────────────────────────────────────────────────────┘
• estado=completed iteraciones=2 conversación=conversation_f0f70c610bda46d8ae9ae0a3f6d60edb
exit=0
```

Reporte del E2E: stdout contiene el `thought`, el tool_call, la observación con
`host(s) up`/`puerto(s) abierto(s)`, el resumen y `exit 0`; además el test comprueba en la
DB que la conversación `react:<run_id>` quedó persistida con `react.system` +
`react.observation`. Verificación del REPL con LLM scriptado (sin red): objetivo,
`/scope`, `/tools`, `/history`, `/approvals`, `/export`, comando inexistente, `/help` y
`/exit`, con auditoría `react.step`/`tool.invoke`/`tool.complete`.

## Decisiones de diseño no cubiertas por el prompt

1. **Hilos**: el bucle ReAct corre en el **hilo principal** (`asyncio.run`) y el stream en
   un thread daemon. El prompt se contradice (FASE 2 dice «en un hilo», FASE 4 «en el hilo
   principal»); se resolvió así porque el callback de aprobación necesita `input()` real en
   el hilo principal.
2. **Sin run events nuevos** (FASE 4 lo prohíbe). El stream consume (a) los run events
   existentes (`react.parse_error`, `react.scope_violation`, `react.clarification_requested`,
   `react.cancelled`) y (b) los `kernel_messages` durables para el thought, los argumentos
   y la observación, porque el evento `react.action` solo lleva `iteration/action/tool_id`.
   La sesión pre-crea la conversación con `memory.ensure_conversation` (título determinista
   `react:<run_id>`) para conocer su id antes de arrancar.
3. **Rechazo humano ≠ fallo de tool**: la denegación inyecta
   `{"status": "denied_by_operator", ...}` y **no** consume el presupuesto de fallos, así
   que una sesión de rechazos termina en `max_iterations`, no en `failed`
   (test dedicado con 4 rechazos).
4. **Selección de proveedor compartida**: `runtime.select_llm_client()` (proveedores reales
   primero, `fake` como último recurso) lo usan `execute_react` y el CLI, para no divergir.
5. **`_build_run_context(payload, context)`**: helper privado que construye el `RunContext`
   con la misma identidad/scope/trace/store que `execute_tool`; la decisión de policy del
   loop usa exactamente ese contexto (nada de lógica de policy duplicada).
6. **Separación de deberes**: la identidad del agente en la CLI es `agent:<agent_id>` y la
   del humano `operator:<usuario del SO>`; `ApprovalService.decide` rechaza la
   autoaprobación, así que una mala configuración produce **denegación** (y deja la fila
   `pending`), nunca una autorización implícita.
7. **Aprobación durable inmediata**: el callback hace `request` + `decide(approved=True)` y
   devuelve el `approval_id`; el gateway lo verifica (`run_id` + `execute:tool:<id>` +
   `status=approved`) antes de ejecutar el handler.
8. **`/clear` solo limpia lo local**: buffer de la sesión y punteros run/conversación; la
   conversación durable y la auditoría encadenada no se borran nunca (`kernel_messages` es
   append-only).
9. **`/export`** escribe Markdown (por defecto `<export_dir>/omni-session-<run_id>.md`);
   cualquier `OSError` se reporta y nunca rompe la sesión.
10. **`--resume <run_id>`** reutiliza el run y su conversación; el objetivo que se escriba
    después continúa ese hilo. Ctrl+C durante un run emite `react.cancel_requested`
    (cancelación cooperativa) y sugiere reanudar, en vez de matar el proceso.
11. **Noise en el render**: `render_tool_call` muestra el riesgo *declarado* de la tool
    (`medium` para nmap) y la observación muestra el noise *medido* por el handler
    (`low` con `-p 22,80`). Es el dato real disponible en cada momento, no una invención.
12. **`/approvals`** usa `ApprovalService.list_pending()` (método aditivo, sin cambiar
    firmas) en lugar de SQL suelto en la CLI.
13. **Prompt no interactivo**: el bloque de aprobación acepta un `reader` inyectable (tests)
    y limita a 5 intentos; sin respuesta válida deniega en vez de quedarse en bucle.
14. **`PROGRAM_VERSION = "3.0.0"`** (`nexus_core/cli/__init__.__version__`): el proyecto no
    tenía constante de versión y el README se presenta como «NEXUS Sovereign 3.0».

## Limitaciones y lo que no se hizo

* **No hay CRUD de engagements en la CLI** (fuera de alcance): solo lee con
  `--list-engagements`/`--engagement`. Sin engagement activo el REPL arranca igual y las
  tools que exigen scope se deniegan.
* El E2E necesita proveedor real + `nmap` + red; está *gated* por las tres condiciones
  (`NEXUS_E2E=1`, provider, `nmap`).
* El E2E ejecuta un nmap real contra `scanme.nmap.org`, el target autorizado del
  engagement de prueba.
* En un pipe sin TTY el protocolo `y/n/e/?` degrada a denegación tras 5 intentos; no hay
  modo de aprobación por flag (no estaba en el spec).
* No se modificó el schema: las aprobaciones y el historial reutilizan
  `kernel_approvals`, `kernel_conversations` y `kernel_messages`.

## Nota sobre el commit

No se usó `git add -A`. El árbol ya tenía WIP **ajeno a esta misión** y se dejó sin
commitear, igual que en la misión anterior:

* `nexus_core/tests/integration/test_nmap_e2e.py` (modificado: añade `domains` al scope del
  E2E de nmap — no lo hice yo y no puedo avalarlo),
* `list_models.sh` y `react_e2e_manual.py` (sin trackear, de misiones previas).

Si quieres que entren en algún commit, dime y los incluyo explícitamente.
