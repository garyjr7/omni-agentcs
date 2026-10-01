# A2_RESULT — medidas después de los cambios

Fecha: 2026-10-01. Rama: `fix/cancellation-sandbox-worker`.
Base: `1c06741`. 26 tools durables. Recon previo: `A2_RECON.md`.

## Resumen

| Criterio | Antes | Después |
|---|---|---|
| Cancelación de sandbox | huérfanos tras `task.cancel()` | process group propio + SIGTERM→SIGKILL; 0 huérfanos |
| Estados de `SandboxResult` | completed/timed_out | + `cancelled`, `orphans_detected`, `duration_seconds` |
| Cancelación del bucle ReAct | solo cooperativa entre iteraciones | también interrumpe la tool en vuelo |
| Contrato de sandbox | implícito por `NEXUS_ENV` | `SandboxMode` + garantías en banner y `/doctor` |
| Estado del detector | present/absent | + `DETECTED` vs `RUNNABLE` (`verify_tool_in_sandbox`) |
| Worker lease | sin renovación | `renew_task_lease` + heartbeat cada 30s |
| Suite | 1391 passed, 30 skipped | **1436 passed, 30 skipped** (+45) |

## Fase 2 — cancelación real (hallazgo #2)

`nexus_core/kernel/sandbox.py`:

- `LocalSandbox.run` (y `OCISandbox.run`) lanzan el hijo con
  `start_new_session=True`: un process group por ejecución.
- `SandboxResult` gana `cancelled`, `orphans_detected`, `duration_seconds`.
- `terminate(grace_seconds)` explícito: SIGTERM al grupo, espera
  `grace_seconds` (default 3s), SIGKILL si sigue vivo, y cuenta descendientes.
- `run(..., cancel_event=..., grace_seconds=...)`: si el evento se setea,
  termina el grupo y devuelve `cancelled=True`. Un `task.cancel()` externo
  también mata el grupo antes de re-lanzar `CancelledError`.
- `_count_process_group` (vía `/proc`) detecta huérfanos.

`nexus_core/agent/react.py`:

- `run_react_loop(..., cancel_event=None)`; si se omite, usa
  `context.cancel_event`.
- `_await_tool` compite la llamada a la tool contra el evento y contra el
  timeout; al cancelar, cancela y drena la tarea (lo que dispara la limpieza
  del sandbox) y devuelve `cancelled=True`.
- Nuevos estados de salida: `phase="between_iterations"` y `phase="tool"` en
  el evento `react.cancelled`.

`nexus_core/kernel/runtime.py`: `ExecutionContext.cancel_event` (default
`None`) para propagar la señal desde el worker/CLI sin tocar las firmas
públicas de `ToolGateway`/`execute_tool`/`execute_react`.

`nexus_core/cli/session.py`: `run_objective` crea un `asyncio.Event`, lo pasa a
`run_react_loop` y `_with_cancel` lo setea al detectar Esc/Ctrl+C.

E2E de cancelación real (`test_e2e_cancellation_real.py`):

```text
test_cancellation_kills_sleep_and_leaves_no_orphans PASSED
test_loop_cancellation_kills_the_tool_sandbox PASSED
# pgrep -x sleep tras los tests: OK: no orphans
```

## Fase 3 — contrato de sandbox (hallazgo #3)

`nexus_core/kernel/sandbox_modes.py`:

```text
local: fs=False net=False net_tools=True
local_strict: fs=False net=False net_tools=True
oci: fs=True net=True net_tools=False
oci_network: fs=True net=False net_tools=True
```

- `active_mode()` por `NEXUS_SANDBOX_MODE` (si no, production→oci,
  resto→local_strict). `sandbox_for_mode()` construye el runner y lanza
  `NotImplementedError` para `oci_network` (documentado en
  `docs/adr/ADR-004-sandbox-modes.md`).
- Banner: `26 tools · N providers · sandbox: local_strict · engagement: …`.
- `/doctor`: sección `Sandbox` con modo + garantías (FS, red, proceso,
  recursos, tools network) en texto y JSON.
- `provisioner/detector.verify_tool_in_sandbox`: ejecuta el comando de
  verificación **dentro** del sandbox y distingue
  `ABSENT`/`DETECTED`/`RUNNABLE`/`FAILED`.
- `nexus.system.check_env` reporta `sandbox_state` en cada tool (opt-in
  `verify_sandbox` para pasar de `detected` a `runnable`).

## Fase 4 — worker lease renovable (hallazgo #9)

- `ControlStore.renew_task_lease(task_id, worker_id, lease_seconds=60)`:
  renueva solo si el worker sigue siendo dueño de una tarea `running`.
- `nexus_worker._execute_with_heartbeat`: renueva cada 30s
  (`LEASE_RENEW_INTERVAL_SECONDS`, lease de 120s); si la renovación falla,
  setea `context.cancel_event` para que el executor en vuelo aborte.

E2E de lease (`test_e2e_long_task_lease.py`):

```text
test_renewed_lease_blocks_second_worker PASSED
test_expired_lease_is_reclaimable PASSED
```

En el primero, worker 1 sostiene la tarea más allá de su lease original
(renovando) y `worker-2` obtiene `None` al reclamar; al terminar, la tarea
queda `status=completed` con `lease_owner=None`.

## Verificación

```text
9 imports OK · 26 tools · ruff F,E9 clean
NO_COLOR=1: 1436 passed, 30 skipped
sin NO_COLOR: 1436 passed, 30 skipped
pgrep -x sleep: OK: no orphans
```

Tests añadidos (+45):

- `test_sandbox_cancellation.py` (10)
- `test_react_loop_cancel.py` (4)
- `test_sandbox_modes.py` (9)
- `test_tool_sandbox_verification.py` (6)
- `test_doctor_sandbox_section.py` (3)
- `test_worker_lease_renewal.py` (9)
- E2E: `test_e2e_cancellation_real.py` (2), `test_e2e_long_task_lease.py` (2)

## Decisiones de diseño no cubiertas por el brief

- **No se tocaron las firmas públicas** de `ToolGateway.invoke`,
  `execute_tool` ni `execute_react` (regla 4), a diferencia del pseudocódigo
  de la misión (2.4). La cancelación viaja por `asyncio.Task.cancel()` +
  `ExecutionContext.cancel_event` + `run_react_loop(cancel_event=...)`, así
  que ningún handler ni el gateway cambiaron de firma.
- **`RunContext` no se modificó** (vive en `kernel/models.py`, fuera de la
  lista permitida): el bucle raza la llamada a la tool en vez de inyectar el
  evento en el handler, lo que además cubre tools que no tocan el sandbox.
- `sandbox_for_environment` se dejó intacto para no cambiar el
  comportamiento existente; el modo explícito se expone por separado
  (`sandbox_for_mode`/`active_mode`).
- `verify_tool_in_sandbox` ejecuta con `LocalSandbox` (mismo allowlist, PATH,
  HOME y workspace que en desarrollo); verificar en OCI requiere el runtime de
  contenedores y queda fuera de alcance.
- `nexus.system.check_env` mantiene el coste bajo por defecto: solo ejecuta
  la verificación en sandbox con `verify_sandbox=true`.
