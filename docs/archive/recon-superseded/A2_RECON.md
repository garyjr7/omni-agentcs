# A2_RECON — medidas antes de los cambios

Fecha: 2026-10-01. Rama: `fix/cancellation-sandbox-worker`.
Base: `1c06741`. 26 tools durables. Suite base: **1391 passed, 30 skipped**.

## 1.1 Cancelación actual (hallazgo #2)

`grep` sobre `nexus_core/kernel/sandbox.py`:

- `LocalSandbox.run` usa `asyncio.create_subprocess_exec` **sin**
  `start_new_session=True`: el hijo comparte el process group del host.
- En `asyncio.TimeoutError` hace `process.kill()` y `await communicate()`.
- **No** hay manejo de `asyncio.CancelledError`: al cancelar la tarea, el
  `await process.communicate()` se interrumpe y el proceso queda huérfano.
- `SandboxResult` solo tiene `exit_code/stdout/stderr/timed_out`; no hay
  `cancelled`, `orphans_detected` ni `duration_seconds`.
- `OCISandbox.run` tiene el mismo problema (solo `process.kill()`).

Reproducción real ejecutada:

```text
cancelado (CancelledError propagado)
pgrep rc: 0 pids: ['6539', '6541']
sleep huerfano: True
```

Conclusión: tras `task.cancel()` sobre `sandbox.run(["sleep","60"])` queda un
`sleep 60` vivo. **No** se distingue cancelado de timeout.

## 1.2 Contrato de sandbox actual (hallazgo #3)

| Aspecto | LocalSandbox | OCISandbox |
|---|---|---|
| HOME | efímero `.sandbox_home` (workspace) | tmpfs `/home/sandbox` |
| PATH | `/usr/local/bin:/usr/bin:/bin` | `PATH=/usr/local/bin:/usr/bin:/bin` (env del runner) |
| Red | la del host | `--network none` |
| Filesystem | workspace + resto del host | workspace bind + tmpfs |
| UID | del usuario | 65532:65532 |
| Process group | **heredado del host (bug)** | heredado del host |
| Límites de recursos | no | memory/cpus/pids-limit |

No existe noción explícita de "modo": `sandbox_for_environment` decide por
`NEXUS_ENV` (development → LocalSandbox, production → OCISandbox) sin exponer
qué garantías ofrece cada uno. El detector (`provisioner/detector.py`) declara
un binario `present` si `shutil.which` lo encuentra y `probe_command` (fuera del
sandbox) responde; **nunca** verifica que ejecute dentro del sandbox, así que
un binario "presente" puede fallar en el runner (dependencias rotas, pip
`--user`, etc.). No hay `RUNNABLE` en el estado.

## 1.3 Worker lease actual (hallazgo #9)

`grep "lease|claim_task|renew|heartbeat"`:

- `control_store.claim_task(worker_id, lease_seconds=60)` fija `lease_until` y
  `lease_owner`, con `status='running'`.
- `claim_task` permite reclamar de nuevo cualquier tarea `running` cuyo
  `lease_until < now` — pero **no existe** `renew_task_lease`.
- `nexus_worker.py::main` hace `claim_task` y ejecuta
  `asyncio.wait_for(registry.execute(...), timeout=task["timeout_seconds"])`
  **sin renovar** el lease durante la ejecución.

Reproducción real ejecutada (lease de 1s para no esperar 60s):

```text
worker-1 claimed: True lease_until: 2026-10-01T16:11:31.327761+00:00
worker-2 claimed while worker-1 still running: True owner: worker-2
has renew_task_lease: False
```

Conclusión: una tarea que corre más que `lease_seconds` ve expirar su lease y
un segundo worker la reclama **mientras el primero sigue corriendo**; la misma
unidad de trabajo se ejecuta dos veces.

## Plan

1. `LocalSandbox.run`: `start_new_session=True`, `cancel_event`, `grace_seconds`,
   SIGTERM→grace→SIGKILL al process group, detección de huérfanos, 3 estados
   (`completed`/`timed_out`/`cancelled`); `terminate()` explícito. Igual para
   `OCISandbox` (kill best-effort).
2. `run_react_loop(cancel_event=...)`: aborta entre iteraciones y compite la
   llamada a la tool contra el evento, cancelando la tarea (que dispara la
   limpieza del sandbox). `ExecutionContext.cancel_event` lo propaga desde el
   worker. CLI conecta el evento a Esc/Ctrl+C (sin tocar firmas de
   ToolGateway/execute_tool/execute_react).
3. `sandbox_modes.py` con `SandboxMode`/`SandboxGuarantees`/`GUARANTEES`, modo
   activo por env, expuesto en banner y `/doctor`; `verify_tool_in_sandbox`
   (ABSENT/DETECTED/RUNNABLE/FAILED) y `check_env` con ambos estados; ADR-004.
4. `renew_task_lease` en `ControlStore` + heartbeat en `nexus_worker.py`
   (renueva cada 30s; si pierde propiedad, cancela el executor por
   `ExecutionContext.cancel_event`).
