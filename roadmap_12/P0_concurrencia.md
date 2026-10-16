# BAJIOWARE — Corrección P0 de concurrencia y estado

Fecha: 12 de octubre de 2026. Implementación sobre la auditoría `10.md`.

## Resultado

Se corrigieron los cuatro vectores solicitados: reservas de presupuesto, cadena de auditoría, leases de tareas y reconciliación de workflows. Los cambios se aplicaron al código; los bloques de este informe se extraen de la implementación actual. No se agregaron dependencias de ejecución.

| Vector | Cierre implementado |
|---|---|
| Presupuesto | Lectura de consumo y creación de reserva bajo una misma exclusión transaccional. SQLite conserva `BEGIN IMMEDIATE`; PostgreSQL bloquea una fila identificada por tenant/raíz mediante `FOR UPDATE`. Liquidación y liberación usan la misma clave. |
| Auditoría | Bloqueo `audit:global` desde la lectura del último hash hasta el commit del sucesor. Se conserva el formato de cadena global y la compatibilidad de verificación de registros anteriores. |
| Leases | Columna `lease_generation BIGINT`, incremento en cada reclamación y CAS con ID, propietario, generación, estado running y vigencia. El reloj de base de datos comprueba expiración después de adquirir el bloqueo de la fila. Se comprueba `rowcount`; un resultado obsoleto no completa ni reencola la tarea. |
| Workflows | Exclusión por tenant/run y CAS del paso antes del INSERT de tarea. Tarea, referencia, transición y outbox se confirman o revierten juntos. Incluye pasos de compensación. |
| Worker | Propaga la generación reclamada. Un heartbeat negativo o con excepción señala cancelación y cancela la corrutina. `LeaseLost` se maneja sin derribar el bucle ni registrar un reintento de una generación obsoleta. |

## Primitiva de bloqueo

`kernel/database.py` introduce un protocolo tipado de conexión. `ControlStore.locked_transaction` administra commit, rollback y cierre de conexión. No se utilizan locks Python como garantía de exclusión entre workers.

PostgreSQL usa `kernel_transaction_locks(lock_key PRIMARY KEY)`: el INSERT con conflicto ignorado resuelve la creación simultánea de una clave, y el SELECT FOR UPDATE la bloquea hasta terminar la transacción. Se fija READ COMMITTED para que la lectura posterior a esperar el bloqueo vea el último estado confirmado. SQLite obtiene su bloqueo de escritura antes de leer y mantiene WAL.

Las claves de presupuesto y workflow son arreglos JSON canónicos para evitar ambigüedades por concatenación. La auditoría tiene una única clave global. Las filas de bloqueo son durables y no se borran en caliente, porque eliminarlas mientras existen participantes podría dividir la exclusión.

## Migración y compatibilidad

- `initialize()` crea la tabla de bloqueo y añade `lease_generation` a bases existentes, tanto SQLite como PostgreSQL. La migración es idempotente y tiene pruebas sobre tablas sin la columna.
- `renew_task_lease`, `complete_task` y `fail_or_retry_task` requieren el argumento nombrado `lease_generation`. Se actualizaron worker, runtime y todos los llamadores presentes en el repositorio.
- Los clientes externos de estos métodos deben transmitir la generación devuelta por `claim_task`; no deben consultarla de nuevo para sustituir un token antiguo.
- El despliegue requiere detener o drenar los workers antiguos, migrar y reiniciar todos con la versión nueva. Un worker antiguo conserva SQL sin fencing y no es seguro mezclar versiones.
- El formato y los hashes de auditoría anteriores se mantienen. El parche no repara una cadena que ya estuviera dañada.

## Límites precisos de las garantías

El presupuesto garantiza admisión serializada de reservas respecto del límite suministrado para la raíz. El consumo real reportado por un proveedor puede superar su estimación; se conserva ese consumo real al liquidar y no se falsea para hacerlo caber en el techo. Las políticas de estimación/proveedor siguen siendo responsables de evitar ese exceso.

El fencing protege actualizaciones de tareas y su resultado durable. La cancelación del worker no implica ejecución exactamente una vez sobre sistemas externos: efectos ya realizados y la recuperación semántica del journal requieren sus controles propios. No se modificó la política de recuperación A→B de `InvocationJournal` en este cambio.

La cadena global serializa escritores de auditoría de todos los tenants; es una elección de compatibilidad y un límite de throughput conocido. SQLite continúa serializando escritores a nivel de base. Las pruebas usan conexiones independientes concurrentes; no representan una certificación de tolerancia a particiones de red ni una medición de capacidad productiva.

## Verificación

- **Suite completa final:** 2 872 pruebas aprobadas, 35 omitidas y una advertencia de deprecación de `google.genai`; duración 109,06 s. No hubo fallos.
- **Backends comprobados:** SQLite con WAL y PostgreSQL 18.6 local, en schemas aislados por caso. Las 26 variantes de la nueva matriz de integración se ejecutaron: 13 sobre SQLite y 13 sobre PostgreSQL.
- **Worker:** cuatro casos nuevos para cancelación por heartbeat fallido y continuidad después de perder el lease durante éxito/error del ejecutor.
- **Controles estáticos:** `make lint`, `make typecheck` (17 archivos Python modificados/nuevos), `make syntax` y `git diff --check` satisfactorios.
- **Entorno:** E2E externo desactivado (`NEXUS_E2E=0`); DSN de PostgreSQL de prueba explícito y `DATABASE_URL` vacío. La instancia temporal se alojó en `/tmp`, independiente de las bases de la aplicación.
- **Comando de regresión:** `.venv/bin/python -m pytest nexus_core/tests -q --tb=short`, con las variables de aislamiento indicadas. Las omisiones corresponden a condiciones de habilitación de pruebas de la suite; no se presentan como verificaciones aprobadas.
- **Evidencia local:** resumen de validación guardado en `P0_validacion.txt`.

Se incorporaron pruebas de reservas concurrentes, liquidación/liberación exclusiva, auditoría concurrente entre tenants, leases expirados, reutilización del nombre de worker, competencia entre completar y fallar, expiración durante espera de bloqueo, reconciliadores simultáneos, compensación única, rollback y migración idempotente. Los casos del worker comprueban caída del heartbeat y cambio de propietario antes de completar o registrar un fallo.

CI ejecuta la nueva matriz SQLite/PostgreSQL en el job de PostgreSQL con un DSN de prueba explícito. Cada caso PostgreSQL crea y elimina su propio schema; no usa automáticamente `DATABASE_URL` de la aplicación.

## Código actualizado

Los siguientes bloques corresponden a los métodos modificados principales; los archivos enlazados contienen su contexto completo.

### 1. Transacciones y adaptador PostgreSQL

[Archivo completo](../nexus_core/kernel/control_store.py).

`ControlStore.locked_transaction`:

```python
@contextmanager
def locked_transaction(self, key: str) -> Iterator[DatabaseConnection]:
    """Serialize an invariant before its first read, through commit/rollback.

    SQLite serializes writers database-wide. PostgreSQL narrows the lock to
    a durable key. Never acquire a second connection inside this boundary.
    """
    conn = self.connect()
    try:
        with conn:
            self._lock_transaction(conn, key)
            yield conn
    finally:
        conn.close()
```

`ControlStore._lock_transaction`:

```python
def _lock_transaction(self, conn: DatabaseConnection, key: str) -> None:
    conn.execute("BEGIN IMMEDIATE")
```

`ControlStore.active_lease_sql`:

```python
@property
def active_lease_sql(self) -> str:
    """Evaluate expiration at the database, not before waiting for a lock."""
    return "julianday(lease_until) > julianday('now')"
```

`ControlStore.task_row_lock_sql`:

```python
@property
def task_row_lock_sql(self) -> str:
    return ""  # BEGIN IMMEDIATE already excludes competing SQLite writers.
```

`ControlStore._locked_task`:

```python
def _locked_task(
    self, conn: DatabaseConnection, task_id: str,
) -> dict[str, Any] | None:
    """Acquire the row before evaluating a time-sensitive lease predicate."""
    row = conn.execute(
        "SELECT * FROM kernel_tasks WHERE id=?" + self.task_row_lock_sql,
        (task_id,),
    ).fetchone()
    return dict(row) if row is not None else None
```

### 1.1 Bloqueo PostgreSQL y comprobación de vigencia

[Archivo completo](../nexus_core/kernel/postgres_store.py).

`PostgresControlStore._lock_transaction`:

```python
def _lock_transaction(self, conn: DatabaseConnection, key: str) -> None:
    # READ COMMITTED gives reads *after* a lock wait a fresh snapshot.
    # ON CONFLICT also serializes concurrent creation of the first lock row.
    conn.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
    conn.execute(
        "INSERT INTO kernel_transaction_locks(lock_key) VALUES(?) "
        "ON CONFLICT(lock_key) DO NOTHING", (key,),
    )
    conn.execute(
        "SELECT lock_key FROM kernel_transaction_locks WHERE lock_key=? FOR UPDATE",
        (key,),
    )
```

`PostgresControlStore.active_lease_sql`:

```python
@property
def active_lease_sql(self) -> str:
    return "CAST(lease_until AS TIMESTAMPTZ) > clock_timestamp()"
```

`PostgresControlStore.task_row_lock_sql`:

```python
@property
def task_row_lock_sql(self) -> str:
    return " FOR UPDATE"
```

### 2. Presupuesto

[Archivo completo](../nexus_core/kernel/budget_ledger.py).

`BudgetLedger.reserve`:

```python
def reserve(self, tenant_id: str, *, root_id: str, run_id: str, parent_id: str,
            tokens: int, global_budget: int) -> str:
    """Reserve tokens for one provider request or fail before the call."""
    amount = int(tokens)
    if amount <= 0:
        raise ValueError('reservation must be positive')
    with self.store.locked_transaction(self._lock_key(tenant_id, root_id)) as conn:
        committed = conn.execute(
            '''SELECT COALESCE(SUM(CASE WHEN state='reserved' THEN tokens_reserved
                ELSE tokens_used END),0) AS total FROM kernel_budget_reservations
                WHERE tenant_id=? AND root_id=?''',
            (tenant_id, root_id),
        ).fetchone()['total']
        if int(committed) + amount > int(global_budget):
            raise BudgetExceeded(
                f'tree budget exceeded: {int(committed)}+{amount} > {int(global_budget)}'
            )
        reservation_id = f'reservation_{uuid4().hex}'
        conn.execute(
            '''INSERT INTO kernel_budget_reservations
            (reservation_id,tenant_id,root_id,run_id,parent_id,tokens_reserved,
             tokens_used,state,created_at) VALUES(?,?,?,?,?,?,?,?,?)''',
            (reservation_id, tenant_id, root_id, run_id, parent_id, amount, 0,
             'reserved', utc_now()),
        )
    return reservation_id
```

`BudgetLedger._lock_key`:

```python
@staticmethod
def _lock_key(tenant_id: str, root_id: str) -> str:
    return json.dumps(["budget", tenant_id, root_id], separators=(",", ":"))
```

`BudgetLedger._reservation_key`:

```python
def _reservation_key(self, reservation_id: str) -> str:
    # The reservation's tenant/root never changes. Discover the key before
    # locking, then guard the state transition in the locked transaction.
    with self.store.connect() as conn:
        row = conn.execute(
            "SELECT tenant_id,root_id FROM kernel_budget_reservations "
            "WHERE reservation_id=?", (reservation_id,),
        ).fetchone()
    if row is None:
        raise PermissionError("reservation is not open")
    return self._lock_key(row["tenant_id"], row["root_id"])
```

`BudgetLedger.settle`:

```python
def settle(self, reservation_id: str, actual_tokens: int) -> None:
    amount = max(0, int(actual_tokens))
    with self.store.locked_transaction(self._reservation_key(reservation_id)) as conn:
        updated = conn.execute(
            '''UPDATE kernel_budget_reservations SET tokens_used=?,state='settled',
            released_at=? WHERE reservation_id=? AND state='reserved' ''',
            (amount, utc_now(), reservation_id),
        ).rowcount
    if updated != 1:
        raise PermissionError('reservation is not open')
```

`BudgetLedger.release`:

```python
def release(self, reservation_id: str) -> None:
    with self.store.locked_transaction(self._reservation_key(reservation_id)) as conn:
        updated = conn.execute(
            '''UPDATE kernel_budget_reservations SET state='released',tokens_used=0,
            released_at=? WHERE reservation_id=? AND state='reserved' ''',
            (utc_now(), reservation_id),
        ).rowcount
    if updated != 1:
        raise PermissionError('reservation is not open')
```

### 3. Cadena de auditoría

[Archivo completo](../nexus_core/kernel/audit.py).

`AuditWriter.append`:

```python
def append(
    self,
    *,
    tenant_id: str,
    trace_id: str,
    actor_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    payload: Dict[str, Any],
    decision: str | None = None,
) -> str:
    event_id = f"audit_{uuid4().hex}"
    created_at = utc_now()
    sanitized = self._sanitize(payload)
    # Keep the existing global chain format. The lock includes reading its
    # head and committing the successor, across processes and tenants.
    with self.store.locked_transaction("audit:global") as conn:
        previous = conn.execute(
            "SELECT event_hash FROM kernel_audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else ""
        canonical = json.dumps({
            "event_id": event_id,
            "tenant_id": tenant_id,
            "trace_id": trace_id,
            "actor_id": actor_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "decision": decision,
            "payload": sanitized,
            "previous_hash": previous_hash,
            "created_at": created_at,
        }, sort_keys=True, separators=(",", ":"))
        event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        conn.execute(
            """INSERT INTO kernel_audit_events
            (event_id,tenant_id,trace_id,actor_id,action,resource_type,resource_id,
             decision,payload,previous_hash,event_hash,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (event_id, tenant_id, trace_id, actor_id, action, resource_type,
             resource_id, decision, json.dumps(sanitized, sort_keys=True),
             previous_hash, event_hash, created_at),
        )
    return event_id
```

### 4. Generación, renovación, finalización y reintentos

[Archivo completo](../nexus_core/kernel/control_store.py).

`ControlStore.claim_task`:

```python
def claim_task(self, worker_id: str, lease_seconds: int = 60) -> Optional[Dict[str, Any]]:
    if lease_seconds <= 0:
        raise ValueError("lease_seconds must be positive")
    now = datetime.now(timezone.utc)
    now_value = now.isoformat()
    lease_until = (now + timedelta(seconds=lease_seconds)).isoformat()
    with self.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT * FROM kernel_tasks
            WHERE cancel_requested=0 AND ((status='queued' AND available_at<=?)
               OR (status='running' AND lease_until<?)
            )
            ORDER BY priority ASC, created_at ASC LIMIT 1""",
            (now_value, now_value),
        ).fetchone()
        if not row:
            return None
        updated = conn.execute(
            """UPDATE kernel_tasks SET status='running',lease_owner=?,lease_until=?,
               attempts=attempts+1,lease_generation=lease_generation+1,updated_at=?
               WHERE id=? AND lease_generation=? AND cancel_requested=0 AND
               ((status='queued' AND available_at<=?) OR (status='running' AND lease_until<?))""",
            (worker_id, lease_until, now_value, row["id"], row["lease_generation"],
             now_value, now_value),
        )
        if updated.rowcount != 1:
            return None
        claimed = conn.execute(
            "SELECT * FROM kernel_tasks WHERE id=?", (row["id"],)
        ).fetchone()
        self._transition(conn, row["id"], row["status"], "running", "lease claimed", worker_id)
    return self._decode_row(claimed, ("payload", "result"))
```

`ControlStore.renew_task_lease`:

```python
def renew_task_lease(
    self, task_id: str, worker_id: str, *, lease_generation: int,
    lease_seconds: int = 60,
) -> bool:
    """Renew only this live generation; an expired lease cannot be revived."""
    if lease_seconds <= 0:
        raise ValueError("lease_seconds must be positive")
    with self.locked_transaction("task:" + task_id) as conn:
        self._locked_task(conn, task_id)
        now = datetime.now(timezone.utc)
        lease_until = (now + timedelta(seconds=lease_seconds)).isoformat()
        updated = conn.execute(
            f"""UPDATE kernel_tasks SET lease_until=?,updated_at=?
            WHERE id=? AND lease_owner=? AND lease_generation=?
            AND status='running' AND {self.active_lease_sql}""",
            (lease_until, now.isoformat(), task_id, worker_id, lease_generation),
        )
        return updated.rowcount == 1
```

`ControlStore.complete_task`:

```python
def complete_task(
    self, task_id: str, worker_id: str, *, lease_generation: int,
    result: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> None:
    """Commit result and events only if the live fencing token still matches."""
    from .redaction import sanitize

    result = sanitize(result)
    error = sanitize(error)
    status = "failed" if error else "completed"
    encoded = json.dumps(result) if result is not None else None
    with self.locked_transaction("task:" + task_id) as conn:
        self._locked_task(conn, task_id)
        now = utc_now()
        updated = conn.execute(
            f"""UPDATE kernel_tasks SET status=?,result=?,error=?,lease_owner=NULL,
            lease_until=NULL,updated_at=? WHERE id=? AND lease_owner=?
            AND lease_generation=? AND status='running' AND {self.active_lease_sql}""",
            (status, encoded, error, now, task_id, worker_id, lease_generation),
        )
        if updated.rowcount != 1:
            raise LeaseLost("worker does not own this active task lease generation")
        row = conn.execute(
            """SELECT t.run_id,t.tenant_id,r.workflow_id FROM kernel_tasks t
            JOIN kernel_runs r ON r.id=t.run_id WHERE t.id=?""", (task_id,),
        ).fetchone()
        self._transition(conn, task_id, "running", status, error, worker_id)
        self._outbox(conn, row["tenant_id"], "task", task_id,
                     f"task.{status}", result or {"error": error})
        run_status = "running" if row["workflow_id"] else status
        changed = conn.execute(
            "UPDATE kernel_runs SET status=?,result=?,error=?,updated_at=? "
            "WHERE id=? AND tenant_id=?",
            (run_status, encoded, error, now, row["run_id"], row["tenant_id"]),
        )
        if changed.rowcount != 1:
            raise RuntimeError("task run disappeared during completion")
```

`ControlStore.fail_or_retry_task`:

```python
def fail_or_retry_task(
    self, task_id: str, worker_id: str, error: str, *, lease_generation: int,
) -> str:
    """Retry or dead-letter atomically; stale generations produce no events."""
    from .redaction import sanitize_text

    error = sanitize_text(error)
    with self.locked_transaction("task:" + task_id) as conn:
        row = self._locked_task(conn, task_id)
        if row is None:
            raise LeaseLost("task no longer exists")
        now = datetime.now(timezone.utc)
        retry = row["attempts"] < row["max_attempts"]
        status = "queued" if retry else "dead_letter"
        delay = min(300, 2 ** max(0, row["attempts"] - 1)) if retry else 0
        available = (now + timedelta(seconds=delay)).isoformat()
        updated = conn.execute(
            f"""UPDATE kernel_tasks SET status=?,error=?,available_at=?,
            lease_owner=NULL,lease_until=NULL,updated_at=?
            WHERE id=? AND lease_owner=? AND lease_generation=?
            AND status='running' AND {self.active_lease_sql}""",
            (status, error, available, now.isoformat(), task_id, worker_id,
             lease_generation),
        )
        if updated.rowcount != 1:
            raise LeaseLost("worker does not own this active task lease generation")
        if retry:
            self._transition(conn, task_id, "running", status, "retry: " + error, worker_id)
            return status
        conn.execute(
            """INSERT INTO kernel_dead_letters
            (id,tenant_id,task_id,payload,error,attempts,created_at)
            VALUES(?,?,?,?,?,?,?)""",
            (f"dlq_{uuid4().hex}", row["tenant_id"], task_id, row["payload"], error,
             row["attempts"], now.isoformat()),
        )
        changed = conn.execute(
            "UPDATE kernel_runs SET status='failed',error=?,updated_at=? "
            "WHERE id=? AND tenant_id=?",
            (error, now.isoformat(), row["run_id"], row["tenant_id"]),
        )
        if changed.rowcount != 1:
            raise RuntimeError("task run disappeared during failure")
        self._transition(conn, task_id, "running", status, error, worker_id)
        self._outbox(conn, row["tenant_id"], "task", task_id, "task.dead_letter", {"error": error})
        return status
```

### 5. Reconciliación y compensación

[Archivo completo](../nexus_core/kernel/workflows.py).

`DurableWorkflowEngine.reconcile`:

```python
def reconcile(self, run_id: str, tenant_id: str) -> Dict[str, Any]:
    """Persist task results and enqueue all newly-unblocked steps exactly once."""
    key = json.dumps(["workflow", tenant_id, run_id], separators=(",", ":"))
    with self.store.locked_transaction(key) as conn:
        now = utc_now()
        run = conn.execute(
            "SELECT * FROM kernel_runs WHERE id=? AND tenant_id=?", (run_id, tenant_id)
        ).fetchone()
        if not run:
            raise KeyError("run not found")
        workflow = conn.execute(
            "SELECT definition FROM kernel_workflows WHERE id=? AND tenant_id=?",
            (run["workflow_id"], tenant_id),
        ).fetchone()
        definition = json.loads(workflow["definition"])
        by_key = {step["key"]: step for step in definition["steps"]}
        rows = conn.execute(
            """SELECT s.*,t.status AS task_status,t.result AS task_result,t.error AS task_error,
            c.status AS compensation_status
            FROM kernel_workflow_steps s LEFT JOIN kernel_tasks t ON t.id=s.task_id
            LEFT JOIN kernel_tasks c ON c.id=s.compensation_task_id
            WHERE s.run_id=?""", (run_id,)
        ).fetchall()
        states = {row["step_key"]: dict(row) for row in rows}

        for key, state in states.items():
            task_status = state.get("task_status")
            if (task_status in TERMINAL_TASKS
                    and state["status"] not in {
                        task_status, "compensating", "compensated", "compensation_failed"
                    }):
                conn.execute(
                    "UPDATE kernel_workflow_steps SET status=?,result=?,updated_at=? WHERE id=?",
                    (task_status, state.get("task_result"), now, state["id"]),
                )
                state["status"] = task_status

        failed = any(
            state["status"] in {"failed", "dead_letter", "cancelled"}
            for state in states.values()
        )
        if failed:
            for key, state in states.items():
                if state.get("compensation_status") in TERMINAL_TASKS:
                    final = (
                        "compensated" if state["compensation_status"] == "completed"
                        else "compensation_failed"
                    )
                    conn.execute(
                        "UPDATE kernel_workflow_steps SET status=?,updated_at=? WHERE id=?",
                        (final, now, state["id"]),
                    )
                elif (state["status"] == "completed" and state["compensation_type"]
                      and not state["compensation_task_id"]):
                    task_id = f"task_{uuid4().hex}"
                    claimed = conn.execute(
                        """UPDATE kernel_workflow_steps SET compensation_task_id=?,
                        status='compensating',updated_at=? WHERE id=?
                        AND status='completed' AND compensation_task_id IS NULL""",
                        (task_id, now, state["id"]),
                    )
                    if claimed.rowcount != 1:
                        continue
                    payload = {
                        "compensates_step": key,
                        "original_result": json.loads(state["task_result"] or "null"),
                        "workflow_context": json.loads(run["context"]),
                    }
                    conn.execute(
                        """INSERT INTO kernel_tasks
                        (id,tenant_id,run_id,task_type,status,priority,payload,max_attempts,
                         timeout_seconds,available_at,created_at,updated_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (task_id, tenant_id, run_id, state["compensation_type"], "queued",
                         1, json.dumps(payload), 3, 300, now, now, now),
                    )
                    self.store._transition(
                        conn, task_id, None, "queued", "workflow compensation", "workflow-engine"
                    )
                    self.store._outbox(
                        conn, tenant_id, "task", task_id, "task.compensation.queued",
                        {"run_id": run_id, "step": key},
                    )
            conn.execute(
                "UPDATE kernel_runs SET status='failed',error='workflow step failed',updated_at=? WHERE id=?",
                (now, run_id),
            )
        else:
            for key, state in states.items():
                dependencies = json.loads(state["depends_on"])
                if state["status"] == "pending" and all(states[item]["status"] == "completed" for item in dependencies):
                    step = by_key[key]
                    task_id = f"task_{uuid4().hex}"
                    claimed = conn.execute(
                        """UPDATE kernel_workflow_steps SET task_id=?,status='queued',
                        updated_at=? WHERE id=? AND status='pending' AND task_id IS NULL""",
                        (task_id, now, state["id"]),
                    )
                    if claimed.rowcount != 1:
                        continue
                    payload = dict(step.get("payload", {}))
                    payload["workflow_context"] = json.loads(run["context"])
                    conn.execute(
                        """INSERT INTO kernel_tasks
                        (id,tenant_id,run_id,task_type,status,priority,payload,max_attempts,
                         timeout_seconds,available_at,created_at,updated_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (task_id, tenant_id, run_id, step["task_type"], "queued",
                         step.get("priority", 5), json.dumps(payload), step.get("max_attempts", 3),
                         step.get("timeout_seconds", 300), now, now, now),
                    )
                    self.store._transition(conn, task_id, None, "queued", "workflow step ready", "workflow-engine")
                    self.store._outbox(conn, tenant_id, "task", task_id, "task.queued", {"run_id": run_id, "step": key})
            refreshed = conn.execute(
                "SELECT status FROM kernel_workflow_steps WHERE run_id=?", (run_id,)
            ).fetchall()
            statuses = [row["status"] for row in refreshed]
            run_status = "completed" if statuses and all(item == "completed" for item in statuses) else "running"
            conn.execute(
                "UPDATE kernel_runs SET status=?,updated_at=? WHERE id=?", (run_status, now, run_id)
            )
    return self.store.get_run(run_id, tenant_id) or {}
```

### 6. Heartbeat y manejo de pérdida de lease

[Archivo completo](../nexus_worker.py).

`_execute_with_heartbeat`:

```python
async def _execute_with_heartbeat(
    store: ControlStore,
    task: dict[str, Any],
    worker_id: str,
    registry: ExecutorRegistry,
    context: ExecutionContext,
    timeout_seconds: float,
    *,
    renew_interval: float = LEASE_RENEW_INTERVAL_SECONDS,
    lease_seconds: int = LEASE_SECONDS,
) -> dict[str, Any]:
    """Run an executor while renewing the task lease in the background.

    If a renewal fails the worker no longer owns the task: the executor is
    signalled through ``context.cancel_event`` so a long tool call can be
    interrupted instead of being re-executed concurrently by another worker.
    """
    stop = asyncio.Event()
    lease_error: Exception | None = None
    execution = asyncio.create_task(registry.execute(task, context))

    async def renew_loop() -> None:
        nonlocal lease_error
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=max(0.01, renew_interval))
                return
            except asyncio.TimeoutError:
                pass
            try:
                renewed = await asyncio.to_thread(
                    store.renew_task_lease, task["id"], worker_id,
                    lease_generation=task["lease_generation"], lease_seconds=lease_seconds,
                )
                if not renewed:
                    raise LeaseLost("heartbeat no longer owns an active task lease")
            except Exception as exc:
                # A database failure is also loss of authority: never continue
                # external work while unable to prove ownership.
                lease_error = exc
                cancel_event = getattr(context, "cancel_event", None)
                if cancel_event is not None:
                    cancel_event.set()
                execution.cancel()
                return

    renew_task = asyncio.create_task(renew_loop())
    try:
        return await asyncio.wait_for(execution, timeout=timeout_seconds)
    finally:
        stop.set()
        await asyncio.gather(renew_task, return_exceptions=True)
        if lease_error is not None:
            raise LeaseLost("execution cancelled after heartbeat failure") from lease_error
```

`_process_task`:

```python
def _process_task(
    store: ControlStore, task: dict[str, Any], worker_id: str, registry: ExecutorRegistry,
) -> bool:
    """Run one claim; a stale worker exits this iteration without mutating state."""
    generation = int(task["lease_generation"])
    try:
        context = ExecutionContext(
            store=store, task=task, worker_id=worker_id, cancel_event=asyncio.Event(),
        )
        result = asyncio.run(_execute_with_heartbeat(
            store, task, worker_id, registry, context, task["timeout_seconds"],
        ))
        store.complete_task(
            task["id"], worker_id, lease_generation=generation, result=result,
        )
    except LeaseLost:
        logger.warning("Task %s generation %s lost its lease", task["id"], generation)
        return False
    except Exception as exc:
        try:
            store.fail_or_retry_task(
                task["id"], worker_id, str(exc), lease_generation=generation,
            )
        except LeaseLost:
            logger.warning("Task %s lost its lease before recording failure", task["id"])
            return False
        store.append_run_event(
            task["tenant_id"], task["run_id"], "task.failed",
            {"task_id": task["id"], "error_type": type(exc).__name__, "error": str(exc)[:1000]},
        )
    return True
```
