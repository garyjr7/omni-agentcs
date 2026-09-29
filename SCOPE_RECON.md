# SCOPE_RECON — Reconocimiento previo a Scope Gating en el ToolGateway

Fecha: 2026-09-29
Rama: `feat/scope-gating`
Baseline verificado: `python -m pytest nexus_core/tests/unit -q` → **43 passed**.

## 1. Puntos de integración

### 1.1 `nexus_core/kernel/models.py` (dataclasses canónicas)

- `utc_now()` devuelve ISO 8601 con timezone UTC (`datetime.now(timezone.utc).isoformat()`).
- `RiskLevel` es `str, Enum`. `Identity`, `Resource`, `ToolResult`, `RunContext`,
  `PolicyDecision` son `@dataclass(frozen=True)`.
- `RunContext` es **frozen** y hoy tiene: `tenant_id`, `identity`, `run_id`, `trace_id`,
  `environment`, `budget_tokens`, `budget_usd`. Se puede añadir `scope` al final con
  default `None` sin romper ningún uso existente (todos los usos son posicionales hasta
  `identity` y keyword para el resto).
- `ToolDefinition` es `@dataclass` **mutable** (no frozen); añadir campos con default al
  final es seguro.
- Ya existe `from __future__ import annotations`, por lo que las anotaciones no se
  evalúan en runtime → se puede usar un `TYPE_CHECKING` import para `EngagementScope`
  evitando imports circulares.

### 1.2 `nexus_core/kernel/tool_gateway.py` (dónde se integra)

Firma pública actual:

```python
def __init__(self, policy, audit, approvals=None)
async def invoke(self, tool_id, arguments, context, permissions=(), approval_id=None)
```

Flujo de `invoke()`:
1. Busca `definition` en `self._definitions` (si no existe o `enabled=False` → `KeyError`).
2. `validate(arguments, definition.input_schema or {"type":"object"})` (schema).
3. `decision = self.policy.decide(identity, "execute:tool", Resource(...), permissions, definition)`.
4. `audit.append(action="tool.invoke", decision=allow/deny)`.
5. Si `not decision.allowed` → `PermissionError`.
6. Si `decision.requires_approval` → exige `approval_id` + `approvals.verify`.
7. `store.record_usage(...)` (cuota).
8. Ejecuta handler, exige `ToolResult.success`, valida tamaño de salida, audita
   `tool.complete`; en excepción audita `tool.failed` y re-lanza.

**Punto de inserción del scope gating:** entre el paso 2 (schema) y el paso 3 (policy),
tal como pide el prompt. `invoke()` no cambia su firma → los dos tests existentes del
gateway siguen pasando.

`__init__` se debe extender con `scope_validator=None` (parámetro opcional al final).

### 1.3 `nexus_core/kernel/policy.py` (allow/deny)

- `PolicyEngine.decide(identity, action, resource, permissions, tool)` devuelve
  `PolicyDecision(allowed, reason, policy_id, ...)`.
- Cross-tenant siempre denegado. Sin store → decide por rol/permiso.
- `execute:*` requiere rol `operator` o `admin` (o permiso explícito).
- `RiskLevel.HIGH/DESTRUCTIVE` → `requires_approval=True`.
- El scope gating es **ortogonal** a la policy: ocurre antes.

### 1.4 `nexus_core/kernel/audit.py` (cómo se audita)

- `AuditWriter.append(*, tenant_id, trace_id, actor_id, action, resource_type, resource_id, payload: Dict, decision=None) -> str`.
- Hash-chain global (sha256 sobre canonical JSON + `previous_hash`), verificable con
  `verify_chain()`. `Export(...)` y `_sanitize()` redactan claves sensibles.
- Para el scope denial se emitirá `action="scope.denied"`, `resource_type="tool"`,
  `resource_id=tool_id`, `payload={"target_keys":[...], "reason": <str[:500]>}`,
  `decision="deny"`.

### 1.5 `nexus_core/kernel/control_store.py` (SCHEMA + migraciones)

- `SCHEMA` es un `executescript` idempotente (`CREATE TABLE IF NOT EXISTS ...`).
- `ControlStore.initialize()`: `conn.executescript(SCHEMA)` → `_migrate_sqlite(conn)` →
  `INSERT OR IGNORE` del tenant `system`.
- `_migrate_sqlite` sólo hace ALTERs de columnas de tablas preexistentes
  (`kernel_tasks`, `kernel_connectors`, `kernel_workflow_steps`) y registra la migración
  `version=1`. **No se tocará** para la tabla nueva (es `CREATE TABLE IF NOT EXISTS`).
- `connect()` activa `PRAGMA foreign_keys=ON`, por lo que la tabla nueva debe respetar
  `FOREIGN KEY(tenant_id) REFERENCES kernel_tenants(id)`. El tenant `system` existe tras
  `initialize()`, así que `create()` con `tenant_id="system"` funciona.

### 1.6 `nexus_core/kernel/migrations.py`

`MigrationRunner` aplica `Migration(version, name, up, down)` reversibles. NO se usará
para `kernel_engagements` (schema idempotente, tabla nueva sin datos que migrar).

### 1.7 Tests existentes relevantes

- `nexus_core/tests/unit/test_kernel_offline.py::test_tool_gateway_requires_approval_and_audits`
  → construye `ToolGateway(PolicyEngine(), AuditWriter(store), approvals)` y cuenta
  **exactamente 3** eventos de auditoría. Un tool sin campos de scope NO debe generar
  eventos extra.
- `...::test_tool_gateway_validates_schema_quota_and_output`
  → tool sin scope, verifica cuota y salida exacta del `ToolResult`.
- `nexus_core/tests/unit/test_sovereign_runtime.py` → patrón de `ControlStore` temporal,
  task durable y gateway; sirve de referencia para tests de integración.

### 1.8 Entorno

- No hay `python`/`pytest`/`ruff` en PATH global. El repo trae `.venv/` con
  `pytest 9.1.1` y `ruff 0.16.1` (Python 3.12.3). Se invoca `.venv/bin/python -m pytest`
  desde la raíz del repo.
- `ruff.toml` raíz: `target-version="py312"`, `line-length=100`.

## 2. Decisiones de diseño del scope gating

1. **Desacoplamiento**: `ToolGateway` recibe un callable `scope_validator`, no importa el
   paquete `nexus_core.scope`. Así el gateway funciona aunque el módulo de scope no esté
   instalado.
2. **Detección de IPs privadas**: por diseño, para una IP objetivo (o IP resuelta de un
   dominio) el chequeo de rango privado ocurre **antes** de la contención en CIDR. Así una
   IP privada que no cae en ningún CIDR privado del scope produce `ScopePrivateIP`
   (subclase de `ScopeViolation`) en lugar de un genérico "fuera de scope".
3. **`urls` en `EngagementScope`**: se persisten, pero el matching de targets URL sigue
   literalmente la regla del prompt (extraer host → validar como IP o dominio). No hay
   allowlist por path.
4. **`localhost`**: aunque no contiene `.`, se acepta como dominio porque el resolver está
   especificado para resolverlo. El validator decide si sus IPs (loopback) están
   autorizadas.
5. **`create()` del store**: usa INSERT simple para respetar `UNIQUE(tenant_id, name)`;
   `created_at` vacío se rellena con `utc_now()`.
6. **`canonical_form()`**: JSON canónico con `sort_keys=True` y separadores compactos,
   excluyendo el campo `signature`. Es determinista y estable para HMAC-SHA256.
