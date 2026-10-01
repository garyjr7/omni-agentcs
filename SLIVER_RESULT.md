# SLIVER_RESULT — Integración de Sliver C2 vía gRPC

Rama: `feat/sliver-bridge` · commit único
`feat(c2): Sliver bridge via gRPC with server, implants, sessions, exec and pivot tools`
(no se hizo push).

## 1. Resultado

| Criterio | Estado |
| --- | --- |
| 9 imports OK | ✅ |
| 31 tools (26 + 5 Sliver) | ✅ |
| 1436 tests previos siguen pasando | ✅ (1511 passed, 33 skipped) |
| ≥10 tests del cliente | ✅ 20 (`test_sliver_client.py`) |
| ≥8 tests de parsers | ✅ 13 (`test_sliver_parser.py`) |
| ≥15 tests de handlers | ✅ 31 (`test_sliver_handlers.py`) |
| ≥3 tests E2E opt-in | ✅ 3 (`test_sliver_e2e.py`, hoy *skipped*) |
| Ruff clean, cero TODOs | ✅ |
| `sliver-py` en requirements | ✅ (`nexus_core/requirements.txt`, `requirements-prod.in`, `requirements-dev.txt`) |
| `SLIVER_OPERATOR_CONFIG` en `.env.example` | ✅ |
| Sessions registradas en `kernel_sessions` | ✅ |
| `sliver_exec` requiere pertenencia al engagement | ✅ |
| `sliver_exec` rechaza comandos destructivos | ✅ |
| Ningún handler usa subprocess | ✅ |
| Fail-closed cuando el server no responde | ✅ |

Suite completa, en ambos modos de color:

```
NO_COLOR=1 .venv/bin/python -m pytest nexus_core/tests -q   → 1511 passed, 33 skipped
env -u NO_COLOR .venv/bin/python -m pytest nexus_core/tests -q → 1511 passed, 33 skipped
```

78 tests nuevos (75 ejecutados + 3 E2E skip): cliente 20, parser 13, handlers 31,
CLI 11, E2E 3.

## 2. Entregables

Nuevos:

- `nexus_core/integrations/sliver/client.py` — cliente async fail-closed.
- `nexus_core/integrations/sliver/__init__.py`.
- `nexus_core/tools/parsers/sliver.py` — `SliverServerInfo`, `SliverSession`,
  `SliverExecResult`, `SliverPivotInfo` + parse fns.
- `nexus_core/tools/handlers/sliver_{server,implants,sessions,exec,pivot}.py`
  + `sliver_common.py` (helpers compartidos).
- `nexus_core/tests/sliver_support.py`, `test_sliver_{client,parser,handlers}.py`,
  `test_cli_sliver_session.py`, `integration/test_sliver_e2e.py`.
- `SLIVER_RECON.md`, `SLIVER_RESULT.md`.

Modificados:

- `nexus_core/tools/registry.py` (+5 entradas).
- `nexus_core/cli/session.py`, `nexus_core/cli/commands.py` (modo sesión + meta).
- `nexus_core/kernel/tool_gateway.py` (1 condición, ver §3.3).
- `nexus_core/provisioner/data/install_recipes.json` (+ recipe `sliver-py`).
- `nexus_core/requirements.txt`, `requirements-prod.in`, `requirements-dev.txt`,
  `.env.example`, `README.md`.
- `nexus_core/tests/unit/test_{system_env_handler,recipes,prompt_optimization}.py`
  (catálogo 26 → 31).

## 3. Decisiones de diseño no cubiertas por el brief

### 3.1 La API real de `sliver-py 0.0.19` difiere del borrador

Documentado en `SLIVER_RECON.md`. Resumen:

1. **No existe `disconnect()` público.** El canal gRPC vive en `client._channel`.
   `SliverClient.disconnect()` lo cierra siempre (`await channel.close()`),
   tolerante a fallos, intentando primero un `disconnect()` si algún día existiera.
2. **Los RPC devuelven mensajes protobuf**, no `dict`. El wrapper los convierte con
   `MessageToDict(..., preserving_proto_field_name=True, always_print_fields_with_no_presence=True)`,
   de modo que los parsers trabajan con datos planos y los tests no necesitan protobuf.
3. **`InteractiveSession.execute(exe, args, output=True)`** no acepta una línea de
   shell. `execute_command()` elige el intérprete por SO (`cmd.exe /c` en Windows,
   `/bin/sh -c` en el resto) y pasa `args` como lista.
4. `kill_session()` devuelve `None`; el wrapper devuelve
   `{"session_id", "killed": True}`.

### 3.2 Pivoting por el stub de bajo nivel

`sliver-py 0.0.19` **no expone ninguna API de alto nivel** para `portfwd` / SOCKS5
(se verificó el directorio completo de `InteractiveSession`). El único camino es
el stub gRPC generado. `SliverClient` usa, a través de `_stub_call`, exactamente
estas RPC y mensajes:

| Acción | RPC | Request | Response |
| --- | --- | --- | --- |
| `list` | `PivotSessionListeners` | `sliverpb.PivotListenersReq` | `sliverpb.PivotListeners` |
| `portfwd` | `Portfwd` | `sliverpb.PortfwdReq{Port,Protocol=6,Host}` | `sliverpb.Portfwd` |
| `socks5` | `CreateSocks` | `sliverpb.Socks` | `sliverpb.Socks{TunnelID}` |
| `kill` | `PivotStopListener` | `sliverpb.PivotStopListenerReq{ID}` | `commonpb.Empty` |

Cada request lleva el dueño (`Request.SessionID` / `Request.BeaconID`), así que
sigue estando tan acotado como las llamadas de alto nivel. Esto se aisló en el
cliente: los handlers no conocen protobuf.

### 3.3 Una condición del gateway (necesaria, conservadora)

`ToolGateway.invoke` delegaba en `validate_session_scope` **solo** para tres
ids hardcodeados (`nexus.session.*`). Como nuestras tools tienen
`scope_required=True` + `scope_target_field=None`, el `scope_validator` normal
(`make_scope_validator`) habría lanzado `ValueError("scope_target_field 'None'
missing")` y **ninguna tool Sliver habría pasado por el gateway** (ReAct o REPL).

Se generalizó la condición:

```python
if definition.scope_target_field is None:
    validate_session_scope(context)   # tools acotadas al engagement
else:
    self.scope_validator(context, definition, arguments)
```

Es una generalización de un comportamiento existente, no un cambio de semántica:
los únicos descriptores con `scope_target_field=None` son hoy `nexus.session.*`
(ya iban por esa rama) y los tres Sliver nuevos. Verificado: los 68 tests de
handlers MSF/session siguen pasando. No se tocó `PolicyEngine`, `ScopeValidator`,
`AuditWriter`, `sandbox.py` ni ninguna firma pública.

### 3.4 `target_host` sin puerto

El peer de Sliver es `host:puerto` (`203.0.113.10:4444`).
`ScopeValidator.validate("host:puerto")` lo interpreta como dominio y lo rechaza,
y `kernel_sessions.register` exige un `target_host` validable. Por eso el helper
`target_host()` recorta el puerto (y soporta IPv6 `[::1]:443`) antes de registrar.
Una session sin peer no se registra y, como no se puede validar, **no se muestra**
(fail-closed).

### 3.5 Registro y filtrado

`nexus.c2.sliver_sessions` registra en `kernel_sessions` solo las sessions aún
desconocidas (`session_type="sliver:session"|"sliver:beacon"`), sin reasignar la
propiedad de un id ya existente (un registro con otro `engagement_id` hace que la
session se oculte). `sliver_exec`/`sliver_pivot` reutilizan
`SessionRegistry.denial`, así que una session ajena o de otro engagement se
rechaza antes de cualquier RPC.

### 3.6 Modo sesión del REPL: aditivo

`OmniSession.active_session_backend` (`"msf"` por defecto) permite que el mismo
modo sesión sirva a ambos C2. El prompt MSF no cambia (**verificado** por el test
de regresión existente); solo con backend Sliver emite `[sliver:<id>/<kind>]` y
enruta los comandos por `nexus.c2.sliver_exec`. Meta-comandos nuevos: `/sliver`,
`/implants`, `/sessions --sliver`.

### 3.7 Tests existentes actualizados (26 → 31)

Tres tests afirmaban literalmente «26 herramientas». Se actualizaron al catálogo
real de 31 y se añadió la verificación de la recipe `sliver-py`:

- `test_system_env_handler.py::test_check_env_registered_in_catalog`,
- `test_prompt_optimization.py` (renombrado a `..._for_31_tools`, tope 6500 chars;
  el catálogo compacto mide 5733),
- `test_recipes.py::test_load_recipes_valid_json` (15 → 16 recipes).

## 4. Fail-closed (evidencia)

- Sin `SLIVER_OPERATOR_CONFIG` → `ToolResult(verification_method="sliver_auth_missing")`.
- Config ilegible/JSON inválido → `sliver_auth_missing`.
- Server caído / timeout → `sliver_unavailable` (`verified=False`).
- Sesión no registrada / de otro engagement / fuera de scope → se rechaza antes
  de cualquier RPC.
- Comando destructivo o con metacaracteres de shell → `ValueError` antes del RPC.

## 5. E2E

El team server **no está corriendo** en `localhost:31337`, así que los 3 E2E se
saltan (documentado en `SLIVER_RECON.md` §5). Para ejecutarlos:

```bash
export SLIVER_OPERATOR_CONFIG=~/.sliver-operator.cfg
NEXUS_E2E=1 .venv/bin/python -m pytest nexus_core/tests/integration/test_sliver_e2e.py -v
```

No se instaló ni arrancó el servidor (requiere aprobación humana explícita).

## 6. Verificación ejecutada

```
9/9 imports OK · 31 tools · ruff (F,E9) clean · 0 TODOs
grep subprocess|Popen|os.system|shell=True en handlers+integración → OK
1511 passed, 33 skipped  (ambos modos de color)
```
