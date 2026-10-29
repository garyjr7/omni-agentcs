# Orquestador paralelo — implementación

**Fecha:** 2026-10-28 · **Alcance:** que un turno del bucle ReAct pueda lanzar
varias herramientas independientes a la vez (nmap + gobuster), con el mismo
gobierno por llamada, y que el modelo reciba **un solo bloque** con todos los
resultados en el turno siguiente.

Antes: una acción = una tool. `nmap` terminaba, el modelo leía la observación, y
solo entonces podía pedir `gobuster`. Dos escaneos independientes costaban dos
vueltas completas al proveedor.

---

## 1. Cómo se modificó el bucle ReAct

### Contrato (`nexus_core/kernel/domain_dto.py`)

Nuevo `ToolCallBatch` (`action: "tool_calls"`) con `calls: [ToolCallSpec]`:

```json
{
  "thought": "recon en paralelo sobre el mismo host",
  "action": "tool_calls",
  "calls": [
    {"tool_id": "nexus.recon.nmap", "arguments": {"target": "10.10.10.5", "flags": ["-sV"]}, "expected_outcome": "puertos"},
    {"tool_id": "nexus.web.gobuster", "arguments": {"url": "http://10.10.10.5"}, "expected_outcome": "directorios"}
  ]
}
```

* **Mínimo 2, máximo 4 llamadas** (`MAX_PARALLEL_TOOL_CALLS`). Una llamada sola se
  normaliza a `tool_call`, así el camino de una tool no cambia nunca; cinco o más
  se rechazan como respuesta inválida y el bucle pide corrección.
* `tool_id`/`arguments` siguen existiendo como propiedades (la primera llamada),
  de modo que todo lo que leía la acción de forma escalar -telemetría, el
  mensaje del asistente, el contrato del prompt- sigue funcionando.

### Parser (`nexus_core/agent/parser.py`)

Tolerante, como el resto del transporte de este proyecto:

| Lo que emite el modelo | Lo que se entiende |
|---|---|
| Objeto `action: "tool_calls"` con `calls` | batch |
| Array de ≥ 2 objetos `action: "tool_call"` | batch (con `thought` del primero) |
| Objeto sin `action` con `tool_calls: [...]` | batch |
| Array u objeto con **una** llamada | `tool_call` normal |
| Array con acciones heterogéneas | primera acción + warning (como antes) |

Cuando el array se interpreta como batch se deja de emitir el warning engañoso
"multiple actions; using the first one": ya no se descarta ninguna.

### Bucle (`nexus_core/agent/react_coordinator.py`)

`_iteration_body` enruta `ToolCallBatch` a `_batch_turn()`. La forma del turno es
la misma: ocupa una iteración, cuenta tokens, respeta el presupuesto, el
`--max-iterations` y el margen de cierre forzado. Cambia el interior:

1. **Pre-vuelo por llamada** (`_call_refusal`): catálogo, subconjunto del
   subagente activo, PLAN-FIRST y tool retirada. Es el mismo predicado que usa
   el turno de una sola tool (el `_check_tool` se refactorizó para compartirlo),
   así que `tool_calls` **no puede ampliar** lo que el modelo tiene permitido.
2. **Aprobación por llamada** (`_review_call`): `PolicyEngine` + `OperatorMode` +
   el callback humano, una vez por tool. Un denegado por el operador, por la
   policy o por el catálogo queda como resultado de **esa** llamada.
3. **Ejecución concurrente** (`nexus_core/agent/parallel.py`): las que
   sobrevivieron se lanzan con `asyncio.gather`, un `Semaphore` y un timeout
   individual por llamada.
4. **Contabilidad por llamada**: cada tool deja su entrada en `result.actions`
   (con `batch_index`/`batch_size` e `invocation_signature`), su fila de auditoría
   y su `telemetry.note_tool`.
5. **Una observación**: `_inject_observation` escribe **un** mensaje
   (`parallel.tools`) con el bloque consolidado, y un evento
   `react.parallel_batch` en el journal con ids, contadores y duración.

### Límites (`parallel.py`)

| Variable | Por defecto | Efecto |
|---|---|---|
| `NEXUS_PARALLEL_TOOL_LIMIT` | derivado del hardware (1–3) | llamadas simultáneas (1 = secuencial, máx. 3); ver `PERFORMANCE_TUNING.md` |
| `NEXUS_PARALLEL_CALL_TIMEOUT` | `timeout_per_tool_seconds` del bucle | techo por llamada; una `nmap -p-` colgada no bloquea al resto |

Los dos límites existen por separado a propósito: la concurrencia protege la CPU
y el enlace de la caja (que también está corriendo Metasploit), el timeout
protege al **turno** de una sola herramienta que no vuelve.

El valor por defecto de la concurrencia ya no es un 3 fijo: sale de los núcleos y
la RAM detectados (1–2 núcleos → 1, 3–8 → 2, más → 3; menos de 4 GiB de RAM → 1),
con `NEXUS_PARALLEL_TOOL_LIMIT` como override. El detalle y la inyección de
`nice`/`cpulimit` en el sandbox están en `PERFORMANCE_TUNING.md`.

---

## 2. Seguridad cuando se lanzan herramientas en paralelo

La regla es una: **un batch es una pista de planificación, nunca una vía de
escape del gobierno**. Nada se decide en lote.

* **Scope, RoE, aprobaciones y auditoría siguen en el `ToolGateway`**, que se
  invoca una vez por llamada (`execute_tool(payload, context)`). El gateway
  vuelve a validar el destino contra el scope firmado y deja su auditoría: el
  pre-vuelo del coordinador nunca sustituye esa comprobación, solo evita gastar
  una llamada en algo que ya se sabe imposible.
* **Aprobación individual.** Tres tools = tres preguntas al operador (`review`
  por llamada). No hay "aprobar todo el batch", que sería exactamente el atajo
  que la gobernanza intenta impedir.
* **`ApprovalRequired` no es local.** Si una llamada necesita una aprobación que
  no tiene, el run se detiene con `status="blocked"`, igual que en el camino de
  una sola tool: la ausencia de aprobación no se puede compensar ejecutando las
  otras.
* **Política elegida para los demás fallos: continuar y reportar.** Un
  `ScopeViolation`, una denegación de la policy o un `PermissionError` de una
  llamada **no** cancela las que ya estaban autorizadas y en vuelo. Razones:
  1. cada llamada pasó su propio scope/aprobación, así que una denegación no dice
     nada de las demás;
  2. cancelar tareas a mitad mataría subprocesos en marcha y este proyecto ya
     trató los grupos huérfanos como un bug medido (ver los tests de cancelación);
  3. el resultado consolidado nombra la que falló y el modelo pivota.
  Lo que **sí** cierra el run es lo de siempre: `ApprovalRequired`, la
  insistencia en un objetivo fuera de scope (`MAX_CONSECUTIVE_SCOPE_DENIALS`, que
  el batch acumula por objetivo igual que el camino secuencial) y quedarse sin
  tools utilizables.
* **PLAN-FIRST también aplica por llamada**: sin plan, cada tool que toca el
  objetivo se rechaza con el `next` que lo desbloquea, y las de solo lectura
  pasan. No se puede "colar" un ataque dentro de un batch.
* **Retiro por fallos**: `timeout`, `unavailable` y los errores de tool cuentan
  la racha **por herramienta** (`_note_tool_failure`), así que un batch que
  insiste en la misma tool rota la retira para el siguiente turno.
* La salida de cada llamada se acota a `RESULT_OUTPUT_CHARS` (2 000) antes de
  entrar en el prompt; `evidence` y `assertions` **no** se recortan, porque son lo
  que leen el plan y las puertas de cierre.

---

## 3. Consolidación de salidas

El modelo recibe un único mensaje JSON en el turno siguiente:

```json
{
  "success": false,
  "parallel": true,
  "tool_calls": 2,
  "succeeded": 1,
  "failed": 1,
  "executed": 2,
  "refused": 0,
  "concurrency": 3,
  "duration_ms": 4121,
  "results": [
    {"tool_id": "nexus.recon.nmap", "arguments": {"target": "10.10.10.5"},
     "success": true, "outcome": "success", "duration_ms": 3900,
     "invocation_id": "…", "evidence": {…}, "assertions": [ … ],
     "output": {"ports": [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}]}},
    {"tool_id": "nexus.web.gobuster", "arguments": {"url": "http://10.10.10.5"},
     "success": false, "outcome": "negative", "duration_ms": 1200,
     "error": "403 en todas las rutas", "guidance": "…"}
  ],
  "guidance": "1 de 2 llamadas en paralelo fallaron (`nexus.web.gobuster`). Lee `results`: … Las que sí terminaron ya aportaron su evidencia: no las repitas…"
}
```

Por qué así y no una observación por tool:

* **Una vuelta, no N.** El objetivo del cambio es que el modelo vea nmap y
  gobuster juntos; N mensajes separados también funcionarían, pero el bloque
  único es el que el prompt puede citar como "esto es lo que hice a la vez" y el
  que el journal muestra como un turno.
* **`results` es un array ordenado por `batch_index`**, así que el modelo puede
  correlacionar cada entrada con la llamada que pidió (`tool_id` + `arguments`).
* **Cada entrada trae su propio `outcome`**, el mismo vocabulario que la
  observación de una sola tool (`success`, `negative`, `timeout`, `scope_denied`,
  `denied`, `governance_denial`, `error`…), más `error` y `guidance` cuando toca.
  El modelo no tiene que adivinar cuál falló.
* **`guidance` a nivel de bloque** solo aparece cuando hay fallos y dice
  explícitamente qué no repetir; el turno siguiente no gasta una iteración
  releyendo el mismo escaneo.
* **`refused`** distingue las que nunca llegaron al gateway (catálogo,
  PLAN-FIRST, aprobación) de las que se ejecutaron y fallaron: son dos acciones
  distintas para el modelo.
* La evidencia (`assertions`, `evidence`, `invocation_id`) viaja intacta por
  resultado, así que el plan, las puertas de cierre y el extractor de informes
  siguen viendo lo mismo que con llamadas secuenciales.

---

## 4. Cómo probarlo en tu Kali

```bash
# 1. El mismo objetivo que antes costaba dos turnos, en uno:
omni --objective "Sobre 10.10.10.5: enumera puertos con nmap y en paralelo busca
  directorios web con gobuster. Usa 'tool_calls' para lanzar ambas en el mismo turno." \
  --stream-json

# 2. Comprueba en el journal que fue un batch (y qué corrió a la vez):
sqlite3 ~/.local/share/omni/control.db \
  "SELECT event_type, payload FROM kernel_run_events
    WHERE event_type IN ('react.parallel_batch','react.scope_violation')
    ORDER BY sequence DESC LIMIT 5;"

# 3. Compara con el comportamiento secuencial (misma instrucción, sin paralelismo):
NEXUS_PARALLEL_TOOL_LIMIT=1 omni --objective "…" --stream-json

# 4. Sin proveedor real, para ver el contrato de punta a punta. El fixture
#    repite siempre el mismo batch, así que se corta el run a una iteración:
printf '%s' '{"default": {"content": "{\\"thought\\":\\"dos lecturas\\",\\"action\\":\\"tool_calls\\",\\"calls\\":[{\\"tool_id\\":\\"nexus.system.status\\",\\"arguments\\":{}},{\\"tool_id\\":\\"nexus.system.check_env\\",\\"arguments\\":{}}]}"}}' > /tmp/par.json
NEXUS_LLM_FIXTURES=/tmp/par.json omni --objective "comprueba el entorno" \
  --max-iterations 1 --stream-json | grep parallel_batch
# → {"type": "react.parallel_batch", ... "tool_ids": ["nexus.system.status",
#    "nexus.system.check_env"], "tool_calls": 2, "succeeded": 2, ...}
```

En la TUI, el bloque consolidado aparece como una sola observación con las N
ramas de resultado; en `--stream-json` el evento `react.parallel_batch` trae
`tool_ids`, `tool_calls`, `succeeded`, `failed`, `concurrency` y `duration_ms`.

Tests: `pytest nexus_core/tests/unit/test_parallel_tools.py -q` (18). El prompt
paga 427 caracteres por el contrato (`test_prompt_optimization.py` documenta el
nuevo techo: +130 tokens en el turno compacto, +137 de media).

---

## 5. Límites conocidos

* **Solo tools independientes.** El motor no analiza dependencias: si el modelo
  mete en un batch una tool que necesitaba la salida de otra, la ejecutará con
  los argumentos que escribió. El prompt lo dice explícitamente y el camino
  normal (`tool_call`) sigue siendo el de las cadenas.
* **El coste de un batch es el de un turno** a efectos de `max_iterations`, pero
  puede gastar mucha más pared de reloj que una sola tool: por eso el techo de
  concurrencia y el timeout por llamada son configurables.
* **Las guardas anti-bucle del turno simple no se aplican al batch**: la
  repetición exacta de una llamada fallida (V1-26), la rama cerrada y la barrera
  sin intentos son higiene del camino secuencial. Un batch **no** salta
  autorización -scope, RoE y aprobación se evalúan por llamada- pero un modelo
  que insista en la misma tool rota dentro de un batch solo se frena por el
  retiro por fallos, no por la corrección de repetición. Se deja así a propósito:
  mover esas guardas al batch cambiaría su semántica (¿repetición contra qué
  llamada anterior?) y el presupuesto por turno ya acota el daño.
* **Los subagentes automáticos** (`_maybe_autospawn`) siguen ejecutando su turno
  con el cliente y el catálogo que reciben; el batch no cambia su contrato.
