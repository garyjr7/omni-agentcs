# MASTER ROADMAP — OMNI / OmniAgentCS

> **Documento único de verdad.** Consolida las auditorías, planes y promesas ya
> emitidas, las cruza con el código de `430dcfb` y define el orden de ejecución.
> No sustituye a los documentos de origen: los indexa, los clasifica y evita que
> dos fases futuras implementen lo mismo de forma incompatible.

| Dato | Valor |
|---|---|
| Fecha | 2026-10-21 |
| Commit de código auditado | `430dcfb` — *Caja Negra por defecto, sin esperas pasivas y NFS sin root* |
| Roadmap base | `1a96924` — MASTER_ROADMAP + INDEX |
| Ejecución W1.2 + PTY P0 | `49691be` |
| Ejecución P1 (`session_ref`) | `07e3cdc` |
| Ejecución P1.5 (productor `webshell`) | `2d5b318` |
| Ejecución V10 (HackPark: PoC + CSRF) | `88f1210` |
| Ejecución V11 (HackPark: PoC en el objetivo) | commit de V11 (`HEAD` al cerrar esa entrega) |
| Ingesta de evidencia web + identidades (B0/B1) | §5.17 — `html_evidence` + `identity_derivation` (2026-10-23) |
| Validación de identidad sin contraseña (B1) | §5.18 — `nexus.attack.ad_user_enum` |
| Ledger por camino (B2) | §5.19 — `VectorEntry` en `agent/coverage.py` |
| Reflexión auditable (B3) | §5.20 — `agent/reflection.py` + evento `react.reflection` |
| Suite tras B0/B1/B2 | **4 184 passed / 53 skipped** |
| Suite tras B3 | **4 195 passed / 53 skipped** |
| Techo del blackboard por clave (V0-2) | §5.21 — `kernel/blackboard.py` |
| Suite tras V0-2 | **4 199 passed / 53 skipped** |
| Auditoría de origen | `9a61785` — auditoría MCP/PTY |
| Rama | `feat/orchestration-phase-2-close` |
| Regla de esta entrega | **V11**: el PoC tiene que llegar al objetivo (form_params reales, next_steps y subida de temas) sin tocar `ToolGateway` |
| Suite de referencia (`430dcfb`) | **3 735 passed / 53 skipped** |
| Suite tras W1.2 + PTY P0 | **3 753 passed / 53 skipped** |
| Suite tras P1 | **3 767 passed / 53 skipped** |
| Suite tras P1.5 | **3 776 passed / 53 skipped** |
| Suite tras V10 | **3 801 passed / 53 skipped** |
| Suite tras V11 | **3 814 passed / 53 skipped** |
| Catálogo | **83 tools durables**, **22 parsers** nativos |

---

## 0. Cómo leer este documento

### 0.1 Estados

| Estado | Significado |
|---|---|
| **[HECHO]** | Implementado y cubierto por tests o por un contrato ejecutable en `430dcfb`. |
| **[PENDIENTE]** | Necesario, no implementado (o parcial), y no depende de una decisión externa. |
| **[BLOQUEADO]** | Necesario, pero condicionado a otra pieza o a una decisión del operador. |
| **[DESCARTADO]** | Evaluado y rechazado por gobernanza, coste o antipatrón. No se reintenta sin reabrir la decisión. |

### 0.2 Evidencia

Las notas citan `fichero:línea` cuando el estado se comprobó en código. Cuando la
clasificación procede de un documento y no se re-midió en esta pasada, se indica
expresamente `[DOC]`. La suite se re-ejecutó tras P1:
**3 814 passed / 53 skipped**. La línea base del commit auditado era
**3 735 passed / 53 skipped**; W1.2 + PTY P0 añadieron 18 tests, P1 otros 14,
P1.5 otros 9, V10 otros 25 (PoC preparado, CSRF en `web.request`, barrido
CSRF en `cred.bruteforce`, normalización de URL en `nikto` y los contratos de
prompt/catálogo/skills que los acompañan) y V11 otros 13 (form_params de
ASP.NET, `next_steps` por tipo de archivo, `compile_and_upload` y su aceptación
contra un panel WebForms local real).

### 0.3 Qué NO es este documento

- No es un plan de marketing ni una promesa de autonomía genérica.
- No reabre los ADR: `ADR-004` (sandbox), `ADR-005` (ledger de cobertura) y
  `ADR-006` (Caja Negra por defecto) siguen vigentes.
- No declara cerrado ningún gate que exija aceptación de campo. Un test de
  primitiva no sustituye una cadena revalidada.

### 0.4 Correspondencia con el formato solicitado

| Sección pedida | Dónde está |
|---|---|
| 1. Estado arquitectónico actual | §1, con el desglose por capas en §1.1–§1.5 y la línea base en §1.6 |
| 2. Matriz de estado de features | §3, dividida en P0 (§3.1), P1 (§3.2), P2 (§3.3), arquitectura (§3.4) y MCP (§3.5) |
| 3. El plan de vuelo | §5, con las fases P0–P4, la corrección W1.2 y los descartes |

El inventario de auditorías y planes que alimenta la matriz está en §2; el
veredicto razonado sobre MCP/PTY y el detalle de «code complete, not wired» están
en §4 y §1.7.

---

## 1. Estado arquitectónico actual

OMNI es un **cuerpo gobernado**: el modelo propone una acción; el `ToolGateway`
decide si puede ejecutarse; solo un verificador determinista puede convertir el
resultado en hecho. Esa frontera es el activo que no se puede romper.

```
modelo (JSON) ─► ReActCoordinator ─► execute_tool() ─► ToolGateway.invoke()
                                                         │
   1. OperatorMode (plan/exec/trust) ────────────────────┤
   2. JSON Schema Draft 2020-12 ─────────────────────────┤
   3. scope HMAC + target del scope ─────────────────────┤
   4. RoE (kill switch, ventana, rate, prohibidos) ──────┤
   5. PolicyEngine (riesgo → aprobación humana) ─────────┤
   6. approval.consume(id exacto) ───────────────────────┤
   7. hooks pre_tool_use ────────────────────────────────┤
   8. InvocationJournal.prepare/start (step_key, lease) ─┤
   9. handler (sandbox) → ToolResult ────────────────────┤
  10. derive_assertions() → persist_assertions() ────────┤
  11. ToolResultDTO + audit tool.complete + journal.finish┘
                                                         │
                    blackboard de hechos verificados ◄────┘
                                                         │
                    planner (7 fases) + ENGAGEMENT_PLAN ◄┘
```

Puntos exactos: `kernel/tool_gateway.py:245` (invoke), `:268` (modo), `:270`
(schema), `:274` (scope), `:306` (target), `:327` (RoE), `:343` (política),
`:380` (aprobación), `:460` (journal), `:555` (assertions), `:585`
(persistencia). `kernel/runtime.py:269` es la entrada que construye el gateway y
`:297` el catálogo que registra.

### 1.1 Ingesta

- **83 tools durables** en `tools/registry.py`, registradas por tenant y con
  `effect`, `scope_required`, `sandbox_required` y permisos explícitos.
- Ninguna tool se invoca fuera de `execute_tool` → `ToolGateway`; el bucle ReAct
  no tiene una segunda vía de ejecución.
- La ingesta externa (MCP) existe como código (`integrations/mcp/`, 964 líneas)
  pero **no está encendida** en el runtime (§4).
- Canales entrantes: `nexus.post.listener` (one-shot), `nexus.post.ntlm_capture`
  y `nexus.post.job` (background gobernado). Desde W1.2 el listener valida el peer
  **antes** de leer o enviar nada; un peer fuera de scope se cierra sin
  interacción (§3.1, V1-1).

### 1.2 Transformación

- **22 parsers nativos** en `tools/parsers/` con `PARSERS_VERSION`; la salida de
  una tool solo se promueve si el parser y el método de verificación coinciden.
- **Ingesta de evidencia web (B0/B1, §5.17)**: `kernel/html_evidence.py`
  convierte una respuesta HTML en emails, personas con rol, enlaces same-origin
  y tecnología; `kernel/identity_derivation.py` detecta la convención
  (`j.doe` + `Joanne Doe` ⇒ `initial.last`) y devuelve candidatos ordenados por
  confianza y prioridad del rol. `derive_assertions` promueve **solo** la
  dirección publicada (`email` y su parte local como `user`); lo derivado viaja
  como hipótesis en la observación (`extracted.identities`).
- `kernel/fact_verification.py:746` (`derive_assertions`) deriva `host`,
  `service`, `endpoint`, `access`, `credential`, `privilege`, `loot`, `session`
  y hechos de superficie a partir de la observación.
- `nexus.session.pty` **ya tiene branch** (`capture`/`wait`): una flag produce
  `loot`, la línea canónica `uid=0(root)` produce `privilege`, y sin ninguna de
  las dos la observación queda marcada `unverified_observation` (no se inventa un
  hecho negativo). `mcp.*` sigue sin branch hasta P3 (§5.2).
- La validación de entrada es JSON Schema completo (Draft 2020-12,
  `kernel/schema_validation.py`), no el subconjunto antiguo. `V1-10` está
  cerrado; la fila `P1-C` de `BACKLOG.md` está **obsoleta**.

### 1.3 Almacenamiento

| Sitio | Qué guarda | Límite actual |
|---|---|---|
| `kernel_knowledge_documents` + `Blackboard` | hechos tipados con procedencia y merge por `source_uri` | `FACT_ROWS_CEILING` antes del merge; puede truncar hechos distintos (§3.1, V0-2) |
| `kernel_audit` | cadena encadenada por hash | correcto; no sustituye evidencia de campo |
| `kernel_approvals` | aprobaciones durables de un solo uso | correcto |
| `kernel_invocations` | journal `prepared→running→succeeded/unknown`, step key, lease, `result_ref` | no promete exactly-once remoto |
| `kernel_artifacts` | CAS con SHA256; informes y salidas grandes | `nexus.post.job` aún no devuelve `artifact_ref` |
| `kernel_sessions` | sesiones durables (id, tipo, target, run, `opened_by_tool`, `closed_at`) | solo lo pueblan MSF y Sliver; no hay `transport`/`transport_ref` ni liveness |
| `kernel_budget_reservations`, `kernel_supervisor_roots` | cuota global durable del árbol de agentes | correcto para el árbol actual; no es cuota distribuida |

### 1.4 Orquestación

- `agent/planner.py`: 7 fases deterministas derivadas del blackboard; desde
  `0c92d5a` el **plan de engagement es obligatorio antes de atacar** y se escribe
  en `loot/ENGAGEMENT_PLAN.md` (`agent/engagement_plan.py`,
  `tools/handlers/plan_engagement.py`).
- `agent/react_coordinator.py`: bucle único; los perfiles son *hints* desde el
  loop v2, no intersecciones de tools (`NEXUS_LEGACY_PROFILES=1` restaura el
  comportamiento antiguo).
- `agent/supervisor.py`: auto-spawn opt-in por cambio de familia de fase, con
  raíz durable y ledger de reservas (`FASE2 P2-C`).
- **Selección multi-vector parcial**: el ledger ya da veredicto por *camino*
  (B2, §5.19) y el pivote ordena el siguiente cuando el actual está cerrado, pero
  el plan sigue eligiendo **una fase** y no compara vectores con coste/beneficio
  ni mantiene ramas en paralelo (V0-12 sigue abierta).
- **No hay bus tipado ni workers dinámicos**: los subagentes son un árbol
  supervisor, no un bus de eventos (WP5).

### 1.5 Gobernanza

- Scope HMAC firmado, RoE, política de riesgo, aprobaciones durables, hooks
  pre/post tool, journal con fencing y auditoría encadenada.
- `read_only` ya no permite acciones en Plan Mode: el contrato de efectos está
  cerrado (`test_effect_contract.py`) y el rechazo ocurre antes del handler. La
  cifra histórica 26 `read_only` / 38 activos (`09_PLAN_V1_EJECUCION.md`, W1.1)
  corresponde al catálogo de 64 tools, no al de 78.
- Redacción **por nombre** en la frontera de persistencia y redacción **por
  valor conocido** en los cuatro canales que reciben texto del objetivo: SSH,
  `nexus.web.request`, `nexus.post.shell_exec` y `nexus.session.pty` (V1-6).
  `secrets_for_redaction` combina argumentos secretos, handles `vault:` y los
  hechos `credential` **verificados** del engagement.
- `oci_network` **no existe**: el modo falla explícitamente
  (`kernel/sandbox_modes.py:150`). En `oci` no hay red; en `local_strict` no hay
  aislamiento de egress.

### 1.6 Línea base verificada

| Dato | Valor | Fuente |
|---|---|---|
| Tools durables | 79 | `tools/registry.py`; `docs/missions/audit-v1/catalog.json` |
| Parsers | 21 módulos | `tools/parsers/` |
| Tests | 3 801 passed / 53 skipped | suite completa tras V10 |
| Prompt estático | 28 665 chars; ~6 989 tok/turno | `test_prompt_optimization.py` |
| Sandbox por defecto | `local_strict` en dev; `oci` en producción | `kernel/sandbox_modes.py:148` |
| MCP | 964 líneas, 41 tests en `test_mcp_integration.py` | `integrations/mcp/` |
| PTY | 268 líneas de manager + 16 tests (lifecycle, guard, egress, redacción, artifact, assertions, reaper) | `kernel/pty_sessions.py`, `test_session_pty.py` |

### 1.7 «Code complete, not wired»

Estas piezas existen, están testeadas y **no están conectadas al camino real**.
Es el concepto más importante de este roadmap: no hay que reescribirlas, hay que
encendarlas sin abrir una puerta lateral al gateway.

| Pieza | Qué existe | Qué falta exactamente | Riesgo de encenderla mal |
|---|---|---|---|
| **MCP** (`integrations/mcp/`) | Cliente SDK con timeouts, entorno hijo sin secretos, allowlist, manifiesto de capacidades, bridge que registra tools durables y revalida la allowlist en cada llamada. 41 tests. | `sync_from_config` **solo se llama desde un test** (`test_mcp_integration.py:616`). Falta: llamada en bootstrap (`runtime.execute_tool` tras construir el catálogo, `runtime.py:297`), `/mcp list\|status\|reload`, doctor, bloque compacto en el prompt, branch de transporte en `assess_tool_catalog`, branch `mcp.*` en `derive_assertions` (fase P3), y excluir `mcp.` del chequeo AST de `test_catalog_ledger_consistency`. | Registrar MCP sin parser produce «capacidad sin evidencia»: tools que ejecutan y no escriben hechos. Registrar antes de decidir red choca con `oci`. |
| **PTY** (`kernel/pty_sessions.py` + `tools/handlers/session_pty.py`) | Driver tmux por run, acciones `start\|send\|capture\|wait\|kill`, scope, audit, límites de nombre/líneas. Tool registrada (`registry.py:361`). **P0 cerrado**: guard OCI, checks léxicos, artifact CAS, assertions, `wait`≤60 s y reaper. **P1 cerrado**: el listener keep-open y `shell_exec` reutilizan el mismo manager con `transport_ref` durable. | Un pane local no tiene target remoto que registrar: se lista por descubrimiento tmux, con `durable=false` (los canales con peer sí viven en `kernel_sessions`). | Convertir PTY en una puerta trasera de egress y una bomba de tokens (ya mitigado en P0). |
| **`sync_from_config`** | Descubre todos los servidores y registra solo tools allowlisted con `replace=False`. | Nadie lo invoca en producción; no es idempotente frente a un fallo de arranque porque no se llama. | Si se llama antes del catálogo, o sin `NEXUS_MCP_CONFIG`, puede romper el arranque o el conteo del ledger. |
| **Batch runner** (`kernel/batch.py`) | Concurrencia acotada, backpressure, cancelación y estados `completed/failed/cancelled`. | Cableado en `scripts/omni_tool.py`, **no** como tool del modelo. | Exponerlo sin cuota por target convertiría un barrido en una tormenta. |
| **Model router** (`kernel/model_router.py`) | Rutas por clasificación, presupuesto y fallback. | Solo lo usan tests (`test_kernel_offline.py`). | Enrutar sin telemetría de coste puede ocultar el gasto por turno. |
| **Transporte `webshell`** | **[HECHO]** (P1.5) `nexus.web.upload` registra la sesión tras probar `id` contra la URL indicada en `shell_url`; `nexus.web.wp_exec` la registra con `restore=false`. `shell_exec(transport="webshell")` resuelve el `transport_ref` (URL + método + parámetro) y `session.kill` cierra la fila. 9 tests en `test_webshell_session.py`. | Verificado contra un servidor HTTP local; falta el e2e contra un panel real que renombre o mueva el fichero subido. | Registrar sin probar ejecución convertiría un 200 del formulario en un falso acceso. |
| **`nexus.post.job`** | Lanza y consulta jobs gobernados. | `jobs.status` no devuelve `artifact_ref`/`journal_ref`; el resultado queda en el journal y no se puede leer desde el job. | Empuja al modelo a esperar en vez de usar el job como alternativa. |

---

## 2. Inventario de fuentes

### 2.1 Documentos que mandan

| Documento | Qué decide | Estado en este roadmap |
|---|---|---|
| `docs/missions/audit-v1/00_DICTAMEN.md` | 38,77/100 histórico, 10 bloqueadores, 12 P0 / 15 P1 / 7 P2 | Base de la deuda. Score **no recalculado**; no se usa como gate. |
| `docs/missions/audit-v1/06_BRECHA_A_100.md` | 43 brechas V0 + 16 V1 con prioridad y esfuerzo | Filas de §3. |
| `docs/missions/audit-v1/07_PLAN_MEJORA_V1.md` | Arquitectura por capas y olas F0–F5 | Absorbido por §1 y §5. |
| `docs/missions/audit-v1/09_PLAN_V1_EJECUCION.md` | Secuencia W0–W4 y estado de cierre | W0 y W1.1 cerradas; W1 resto pendiente. |
| `docs/missions/audit-v1/10_VERIFICACION_CIERRE_V1.md` | Qué sigue abierto y correcciones al acta | Fuente de V1-1/V1-2/V1-4/V1-10 y de la advertencia «cierre administrativo ≠ gate técnico». |
| `docs/missions/PLAN_OMNIAGENTCS_V4.md` | Gaps G1–G9, fases V4.0–V4.6, UX/TUI | §3.4; varias fases ya entregadas. |
| `docs/missions/PLAN_ESCALADA_OMNI.md` | WP0–WP10, «lo que NO hacer», definición de nivel FreeBuff | §3.4 y §5.5. |
| `docs/missions/FASE2_ORQUESTACION_AVANZADA.md` | Hooks, StopVerifier, Supervisor, Journal | Cerrada con límites declarados; §3.4. |
| `docs/missions/AUDITORIA_ARQUITECTONICA_MCP_PTY_2026-10-21.md` | Veredicto y orden P0–P4 de MCP/PTY | §4 y §5. |
| `BACKLOG.md` | Ledger de deuda P1-A/B/C, UX y tipado | Fuente, con una fila obsoleta (P1-C). |
| `docs/adr/ADR-004/005/006` | Sandbox, ledger de cobertura, Caja Negra | Invariantes; no se reabren. |

### 2.2 Documentos de apoyo (no mandan)

- `docs/missions/diag/*_2026-10-15.md`, `diag_rerun*`, `blackbox_freebuff_vs_omni_2026-10-19.md`,
  `vulnversity_freebuff_vs_omni_2026-10-19.md`: mediciones de runs. Se citan como
  evidencia, no como plan.
- `docs/missions/ANALISIS_OMNI_VS_FREEBUFF.md`, `MANUAL_VS_AGENT.md`: diagnóstico
  n=1; orientan prioridades, no aceptación.
- `docs/missions/PLAN_ESCALADA_OMNI.md` §7: fuente de los **[DESCARTADO]**.
- `qa_runs/`: campaña QA; sus bugs ya están absorbidos por fases posteriores.

### 2.3 Fuera del ledger

- `roadmap_12/`: **WIP no versionado**; no se cita como verdad.
- `docs/missions/BACKLOG.md`, `PLAN_MAESTRO_BAJIOWARE.md`,
  `docs/missions/platform/**`: linaje NEXUS/BAJIOWARE. Solo consulta.
- `docs/archive/**`: superado.

---

## 3. Matriz de estado de features

### 3.1 P0 — bloqueadores de V2

| Feature / Fix | Origen | Estado | Notas / bloqueadores |
|---|---|---|---|
| Plan-First: TODOs obligatorios antes de atacar y al cerrar | `0c92d5a`, `AUD_MCP_PTY` | **[HECHO]** | `agent/engagement_plan.py` + `plan_engagement.py`; 860 líneas de tests. El plan vive en `loot/ENGAGEMENT_PLAN.md` y lo comparten los subagentes. |
| Hydra web + `session_ref` + reutilización de credencial | `5fdf86a`, BACKLOG | **[HECHO]** | `cred_bruteforce` devuelve `session_ref`; `http_request` lo consume como handle `vault:<hex>`; `ssh_post` reutiliza la credencial validada; `crack_hash` cubre el análisis offline. |
| Efectos `read_only` en Plan Mode | `V1-3` | **[HECHO]** | Contratos de efecto + rechazo previo al handler; `test_effect_contract.py`. |
| Redirect HTTP sin revalidar destino | `V1-4` | **[HECHO]** | `http_request.py:79` solo sigue redirects **same-origin**; un cambio de host no se persigue. |
| JSON Schema completo en el gateway | `V1-10` | **[HECHO]** | `schema_validation.py` delega en `jsonschema` Draft 2020-12; 7 tests, incluido «todo keyword declarado se aplica». La fila P1-C de `BACKLOG.md` es obsoleta. |
| Resultados negativos no se convierten en `ProviderFailure` | `V0-22` | **[HECHO]** | `tool_gateway.py:518` conserva `negative`/`denied`/`unsupported`; `unavailable` solo cuando el backend no respondió. |
| Batch con presupuesto de CPU/concurrencia | `V0-9` | **[HECHO]** | `kernel/batch.py` (4 global / 1 por target, backpressure, cancelación) y CLI `scripts/omni_tool.py`. No es tool del modelo; ver §5.5. |
| Listener valida el peer antes de interactuar | `V1-1` | **[HECHO]** | W1.2: el subproceso recibe los CIDR/exclusiones ya autenticados y cierra al peer fuera de scope antes del primer `recv`/`sendall` (`listener.py`). Test end-to-end: un peer conecta y recibe **0 bytes**. El handler repite la validación con el scope firmado como defensa en profundidad. |
| Secretos opacos en la redacción | `V1-6` | **[HECHO]** | W1.2: `secrets_for_redaction` reúne argumentos secretos, handles `vault:` y hechos `credential` verificados; `redact_result` se aplica en PTY, `http_request` y `shell_exec` (SSH ya lo tenía). Tests con un secreto real del vault en los tres canales. Límite: solo valores conocidos, no un detector genérico. |
| SARIF en `format=both` | `V0-5` | **[PENDIENTE]** | `report_generate.py:212`: SARIF solo se escribe con `format="sarif"`. `both` produce JSON+MD+HTML y omite el SARIF ya calculado. |
| Egress aislado con red gobernada | `V1-2`, `P1-B` | **[BLOQUEADO]** | `sandbox_modes.py:150` lanza `SandboxModeNotImplemented` para `oci_network`. Depende de implementar/filtrar egress por scope (5–8 días) o de un broker de red. |
| Pivote con sesión y transferencia durable | `V0-20` | **[PENDIENTE]** | Hay `pivot_http`, `pivot_bruteforce`, `ssh_upload`, pero no un objeto de transferencia/sesión que sobreviva al turno ni un `session_ref` de pivote. |
| Cancelación remota reconciliada | `V0-28` | **[PENDIENTE]** | No hay camino de cancelación de una invocación en vuelo en el gateway; el journal marca `unknown` y exige aprobación de retry, que es contención, no cancelación. |
| Webshell y escalada gobernados | `V0-3` | **[PENDIENTE]** | `web.upload` y `wp_exec` existen; la escalada sigue siendo payload del operador y no hay cadena acreditada de webshell→sesión→privesc. |
| C2 autónomo acreditado | `V1-5` | **[PENDIENTE]** | Sliver está entregado (generate/deploy/loot), pero no hay cadena autónoma medida en un lab multi-host. |
| Blackboard sin duplicados ni capturas sin acreditar | `V0-2` | **[HECHO]** | §5.21: la ventana se aplica a **claves**, no a filas (una clave reescrita ya no desaloja a sus vecinos); `limit` cuenta claves, y una clave con más de 20 versiones se relee entera para que el «verified wins» de V1-33 siga valiendo. `summary`, `verified_fact` y `_blackboard_facts` piden el techo en vez del page de 100. La acreditación de capturas Windows es V0-13 y sigue parcial en `RUN_sala09`. |
| Planificador con selección multi-vector | `V0-12` | **[PENDIENTE]** | El planner elige una fase; no compara vectores alternativos con coste/beneficio ni mantiene ramas paralelas. |

### 3.2 P1 — deuda de producto

| Feature / Fix | Origen | Estado | Notas / bloqueadores |
|---|---|---|---|
| NetExec con salida/exit normalizados | `V0-16` | **[HECHO]** | `handlers/netexec.py` usa `parsers/netexec.py` y devuelve estructura estable. |
| Dump git sin depender del index del operador | `V0-6` | **[HECHO]** | `handlers/git_dump.py` con script propio; `test_post_audit_backlog.py` importa `GIT_SCRIPT`. |
| DAST/OOB para clases web de sala04 | `V0-10` | **[PENDIENTE]** | Nuclei/dalfox corren sin callbacks OAST por diseño; falta un canal OOB gobernado y aceptación. |
| Catálogo de explotación y cuarentena | `V0-15` | **[PENDIENTE]** | `searchsploit` existe; no hay cuarentena/acreditación de exploits. |
| Consulta de modelo local en el objetivo | `V0-25` | **[PENDIENTE]** | Sigue resolviéndose con `ssh_exec` + script ad-hoc; no hay tool gobernada. |
| Reporte crece con ids, no con hallazgos | `V0-32` | **[PENDIENTE]** | El render imprime todos los `run_id` del engagement; falta agrupar por hallazgo. |
| XMPP sin BOSH | `V0-35` | **[PENDIENTE]** | No hay handler XMPP en el catálogo. |
| Vhosts/Host uniformes en recon | `V0-7` | **[PENDIENTE]** | `ffuf` acepta `Host` estático y subdominios; `gobuster` modo vhost sigue devolviendo 0. |
| Tres salas sin reporte durable | `V1-7` | **[PENDIENTE]** | Faltan reportes de salas 04/10/11; es evidencia, no código. |
| Gates de lint/canary | `V0-29` | **[HECHO]** | Ruff y `make lint` verdes; test de canary con control negativo. |
| Ledger inventario/deuda coherente | `V1-8` | **[HECHO]** | 5 tests; 64 ids AST/runtime/CLI/JSON coincidentes; huecos V0-8/V0-23 declarados. |
| Mypy y runner | `V1-9` | **[HECHO]** | `make typecheck` verde en el alcance declarado; deuda TUI aparte. |
| Análisis de credenciales offline en catálogo | `V1-11` | **[HECHO]** | `nexus.post.crack_hash` (commit `5fdf86a`). |

### 3.3 P2 — residual

| Feature / Fix | Origen | Estado | Notas / bloqueadores |
|---|---|---|---|
| Wordlist dirbuster de Kali | `V0-1` | **[PENDIENTE]** | `DEFAULT_SYSTEM_WORDLIST_DIRS` no incluye la ruta estándar; hay que resolver el symlink sin escapar del root. `[DOC]` |
| SMB sin borrado autorizado y detección completa | `V0-14` | **[PENDIENTE]** | `[DOC]` |
| Pwn solo ELF64 / ret2libc estrecho | `V0-17` | **[PENDIENTE]** | `[DOC]` |
| Scope del cebo incompleto | `V0-37` | **[PENDIENTE]** | `[DOC]` |
| Installer MSF parcial | `V0-4` | **[PENDIENTE]** | `[DOC]` |
| HIDS del evaluador no correlacionado | `V0-42` | **[PENDIENTE]** | `[DOC]` |

### 3.4 Arquitectura, orquestación y producto

| Feature / Fix | Origen | Estado | Notas / bloqueadores |
|---|---|---|---|
| Sandbox `local_strict` con confinamiento de workspace | `ESCALADA WP1`, ADR-004 | **[HECHO]** | `kernel/sandbox.py`; no aísla host/red. |
| `nexus.shell.exec` gobernado | `ESCALADA WP1` | **[HECHO]** | Registered at `registry.py:360`; resumen + artifact; tests. |
| PTY base (tmux) | `ESCALADA WP1` | **[HECHO]** | `PtySessionManager` + tool; 16 tests (lifecycle real, guard, egress, redacción, artifact, assertions, reaper). |
| PTY gobernado (P0) | `AUD_MCP_PTY §5.2` | **[HECHO]** | Guard OCI, checks léxicos en `start`/`send`, artifact CAS + resumen, branch en `derive_assertions`, `wait`≤60 s y reaper en `session_end`. §5.1. |
| `session_ref` + reverse shell (P1) | `AUD_MCP_PTY §3.2` | **[HECHO]** | `kernel_sessions.transport/transport_ref/liveness`; `nexus.session.list` unificado; `shell_exec` `pty`/`raw`; listener keep-open con peer validado en el proceso que acepta y `session_ref`; `session.kill` cierra tmux y `closed_at`. 14 tests en `test_session_ref_p1.py`. §5.2. |
| Productor de sesiones `webshell` | `AUD_MCP_PTY §3.2` | **[HECHO]** | `web_upload` (con `shell_url`) prueba `id` y registra la sesión; `wp_exec` la registra con `restore=false`; `transport_ref` guarda URL+método+parámetro. 9 tests en `test_webshell_session.py`. §5.2. |
| Loop v2: un perfil, planner como hint | `ESCALADA WP2` | **[HECHO]** | `NEXUS_LEGACY_PROFILES` para volver atrás; `test_wp2_loop_v2.py`. |
| Prompt de 3 capas | `ESCALADA WP3` | **[PENDIENTE]** | Medido 28 665 chars estáticos / ~6 989 tok por turno; el objetivo ≤5 000 no se cumple. |
| Skills con divulgación progresiva | `ESCALADA WP4` | **[HECHO]** | `nexus.skill.list\|load`, `.agents/skills/`; tests. |
| Bus tipado + workers dinámicos | `ESCALADA WP5` | **[PENDIENTE]** | No hay módulo de bus; el supervisor es un árbol, no un bus. |
| Model routing por coste/clasificación | `ESCALADA WP9` | **[PENDIENTE]** | `kernel/model_router.py` existe pero solo lo usan tests. |
| Hooks de ciclo de vida | `FASE2 P2-A` | **[HECHO]** | Confianza fuera del repo, `session_end` garantizado; límites OCI declarados. |
| StopVerifier | `FASE2 P2-B` | **[HECHO]** | Fail-closed; objeción inyectada y auditada. |
| AgentSupervisor + cuota durable + auto-spawn | `FASE2 P2-C` | **[HECHO]** | Opt-in; raíz durable y reserva antes del proveedor. |
| Journal con step key, fencing y resume | `FASE2 P2-D` | **[HECHO]** | No exactly-once remoto; PostgreSQL probado en cluster efímero. |
| TUI: alt-screen, tarjetas, modal, streaming | `PLAN_V4 §4` | **[HECHO]** | Ver §10 del PLAN_V4. |
| Markdown anidado completo | `PLAN_V4 §4.4` | **[PENDIENTE]** | Listas anidadas pendientes. |
| Backpressure del transcript | `BACKLOG P1-UX-6` | **[PENDIENTE]** | 10 000 segmentos retenidos (~26,6 MB de pico medido). |
| Distribución `pyproject` / `pipx` | `PLAN_V4 §3.6` | **[HECHO]** | `pyproject.toml` presente; falta repetir la aceptación `pipx install` desde cero en Kali. |
| Caja Negra por defecto | `430dcfb`, ADR-006 | **[HECHO]** | RoE es la única restricción de técnica; sin esperas pasivas. |

### 3.5 MCP

| Feature / Fix | Origen | Estado | Notas / bloqueadores |
|---|---|---|---|
| Cliente MCP con timeouts y entorno hijo sin secretos | `AUD_MCP_PTY §2` | **[HECHO]** | `integrations/mcp/client.py`; allowlist de entorno y marcadores de secreto. |
| Registro/allowlist y manifiesto de capacidades | `AUD_MCP_PTY §2.4` | **[HECHO]** | `registry.py`; `capability()` exige effects/scope/sandbox coherentes. |
| Bridge que hereda el `ToolGateway` | `AUD_MCP_PTY §2.2` | **[HECHO]** | `gateway_bridge.py`: `replace=False`, re-chequeo de allowlist, descripción no confiable, timeouts auditados. |
| Wiring P2 (sync en bootstrap + CLI/doctor/prompt) | `AUD_MCP_PTY §5.2` | **[BLOQUEADO]** | `sync_from_config` solo lo llama un test. Depende de decisión de despliegue y del contrato de catálogo. |
| Evidencia tipada P3 (parser + assertions) | `AUD_MCP_PTY §5.2` | **[BLOQUEADO]** | Sin parser declarado, `mcp_unverified` es el estado correcto; no se permite que un servidor declare hechos. |
| MCP de red P4 (masscan/rustscan) | `AUD_MCP_PTY §5.2` | **[BLOQUEADO]** | Requiere `oci_network` o broker de red gobernado. No empezar antes. |

### 3.6 Evidencia, identidad y cobertura por camino (B0–B3)

Nacen del run de HackPark en el que el correo `j.doe@services.local` y el equipo
(`Jack Rock - IT Staff`) estaban en páginas que el motor descargó y no leyó. No
son una fase nueva: son la capa entre la observación y la acción.

| Feature / Fix | Origen | Estado | Notas / bloqueadores |
|---|---|---|---|
| Ingesta de evidencia HTML (B0) | Medido HackPark | **[HECHO]** | `kernel/html_evidence.py`: emails, personas con rol, enlaces, tecnología, corte a 200 KB. El handler `nexus.web.request` publica `extracted` y `next_steps` con las rutas sin visitar (`/about.html` deja de depender de que el modelo lo note). |
| Derivación de identidades (B1) | Medido HackPark | **[HECHO]** | `kernel/identity_derivation.py`: convención confirmada por una dirección publicada, candidatos con `confidence` (1.0 observada / 0.9 nombre+correo / 0.6 convención / 0.3 conjetura), `priority_targets` por rol. Sin dominio no se inventa ninguna cuenta. |
| Validación barata antes de la contraseña (B1) | Medido HackPark | **[HECHO]** | `nexus.attack.ad_user_enum` (§5.18): kerbrute si está (veredicto por cuenta, `attribution=full`) o `GetNPUsers -no-pass` si no (`partial`: prueba las que nombra y deja el resto `unknown`). No envía contraseña, así que no mueve el contador de bloqueo (`lockout_risk: none`). Los hashes AS-REP van al vault y `crack_hash` gana `krb5asrep`/`krb5tgs`. |
| Ledger por camino `servicio × técnica` (B2) | Requisito de la v1 | **[HECHO]** | `VectorEntry` en `agent/coverage.py` (§5.19): cada `vulnerability` que nombra una ruta (CVE/id/path) es un ítem con su veredicto; un `barrier` que nombra la ruta cierra **solo** ese camino y el servicio sigue abierto mientras queden pendientes. El pivote ordena el siguiente camino en vez de abandonar el servicio. |
| Reflexión auditable por turno (B3) | Requisito de la v1 | **[HECHO]** | `agent/reflection.py` (§5.20): tras 3 turnos sin hechos nuevos el prompt nombra los hechos **verificados y accionables** cuyo valor no aparece en ningún argumento de la ronda, y el evento `react.reflection` guarda el texto. No decide ni autoriza: el modelo elige y el gateway gobierna. |

---

## 4. Veredicto MCP y PTY

### 4.1 Veredicto

1. **PTY: sí, ahora, pero como gobernanza y evidencia.** No es una feature nueva:
   es cerrar un canal que ya existe y hoy puede saltarse egress, inundar el
   prompt y morir en OCI sin explicación.
2. **MCP: no todavía.** Encenderlo antes de resolver parser y red produce
   capacidad sin evidencia; encenderlo en `oci` produce tools que no pueden
   alcanzar la red que necesitan.
3. **La decisión de despliegue manda.** Si OMNI corre en `oci` (producción), PTY
   persistente y MCP-stdio con red no pueden funcionar sin un broker externo. Si
   corre en `local_strict` (lab), sí, pero sin aislamiento de host/red.

### 4.2 Por qué MCP no rompe el gateway (y qué falta para conectarlo)

El bridge ya hace lo correcto: registra la tool con `replace=False` y su handler
solo se alcanza por `execute_tool → ToolGateway`. No hay `call_tool` fuera del
handler. Para encenderlo sin romper nada:

1.   Llamar `await sync_from_config(registry)` **después** de construir el catálogo
   first-party (`runtime.py:297`) y **antes** de renderizar el prompt.
2. Hacerlo **no fatal**: sin `NEXUS_MCP_CONFIG` no hay servidores, no hay error, y
   el catálogo queda en 78.
3. Ser **idempotente**: `sync_registry` ya desregistra los `mcp.*` anteriores.
4. Excluir `mcp.` del chequeo AST de `test_catalog_ledger_consistency` o marcar
   esos ids como externos; su contrato lo valida el manifiesto, no el AST.
5. Añadir branch de transporte en `assess_tool_catalog` para que no caiga en
   `unassessed`.
6. Añadir branch `mcp.*` en `derive_assertions` **solo** en P3 y solo con un
   parser del enum cerrado; hasta entonces, `mcp_unverified` es explícito.
7. Aislar los tests con `NEXUS_MCP_CONFIG` vacío para no alterar el conteo de
   tools activas.

### 4.3 Por qué PTY no rompe el gateway

`nexus.session.pty` ya es una tool durable con `effect=execution`, scope y audit.
El trabajo P0 fue **endurecer su handler**, no crear una vía nueva; ya está
implementado:

- Detecta `OCISandbox` y devuelve `outcome="unavailable"` con
  `pty_requires_persistent_sandbox`.
- `start`/`send` pasan por los mismos checks léxicos de `shell_exec_local`
  (`passive_wait_reason`, deny list, `fetch_targets`).
- Devuelve resumen + artifact CAS (sha256 y `artifact_ref`) en vez de 64 KiB.
- `derive_assertions` deriva `loot`/`privilege` de `capture`/`wait`; sin
  evidencia, la observación se marca `unverified_observation` (no se inventa un
  hecho negativo).
- TTL de 1 h, reaper en `session_end`, `wait` ≤60 s y `pattern` obligatorio.

Nada de eso toca el orden del gateway ni el contrato de `ToolResult`.

### 4.4 Lo que cerró P1 (`session_ref`)

`kernel_sessions` era un UUID durable poblado solo por `msf_exploit` y
`sliver_sessions`. P1 añadió:

- columnas `transport`, `transport_ref`, `liveness` (migración aditiva SQLite y
  PostgreSQL, con `msf` como valor por defecto de las filas históricas);
- `nexus.session.list` unificado: MSF en vivo (sigue fallando cerrado si el
  daemon configurado no responde), filas durables de cualquier transporte y
  panes tmux del run; todas con `session_ref`;
- `nexus.post.shell_exec` con transport `pty`/`raw`, que resuelve el
  `transport_ref` de la fila, exige que pertenezca al prefijo del run y aplica
  los checks léxicos de PTY antes de enviar;
- `listener` en modo `keep_open`: el peer se valida **en el proceso que acepta**
  antes del primer byte, la fila nace `pending` y solo se enlaza al peer tras
  pasar el scope firmado; el agente recibe el `session_ref` en la misma llamada;
- `nexus.session.kill` cierra el pane tmux, pide el cierre a MSF/Sliver y marca
  `closed_at` (un listener sin peer también se puede cerrar).

P1.5 cerró el productor de `webshell`: `nexus.web.upload` lo registra cuando el
llamante aporta `shell_url` y la prueba `id` devuelve salida real; `wp_exec` lo
registra solo con `restore=false` (con el fichero restaurado la URL deja de
ejecutar). El e2e de campo con una reverse shell real sigue sin ejecutarse: el
bridge se prueba con un socket local y un pane tmux real por separado, y el
webshell contra un servidor HTTP local.

---

## 5. El plan de vuelo

### 5.1 Fase P0 — PTY gobernado (1–2 días) — **EJECUTADA**

| Paso | Cambio | Ficheros | Test de aceptación |
|---|---|---|---|
| P0.1 | Guard de sandbox: detectar `OCISandbox`, devolver `unavailable` + `pty_requires_persistent_sandbox` | `tools/handlers/session_pty.py` | `test_oci_sandbox_fails_explicitly_before_tmux` |
| P0.2 | Checks léxicos en `start`/`send`: `passive_wait_reason`, deny list y `fetch_targets` | `handlers/session_pty.py`, reutilizar `shell_exec_local` | `test_send_refuses_wait_denylist_and_out_of_scope_fetch`, `test_start_refuses_an_out_of_scope_fetch_too` |
| P0.3 | Captura resumida + artifact CAS con sha256; no 64 KiB al prompt | `handlers/session_pty.py`, `kernel/artifacts.py` | `test_capture_returns_artifact_and_a_bounded_summary` |
| P0.4 | `derive_assertions` branch `nexus.session.pty` para `capture`/`wait`; `unverified_observation` sin evidencia | `kernel/fact_verification.py` | `test_capture_assertions_derive_loot_and_privilege`; `test_capture_without_a_flag_or_root_derives_no_fact`; `test_capture_without_evidence_is_an_unverified_observation` |
| P0.5 | TTL/reaper en `session_end`; `wait` ≤60 s y `pattern` obligatorio | `kernel/pty_sessions.py`, `agent/react.py` | `test_reaper_closes_every_session_of_the_run`, `test_loop_reaps_pty_sessions_before_session_end`, `test_wait_longer_than_sixty_seconds_is_rejected_by_the_contract` |
| P0.6 | Redacción V1-6 en PTY (`capture`) y artifact | `kernel/redaction.py`, `handlers/session_pty.py` | `test_capture_redacts_a_secret_known_to_the_vault` |

**Gate P0:** cumplido en la suite afectada (16 tests PTY + 3 de redacción); el
e2e con tmux real cubre `send`/`wait`/`capture` y el reaper. La suite completa se
ejecuta antes del commit.

### 5.2 Fase P1 — `session_ref` y reverse shell (2–4 días) — **EJECUTADA**

| Paso | Cambio | Ficheros | Test de aceptación |
|---|---|---|---|
| P1.1 | Migración aditiva `transport`/`transport_ref`/`liveness`; registro inmutable del handle | `kernel/control_store.py`, `kernel/postgres_store.py`, `kernel/sessions.py` | `test_migration_adds_transport_columns_and_round_trips` |
| P1.2 | `nexus.session.list` unificado (durable + MSF vivo + panes tmux) con `session_ref` | `handlers/msf_session_list.py`, `kernel/pty_sessions.py` | `test_session_list_returns_a_durable_pty_session_ref` |
| P1.3 | `shell_exec` `pty`/`raw`: resuelve `transport_ref`, valida prefijo del run, checks léxicos, captura delta | `handlers/shell_exec.py`, `handlers/session_pty.py` | `test_shell_exec_pty_runs_a_command_in_the_registered_session`, `test_shell_exec_pty_refuses_denied_and_out_of_scope_commands` |
| P1.4 | `listener` keep-open: bridge tmux, peer-first, fila `pending` → bind al peer, `session_ref` inmediato | `handlers/listener.py` | `test_listener_keep_open_registers_a_pending_session_and_binds_its_peer`, `test_keep_open_bridge_pumps_the_socket_and_the_pane` |
| P1.5 | `session.kill` cierra tmux y `closed_at`; rama Sliver y webshell | `handlers/msf_session_kill.py` | `test_session_kill_closes_the_row_and_the_tmux_pane` |
| P1.6 | Hechos `access`/`privilege`/`loot` desde `session_pty_command`/`session_raw_command` | `kernel/fact_verification.py` | `test_shell_exec_channel_assertions_promote_access_privilege_and_loot` |

**Gate P1:** cumplido en la suite afectada (14 tests nuevos). El bridge real
mueve bytes en ambos sentidos y un peer fuera de scope no llega a enlazarse. El
e2e con una reverse shell de campo (socat/nc contra una víctima) **no** se
ejecutó; queda como aceptación pendiente.

**Productor `webshell` (P1.5, misma entrega):**

| Paso | Cambio | Ficheros | Test de aceptación |
|---|---|---|---|
| W.1 | `web_upload` prueba `id` contra `shell_url` y solo entonces registra la sesión | `handlers/web_upload.py`, `kernel/sessions.py` | `test_upload_probes_the_webshell_and_returns_a_session_ref`, `test_upload_probe_without_command_output_creates_no_session` |
| W.2 | `wp_exec` registra la sesión únicamente si el implante persiste (`restore=false`) | `handlers/wp.py` | `test_wp_exec_registers_a_durable_webshell_when_the_implant_persists`, `test_wp_exec_restoring_the_file_creates_no_session` |
| W.3 | `shell_exec(transport="webshell")` resuelve URL/método/parámetro del `transport_ref` | `handlers/shell_exec.py`, `kernel/sessions.py` | `test_shell_exec_webshell_posts_the_command_to_the_registered_url`, `test_shell_exec_webshell_refuses_a_different_url` |
| W.4 | Hechos `access`/`privilege`/`loot` desde `session_webshell_command` | `kernel/fact_verification.py` | `test_shell_exec_webshell_assertions_promote_access_privilege_and_loot` |
| W.5 | `session.kill` cierra la fila webshell | `handlers/msf_session_kill.py` | `test_session_kill_closes_a_webshell_row` |

**Gate W:** cumplido con un servidor HTTP local real (upload multipart, POST y
GET de comandos). Queda pendiente el panel real que renombre/mueva el fichero:
en ese caso la URL de `shell_url` debe ser la final.

### 5.3 Fase P2 — MCP de lectura cableado (3–5 días, tras decisión de red)

1. `sync_from_config` en bootstrap (idempotente, no fatal, off sin config).
2. `/mcp list|status|reload` + doctor + métrica de uso + auditoría de sync.
3. Branch de transporte en `assess_tool_catalog`; ajustar el ledger AST.
4. Bloque compacto de MCP en el prompt (máx. 10 ids; catálogo bajo demanda).
5. Solo servidores `effects=["read"]`, sin red, `scope_required=false`; probar
   con un servidor eco local.

**Gate P2:** `mcp.*` visible en catálogo, el gateway aplica aprobación/auditoría,
`mcp_unverified` explícito y cero regresiones de conteo.

### 5.4 Fase P3 — MCP con evidencia tipada (1 semana)

1. `parser` en el manifiesto (enum cerrado).
2. Branch `mcp.*` en `derive_assertions`.
3. Tests negativos: un servidor **no** puede escribir `privilege`/`loot`; sin
   parser no hay assertions; el `invocation_id` es el del gateway.

**Gate P3:** una tool MCP de lectura produce un hecho tipado con procedencia y
otra sin parser queda `mcp_unverified`; ninguna puede fabricar privilegio.

### 5.5 Fase P4 — MCP de red (bloqueada)

No empezar hasta que exista `oci_network` (egress filtrado por scope) o un broker
de red gobernado. Hoy `oci_network` lanza `SandboxModeNotImplemented`; en `oci`
puro no hay red; en `local_strict` un servidor puede salirse del scope.

### 5.6 Correcciones inmediatas fuera de fase (W1.2) — **EJECUTADA**

1. **V1-1 — listener peer-first.** El subproceso recibe CIDR/exclusiones ya
   autenticados y cierra al peer fuera de scope antes del primer `recv`/`sendall`.
   Test end-to-end: el peer conecta y recibe 0 bytes.
2. **V1-6 — redacción por valor en todos los canales.** `secrets_for_redaction`
   combina argumentos secretos, handles del vault y hechos `credential`
   verificados; `redact_result` se aplica en PTY, `http_request` y
   `nexus.post.shell_exec` (SSH ya lo tenía).

Orden ejecutado: W1.2 → PTY P0 → P1 (`session_ref`). Siguiente decisión: P2 (MCP
cableado), condicionada a la decisión de red.

### 5.7 Lo que NO se hará (y por qué)

| Idea | Veredicto | Razón |
|---|---|---|
| Añadir tools para cubrir técnicas | **[DESCARTADO]** hasta cerrar 4/6 salas | 31/68 tools ya no las usa nadie; el problema es selección/ejecución. |
| RAG de writeups de THM | **[DESCARTADO]** | Sobreajuste, leakage y se rompe al cambiar de sala. |
| Consultar MITRE ATT&CK en vivo | **[DESCARTADO]** | Convierte cada decisión en una llamada lenta y cara; las técnicas se codifican como hints deterministas con el ID como metadato, no como consulta. |
| Paralelismo multi-agente en la v1 | **[DESCARTADO]** para v1 | El supervisor es un árbol secuencial (profundidad 2, 4 hijos); prometer un enjambre antes del ledger por camino multiplica el coste y diluye la procedencia. |
| Vector DB para todo | **[DESCARTADO]** | FTS5 + ripgrep cubren journal y artefactos; embeddings solo >10k docs. |
| Más subagentes por fase | **[DESCARTADO]** | Es la causa de `rerun6`/`rerun13`; workers solo para fan-out. |
| Planificador más listo | **[DESCARTADO]** | El planner determinista es el cuello; se convierte en `plan_hint`. |
| Subir el presupuesto de tokens | **[DESCARTADO]** | `rerun13` murió con el trabajo hecho; el problema es el techo, no el tamaño. |
| Cambiar de modelo primero | **[DESCARTADO]** | El corpus no atribuye los fallos al modelo; agotar loop/prompt antes. |
| «Que funcione siempre» | **[DESCARTADO]** | No existe; la fiabilidad es reintento barato y evidencia. |
| Que un servidor MCP declare hechos | **[DESCARTADO]** | Rompe la procedencia: el verificador es nuestro, no del servidor. |
| HTTP MCP con `sandbox_required=true` | **[DESCARTADO]** | El sandbox local no puede aislar un proceso remoto; el manifiesto lo rechaza. |
| Proxy como equivalente a egress aislado | **[DESCARTADO]** | Un binario que ignore el proxy se salta el alcance; no es aislamiento. |
| Exactly-once remoto | **[DESCARTADO]** como promesa | El journal evita replay y fencing; no es una garantía distribuida. |
| Auto-aprobación del retry | **[DESCARTADO]** | Viola la regla de que una aprobación la concede un humano. |

### 5.8 Higiene del ledger

- Corregir `BACKLOG.md` P1-C: el schema completo ya está implementado; la fila
  debe cerrarse o reescribirse como «regresión de dialectos».
- Anotar V0-2 con el residual exacto: `LIMIT` antes del merge.
- Añadir a `BACKLOG.md` los tres «code complete, not wired» que no figuran:
  `sync_from_config`, `model_router`, `jobs.status` sin `artifact_ref`.
- No abrir una fase nueva por cada P1: el orden es P0 → P1 → P2/P3.

### 5.9 Run V10 contra HackPark — los dos muros, cerrados (2026-10-21) — **EJECUTADA**

Run `run_93546320c2bb47a780e4a2c6e4916584` (traza en
`/tmp/hackpark-run-v10.ndjson`, 122 eventos). El motor de gobernanza y el
Plan-First funcionaron: el run identificó `Microsoft-IIS 8.5` + `BlogEngine.NET
3.3.6.0`, registró el `web_app`, encontró el login y el panel, y cerró la rama
con `barrier` en vez de repetir sin fin. Los dos muros fueron de **capacidad**:

| Muro medido | Por qué bloqueaba | Fix implementado | Test de aceptación |
|---|---|---|---|
| Login ASP.NET con `__VIEWSTATE`/`__EVENTVALIDATION` | Hydra no puede refrescar tokens; cada POST se rechaza antes de probar la contraseña y el barrido termina `negative` sin haber probado nada | `csrf_mode` en `cred.bruteforce`: GET por intento, extracción de `<input type=hidden>`, cookie de sesión y barrido nativo; **auto-detección** si la página declara tokens | `test_csrf_mode_sweeps_a_real_aspnet_form`, `test_a_token_protected_form_switches_to_the_csrf_sweep_by_itself` |
| `CVE-2019-6714` identificado, PoC nunca obtenido | `searchsploit` dice *si existe*; no copia, no lee y no prepara el exploit | `nexus.exploit.find_and_prepare`: busca, copia a `loot/exploits/`, devuelve ruta + sha256 + código y candidatos ordenados | `test_cve_search_copies_the_poc_and_returns_its_code` |
| Petición manual a un formulario con tokens | El cliente HTTP sólo enviaba el `data` del modelo | `csrf_mode` + `csrf_form_url` en `nexus.web.request` (mismos tokens y cookie del GET) | `test_csrf_mode_extracts_viewstate_and_reuses_the_session_cookie` |
| `nikto(target="http://10.0.0.1")` rechazado | La tool declaraba host, pero el modelo lee un servicio 80 como URL; costo: un turno (iteración 9) | `nikto` acepta host o URL y deriva host/puerto/TLS | `test_an_http_url_is_reduced_to_its_host_and_port` |

**Por qué esto no es un parche de una sala:** el PoC se elige por rango
(webapps y texto antes que DoS/local/binario), el CSRF se detecta por el HTML
y no por el nombre del CMS, y ambos caminos son genéricos (BlogEngine, WordPress,
Joomla, ASP.NET MVC, Rails, Django). El prompt y `web-recon-master` ahora ordenan
el flujo completo **buscar → leer → adaptar → subir → accionar → verificar**, y
el login con tokens pasa por `csrf_mode` en lugar de confiar en que el modelo lo
adivine.

**Límites declarados:**

- El barrido CSRF es **secuencial** (el viewstate va atado a su GET); con
  `rockyou.txt` completo y un objetivo lento el presupuesto puede cortarlo, y el
  resultado es `timeout` con `start_at` para el siguiente slice, no un falso
  negativo.
- `find_and_prepare` trabaja contra la **base local** de Exploit-DB. Si el PoC no
  está en la copia instalada, devuelve `found=false`; no descarga de Internet.
- Se sigue exigiendo `failure_string` discriminante: la sonda CSRF lo valida con
  el mismo flujo de tokens antes de gastar la wordlist.
- El e2e contra un panel ASP.NET real con cookies `SameSite`/`Secure` y un
  `VIEWSTATE` rotado por sesión no se ejecutó; la aceptación usa un servidor
  HTTP local real.

### 5.10 Run V11 contra HackPark — el PoC llega al objetivo (2026-10-21) — **EJECUTADA**

Run `run_21d83735df4e4e64833373d81533c89e`. El run hizo lo que V10 no pudo:
identificó BlogEngine.NET 3.3.6.0, tradujo el fingerprint a `CVE-2019-6714` y
**descargó** el PoC con `find_and_prepare`. Los tres muros restantes fueron de
capacidad, no de gobernanza:

| Muro medido | Por qué bloqueaba | Fix implementado | Test de aceptación |
|---|---|---|---|
| `form_params` rechazaba los nombres de ASP.NET (`ctl00$MainContent$LoginUser$UserName`) | El validador vetaba espacios y todo lo que no fuera un nombre simple; el run tenía formulario, usuario y wordlist y no llegó a probar una contraseña | Se acepta cualquier carácter de un nombre de campo; sólo se rechazan `:` y `?` (estructura de hydra) y los segmentos sin `nombre=valor` | `test_aspnet_field_names_are_accepted_verbatim`, `test_a_form_param_pair_without_a_name_is_rejected` |
| El PoC no traía instrucciones | `next_steps` decía «lee, adapta, sube, acciona»; `46353.cs` es un control ASP.NET (`<%@ Control %>`), no un programa, y sólo se ejecuta como `PostView.ascx` en un tema | `next_steps` por extensión y por markup: tema `.ascx`, script `.py`, binario `.exe`, `.cs` sin markup → compilar; añade el paso de callback si el PoC trae `ATTACKER_IP`/`LHOST`/`LPORT` | `test_a_blogengine_theme_control_gets_upload_instructions`, `test_a_python_poc_names_the_shell_exec_runner` |
| No había camino gobernado para subir el exploit de tema | `nexus.web.upload` no reconoce un control ASP.NET, no inyecta el callback y no distingue un 200 de un archivo ejecutable | `nexus.exploit.compile_and_upload`: prepara en `loot/exploits/prepared/`, sube `.ascx` con `csrf_mode=true`, compila un `.cs` puro con `mcs` en el sandbox, verifica con `id` y devuelve `session_ref`; un 4xx/5xx es `exploit_upload_rejected` | `test_blogengine_theme_is_uploaded_as_ascx_and_registers_a_session`, `test_the_post_is_rejected_when_csrf_mode_is_turned_off` |
| La skill no enrutaba el PoC | El flujo «buscar → leer → adaptar → subir» no decía qué hacer con cada tipo de archivo | Regla de oro (PoC en mano) en `web-recon-master` y en el prompt del sistema | `test_the_web_recon_skill_routes_a_poc_by_file_type` |

**Por qué no es un parche de sala:** el validador acepta la gramática real de
un formulario (ASP.NET, PHP, Django), `next_steps` decide por el archivo que
Exploit-DB entregó y no por el nombre de la sala, y la subida es la misma
tool gobernada que ya usa cualquier webshell. La aceptación se hizo contra un
panel WebForms local real que rechaza el POST sin tokens y ejecuta `id`.

**Límites declarados:**

- El `.ascx` sólo se ejecuta desde la ruta de temas del CMS: `shell_url` la
  aporta el operador y el handler no la adivina.
- La inyección de callback sólo sustituye placeholders literales; un PoC con la
  IP escrita a mano se marca `callback_placeholder_missing` para editarlo.
- `mcs` no está en el entorno de desarrollo: la ruta de compilación se prueba
  con el compilador simulado y un fallo se reporta `unavailable` (nunca se sube
  un `.cs` que el objetivo no ejecuta).
- `form_url` descarta la query string (no se envía en el POST); la ruta y la
  cookie de la sesión resuelven el redirect. Un `?` ya no bloquea el barrido
  (§5.13).

### 5.11 Regla de avance hacia producción

El roadmap es el contrato de salida a producción, no un diario: **cada run que
se cierra actualiza esta sección y sus métricas en el mismo commit**. Una pared
medida se convierte en capacidad genérica (validator, `next_steps`, tool
gobernada) con su test de aceptación; una sala no se «arregla» con un caso
especial. El orden sigue siendo P0 → P1 → P2/P3; V10, V11 y V12 no abren fases
nuevas, cierran las paredes que impedían recorrer la cadena completa. Lo que
falta para producción no es una tool más: es la aceptación de campo contra un
objetivo real (panel ASP.NET con `SameSite`/`Secure`, `VIEWSTATE` rotado) y la
decisión de red para P2 (MCP de lectura).

### 5.12 Run V12 contra HackPark — presupuesto y tolerancia a fallos (2026-10-21) — **EJECUTADA**

Run `run_66db1fce65b2465eb799a53d0f9299b2` (`/tmp/hackpark-run-v12.ndjson`,
21 iteraciones, 804 s). El PoC llegó al objetivo por segunda vez, pero el run
murió con `status=budget_exceeded` **antes de probar una contraseña**: el barrido
llegó a 75 de 5 000 intentos y el motor le dijo al agente `unavailable`.

| Muro medido | Evidencia | Fix implementado | Test de aceptación |
|---|---|---|---|
| `--max-iterations 50` compró **21 turnos** | 252 294 / 250 000 tokens; `react.budget_exceeded` en la iteración 21 (suma de `prompt_tokens` = 248 205, ~11 800/turno) | El techo se **deriva** del techo de iteraciones: `max_iterations × 11 800 × 1,2`, nunca por debajo de 250 000; `--budget-tokens` como override explícito (`0` = ilimitado) y `run.complete` publica `tokens_per_turn`, `budget_turns`, `tokens_spent`, `budget_tokens` | `test_the_budget_follows_the_iteration_ceiling` (50 ⇒ 708 000), `test_the_default_iteration_count_keeps_the_reviewed_ceiling`, `test_the_run_publishes_tokens_per_turn_and_budget_turns` |
| Un `URLError: timed out` mató el barrido a los 92 s | `cred_run_…_2u0m4n5h`: 75 intentos en 55 s (1,36/s); el cliente salió con `{"ok": false, "error": "URLError: <urlopen error timed out>"}` y el handler lo clasificó `unavailable` | El cliente CSRF reintenta la **misma** contraseña una vez y sigue con la siguiente; 10 entradas perdidas seguidas cortan el slice con `outcome=partial` + `next_start_at`, nunca `unavailable` si hubo al menos un intento; `negative` exige que **toda** la slice se probó (`tested >= attempts`); evidencia con `request_timeouts` y `attempts_per_second` | `test_a_cut_request_does_not_abort_the_sweep` (1 420 entradas, 1 de cada 10 peticiones cortada, la última es la buena), `test_a_client_that_tested_something_is_partial_not_unavailable` |
| La barrera del modelo cerró la única rama viva | Iteración 17 (`barrier` sobre `10.0.0.1:80`) con `sweep_attempted: false`; `coverage` la leyó como `descartado` y el pivote mandó el run a RDP 3389 | `barrier` lleva procedencia: `record_fact` sella `sweep_attempted: false` + `provenance: model_claim`; `cred.bruteforce` (wordlist agotada) y el cierre del bucle sellan `true` + `outcome`; `coverage.barrier_is_conclusive` ignora la barrera con `sweep_attempted: false`, `invalid_*`, `unavailable`, `partial`, `timeout`, `rejected` | `test_the_v12_barrier_does_not_close_the_branch`, `test_a_finished_sweep_still_closes_its_branch`, `test_an_inconclusive_barrier_never_closes_a_branch[7 casos]`, `test_record_fact_stamps_the_provenance_of_a_model_barrier` |
| Dos rechazos **de argumento** dispararon el pivote | Iteraciones 13-14: `form_url` con query, `^PASS^` ausente; iteración 15 `invalid_failure_string`; `consecutive_no_progress` = 5 → `react.stuck_detected` | Un rechazo de argumento (schema, `ValueError`, `invalid_*`, `input_rejected`) no mueve `consecutive_no_progress` durante `MAX_FREE_ARGUMENT_REJECTIONS = 2`; desde el tercero cuenta, para que un modelo que adivina no queme el run | `test_two_argument_rejections_do_not_move_the_pivot`, `test_rejections_past_the_free_budget_still_count` |
| La skill activa se reenviaba entera cada turno | `render_skills` incluía el cuerpo (18 KB) en **todos** los prompts cuando la skill venía de `--skill` | El cuerpo viaja una vez (`skill_bodies`); después el bloque lleva el índice y el `sha256`; el marcado ocurre tras un decode válido para que un reintento por JSON inválido siga viendo la receta; recargar con `nexus.skill.load` la vuelve a entregar | `test_a_skill_body_is_rendered_only_when_it_is_due`, `test_the_prompt_carries_an_active_skill_body_only_once` |

**Corrección de la medición (importante):** en el análisis previo se atribuyó a la
skill un 35 % del presupuesto. Los artefactos no lo sostienen: el cuerpo de 18 KB
se pagó **una vez** en la iteración 3 (+3 970 tokens) y `bounded_context`
(6 000 chars) lo dejó fuera a partir de la 4. El suelo por turno (~9-10 k) es
prompt de sistema + catálogo + hechos + historial, no la skill. R2 sigue siendo
un arreglo real (con `--skill` el cuerpo sí se repetía), pero **el turno extra
viene de R1**, no de aquí: se documenta para no vender una ganancia que no existe.

**Lo que estos fixes NO resuelven (medido, no supuesto):**

- **Throughput del barrido:** 1,36 intentos/s (GET+POST por intento). Con
  `1qaz2wsx` en la línea **1 420** de `rockyou.txt` hacen falta ~1 041 s; el techo
  por defecto era 885 s (900 − margen). **Resuelto en §5.13**: el contrato publica
  1 800 s y el barrido por defecto dispone de 1 785 s, por encima de los ~1 041 s
  que necesita la credencial; el `GET` reutilizado por slice sigue pendiente como
  optimización, no como bloqueo.
- **La sonda CSRF no reporta `hidden_fields`** (el payload de `mode=probe` no los
  incluye), así que `_probe_verdict` siempre ve `[]` y el handler no puede
distinguir "el panel no emite tokens" de "el cliente no los buscó". Se corrigió la
  parte del script que sí los emite; falta que el handler actúe sobre
  `hidden_fields == []` con un `invalid_csrf` explícito.
- **`shell_url` sigue siendo del operador** (§5.10): la cadena autónoma se detiene
  en la subida del tema si nadie aporta la ruta.
- El barrido CSRF sigue siendo secuencial y no paraleliza por diseño (el viewstate
  va atado a su GET).

Verificación: `.venv/bin/python -m pytest nexus_core/tests -q` → **3 836 passed /
53 skipped**; `make lint` limpio; `make typecheck` sin errores en 13 ficheros.

### 5.13 Run V13 contra HackPark — encadenar el PoC y quitar topes artificiales (2026-10-21) — **EJECUTADA**

Run `run_cc0cb0ce695047ac9a6b9e29d20f9974`. El presupuesto derivado de V12
funcionó (el run llegó a la iteración 52 y al formulario correcto), y quedaron
dos paredes: el agente no encadenó `find_and_prepare` con `compile_and_upload`, y
`nexus.cred.bruteforce` seguía rechazando lo que el objetivo sí admite.

| Muro medido | Evidencia | Fix implementado | Test de aceptación |
|---|---|---|---|
| El techo de 900 s rechazó un barrido de 1 200 s | Iteración 52: `timeout_seconds=1200` → error de contrato; el run improvisó `hydra` por `nexus.shell.exec` y gastó 5 turnos | `CRED_TOOL_TIMEOUT_SECONDS` = **1 800** (igual que `nmap`/`nikto`/`gobuster`); el barrido por defecto usa `1800 − 15` = 1 785 s; el techo del bucle sube a `timeout_per_tool_seconds = 1860` para que el handler -no la cancelación- responda `timeout` | `test_a_long_sweep_budget_is_accepted`, `test_the_handler_slices_by_default_and_publishes_no_ceiling`, `test_the_loop_ceiling_leaves_room_for_the_tool_to_answer_timeout` |
| `form_url` con query string era un error | `/Account/login.aspx?ReturnURL=/admin/` rechazado por el validador | La query (y el fragmento) se **descartan** en `_normalize_form_url`; `?` es estructura de hydra y el login ASP.NET autentica por el cuerpo. La evidencia publica `form_query_dropped` | `test_a_form_url_with_a_query_is_normalized_to_its_route` (⇒ `/login.aspx`), `test_a_bare_form_path_with_a_query_is_normalized_too` |
| `form_params` sin `^PASS^` bloqueaba el barrido | Los tres campos WebForms estaban, el placeholder de contraseña no | Se rellena el campo de contraseña (`$Password=^PASS^`) o se añade `pass=^PASS^` si no hay ninguno con nombre de contraseña; se rechaza seguir sin `^USER^`. La evidencia publica `form_params_autofill` | `test_a_missing_pass_placeholder_is_filled_in_the_password_field` |
| `compile_and_upload(exploit_path="46353")`: el ID, no la ruta | `find_and_prepare` había devuelto `path`; el agente pasó el EDB-ID y perdió 8 iteraciones buscando el archivo | El contrato del campo nombra la regla (usa el `path` exacto, nunca el ID/CVE) y el handler **resuelve** un ID suelto si coincide con un único PoC de `loot/exploits/`; si no, el error lista las rutas reales. La evidencia publica `requested_as`/`resolved_from` | `test_an_edb_id_resolves_to_the_prepared_poc`, `test_an_unknown_reference_lists_the_real_paths` |
| La orden no estaba en el prompt ni en la skill | El modelo sabía qué tool usar, no qué campo pasarle | La regla viaja en `CMS_EXPLOIT_RULE_PROMPT`, en `web-recon-master` («usa el campo `path` tal cual, no el EDB-ID ni el CVE») y en el último `next_steps` de `find_and_prepare`, junto a la ruta; el catálogo lo repite en la descripción de `exploit_path` | `test_the_prompt_names_the_path_field_for_compile_and_upload`, `test_the_web_recon_skill_routes_a_poc_by_file_type`, `test_a_blogengine_theme_control_gets_upload_instructions` |

**Por qué no es un parche de sala:** ni el ID `46353` ni `ReturnURL` aparecen en el
handler como casos especiales. El techo es el mismo que publican las demás tools
largas, la normalización de URL se aplica a cualquier `?`, el relleno de
`^PASS^` busca el nombre de campo y no la sala, y la resolución del ID vale para
cualquier PoC que `find_and_prepare` haya dejado en `loot/exploits/`.

**Límites declarados:**

- Un ID suelto sólo se resuelve con **una** coincidencia; con varias, el error
  nombra los candidatos en vez de elegir por el modelo.
- `^PASS^` se añade al primer campo con nombre de contraseña **vacío**; si todos
  traen valor, cae en `pass=^PASS^`, que es una suposición declarada en
  `form_params_autofill` (el barrido puede fallar, pero ya no se bloquea).
- La query descartada **no** se reenvía como campo del POST: el redirect lo
  resuelve la cookie de sesión, no `ReturnURL`.
- Sigue abierta la sonda CSRF con `hidden_fields == []` (§5.12) y `shell_url`
  sigue siendo del operador (§5.10).

Verificación: `.venv/bin/python -m pytest nexus_core/tests -q` → **3 842 passed /
53 skipped**; `make lint` limpio; `make typecheck` sin errores en 9 ficheros.

### 5.14 Run V14 contra HackPark — la subida deja de mentir (2026-10-21) — **EJECUTADA**

Run `run_56fe8f6dce3e4087a06cca308829ded8`. Los fixes de V13 funcionaron
(Hydra encontró `admin` con el presupuesto de 1 800 s, `form_url` normalizado,
`session_ref` válido) y el run se atascó en el último paso: subir el exploit. La
subida no autenticó y la tool la declaró buena.

| Muro medido | Evidencia | Fix implementado | Test de aceptación |
|---|---|---|---|
| El POST multipart no llevaba la cookie del panel | Iteración 26: el handler recibió `session_ref: vault:6a07e383…` y el panel contestó **302 a `/Account/login.aspx`** | `compile_and_upload` **resuelve** el `session_ref` contra el vault antes de construir el POST (el valor nunca pasa por el contexto del modelo), lo envía como cabecera `Cookie` del multipart y publica `cookie_applied`/`panel_session_ref` en la evidencia | `test_the_panel_session_cookie_reaches_the_multipart_post` |
| Un 302 a login se leyó como éxito | `outcome="success"` con un cuerpo de 8 KB (la página de login) | Un `3xx` cuyo `Location` contiene `login` es `verification_method="exploit_upload_rejected"` con `login_redirect`/`redirect_location` en el resultado; el `next_steps` pide el `session_ref` del panel | `test_a_redirect_to_login_is_a_rejected_upload` |
| Un 200 sin señal de éxito se leyó como archivo subido | El CMS contesta 200 con su propio panel aunque no acepte el tema | Sin `session_ref` de webshell (sonda `id` ejecutada), el cuerpo debe contener una señal de aceptación (`The theme was uploaded`, `successfully`, `uploaded`…) y no de rechazo (`invalid`, `error`, `denied`); si no, `exploit_upload_rejected` con `success_signal` en la evidencia | `test_a_body_without_a_success_signal_is_not_a_landed_file` |
| `callback_host` era la IP del objetivo | El agente pasó `10.0.0.1` (el propio HackPark) en lugar de la IP de Kali: un tema que aterrizara habría abierto la shell contra la víctima | El host de `callback_host` se compara con el de `target_url` (URL, `host:puerto` o host suelto, vía `urlsplit`); si coinciden, `verification_method="invalid_callback"` antes de escribir el artefacto o tocar la red | `test_a_callback_host_that_is_the_target_is_refused`, `test_a_callback_host_with_a_scheme_and_port_is_compared_by_host` |
| El endpoint del tema no estaba en la orden | El POST fue a `/admin/app/editor/editpost.cshtml` (editor de posts), no al gestor de temas | `CMS_EXPLOIT_RULE_PROMPT` y `web-recon-master` nombran `POST /admin/app_themes.aspx` con el campo `ctl00$MainContent$UploadTheme$fuTheme` y un `theme_name` único, y prohíben `editpost.cshtml` | `test_the_prompt_names_the_blogengine_theme_endpoint`, `test_the_web_recon_skill_routes_a_poc_by_file_type` |

**Por qué no es un parche de sala:** el handler no conoce BlogEngine. La cookie
se resuelve por el handle del vault (cualquier login que el motor haya validado),
el rechazo se decide por el `Location` y por el cuerpo (no por el nombre del CMS),
y la comprobación del callback compara hosts, no una IP concreta. La orden del
endpoint es el único texto específico, y vive en el prompt/skill, no en el código.

**Límites declarados:**

- La cookie vale lo que valga la entrada del vault: una sesión caducada sigue
  fallando, pero ahora el resultado es `exploit_upload_rejected`, nunca `success`.
- La señal de éxito es una heurística sobre el cuerpo. Un CMS con otro mensaje y
  sin `shell_url` se reporta rechazado aunque el archivo haya aterrizado: la
  prueba dura sigue siendo la sonda `id` que devuelve `session_ref`.
- El 302 sólo se marca como fallo de sesión si `Location` contiene `login`; un
  panel que redirige a otra ruta conserva el chequeo de cuerpo.
- La comparación de callback es por host: el mismo objetivo alcanzado por otro
  nombre (IP vs DNS) no se detecta, y un `callback_host` con puerto comparte host
  a propósito.

Verificación: `.venv/bin/python -m pytest nexus_core/tests -q` → **3 848 passed /
53 skipped**; `make lint` limpio; `make typecheck` sin errores.

### 5.15 Run V15 contra HackPark — el ledger deja de pisar la orden (2026-10-21) — **EJECUTADA**

Run `run_e971fff78593498081567bdfc602d23a`. El objetivo pedía una cosa y el motor
ordenó otra distinta, y el modelo obedeció al motor: 40 turnos, 540 641 tokens,
0 hallazgos, parado en acceso inicial.

| Muro medido | Evidencia | Fix implementado | Test de aceptación |
|---|---|---|---|
| El pivote ordenó una rama que el objetivo había excluido | Iteración 12, `react.coverage_pivot`: `Siguiente rama: 10.0.0.1:3389/tcp ms-wbt-server`, con un objetivo que decía «NO hagas pivoteo» y nombraba `POST /admin/app_themes.aspx` | `parse_directive` lee la orden (hosts, `host:puerto`, rutas de documento y frases de límite: `no hagas pivoteo`, `único host`, `sin pivoteo`…) y `pivot_hint` no puede ordenar una rama que la orden excluye | `test_the_pivot_never_orders_a_branch_the_objective_excluded` |
| La orden desaparecía en cuanto había una racha sin hechos | `no_progress=5` en :80 con :3389 pendiente; el aviso sustituyó al objetivo | Con directiva activa, el aviso ordena **volver** a la rama nombrada y corregir el argumento (ruta, campo, credencial, sesión), no cambiar de servicio; cita la frase literal del operador | `test_a_directive_brings_a_wandered_run_back_to_the_named_branch` |
| Incluso un ramal cerrado servía para pivotar fuera del alcance | El pivote sobre un servicio `descartado` apunta siempre a la siguiente rama abierta | Con directiva, un ramal cerrado no autoriza a salir del alcance: pide `request_clarification` y prohíbe cerrar ramas para «desbloquear» el ledger | `test_a_directive_does_not_order_a_pivot_out_of_a_dead_branch` |
| La línea `Siguiente rama:` del prompt también proponía la rama excluida | `FRONTERA: 2/2 servicios sin veredicto. Siguiente rama: …:3389` | La frontera elige primero una rama nombrada por el objetivo y el bloque lleva `DIRECTIVA DEL OPERADOR (prioridad sobre este ledger)` | `test_the_frontier_line_does_not_point_at_an_excluded_branch`, `test_the_prompt_carries_the_directive_ahead_of_the_frontier` |
| La decisión no era auditable | El evento sólo llevaba `hint`, `focus` y `open_work` | El payload publica `directive: {refs, paths, no_pivot}` (parseado desde `self.objective` en cada turno, no cacheado) | `test_the_coordinator_honours_the_objective_it_was_given` |

**Por qué no es un parche de sala:** `parse_directive` no conoce HackPark ni
BlogEngine. Lee direcciones, rutas de documento y frases de límite; con un
objetivo genérico devuelve una directiva inactiva y el pivote conserva su texto
medido (`test_without_a_directive_the_pivot_keeps_its_measured_order`).

**Límites declarados:**

- La directiva no convierte una rama muerta en viva: ordena corregir el argumento
  y, si el alcance está limitado, preguntar. No sustituye la evidencia.
- Es un parser de texto: una orden implícita no la activa, y un objetivo que
  nombre un DNS no se cruza con la IP que descubre `nmap`.
- El pivote sigue siendo un texto en el prompt; el modelo puede desobedecerlo. Lo
  que cambia es que ya no recibe una orden que contradice al humano.
- Cubre el ledger de cobertura; `budget_hint`, `webshell_hint` y `robots_hint` no
  se han revisado contra la directiva.
- El V15 no se ha re-ejecutado: la aceptación es unitaria y de prompt.
- Queda abierto el fallo de `nexus.workspace.search` de la iteración 8
  (`post-condition was not verified` con coincidencias en la salida): no se
  reproduce con el árbol actual y ya existe
  `test_workspace_search_keeps_the_matches_of_a_dirty_walk`.

Verificación: `.venv/bin/python -m pytest nexus_core/tests -q` → **3 857 passed /
53 skipped**; `make lint` limpio; `make typecheck` sin errores.

Detalle completo: `docs/missions/diag/hackpark_v15_2026-10-21.md`.

---

### 5.16 Campaña DeadDrop — multi-red con pivote (2026-10-22) — **EJECUTADA EN PARTE**

Sala con dos capas: DMZ `10.0.0.1` y LAN `10.0.0.1/24` alcanzable
sólo desde ella (`10.0.0.1` DC, `.51` workstation). Seis runs, 44 turnos
de agente entre todos. Fase 1 y 2 cumplidas **por el motor**; la fase 3 quedó
bloqueada cuando la instancia de la sala dejó de responder a las 03:12 UTC.

| Muro medido | Evidencia | Fix implementado | Test de aceptación |
|---|---|---|---|
| `service` no podía acotar el fingerprint | P1: `-p 22,80` descartado y `-p- -sV -sC` corrió 333 s | `selects_ports` distingue una selección real del barrido y quita `-p-` del perfil `service` | `test_service_profile_narrows_to_the_ports_the_model_named` |
| El plan palpaba el pivote con hechos de la DMZ | P1 iteración 2: `done: [recon, pivot, enum-lan]` con sólo 22/80 de `.200` | Un TODO que nombra hosts sólo acepta hechos de esos hosts | `test_a_todo_that_names_hosts_waits_for_a_fact_on_that_host` |
| Un paso «desde A hacia B» se cerraba con A | P2 iteración 2: el TODO citaba `.200` como origen y el hecho de `.200` lo cerró | `proven_hosts`: si el TODO nombra un host ya probado y otro nuevo, sólo el nuevo lo cierra | `test_a_step_from_a_proved_host_to_a_new_one_is_not_proved_by_the_source` |
| La skill de web prohibía la sonda que abre la sala | P1/P3: 5 y 30 min de wordlists con `/login` vulnerable a `admin'-- -` | Tres sondas deterministas, Hydra sólo si el login enumera usuarios, y cada fichero que el panel lista es una lectura | `test_the_login_hint_orders_the_three_probes_on_a_form_read` |
| El modelo leía el login y volvía a barrer | P3 iteración 5-6 y P4 iteración 5-6 | `login_probe_hint` (planner, determinista) inyecta la orden y emite `react.login_probe` | `test_the_loop_injects_the_login_probe_hint_once` |
| `crack_hash` no leía una línea de `/etc/shadow` | P4 iteración 45: «hash_type could not be autodetected» sobre `svc-drop:$6$…:19700` | `_hash_field` extrae el campo con prefijo crypt | `test_a_shadow_line_is_read_as_its_hash_field` |
| El schema de `crack_hash` rechazaba lo que el handler soporta | P4 iteración 44: `sha512crypt` «is not one of» | El enum pasa a ser `CRACK_FORMATS` + `auto` | `test_the_hash_type_enum_admits_every_format_the_handler_supports` |
| Un `full_tcp` expirado devolvía un timeout sin hechos | P5: 600 s, 0 hechos, todas las fases a ciegas | Un barrido que expira reintenta top-1000 `--min-rate 1000` | `test_a_timed_out_full_sweep_is_retried_with_top_ports` |
| El rescate no cabía en el presupuesto de la tool | P6: 600,2 s y el reintento cancelado al arrancar | Con `-p-` el barrido reserva `600 - 180 - 15` s | `test_full_tcp_profile_scans_all_ports_with_its_own_timeout` |
| Una sonda «parecida» silenciaba el aviso del login | P7 iteraciones 6-11: `username[$ne]=invalid`, `username=admin&password[$ne]=x`; el bypass no corrió y el run volvió a gobuster | Sólo cuentan los tres payloads canónicos; si hay paráfrasis, segunda orden con los que faltan verbatim | `test_a_paraphrased_probe_does_not_count_and_the_hint_names_the_exact_payload` |
| `passwd ` como substring prohibía leer `/etc/passwd` | P8 iteraciones 25-30: seis turnos reescribiendo `cat /etc/passwd`, el rechazo parecía credencial rechazada | La lista prohíbe el comando `passwd`/`chpasswd` (palabra de comando) y el error nombra `enum_system` | `test_ssh_exec_reads_etc_passwd_and_still_refuses_a_password_change` |

**Por qué no son parches de sala:** `selects_ports` y el reparto de presupuesto
son de `nmap`; `proven_hosts` cruza IPv4 del TODO con IPv4 del hecho;
`login_probe_hint` detecta un `<form>` con campo de contraseña; `_hash_field`
parte por `:` buscando un prefijo crypt. Nada nombra DeadDrop.

**Límites declarados:**

- El foothold SSH no lo ejecutó OMNI: lo validó el operador con la password
  crackeada a mano. El run P4 se quedó en registrar el hash como hecho.
- ~~No hay primitiva de abuso de ACL~~ **cerrado 2026-10-22**:
  `nexus.attack.ad_acl` (`read`/`write`/`take_ownership`) sobre
  `impacket-dacledit` y `impacket-owneredit`, con el parser escrito contra el
  formato real de Impacket 0.13 y `Object type (GUID)` → `ResetPassword` /
  `DCSync` / `AddMember`. 21 tests, catálogo a 80 tools, perfiles `common`,
  `post` y `lateral`. Sigue fuera `bloodyAD`/`net rpc group addmem`.
- ~~`nexus.web.request` sólo aceptaba `session_ref`~~ **cerrado 2026-10-22**:
  una respuesta con `Set-Cookie` se guarda en el vault y se devuelve como
  `session_ref`; `evidence.session_ref_issued` distingue el handle nuevo del
  usado, y un refresco de la misma cookie conserva el que ya había. Verificado
  en P8: el bypass devolvió el handle y las cuatro peticiones del panel lo usaron
  tal cual.
- **Pivote sin primitiva gobernada** (abierto, medido en P8, iteraciones 51-69):
  con un `access` probado y un objetivo en otra subred, el modelo usa
  `shell.exec` + `ssh -i` y lanza `nxc` **desde el operador**, que no tiene ruta;
  la skill `pivot-socks` existe y no se carga. Falta el aviso determinista
  (tablero con `access` + objetivo fuera de la subred del operador → `ssh -D` y
  `proxychains4`).
- **Grupos de proceso huérfanos** (abierto): al matar el run desde fuera, los
  hijos del sandbox sobreviven porque crean sesión propia. Medido: dos `nmap -p-`
  vivos 1 h 04 min y 1 h 18 min después de P5/P6, y dos `hydra` en el ciclo
  anterior. Falta un reaper de grupos al arrancar el run.
- `cred.bruteforce` dejó `hydra` huérfanos al matar el run desde fuera y devolvió
  `partial` a los 571 s con 300 s de presupuesto.
- La sala dejó de responder a las 03:12 UTC: los runs P5/P6 miden la caída del
  objetivo, no un defecto del motor. Volvió a las 04:00 UTC y las cinco
  respuestas quedaron cerradas (la escalada del DC es **membership**:
  `synthetic-user` → `ITSupport-Admins` → `Domain Admins`, no un ACE sobre el equipo).

Detalle completo: `docs/missions/diag/deaddrop_campaign_2026-10-22.md` y
`docs/missions/diag/deaddrop_p1_2026-10-22.md`.

### 5.17 B0/B1 — la página deja de ser HTML y empieza a ser evidencia (2026-10-23) — **EJECUTADA**

Origen medido: en el run de HackPark, la iteración 30 pidió `index.html`, cuyo
pie imprimía `j.doe@services.local`, y nunca pidió `/about.html`, enlazada en el
nav y con el equipo y sus roles. El motor no podía registrar ninguna de las dos
cosas: `user` y `email` son tipos de hecho legales (`blackboard.py:32-33`,
`planner.py:92`) y el único productor de `user` era `nexus.web.wp_enum`
(`fact_verification.py:1012`); ningún handler leía un `href` ni una dirección.

| Paso | Cambio | Ficheros | Test de aceptación |
|---|---|---|---|
| B0.1 | Extractor determinista de página: emails, personas con rol, enlaces resueltos (interno/externo, navegable), tecnología, corte a 200 KB y listas acotadas | `kernel/html_evidence.py` | `test_html_evidence.py` (8 tests: correo, roles, «IT Staff» no es persona, enlaces, tecnología, corte) |
| B0.2 | El handler publica `extracted` y `next_steps` (rutas enlazadas sin visitar + candidatos a validar) sin tocar la frontera del gateway | `handlers/http_request.py` | `test_web_identity_evidence.py::test_the_observation_names_the_page_nobody_asked_for` |
| B1.1 | Derivación pura: convención confirmada por dirección publicada, candidatos con confianza y prioridad por rol; sin dominio no hay cuentas | `kernel/identity_derivation.py` | `test_identity_derivation.py` (8 tests) |
| B1.2 | Hechos: `email` (dirección publicada) y `user` (parte local) con `confidence: observed`; lo derivado **no** entra al tablero | `kernel/fact_verification.py` (`WEB_IDENTITY_METHOD`) | `test_the_verifier_asserts_the_printed_address_and_the_local_part`, `test_a_page_with_names_but_no_address_asserts_no_identity` |
| B1.3 | La skill `methodology-senior` enseña a leer `extracted` y prohíbe spray antes de confirmar existencia | `.agents/skills/methodology-senior/SKILL.md` | Manual (skill, no prompt estático: no consume presupuesto por turno) |

**Por qué no es un parche de sala:** el extractor no conoce HackPark ni
BlogEngine. Lee HTML; en cualquier plantilla el pie lleva un correo y la página
de equipo lleva nombres con rol. La derivación es aritmética de cadenas: no hay
una lista de empresas ni de salas. El único texto específico es la skill, que
nombra `/about.html`, `/contact.html` y `/team.html` como *ejemplos* de rutas a
pedir.

**Límites declarados:**

- La dirección en una página prueba que está **publicada**, no que la cuenta
  exista en el directorio: el hecho lleva `confidence: observed` y la validación
  sigue siendo un paso aparte (B1, pendiente de tool).
- La extracción de personas es heurística (nombre capitalizado en un heading o
  junto a un rol). Un nombre sin rol fuera de un heading se descarta: preferimos
  perder un nombre a inventar una persona.
- `next_steps` no garantiza que la ruta exista: propone las que el HTML enlaza.
  Un 404 se registra como endpoint sondeado, no como hallazgo.
- El extractor trabaja sobre `body_preview` (64 KB por defecto): un equipo
  listado solo en JavaScript no se ve; para eso hace falta ejecutar el cliente o
  leer el `.js`, que hoy es una lectura de workspace, no de página.
- La convención se detecta con **una** dirección y **un** nombre que encajen;
  con dos convenciones posibles gana la primera de `CONVENTIONS`
  (`initial.last`), y la evidencia lo dice (`convention_matches`).
- No hay todavía validación de existencia ni control de bloqueo de cuentas: el
  spray sigue siendo una decisión del operador (B1 pendiente).

Verificación: `.venv/bin/python -m pytest nexus_core/tests -q` → **4 172 passed
/ 53 skipped** (B0/B1 juntos); `make lint` limpio; `make typecheck` sin errores.

### 5.18 B1 — la identidad derivada se confirma sin gastar una contraseña (2026-10-23) — **EJECUTADA**

Cierra el paso 2b de `methodology-senior`: `j.rock (0.6, IT Staff)` era una
hipótesis que el motor dejaba al modelo y que ningún tool podía validar sin
credenciales. `cred.bruteforce` no sirve para eso: gasta un intento por prueba y
bloquea cuentas. Faltaba el oráculo de Kerberos.

| Paso | Cambio | Ficheros | Test de aceptación |
|---|---|---|---|
| B1.1 | Parser de los dos oráculos: kerbrute (valida existencia **y** ausencia) y `GetNPUsers -no-pass -usersfile` (valida los que nombra y deja el resto `unknown`; la ausencia no se atribuye porque Impacket imprime `KDC_ERR_C_PRINCIPAL_UNKNOWN` sin nombre) | `tools/parsers/impacket_asrep.py` | `test_kerbrute_decides_existence_and_absence`, `test_getnpusers_proves_the_accounts_it_names_and_nothing_else` |
| B1.2 | Tool gobernado `nexus.attack.ad_user_enum` (LOW, `recon`, scope en `dc_ip`, lista 1–500 validada): escribe la lista en el workspace, prefiere kerbrute y cae a Impacket; sin ninguno devuelve `unavailable` con instrucciones | `handlers/ad_user_enum.py` | 8 tests de handler (argv sin `-p`, lista 600, dedupe, sin respuesta → `negative`) |
| B1.3 | Hechos: `user` verificado para cada cuenta confirmada; AS-REP guardado en el vault y un hecho `credential` con `hash_type: krb5asrep` y solo el handle | `kernel/fact_verification.py` (`USER_ENUM_METHODS`) | `test_the_verifier_confirms_accounts_and_vaults_the_asrep_hash` |
| B1.4 | `crack_hash` entiende `krb5asrep`/`krb5tgs` (formato john y detección por prefijo; la línea no se parte por `:` como un shadow) | `handlers/crack_hash.py` | `test_an_asrep_hash_is_a_known_crack_format` |
| B1.5 | El perfil `services` y `cred` pueden invocarla; catálogo a 83 y `catalog.json` actualizado | `agent/subagents.py`, `tools/registry.py`, `docs/missions/audit-v1/catalog.json` | Ledger AST/runtime/JSON y límites de prompt |

**Por qué no es un parche de sala:** no contiene un dominio, un DC ni un nombre.
El oráculo es Kerberos; el parseo depende del formato documentado de las dos
herramientas, y la diferencia `full`/`partial` es una propiedad del binario, no
del objetivo.

**Límites declarados:**

- Sin kerbrute, la ausencia no se prueba: esas cuentas quedan `unknown` y el
  `next_steps` lo dice. Un run no puede cerrar una rama de identidad con
  «no existe» si el oráculo no lo demostró.
- El oráculo no distingue una cuenta deshabilitada: existe en el directorio. La
  deshabilitación (UAC) no está en la salida de ninguno de los dos.
- Kerberos necesita el 88/tcp alcanzable. Detrás de un túnel, el handler debe
  ejecutarse con el proxy del contrato (§5.16, Tanda F); `ad_user_enum` no lleva
  proxy propio todavía.
- El hash AS-REP se guarda como `krb5asrep` y `crack_hash` lo ataca con `john`;
  el crackeo puede fallar por wordlist, no por formato, y eso se reporta como
  `negative` del crack, no como credencial.
- No se ha ejecutado contra un DC real en esta entrega: la aceptación es unitaria
  con salidas reales de formato (kerbrute 1.0.3 e Impacket 0.13).

---

### 5.19 B2 — un puerto con cuatro caminos deja de ser un solo veredicto (2026-10-23) — **EJECUTADA**

Origen medido (requisito explícito de producto): «algunas pruebas tienen un solo
vector vulnerable, otras cuatro, y el vector puede estar en la web o en otro
puerto». El ledger tenía un ítem por servicio (`coverage.py:1`, «one verdict per
discovered service»): un `barrier` escrito tras el primer callejón cerraba el
`:80` y los otros tres caminos desaparecían del mapa, incluso si ya estaban
probados como hechos.

| Paso | Cambio | Ficheros | Test de aceptación |
|---|---|---|---|
| B2.1 | `VectorEntry` (ref, label, status, verdict) y `SurfaceEntry.vectors`; `vulnerabilities` conserva el contador histórico de hechos para el gate del bucle | `agent/coverage.py` | `test_four_routes_on_one_port_are_four_paths` |
| B2.2 | Atribución: un `barrier` cierra un camino solo si **nombra** su ruta (id, CVE, path o key con `/`/`:`) y es **posterior** al hecho; nunca por el host desnudo ni por una key igual al servicio | `agent/coverage.py` (`_vector_needles`, `_vector_entries`) | `test_a_barrier_closes_the_path_it_names_not_the_whole_service`, `test_a_barrier_older_than_the_path_does_not_close_it`, `test_a_fact_keyed_on_the_service_names_no_path` |
| B2.3 | Estado del servicio: con barreras que nombran rutas, sigue `sondeado` mientras quede un camino sin veredicto; se cierra cuando todos lo tienen. Una barrera que solo nombra el servicio conserva la semántica anterior | `agent/coverage.py` | `test_the_service_closes_once_every_path_has_a_verdict`, `test_a_barrier_that_names_only_the_service_keeps_its_old_meaning` |
| B2.4 | Render: sub-líneas `↳` (máx. 3) y resumen de las ocultas **con su veredicto** («1 descartado»), para que un camino cerrado no se lea como pendiente | `agent/coverage.py` (`MAX_VECTOR_LINES`) | `test_the_ledger_shows_the_paths_and_still_orders_the_service`, `test_a_hidden_path_still_reports_its_verdict` |
| B2.5 | El pivote distingue «servicio con caminos pendientes» de «ramal cerrado» y ordena el siguiente camino sin abandonar el servicio | `agent/coverage.py` (`pivot_hint`) | `test_the_pivot_orders_the_next_path_instead_of_abandoning_the_service` |
| B2.6 | Lectores actualizados al contador explícito (`vulnerabilities`/`vector_count`) en disciplina de rama y coordinador | `agent/branch_discipline.py`, `agent/react_coordinator.py` | Suite de `test_branch_discipline` y `test_surface_coverage` |

**Por qué no es un parche de sala:** no hay un host, un CMS ni una ruta
concreta. La atribución es textual sobre el hecho (`id`/`cve`/`path`) y el orden
sale de `recorded_at`; cualquier target con dos rutas en el mismo puerto se
comporta igual.

**Límites declarados:**

- Un `vulnerability` sin ruta (key = servicio, sin `id`/`cve`/`path`) mantiene la
  rama abierta pero **no** crea camino: el ledger no puede inventar qué ruta es.
- La atribución es textual: una barrera cuya razón cite una ruta cierra ese
  camino aunque el intento fuera en otro. Se declara; la alternativa (exigir un
  campo `vector_ref` en el esquema de `barrier`) queda como decisión de esquema.
- No hay propiedad por camino: `comprometido` sigue siendo del servicio. Marcar
  los cuatro caminos como comprometidos porque hay `access` en el host sería la
  misma mentira que el ledger evita.
- El trabajo sigue siendo **secuencial**: cuatro caminos pendientes se atacan de
  uno en uno; B2 da el mapa, no paralelismo.
- Los `endpoint` de gobuster/ffuf no son caminos por sí solos: una ruta escaneada
  se convierte en camino cuando un `vulnerability` la nombra.
- No se ha re-ejecutado una sala con cuatro vectores reales: la aceptación es
  unitaria sobre hechos sintéticos con las formas que produce el verificador.

### 5.20 B3 — la ronda se pregunta qué tiene y no ha gastado (2026-10-23) — **EJECUTADA**

Origen medido: en HackPark V15 el run tenía en el tablero el nombre del contrato,
la cuenta y la sesión del panel, y gastó los turnos releyendo la misma página; en
DeadDrop P12 el hash y la contraseña SSH ya eran hechos verificados y el run pidió
credenciales con ellos en pantalla. La metodología no faltaba (las skills la
traen): faltaba **mirar atrás**. Un senior pregunta una sola cosa entre observar y
actuar —«¿qué tengo ya que no he usado?»— y B3 hace esa pregunta auditable en vez
de esperar a que el modelo la formule.

| Paso | Cambio | Ficheros | Test de aceptación |
|---|---|---|---|
| B3.1 | Regla determinista: solo hechos **verificados** (`is_verified_fact`) de tipo accionable (credential, vulnerability, user, email, session); «usado» = algún valor del hecho aparece en los `arguments` de una acción de la ronda | `agent/reflection.py` (`unused_facts`) | `test_a_credential_no_action_used_is_the_first_thing_reflected`, `test_an_unverified_fact_is_never_reflected`, `test_a_fact_whose_value_appears_in_the_arguments_is_not_unused` |
| B3.2 | La salida de la herramienta no cuenta como uso: se leen `arguments` y `tool_id`, nunca `output`/`stdout`, para que la acción que produjo el hecho no silencie el aviso | `agent/reflection.py` (`_action_blob`) | `test_the_tool_output_is_not_confused_with_use` |
| B3.3 | Los `endpoint`/`host`/`service` no son leads accionables: una ruta existe en la salida del escáner, no en los argumentos del modelo, así que llamarla «sin usar» sería una mentira | `agent/reflection.py` (`ACTIONABLE_TYPES`) | `test_recon_outputs_are_not_actionable_leads` |
| B3.4 | Umbral y cota: el bloque solo aparece tras `REFLECTION_AFTER_TURNS` turnos sin hechos nuevos, con máximo 5 hechos y 900 caracteres, ordenados credential → vulnerability → user → email → session | `agent/reflection.py` (`render_reflection`) | `test_the_hint_only_appears_after_a_barren_streak`, `test_a_progressing_run_pays_nothing`, `test_the_list_is_bounded_and_ranked` |
| B3.5 | Auditoría de una sola vez por lista: `_refresh_reflection_hint` inyecta el texto, lo guarda en `react.reflection` y lo marca en `audit_step`; el mismo texto no se repite en el siguiente turno | `agent/react_coordinator.py` | `test_the_coordinator_audits_the_reflection_once_per_list`, `test_a_action_that_spends_the_fact_silences_the_reflection` |
| B3.6 | El bloque llega al prompt de sistema junto al ledger, sin tocar el plan | `agent/react_services.py` (`ContextSnapshot.reflection_hint`) | `test_the_prompt_carries_the_reflection_block` |

**Por qué no es un parche de sala:** no hay host, CMS ni ruta concreta. La
regla es textual sobre el hecho y sobre los argumentos de la ronda; el mismo
código sirve para un AD, un panel web o un SSH.

**Límites declarados:**

- «Usado» es un substring en los argumentos: un valor de menos de 4 caracteres
  se ignora a propósito (`/`, `80`, `svc` matchean por accidente) y la key solo
  actúa de respaldo cuando el valor no aporta ningún identificador.
- El aviso es una observación, no una orden: no bloquea la acción repetida, no
  cambia el plan y no autoriza tools. Un run puede seguir releyendo la misma
  página; ahora queda auditado que tenía con qué no hacerlo.
- No hay juicio semántico: dos hechos que nombran la misma cosa con distinta
  grafía cuentan como dos, y un hecho mencionado de pasada (un comentario en los
  argumentos) cuenta como usado.
- La etiqueta evita la forma `<término secreto>: valor` porque el redactor la
  borraría entera (medido en el evento: `credential: [REDACTED]`).
- No se ha re-ejecutado una sala con LLM real: la aceptación es unitaria sobre
  hechos con la forma que produce el verificador.

### 5.21 V0-2 — el techo del tablero se aplica a claves, no a filas (2026-10-23) — **EJECUTADA**

Origen: `Blackboard.list_facts` leía `ORDER BY created_at DESC LIMIT 10 000`
**antes** de fusionar versiones. Cada contenido distinto de una clave es una fila
(`KnowledgeStore.ingest` solo deduplica el contenido idéntico), así que una clave
reescrita muchas veces llenaba la ventana y borraba del tablero a sus vecinos sin
que el merge pudiera notarlo: el resultado seguía pareciendo una lectura
completa. El segundo recorte, `[:limit]` sobre la lista ya fusionada, dejaba el
defecto en 100 claves por defecto mientras `_blackboard_facts` documentaba «every
fact of the engagement» y `summary.total` contaba como mucho 100.

| Paso | Cambio | Ficheros | Test de aceptación |
|---|---|---|---|
| V0-2.1 | Las claves se eligen primero: `GROUP BY source_uri` con `MAX(created_at)` y `LIMIT` sobre claves, ordenadas de más nueva a más vieja | `kernel/blackboard.py` (`_fact_keys`, `FACT_KEYS_CEILING = 500`) | `test_a_key_rerecorded_many_times_does_not_evict_other_facts` |
| V0-2.2 | Las filas se leen después y acotadas **por clave** con `ROW_NUMBER() OVER (PARTITION BY source_uri)`; la clave que llega al tope de versiones se relee entera (tope de filas aparte) para que un verificado antiguo siga ganando | `kernel/blackboard.py` (`_fact_rows`, `MAX_VERSIONS_PER_KEY = 20`) | `test_a_verified_fact_survives_many_newer_agent_versions` |
| V0-2.3 | `limit` cuenta **claves**, no versiones, y el orden es «clave más nueva primero» en vez de depender del orden de inserción de un diccionario | `kernel/blackboard.py` (`list_facts`) | `test_the_limit_counts_keys_not_versions` |
| V0-2.4 | Los lectores que prometen el tablero completo piden el techo: `summary`, `verified_fact` y el `_blackboard_facts` del bucle | `kernel/blackboard.py`, `agent/react_coordinator.py` | `test_the_summary_sees_the_board_past_the_default_page` |

**Por qué no es un parche de sala:** no hay host ni tipo de hecho concreto. La
regla es estructural —claves antes que filas— y sirve igual para un engagement de
cuatro hechos que para uno de miles.

**Límites declarados:**

- El techo son **500 claves**: más allá se pierden las más antiguas, por edad y
  no por número de reescrituras, y la truncación **no se señala** en el retorno
  (sigue siendo una lista). Declararlo con un flag es un cambio de API pendiente.
- La relectura de una clave pesada es una sola consulta con `LIMIT 10 000` global:
  una clave con más de 10 000 contenidos distintos podría dejar sin filas a otra
  clave pesada. No se ha medido; el deduplicado por `sha256` lo hace inalcanzable
  en la práctica.
- `ROW_NUMBER()` exige SQLite ≥ 3.25 o PostgreSQL; no se ha probado contra el
  backend Postgres (la suite corre sobre SQLite).
- El orden depende de `created_at` (texto ISO con microsegundos); dos filas del
  mismo microsegundo quedan en orden indeterminado, igual que antes.
- No se ha re-ejecutado una sala: la aceptación es unitaria. Los tests de
desalojo y de `summary` fallan contra la implementación anterior (comprobado con
`git stash`); el de la clave pesada cubre el camino de relectura, que antes no
existía.


## 6. Criterios de cierre

| Fase | Criterio duro | Lo que **no** cuenta |
|---|---|---|
| P0 PTY | Suite verde + tests OCI/egress/captura→loot/reaper + e2e local | Un test de primitiva sin captura real |
| P1 `session_ref` | e2e con peer fuera de scope rechazado **antes** de interactuar; `access`+`loot` en blackboard | Un skip o un timeout ampliado |
| P2 MCP lectura | `mcp.*` en catálogo, gateway aplica política, 0 regresiones de conteo | Que el servidor responda; eso solo es `mcp_unverified` |
| P3 MCP evidencia | Hecho tipado con `invocation_id` del gateway; negativo de privilegio | `outputSchema` válido como prueba de efecto |
| P4 MCP red | Rutas permitidas/denegadas reales, DNS/rebinding, IPv4/IPv6, cleanup | Un proxy que nadie enforcementa |

**Gate V2 (heredado de audit-v1):** cero P0 abiertas y 12 cadenas de referencia
revalidadas con reporte/manifest. El score 38,77 es histórico y no se usa como
medida actual.

### 6.1 Gate de release v1 (producto público)

El lanzamiento no se mide por salas resueltas sino por cinco invariantes, y una
sola que falle en campo bloquea la release:

| # | Invariante | Dónde se comprueba |
|---|---|---|
| 1 | **Cero éxito falso**: ninguna tool declara `success` con señal ambigua (302 a login, 200 sin efecto, cuerpo sin confirmación) | `exploit_upload` (V14), `cred.bruteforce` (§5.12), `http_request` |
| 2 | **Cero fallo silencioso**: cada servicio y cada camino acaba con veredicto y motivo, y el reporte lo publica | `coverage.py` al cerrar (servicio y camino desde B2) |
| 3 | **Toda afirmación cita `invocation_id`** y hecho verificado | StopVerifier + `annotate_findings` |
| 4 | **Scope y RoE antes de tocar el target** (HMAC, peer-first, callback por host) | tests de scope y `listener` |
| 5 | **Coste publicado**: tokens por hallazgo, iteraciones por rama, presupuesto que no se agota en documentación | `run.complete` |

**Corpus de release (heterogéneo, 6–8 objetivos):** web-only con un vector, web
con cuatro vectores en un mismo `:80`, servicio-only (FTP/SSH), AD con DC,
multi-red con pivote, y un objetivo moderno (API/SPA) que **debe fallar
limpiamente**. Ese último es el test de honestidad: si un run inventa un
hallazgo ahí, la release no sale.

**Promesa de la v1:** web + foothold + AD en una red, con cobertura declarada y
cero afirmaciones sin evidencia. Fuera de la v1: MCP de red, C2 autónomo,
OOB/DAST ciego, cloud/Kubernetes/API, egress aislado en `oci` y paralelismo
multi-agente.

---

## 7. Anexo: evidencia consultada en esta pasada

- **Gobernanza:** `kernel/tool_gateway.py:245-630`, `kernel/schema_validation.py`,
  `kernel/redaction.py`, `kernel/blackboard.py:160-205`, `kernel/sessions.py`,
  `kernel/invocation_journal.py`, `kernel/approvals.py`, `kernel/audit.py`.
- **Ejecución:** `kernel/runtime.py:269-310`, `kernel/batch.py`,
  `tools/registry.py:180-367`, `tools/handlers/session_pty.py`,
  `kernel/pty_sessions.py`, `tools/handlers/listener.py:340-410`,
  `tools/handlers/http_request.py:79`, `tools/handlers/report_generate.py:205-214`.
- **Orquestación:** `agent/planner.py`, `agent/engagement_plan.py`,
  `agent/react_coordinator.py`, `agent/supervisor.py`, `agent/skills.py`.
- **MCP:** `integrations/mcp/client.py`, `registry.py`, `gateway_bridge.py`,
  `tests/unit/test_mcp_integration.py`.
- **Planes:** `docs/missions/audit-v1/{00,06,07,09,10}`, `PLAN_OMNIAGENTCS_V4.md`,
  `PLAN_ESCALADA_OMNI.md`, `FASE2_ORQUESTACION_AVANZADA.md`,
  `AUDITORIA_ARQUITECTONICA_MCP_PTY_2026-10-21.md`, `BACKLOG.md`, `docs/adr/*`.
