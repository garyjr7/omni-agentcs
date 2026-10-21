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
| Ejecución W1.2 + PTY P0 | commit de esta entrega (`HEAD` al cerrar) |
| Auditoría de origen | `9a61785` — auditoría MCP/PTY |
| Rama | `feat/orchestration-phase-2-close` |
| Regla de esta entrega | **cero cambios en `.py`**; solo documentación |
| Suite de referencia (`430dcfb`) | **3 735 passed / 53 skipped** |
| Suite tras W1.2 + PTY P0 | **3 753 passed / 53 skipped** |
| Catálogo | **77 tools durables**, **21 parsers** nativos |

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
expresamente `[DOC]`. La suite se re-ejecutó tras W1.2 y PTY P0:
**3 753 passed / 53 skipped**. La línea base del commit auditado era
**3 735 passed / 53 skipped**; la diferencia son los tests nuevos de esta
entrega.

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

- **77 tools durables** en `tools/registry.py`, registradas por tenant y con
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

- **21 parsers nativos** en `tools/parsers/` con `PARSERS_VERSION`; la salida de
  una tool solo se promueve si el parser y el método de verificación coinciden.
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
- **No hay selección multi-vector**: el plan elige una fase, no un conjunto de
  vectores alternativos con coste/beneficio (V0-12).
- **No hay bus tipado ni workers dinámicos**: los subagentes son un árbol
  supervisor, no un bus de eventos (WP5).

### 1.5 Gobernanza

- Scope HMAC firmado, RoE, política de riesgo, aprobaciones durables, hooks
  pre/post tool, journal con fencing y auditoría encadenada.
- `read_only` ya no permite acciones en Plan Mode: el contrato de efectos está
  cerrado (`test_effect_contract.py`) y el rechazo ocurre antes del handler. La
  cifra histórica 26 `read_only` / 38 activos (`09_PLAN_V1_EJECUCION.md`, W1.1)
  corresponde al catálogo de 64 tools, no al de 77.
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
| Tools durables | 77 | `tools/registry.py`; `docs/missions/audit-v1/catalog.json` |
| Parsers | 21 módulos | `tools/parsers/` |
| Tests | 3 753 passed / 53 skipped | suite completa tras W1.2 + PTY P0 |
| Prompt estático | 27 831 chars; ~6 819 tok/turno | `test_prompt_optimization.py` |
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
| **PTY** (`kernel/pty_sessions.py` + `tools/handlers/session_pty.py`) | Driver tmux por run, acciones `start\|send\|capture\|wait\|kill`, scope, audit, límites de nombre/líneas. Tool registrada (`registry.py:361`). **P0 cerrado**: guard OCI, checks léxicos, artifact CAS, assertions, `wait`≤60 s y reaper. | Sigue sin capturar reverse shells ni escribir `kernel_sessions`; eso es P1 (`session_ref`). | Convertir PTY en una puerta trasera de egress y una bomba de tokens (ya mitigado en P0). |
| **`sync_from_config`** | Descubre todos los servidores y registra solo tools allowlisted con `replace=False`. | Nadie lo invoca en producción; no es idempotente frente a un fallo de arranque porque no se llama. | Si se llama antes del catálogo, o sin `NEXUS_MCP_CONFIG`, puede romper el arranque o el conteo del ledger. |
| **Batch runner** (`kernel/batch.py`) | Concurrencia acotada, backpressure, cancelación y estados `completed/failed/cancelled`. | Cableado en `scripts/omni_tool.py`, **no** como tool del modelo. | Exponerlo sin cuota por target convertiría un barrido en una tormenta. |
| **Model router** (`kernel/model_router.py`) | Rutas por clasificación, presupuesto y fallback. | Solo lo usan tests (`test_kernel_offline.py`). | Enrutar sin telemetría de coste puede ocultar el gasto por turno. |
| **Transporte `webshell`** | Declarado en `nexus.post.shell_exec` (`shell_exec.py:17`). | **Ningún productor** escribe una sesión `session_type="webshell"`; el chequeo de `shell_exec.py:74` no se puede satisfacer hoy. | Un canal que parece disponible y nunca lo está. |
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
| Blackboard sin duplicados ni capturas sin acreditar | `V0-2` | **[PENDIENTE]** | El merge «verified wins» está hecho (`blackboard.py:160-205`), pero el `LIMIT` se aplica **antes** del merge: con muchas versiones, hechos distintos pueden quedar fuera. Falta paginar/priorizar por clave antes del techo. |
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
| `session_ref` + reverse shell (P1) | `AUD_MCP_PTY §3.2` | **[PENDIENTE]** | Unificar `kernel_sessions` con `transport`/`transport_ref`/liveness; `listener` keep-open; `shell_exec` transport `pty`. |
| Loop v2: un perfil, planner como hint | `ESCALADA WP2` | **[HECHO]** | `NEXUS_LEGACY_PROFILES` para volver atrás; `test_wp2_loop_v2.py`. |
| Prompt de 3 capas | `ESCALADA WP3` | **[PENDIENTE]** | Medido 27 831 chars estáticos / ~6 819 tok por turno; el objetivo ≤5 000 no se cumple. |
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

1. Llamar `await sync_from_config(registry)` **después** de construir el catálogo
   first-party (`runtime.py:297`) y **antes** de renderizar el prompt.
2. Hacerlo **no fatal**: sin `NEXUS_MCP_CONFIG` no hay servidores, no hay error, y
   el catálogo queda en 77.
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

### 4.4 Lo que falta para `session_ref` (P1)

`kernel_sessions` ya es un UUID durable, pero hoy solo lo pueblan
`msf_exploit` (`:427`) y `sliver_sessions` (`:63`). Falta:

- columnas `transport`, `transport_ref`, `liveness`;
- un productor para `webshell` (hoy el transporte está declarado y no existe);
- `nexus.session.list` unificado (durable + MSF + Sliver + tmux);
- `nexus.post.shell_exec` con transport `pty`/`raw`;
- `listener` en modo keep-open que registre la sesión con el peer ya validado;
- `nexus.session.kill` que cierre tmux **y** marque `closed_at`.

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

### 5.2 Fase P1 — `session_ref` y reverse shell (2–4 días)

1. Migración aditiva de `kernel_sessions` (`transport`, `transport_ref`,
   `liveness`).
2. `nexus.session.list` unificado.
3. `shell_exec` transport `pty`/`raw`; validación de `session_type`.
4. `nexus.post.listener` keep-open: peer validado **antes** de cualquier comando,
   registro en `kernel_sessions`, transcripción como artifact.
5. `nexus.session.kill` cierra tmux y `closed_at`.

**Gate P1:** e2e con `socat`/`nc` local y scope firmado; hecho `access` + `loot`
en el blackboard; peer fuera de scope rechazado sin interacción.

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

Orden ejecutado: W1.2 → PTY P0. Siguiente: P1 (`session_ref`).

### 5.7 Lo que NO se hará (y por qué)

| Idea | Veredicto | Razón |
|---|---|---|
| Añadir tools para cubrir técnicas | **[DESCARTADO]** hasta cerrar 4/6 salas | 31/68 tools ya no las usa nadie; el problema es selección/ejecución. |
| RAG de writeups de THM | **[DESCARTADO]** | Sobreajuste, leakage y se rompe al cambiar de sala. |
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

---

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
