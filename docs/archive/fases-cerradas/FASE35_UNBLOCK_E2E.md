# Fase 3.5 — Desbloquear el Test E2E (Pre-Fase 4)

> Rama: `feat/unblock-e2e-phase-3-5` · Autor: BAJIOWARE · Team Red
> Fecha: 2026-10-06 · Base: `feat/report-enrichment-phase-3e` (`f078f0e`)
> Alcance: **reparación**, no expansión. Solo se atacan los bloqueantes del
> `docs/missions/TEST_E2E_BOUNTY_HACKER.md` (runs #1 y #2 originales).

## 0. Estado

Los cuatro bloqueantes P0 del primer E2E están **corregidos**, cada uno con test
de regresión, más los tres P1. La suite pasa de **2074** a **2137** tests
unitarios (y **2137 passed / 33 skipped / 0 failed** en `nexus_core/tests`).
El gobernanza (scope firmado HMAC, audit chain, fail-closed, anti-injection) no
se tocó.

El **Test E2E #2** se ejecutó con el código corregido y avanzó donde el #1
moría, pero **no completó la sala**: documentado en
`docs/missions/TEST_E2E_BOUNTY_HACKER_RUN2.md`. El motivo ya **no** es ninguno de
los cuatro bloqueantes, sino un límite de cuenta del proveedor (B5), un binario
de entorno ausente (B6) y razonamiento del modelo. Ver §6.

---

## 1. Alcance y principios

- **Fix, no workaround:** cada cambio ataca la causa raíz reproducida.
- **No romper la gobernanza:** scope, audit, fail-closed y anti-injection
  intactos (se añadieron tests que lo confirman).
- **Tests de regresión:** cada fix reproduce el bug original y lo deja fijado.
- **Sin capacidades nuevas:** cualquier idea de expansión se aparcó en
  `docs/missions/BACKLOG.md`.

---

## 2. B1 — Identidad de binarios, no solo presencia

### Problema

`/usr/bin/httpx` es el **CLI de Python**, no el de ProjectDiscovery. El handler
lo trataba como "post-condition fallida" (`httpx_jsonl_parsed`) en lugar de
"binario equivocado", y el run gastaba tokens hasta morir con un error opaco.

### Solución

- **`nexus_core/provisioner/binaries.py`** (nuevo): tabla `BINARY_IDENTITIES`
  con la firma de cada binario crítico:

  | Binario | Sonda | Firma obligatoria | Marcas de binario equivocado | Instalación |
  | --- | --- | --- | --- | --- |
  | `httpx` | `-version` | `projectdiscovery` | `no such option`, `usage: httpx [options]`, `python` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
  | `whatweb` | `--version` | `whatweb` | — | `sudo apt install whatweb` |
  | `nmap` | `--version` | `nmap` | — | `sudo apt install nmap` (requerido) |

  `check_binary_identity`, `classify_identity` (puro, reutilizable dentro del
  sandbox), `identity_problems`.
- **`--setup`**: `assess_environment(probe_binary=check_binary_identity)` verifica
  identidad y marca el binario equivocado como **no listo** (peor que ausente),
  con la ruta de instalación. `run_setup` imprime una sección
  "BINARIOS EQUIVOCADOS".
- **Preflight de run** (`nexus_core/agent/preflight.py`, nuevo): antes de gastar
  un run, `preflight_binaries()` rechaza binarios equivocados. Fail-closed:
  aborta con mensaje claro y la instalación sugerida. El operador puede continuar
  en modo degradado con **`NEXUS_ALLOW_DEGRADED_TOOLS=1`** (se emite
  `run.preflight_degraded` y los tools afectados se tratan como no disponibles
  vía B3).
- **Handler httpx**: al fallar sin salida, sonda la identidad **dentro del
  sandbox** y devuelve `httpx_binary_mismatch` con la instrucción de instalación,
  en lugar del genérico post-condition.

### Por qué abortar y no degradar por defecto

Un binario **ausente** es ambiguo y B3 lo degrada. Un binario **equivocado** es
una mina: produce datos basura o errores que parecen del agente. Fallar antes de
empezar es más honesto que gastar un engagement. El override explícito mantiene
la operabilidad cuando el operador acepta la degradación.

---

## 3. B2 — Validación de `aggression` en whatweb

### Problema reproducido

`whatweb --aggression=2` **no existe**: whatweb solo acepta 1, 3 o 4. Con 2 sale
con **exit 0** y escribe un log de **2 bytes** (`[\n`), que el parser rechazaba
como `whatweb_parse_failed`. El schema aceptaba `minimum 1, maximum 4` y el
handler incluso mapeaba 2 → "medium".

### Solución

- Schema `aggression` → **`enum: [1, 3, 4]`** (rechazo antes de tocar argv).
- `whatweb_noise_level` → `{1: stealth, 3: aggressive, 4: heavy}`; fuera de
  `(1,3,4)` **lanza ValueError** (defensa en profundidad en el handler).
- **`MIN_VALID_JSONL_BYTES = 10`**: un log más corto que eso es una invocación
  rota, no "un escaneo con 0 targets" → `whatweb_output_too_small`.
- Se deja de forzar `aggression 4 → 3`: 4 es un nivel real (heavy) y ahora se
  honra, con aviso de ruido.

---

## 4. B3 — Degradar la fase, no abortar el run

### Problema

Tres fallos consecutivos de un mismo subsistema (httpx ×2 + whatweb) mataban el
engagement entero.

### Solución (`nexus_core/agent/react.py`)

- **Clasificación de fallos**: `_failure_kind` separa **input**
  (`ValueError`/`SchemaValidationError`, `PermissionError`) de **tool**
  (`RuntimeError` de post-condition, `OSError`, timeouts). Solo los *tool*
  retiran el tool.
- **Retirada por tool**: tras `MAX_TOOL_FAILURES_BEFORE_UNAVAILABLE = 3` fallos
  *de tool*, el id entra en `unavailable_tools`, se elimina del catálogo que ve
  el modelo, se emite `react.tool_unavailable` (auditado) y la observación
  indica qué queda disponible. Los fallos de *input* no retiran nada.
- **Aborto solo si no queda ruta**: `_keep_going_after_failures` — al alcanzar el
  umbral, si el subagente activo conserva alguna tool usable, el contador se
  reinicia y el run pivota. Solo se aborta si **todas** las tools de la fase
  están retiradas.
- **Timeout de fase** (`NEXUS_PHASE_TIMEOUT_SECONDS`, desactivado por defecto):
  al excederse, se retiran los tools de la fase que ya fallaron y se audita
  `react.phase_timeout` + `react.step` con `action="phase_timeout"`.

### Desviación documentada (honesta)

La misión pedía "degradar a la siguiente fase" con el timeout. **No se
auto-avanza la fase**: el planner es determinista y dirigido por el blackboard
(`nexus_core/agent/planner.py`), así que fabricar progreso violaría el invariante
"la fase se deriva de hechos verificados". El timeout retira los tools que ya
fallaron (degradación real por otra ruta) y deja constancia; el cambio de fase
sigue perteneciendo al planner. Aparcado en BACKLOG como posible `phase_override`
explícito del operador.

---

## 5. B4 — Presupuestos dimensionados y contexto acotado

### Problema

`recon=20 000` tokens ÷ ~7 000/iteración ≈ 3 iteraciones. Además, la salida de
nmap podía pesar decenas de KB y el historial de una *work session* acumulaba los
mensajes de **todos** los runs previos sin cota.

### Solución

1. **Budgets ×5** (`nexus_core/agent/subagents.py`): recon 100k, web 80k,
   cred/exploit/postexploit/privesc/lateral 60k, reporter 30k. Configurables por
   engagement con **`NEXUS_SUBAGENT_BUDGET_<ID>`** (`apply_budget_overrides`).
2. **Compactación de observaciones** (`nexus_core/agent/observations.py`, nuevo):
   si la observación supera `MAX_OBSERVATION_CHARS` (20k), se resume por tool
   (nmap → puertos + servicios, httpx → probes, whatweb → fingerprints; genérico
   con listas acotadas y campos de texto truncados) y el payload completo se
   guarda **content-addressed** en el artifact store (`LocalArtifactStore`),
   fijando su `sha256` en el resumen.
3. **Cota de contexto** (`bounded_context`, 8 000 chars): solo se inyectan los
   mensajes más recientes que quepan; el bloque de historial resumido del system
   prompt mantiene la esencia. Esto es lo que permite pasar el límite de TPM del
   proveedor (B5).
4. **Techo de salida por turno ReAct** (`NEXUS_REACT_MAX_TOKENS`, por defecto
   1536): los proveedores con presupuesto TPM cuentan el `max_tokens` *reservado*
   contra la petición; el default 4096 hacía fallar cada llamada aun con prompts
   pequeños.

---

## 6. P1 — Observabilidad

5. **Coste conocido por defecto** (`nexus_core/cli/tui/pricing.py`, nuevo): tabla
   de tarifas de referencia por modelo/proveedor (win-longest-substring). Las
   env `NEXUS_TUI_INPUT_USD_PER_MTOK`/`..._OUTPUT_...` siguen ganando; un modelo
   desconocido queda `cost=None` (nunca se inventa). Groq `gpt-oss-120b` →
   `$0.15/$0.60` por 1M.
6. **Audit `tool.invoke` con argumentos redactados**: además de
   `argument_keys`, se persiste `arguments` saneado con la **misma** política del
   `AuditWriter` (las credenciales nunca van en claro) y `run_id`. La
   transcripción queda autocontenida.
7. **Gating de aprobación ejercitado**: tests que prueban la ruta de **denegación**
   (headless sin trust-mode: la tool HIGH nunca se ejecuta) y la de
   **auto-aprobación auditada** (`tool.trust_mode_approved`).

---

## 7. Bugs/tests corregidos durante la fase

- El test `test_whatweb_handler.py::test_handler_returns_unverified_on_parse_error`
  usaba un payload de 9 bytes que ahora cae en `whatweb_output_too_small`; se
  alargó a uno JSON inválido real.
- Tres tests del ReAct asumían el **antiguo** aborto a los 3 fallos consecutivos.
  Se reescribieron para el comportamiento nuevo (retirada + pivote, o denegación
  de gobernanza que no aborta mientras queden rutas).
- `test_tui_cost.py` asumía que `groq` era desconocido; ahora se usa un
  proveedor realmente desconocido para el placeholder y se añade un test de que
  `groq` sí tiene coste.
- Los dobles de streaming en `test_react_thought_stream.py` no aceptaban
  `**kwargs`; se ajustaron a la interfaz real (`complete`/`stream` aceptan
  `max_tokens`).

---

## 8. Verificación reproducible

```
.venv/bin/python -m pytest nexus_core/tests/unit -q   # 2118 → 2137 passed, 1 skipped
.venv/bin/python -m pytest nexus_core/tests -q        # 2137 passed, 33 skipped, 0 failed
.venv/bin/python -m ruff check <ficheros> --select F,E9   # limpio
.venv/bin/python -m mypy <módulos nuevos> --ignore-missing-imports  # sin hallazgos en código nuevo
```

Tests nuevos:
`test_binaries.py` (10), `test_observations.py` (7), `test_react_degradation.py`
(6), `test_p1_observability.py` (5); ampliados `test_whatweb_handler.py`,
`test_httpx_handler.py`, `test_react_loop.py`, `test_react_approval.py`,
`test_cli_approval.py`, `test_tui_cost.py`, `test_react_thought_stream.py`.

Los hallazgos de mypy restantes están todos en líneas preexistentes
(`nexus_core/agent/react.py` usa `action.tool_id: str | None` en el camino
antiguo; baseline del repo ~95–169 hallazgos). El código nuevo queda limpio.

---

## 9. Lo que sigue bloqueando el E2E (nuevos hallazgos)

El Test E2E #2 (corregido) **no completó** la sala. Ninguno de los cuatro
bloqueantes originales volvió a aparecer. Los motivos, con evidencia en
`TEST_E2E_BOUNTY_HACKER_RUN2.md`:

| # | Hallazgo | Naturaleza | Estado |
| --- | --- | --- | --- |
| **B5** | Groq on-demand **TPM = 8000**; cada petición contaba prompt + `max_tokens(4096)` y devolvía 413 *"Request too large"*. | **Cuenta/proveedor** | **Mitigado**: techo de salida + cota de contexto eliminan el 413 en el run #2. Un run largo seguiría ajustado al límite. |
| **B6** | `rg` (ripgrep) no está instalado → `nexus.workspace.search` falla con `FileNotFoundError`. | **Entorno** | Sin arreglar (instalar `ripgrep` o añadir preflight). |
| **B7** | No existe una tool para **leer el contenido** de un fichero descargado; el agente pidió aclaración al operador para poder leer `task.txt`. | **Diseño/capacidad** | Aparcado en BACKLOG (sería capacidad nueva). |
| **B8** | Razonamiento del modelo `gpt-oss-120b`: eligió tools fuera de la kill-chain y/o declaró `task_complete` prematuramente; reutilizó evidencia de runs previos desde el contexto acotado. | **Modelo** | Fuera del alcance de "reparación". |

Detalle y transcripción: `docs/missions/TEST_E2E_BOUNTY_HACKER_RUN2.md`.

---

## 10. Desviaciones respecto al encargo

| Encargo | Realidad | Motivo |
| --- | --- | --- |
| "abortar el run" si binario equivocado | Aborta por defecto; override `NEXUS_ALLOW_DEGRADED_TOOLS=1` | Un ausente se degrada (B3); un equivocado debe fallar antes de gastar tokens, pero el operador puede aceptar la degradación (§2) |
| "degradar a la siguiente fase" por timeout | Se retiran los tools que fallan y se audita; la fase la decide el planner | No fabricar progreso en un planner determinista (§4) |
| Presupuesto "por coste de salida de tool" | Compactación + artifacto content-addressed + cota de contexto | Cubre el coste real del prompt (que era el que agotaba) y el 413 |
| Test E2E #2 completa la sala | **No completó**; documentado | Bloqueantes nuevos B5–B8, ajenos a los cuatro originales |

---

## 11. Atribución

- Tarifas de referencia: precios públicos de lista (ver `pricing.py`); son para
  contabilidad local, no facturación.
- Salas: *Bounty Hacker*, TryHackMe (laboratorio autorizado).
