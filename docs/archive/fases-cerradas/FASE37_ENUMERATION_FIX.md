# Fase 3.7 — Desbloquear la cadena de enumeración (P0+P1+P2+P3)

Documento de fase. Última iteración de **arquitectura** antes de decidir si el
siguiente cuello de botella es el modelo (Fase 4).

- Rama: `feat/enumeration-fix-phase-3-7`
- Base: `906a0ec` (Fase 3.6 completa)
- Autor: BAJIOWARE · Team Red
- Fecha: 2026-10-07

## 0. Estado

| Métrica | Antes (3.6) | Ahora (3.7) |
| --- | --- | --- |
| Tests unitarios (`nexus_core/tests/unit`) | 2165 passed, 1 skipped | 2173 passed, 1 skipped |
| Suite completa (`nexus_core/tests`) | 2181 passed, 33 skipped, 0 failed | 2189 passed, 33 skipped, 0 failed |
| `ruff check --select F,E9` (ficheros tocados) | limpio | limpio |
| `compileall` (ficheros tocados) | OK | OK |
| `mypy` (ficheros tocados) | sin hallazgos nuevos | sin hallazgos nuevos |
| E2E "Bounty Hacker" | **no completó** (run #3, `clarification`) | **no completó** (E2E #4: arquitectura arreglada, bloquea el modelo) — §9 |

## 1. Alcance y principios

1. **La causa es de arquitectura, no del modelo.** El E2E #3
   (`docs/missions/TEST_E2E_BOUNTY_HACKER_RUN3.md` §5-§6) demostró que
   `gpt-oss-120b` hizo tres acciones correctas y verificadas, no alucinó evidencia
   y no falseó un cierre: se detuvo ante un bloqueo **del sistema**. Aquí se ataca
   ese bloqueo, no su síntoma.
2. **Docs-as-code**: este documento explica el *porqué* de cada decisión, incluidas
   las que se descartaron y por qué.
3. **Gobernanza intacta**: scope firmado, cadena de auditoría, fail-closed,
   aprobaciones durables y anti-injection **no se han tocado**. Un subconjunto de
   subagente solo puede *reducir* la superficie: nada de lo añadido amplía
   autoridad (ni siquiera la gracia de §2.2, que solo hereda tools de solo lectura).
4. **Fix, no workaround**: se corrige la selección de perfil y la ventana en que se
   pierden las tools, no se añade un caso especial para FTP ni para esta sala.
5. **Compatible con Groq** (`openai/gpt-oss-120b`): el modelo por defecto **no
   cambia** en esta fase.
6. **Presupuesto de líneas**: el encargo pide un fix pequeño (~90 líneas). El conteo
   real, con desglose y desviación, está en §6.

Fuera de alcance (documentado, no implementado): preflight de más binarios, activar
DeepSeek V4.1 Flash (Fase 4) y cualquier heurística basada en puertos (§2.1).

## 2. P0 — Enumeración consciente del servicio

### 2.1 Problema y decisión

El planner cierra `recon` con el primer hecho `service` (`Phase.evidence =
("host","service")`) y `PHASE_SUBAGENT["enumeration"]` apuntaba a **`web`**, cuyo
subconjunto no incluye `nexus.recon.ftp` (estaba en `recon` y `cred`). Con un
objetivo cuyo primer servicio enumerable no es web, `_refine()` no tenía a dónde
promocionar (solo promociona a `cred` con hechos `user`/`credential`), así que la
fase quedaba en un perfil que no podía tocar ese servicio: **dependencia circular**
(para enumerar FTP hacía falta FTP; para que el planner diera `cred` hacía falta un
hecho `user` que solo se obtiene enumerando FTP).

**Solución implementada (la correcta, no la mínima):**

- Perfil nuevo **`services`** (fase `enumeration`) con
  `nexus.recon.ftp` + `nexus.recon.netexec` + el subconjunto web completo
  (`WEB_ENUM_TOOLS`, extraído para no duplicar la lista).
- `PHASE_SUBAGENT["enumeration"] = "services"`: la enumeración **entra** por el
  perfil de servicios (cualquiera) y `_refine()` la **estrecha** a `web` cuando
  aparecen hechos `endpoint`/`vulnerability`, y a `cred` cuando hay `user`/`credential`.

Decisiones de diseño y por qué:

- **¿Por qué `services` incluye las tools web?** El encargo pedía «elegir `services`
  solo si el `service` NO es http/https». Implementar esa distinción exige saber el
  tipo de servicio, y el planner solo ve **cuentas** por tipo (`Blackboard.summary()`
  devuelve `counts`), no el detalle del hecho. Las dos alternativas eran (a) hacer
  heurística por puerto (21/22/445… = no web) o (b) propagar el tipo de servicio
  (tocando `Blackboard.summary`, `Plan`, `build_plan`, `plan_from_summary` y sus
  consumidores). Ambas son **peores**: la primera es frágil (HTTPS en 8443, HTTP en
  8080) y la segunda crece la superficie del planner para una decisión que no la
  necesita. Con `services` siendo superconjunto, la propiedad que importa se cumple
  sin heurísticas: **cualquier servicio hallado es enumerable desde el primer
  momento**, y el perfil no puede volver a crear un callejón sin salida. `web` se
  mantiene como refinamiento (subconjunto estricto) para cuando ya hay evidencia web.
- **¿Por qué `read_only=False`?** `nexus.recon.netexec` está en `ACTIVE_TOOLS`
  (puede ejecutar comandos con credenciales) y `validate_registry` prohíbe que un
  perfil read-only lo liste. Se ha preferido **no tocar la clasificación** (dos
  clasificaciones independientes son una invariante de la fase 3A) y aceptar que
  `services` no sea paralelizable (`parallel_safe=False`). Excluir netexec habría
  movido la dependencia circular a SMB, que es el caso más común después de HTTP.
- **¿Por qué no se tocó `_refine` para detectar servicios?** No hacía falta: con el
  perfil por defecto cubriendo ambos mundos, el refinamiento sigue siendo
  evidencia→perfil (`web`/`cred`), que es lo que ya estaba probado.

### 2.2 Desviación respecto al texto del encargo: «scripts de nmap»

El encargo pedía incluir «Scripts de nmap (ftp-anon, smb-enum, etc.)» en el perfil
`services`. **No es posible sin tocar la gobernanza de la herramienta**: el handler
de nmap aplica `NMAP_FORBIDDEN_FLAGS`, que prohíbe `--script`, `--script-args` y
`-A` (un NSE puede ejecutar Lua arbitrario contra el objetivo), y los perfiles
duros son solo `quick`/`full_tcp`/`service`/`top_udp`. La enumeración FTP/SMB real
de esta arquitectura se hace con `nexus.recon.ftp` (LIST/DOWNLOAD, verificado
contra el objetivo real en la fase 3.6 §4) y `nexus.recon.netexec`. Levantar la
prohibición de `--script` es una decisión de política que **no** corresponde a un
fix de enumeración; queda registrada en `BACKLOG.md`.

### 2.3 Tests de regresión

- `test_subagents.py::test_enumeration_with_only_a_service_fact_can_still_enumerate_it`
  (un `service` suelto ⇒ `services`, con `ftp` y `netexec`, y `WEB_ENUM_TOOLS`
  alcanzable desde el mismo perfil; `web` sigue sin `ftp`).
- `test_subagents.py::test_expected_profiles_exist` y
  `test_selection_follows_the_kill_chain[enumeration-services]` actualizados.
- `test_enumeration_fix.py::test_first_service_fact_keeps_the_tools_that_enumerate_it`
  (extremo a extremo en el bucle: el prompt de la iteración de enumeración ofrece
  `nexus.recon.ftp`).

## 3. P1 — No perder las tools de recon al cerrar la fase

### 3.1 Problema

`recon` se cierra en la **misma iteración** en que se registra el primer `service`,
así que las herramientas que descubrieron el servicio (y que aún hacen falta para
enumerarlo) desaparecían en el instante en que se necesitaban. P0 arregla el
subconjunto de la fase nueva, pero no impide perder `nexus.recon.nmap` /
`nexus.recon.subfinder` — que siguen siendo útiles (p. ej. `top_udp`, versiones
ampliadas) justo después de la transición.

### 3.2 Solución: `with_phase_grace`

Función nueva en `subagents.py`:

- Durante las **2 primeras iteraciones** de un perfil nuevo
  (`PHASE_GRACE_ITERATIONS = 2`), el perfil se **ensancha** con las tools del perfil
  anterior **que sean de solo lectura** (`previous.tools - ACTIVE_TOOLS`). La gracia
  no puede heredar `nexus.cred.bruteforce` ni `nexus.attack.*`, aunque estuvieran en
  el perfil previo.
- El perfil anterior se **congela** durante la ventana (`previous_profile`), en vez
  de sobrescribirse en la iteración siguiente: si no, la gracia duraría una única
  iteración. Está cubierto por
  `test_first_service_fact_keeps_the_tools_that_enumerate_it` (nmap corre en las
  iteraciones 2 y 3, y en la 4 el mismo tool ya es denegado por subconjunto).
- El resultado es un **perfil derivado** (`dataclasses.replace`), no una segunda
  comprobación de permisos: el prompt que ve el modelo y el subconjunto que impone
  el bucle siguen siendo **el mismo objeto**, que es la invariante declarada en el
  docstring de `subagents.py`.

**Por qué NO cambiar `Phase.evidence` de `recon`** (la otra alternativa del
informe): exigir «servicio enumerado» para cerrar `recon` obliga a que el planner
lea el detalle de los hechos y a definir qué cuenta como «enumerado» — más
superficie, más fragilidad y una decisión de producto, no un fix. La gracia
consigue el efecto práctico (no perder las tools) sin tocar el planner, que sigue
siendo determinista y solo guiado por el blackboard.

### 3.3 Tests de regresión

`test_subagents.py::test_phase_grace_inherits_only_read_only_tools_for_two_iterations`,
`…::test_phase_grace_never_inherits_active_tools` y
`test_enumeration_fix.py::test_first_service_fact_keeps_the_tools_that_enumerate_it`.

## 4. P2 — Que el bloqueo por subconjunto no termine el run

### 4.1 Implementado: `--subagent <id>` (headless y TUI) y `/subagent`

El bucle ya aceptaba `payload["subagent"]` como pin del operador, pero **la CLI no lo
exponía**: un operador cuyo run se había bloqueado por perfil no podía retomarlo
(`--resume`) con el perfil correcto sin editar la base de datos.

- `nexus_core/cli/main.py`: flag `--subagent ID` con `choices=SUBAGENT_IDS` (argparse
  rechaza un id inventado antes de arrancar; sigue siendo un pin **explícito**, nunca
  automático) y se pasa a `OmniSession(subagent=...)`. El flag vale para **headless y
  TUI**, porque ambos ejecutan objetivos por la misma sesión.
- `nexus_core/cli/session.py` / `headless.py`: `subagent_override` viaja en el
  payload de `react.run`, que es el canal que el bucle ya leía.
- `nexus_core/cli/commands.py`: comando meta `/subagent [ID|auto]` para el REPL/TUI,
  donde no hay flags: muestra el pin activo, lo fija o lo limpia. Un id desconocido
  se **rechaza** (no se propaga al run) y `subagents.select_subagent` sigue siendo
  fail-closed por si el pin llegara por otra vía.

### 4.2 NO implementado (y por qué): avance automático del plan

El informe proponía, como alternativa «mejor», que ante un tool denegado por
subconjunto el bucle **cierre la fase y avance el plan de forma determinista**. Se
ha descartado a propósito:

1. El planner es determinista y **solo** guiado por el blackboard; el propio código
   lo documenta (`react.py`, timeout de fase: «the phase itself is NOT
   auto-advanced: … fabricating progress would corrupt the plan»). Avanzar por una
   denegación sería que una acción del modelo mutara el plan, justo lo que la
   arquitectura evita.
2. Con P0+P1 el caso que lo motivaba (denegación por un subconjunto que no puede
   tocar el servicio hallado) ya no ocurre, y el avance automático daría al modelo
   un camino trivial para **saltarse fases** (proponer un tool de la fase siguiente
   para forzar el salto).
3. Un plan que avanza sin evidencia ensucia la trazabilidad del engagement y del
   reporte, que se apoyan en los hechos registrados.

La denegación sigue siendo fail-closed, auditada (`subagent_tool_denied`) y ahora
**explica** al modelo qué tools le quedan; y el operador tiene el pin de §4.1.

### 4.3 Tests de regresión

`test_enumeration_fix.py::test_subagent_flag_is_exposed_and_validated`,
`…::test_operator_pin_reaches_the_headless_payload`,
`…::test_repl_subagent_command_sets_and_clears_the_pin`.

## 5. P3 — Observabilidad

`orchestrator.subagent` (que ya llevaba `subagent_id`, `previous`, `phase`,
`read_only` y `token_budget`) ahora lleva además **`tools`**: el subconjunto del
perfil activo, ordenado. Es el campo que habría hecho visible en vivo el bloqueante
P1 del E2E #3 (el perfil `web` **sin** `nexus.recon.ftp`). Se registra el
subconjunto del **perfil** (no se restan las tools retiradas por fallo): una tool
retirada por binario ausente se anuncia aparte, en la iteración 0, con
`react.tool_unavailable`.

Test: `test_enumeration_fix.py::test_service_profile_is_announced_with_its_effective_subset`
(comprueba la secuencia `recon` → `services`, el `previous`, y que el subconjunto
anunciado es el que el bucle impone en esa iteración).

## 6. Presupuesto de líneas

Conteo real (`git diff --numstat`, sin contar tests ni docs):

| Fichero | Líneas añadidas | Qué añade |
| --- | --- | --- |
| `nexus_core/agent/subagents.py` | 78 | (perfil `services`, `WEB_ENUM_TOOLS`, `PHASE_SUBAGENT`, `with_phase_grace`) |
| `nexus_core/agent/react.py` | 26 | (hilado de la gracia + `tools` en el evento) |
| `nexus_core/cli/main.py` | 12 | (flag `--subagent`) |
| `nexus_core/cli/session.py` | 6 | (pin en la sesión y en el payload) |
| `nexus_core/cli/headless.py` | 3 | (pin en el payload headless) |
| `nexus_core/cli/commands.py` | 21 | (`/subagent` del REPL) |
| **Total** | **146** | **98 de código** (+48 de comentarios/docstrings/blancas) |

**Desviación honesta**: 98 líneas de código frente al objetivo «~90». El exceso
(+8) es el comando `/subagent` del REPL (parte de «headless **y TUI**» del encargo:
la TUI no tiene flags). Si el operador prefiere la lectura estricta de ~90, ese
comando es la única pieza prescindible sin perder ningún otro entregable: el flag
`--subagent` ya cubre headless y la ejecución de objetivos desde la TUI. **No se
amplió el alcance** en ninguna otra dirección: no hay preflight nuevo, ni cambios de
modelo, ni un segundo fix «de paso».

Tests añadidos (aparte): `test_subagents.py` (+37/−1) y
`test_enumeration_fix.py` (nuevo, 5 tests, 307 líneas).

## 7. Verificación reproducible

```bash
set -o pipefail
.venv/bin/python -m pytest nexus_core/tests/unit -q        # 2173 passed, 1 skipped
.venv/bin/python -m pytest nexus_core/tests -q             # 2189 passed, 33 skipped, 0 failed
.venv/bin/python -m pytest nexus_core/tests/integration -q # 16 passed, 32 skipped
.venv/bin/python -m ruff check <8 ficheros> --select F,E9  # All checks passed
.venv/bin/python -m compileall -q <8 ficheros>             # OK
.venv/bin/python -m mypy <8 ficheros> --ignore-missing-imports --follow-imports=skip
.venv/bin/python omni.py --version                         # omni 3.0.0
.venv/bin/python omni.py --help | grep subagent
```

`mypy --follow-imports=skip` sobre los 8 ficheros tocados: 6 hallazgos, **todos
preexistentes** y fuera de las líneas modificadas (`react.py:399`;
`commands.py:560,941,1425,1427,1428`). Ninguno nuevo.

## 8. Desviaciones respecto al encargo (resumen)

| Encargo | Decisión | Motivo |
| --- | --- | --- |
| `services` con «scripts de nmap» | No incluidos | `NMAP_FORBIDDEN_FLAGS` prohíbe `--script`/`-A`; es política, no fix (§2.2) |
| Elegir `services` «si el servicio no es http/https» | `services` es superconjunto; la distinción se hace por **evidencia**, no por puerto | Evita heurística frágil y evita tocar el planner/kernel (§2.1) |
| Unión de fases «en las 2 primeras iteraciones de `enumeration`» | Generalizado a **cualquier** cambio de perfil, solo tools de solo lectura | Misma semántica, sin caso especial; la gracia no puede ampliar autoridad (§3.2) |
| P2 «alternativa mejor»: avance determinista del plan | **No** implementado | Fabricaría progreso y permitiría saltar fases (§4.2) |
| ~90 líneas | 98 de código | +8 = `/subagent` del REPL; se documenta y se ofrece retirarlo (§6) |

## 9. E2E #4 contra "Bounty Hacker" (10.0.0.1)

Informe completo: `docs/missions/TEST_E2E_BOUNTY_HACKER_RUN4.md`. Artefactos NDJSON:
`examples/e2e-bounty-hacker-run4a.ndjson` (run A, completo) y
`examples/e2e-bounty-hacker-run4b-partial.ndjson` (run B, traza parcial).

- **Run A** — engagement nuevo `eng-4d3a421e6284` (`bounty-hacker-4`,
  `cidrs=['10.0.0.1/32']`): el scope firmado del engagement anterior no se
  amplía para acomodar una IP nueva (gobernanza intacta). Desde cero, **no
  completó**: `subagent_budget_exceeded` tras 9 iteraciones. Hizo la cadena FTP
  completa (list, download de `locks.txt` y `task.txt`, `workspace.read`) pero
  **nunca registró un hecho**, así que el planner no pudo salir de `recon` y el
  modelo re-escaneó hasta que el guardarraíl de presupuesto lo cortó.
- **Run B** — mismo objetivo, engagement del E2E #3 (plan ya en `enumeration`), el
  escenario exacto que se bloqueó. **P0 verificado en vivo**: perfil `services`
  (15 tools) → FTP enumerado → `credential` registrado → plan avanzado a
  `exploitation` (`orchestrator.subagent → exploit`, `previous=services`). **No
  completó**: el modelo necesitó 4 intentos para registrar un hecho válido y luego
  gastó 5 iteraciones en `nexus.exploit.msf_*` con el RPC de Metasploit sin
  configurar. El proceso se terminó externamente en la iteración 15/16 (sin
  `run.complete`).

**Veredicto**: el bloqueante de arquitectura está arreglado (la cadena que era
imposible en el E2E #3 ahora funciona); lo que queda es **el modelo**. Se propone
activar **DeepSeek V4.1 Flash** (infraestructura lista desde la Fase 3.6) para la
Fase 4 y **no seguir iterando sobre la arquitectura**, según el encargo.

## 10. Atribución

BAJIOWARE · Team Red. Causa raíz y plan P0-P3 propuestos en la Fase 3.6
(`TEST_E2E_BOUNTY_HACKER_RUN3.md` §5-§7); implementación y verificación en esta fase.
