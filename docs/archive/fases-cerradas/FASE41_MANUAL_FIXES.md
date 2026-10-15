# Fase 4.1 — Cierre de los 7 hallazgos del RUN7 (motor de tools)

**Autor:** BAJIOWARE · Team Red
**Fecha:** 2026-10-07
**Rama:** `feat/manual-fixes-phase-4-1`
**Origen:** `TEST_MANUAL_BOUNTY_HACKER_RUN7.md` §4.
**Objetivo:** pulir el motor de herramientas para que el **agente autónomo** las
use sin fricción. El modo manual gobernado queda como capacidad de primera clase.

> Reglas de oro respetadas: gobernanza intacta (scope, audit, fail-closed,
> anti-injection), **fix y no workaround**, un test de regresión por hallazgo,
> honestidad radical en lo que no se pudo verificar.

---

## H1 — Truncar el XML crudo de nmap

- **Problema.** `nexus.recon.nmap` devolvía el XML completo (~30 KB) en
  `ToolResult.stdout` aun existiendo `output.scan` ya parseado. En el bucle ReAct
  esto inunda el contexto del modelo (ITPM 7000) y alimenta las explosiones de
  contexto de los E2E.
- **Solución.** Cuando existe `output.scan`, `stdout` se recorta a
  `NMAP_STDOUT_MAX_BYTES = 500` bytes (corte byte-safe con decodificación
  tolerante) y se marca `output["stdout_truncated"] = true` (+ el mismo flag en
  `evidence`). El XML **se parsea antes** de recortar, así que `output.scan` y
  `raw_xml_sha256` quedan intactos. Las rutas de timeout y de XML inválido no
  recortan (no hay `output.scan` y ese stdout sí ayuda a depurar).
- **Archivos.** `nexus_core/tools/handlers/nmap.py` (constante `NMAP_STDOUT_MAX_BYTES`,
  `truncate_stdout()`), tests en `nexus_core/tests/unit/test_nmap_handler.py`.
- **Tests.** `test_handler_truncates_raw_xml_stdout_when_scan_is_parsed`
  (XML > 30 KB → `stdout` ≤ 500 B, `scan` intacto, sha256 sobre el XML completo),
  `test_handler_keeps_small_stdout_intact`, `test_truncate_stdout_is_byte_safe`.

## H2 — `report.generate` hereda el `engagement_id`

- **Problema.** `nexus.report.generate` exigía `engagement_id` en los argumentos
  pese a que la sesión ya tiene un engagement activo firmado; incoherente con el
  resto de tools.
- **Solución.** `engagement_id` pasa a ser **opcional** en el `input_schema`. El
  handler usa el argumento explícito si existe y, si no, el engagement activo del
  contexto (`context.scope.engagement_id`). Si no hay ninguno de los dos,
  devuelve `report_missing_engagement` (fail-closed, sin inventar alcance).
- **Archivos.** `nexus_core/tools/handlers/report_generate.py`, tests en
  `nexus_core/tests/unit/test_report_handler.py`.
- **Tests.** `test_report_inherits_active_engagement` (sin argumento → engagement
  activo), `test_report_without_engagement_is_not_verified`, y
  `test_report_validates_arguments` (el resto del esquema sigue validándose).

## H3 — Los hechos alimentan findings e inventario

- **Problema.** Tras registrar `credential`/`access`/`privilege`/`vulnerability`,
  el informe seguía mostrando 1 finding y «Inventario: no registrado»: la cadena
  de compromiso no se reflejaba.
- **Solución.** El extractor lee el blackboard del engagement
  (`Blackboard.list_facts`) y mapea **cada hecho a un finding** (severidad y
  metadatos por `FACT_TYPES`: `privilege`→critical, `credential`/`access`/
  `vulnerability`/`session`/`loot`→high, resto→info) y a **un item de inventario**
  con el recuento por tipo. La lectura es best-effort: un blackboard roto nunca
  tumba el informe. El `source` del hecho se conserva como `discovered_by_tool`.
- **Archivos.** `nexus_core/report/extractor.py` (`_load_facts`, `_fact_findings`,
  `_fact_inventory`, `_FACT_SEVERITY`, `_FACT_META`), tests en
  `nexus_core/tests/unit/test_report_extended.py`.
- **Tests.** `test_facts_become_findings_and_inventory` (los **8 hechos del RUN7 →
  8 findings** + inventario poblado y renderizado con «Inventario del engagement
  (8 hecho(s))»), `test_no_facts_means_no_inventory`.

## H4 — `omni tool` como subcomando de primera clase

- **Problema.** No había forma oficial de invocar una tool suelta; el RUN7 usó un
  script auxiliar (`scripts/omni_tool.py`).
- **Solución.** Nuevo `nexus_core/cli/tool.py` y subcomando `omni tool`:
  - `omni tool --list` lista las tools durables del tenant (no requiere
    engagement: se resuelve antes de la selección).
  - `omni --engagement ID tool <tool_id> '<json>'` invoca **una** tool por la
    **misma puerta gobernada** (`OmniSession.invoke_tool` → `execute_tool`).
    (Convención argparse: los flags van antes o después del grupo posicional
    `<tool_id> '<json>'`, nunca en medio.)
  - `--trust-mode` se reenvía (auto-aprobación de alto riesgo); el subcomando no
    tiene stdin interactivo, así que deniega por defecto (fail-closed).
  - Códigos de salida: `0` verificado, `1` denegado/fallido/sin verificar, `2`
    error de uso (JSON inválido).
- **Archivos.** `nexus_core/cli/tool.py` (nuevo), dispatch en
  `nexus_core/cli/main.py` (flag `--list`), tests en
  `nexus_core/tests/unit/test_cli_tool_command.py`.
- **Tests.** Invocación (`test_run_tool_command_invokes_and_prints`,
  `test_main_tool_invokes_through_the_session`), scope
  (`test_run_tool_command_blocks_out_of_scope_target`), aprobación
  (`test_run_tool_command_denies_high_risk_without_trust_mode`), listado y parseo.
  El antiguo `scripts/omni_tool.py` queda superado por el subcomando.

## H5 — Declarar `paramiko` y retirar `nexus.post.*` si falta

- **Problema.** `paramiko` no estaba declarado aunque `ssh_post` lo requiere;
  funcionaba por el `python3` del sistema, no por una dependencia explícita.
- **Solución.** `paramiko>=3.4,<4` se declara en `requirements-prod.in`. El
  preflight incorpora un sondeo de **módulos Python en runtime**
  (`nexus_core/provisioner/runtime_deps.py`) y, si falta `paramiko`, **retira**
  `nexus.post.ssh_exec` y `nexus.post.enum_system` para el run (B3): no se gasta
  una iteración descubriendo `ssh_unavailable`. Un módulo ausente **no bloquea**
  el run, solo retira tools (igual que B6 con binarios).
- **Archivos.** `requirements-prod.in`, `nexus_core/provisioner/runtime_deps.py`
  (nuevo), `nexus_core/agent/preflight.py` (`_unavailable_tools`,
  `preflight_binaries(module_finder=...)`, `unavailable_tools_from_env(module_finder=...)`),
  tests en `nexus_core/tests/unit/test_binaries.py`.
- **Tests.** `test_missing_python_module_retires_its_tools`,
  `test_preflight_retires_ssh_tools_without_paramiko`,
  `test_unavailable_tools_from_env_includes_missing_modules`. Los tests de
  binarios existentes fijan el sondeo de módulos (`module_finder`) para seguir
  siendo herméticos.

## H6 — Coste/beneficio manual vs. agente

- **Acción.** `docs/missions/MANUAL_VS_AGENT.md`: tabla comparativa RUN #6
  (agente) vs RUN #7 (manual) — fases alcanzadas, tokens, tiempo, tasa de éxito,
  gobernanza — con lectura, recomendación de uso y límites de la comparación.
- **Sin tests** (documento).

## H7 — Capturar `ScopeViolation` en `invoke_tool`

- **Problema.** `OmniSession.invoke_tool` capturaba
  `(PermissionError, ValueError, RuntimeError, KeyError, TypeError)`, pero
  `ScopeViolation` hereda de `Exception`. Una llamada fuera de alcance **se
  bloqueaba correctamente (fail-closed, el target nunca se toca)** pero reventaba
  con un traceback en lugar de un error limpio.
- **Solución.** `invoke_tool` captura `ScopeViolation` y renderiza un mensaje de
  scope limpio (`<tool> bloqueado por scope: <motivo> (target: <target>)`),
  devolviendo `None` sin traceback. **No cambia el comportamiento de seguridad**:
  la ejecución se seguía bloqueando antes de tocar el target; solo se arregla la
  presentación en la ruta manual.
- **Archivos.** `nexus_core/cli/session.py` (import + rama `except ScopeViolation`),
  tests en `nexus_core/tests/unit/test_cli_tool_command.py`.
- **Tests.** `test_invoke_tool_renders_scope_violation_without_traceback` y
  `test_run_tool_command_blocks_out_of_scope_target` (mensaje limpio, sin
  `Traceback`, salida `1`).

---

## Verificación

Comandos ejecutados en la rama `feat/manual-fixes-phase-4-1` (venv `.venv`,
Python 3.14):

```
.venv/bin/python -m pytest nexus_core/tests -q          # suite completa
.venv/bin/python -m ruff check --select F,E9 nexus_core  # lint acotado
.venv/bin/python -m compileall -q nexus_core            # importabilidad
```

Resultado (baseline Fase 4.0 = 2218 passed, 33 skipped):

- **pytest:** **2245 passed, 33 skipped** (27 tests de regresión nuevos: H1 ×3,
  H2 ×2, H3 ×2, H4/H7 ×17, H5 ×3).
- **ruff `F,E9`** (`make lint`, incluye `omni.py`/`nexus_worker.py`): limpio.
- **compileall** (`make syntax`): limpio.
- **mypy:** el repo **no tiene configuración de mypy**, así que no es una puerta
  fija del proyecto: ejecutado en crudo reporta ~163 errores preexistentes en
  fuente (y ~181 contando tests), sin relación con esta fase. En los módulos
  nuevos (`cli/tool.py`, `provisioner/runtime_deps.py`) y en los tocados
  (`preflight.py`, `nmap.py`, `report_generate.py`) mypy no añade errores nuevos;
  el único en una línea nueva (`extractor.py` `_fact_targets`) reproduce el
  patrón `Any | dict | None` ya presente en el propio fichero (líneas 579-580).

### Gobernanza

Ninguno de los cambios relaja scope, aprobación, auditoría ni anti-injection.
H2 y H3 solo **leen** el alcance/blackboard activos; H4 entra por
`OmniSession.invoke_tool` (misma puerta); H5 retira tools (más fail-closed); H7
solo mejora el mensaje de un bloqueo que ya ocurría. La llamada fuera de alcance
sigue bloqueándose antes de tocar el objetivo.
