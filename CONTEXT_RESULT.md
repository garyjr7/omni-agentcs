# CONTEXT_RESULT — medidas después de los cambios

Fecha: 2026-10-01. Rama: `feat/context-continuity-report`.
Base: `90fb7f5`. 26 tools durables.
Recon previo: `CONTEXT_RECON.md` (medidas antes).

## Resumen

| Criterio | Antes | Después |
|---|---|---|
| Conversaciones por engagement | 1 por run (`react:<run_id>`) | 1 sesión de trabajo `work:<engagement>` compartida |
| `/ask` | historial local en memoria, no persiste | escribe en la sesión de trabajo (`source=ask`) |
| `/clear` | resetea `conversation_id` local | rota a una sesión nueva y archiva la anterior |
| Catálogo renderizado | 19 313 chars | **4 880 chars** |
| Prompt de sistema | 40 523 chars | **7 105 chars** |
| `nexus.recon.nmap` en el prompt | 3 | **1** |
| Presupuesto de tokens por run | no existe | `NEXUS_RUN_BUDGET_TOKENS` (+ `budget_tokens` en payload) |
| Tools representadas en el reporte | 6 | **16** (las 10 nuevas incluidas) |
| Secciones del reporte | findings / failed / timeline | + inventario / referencias / superficie / evidencia |
| Schema JSON del reporte | `nexus.engagement_report/1` | **`nexus.engagement_report/2`** |
| Suite de tests | 1350 passed, 30 skipped | **1391 passed, 30 skipped** |

## Fase 1 — continuidad conversacional (hallazgo #7)

### Diseño implementado

- `nexus_core/agent/memory.py`: helpers de sesión de trabajo
  (`work_session_title`, `find_work_conversation`, `ensure_work_conversation`,
  `start_work_conversation`, `prior_objectives`).
- `nexus_core/cli/session.py`: `OmniSession._ensure_work_session()` y
  `rotate_work_session()`. `run_objective` reutiliza la sesión y pasa
  `conversation_id=` a `run_react_loop`; cada objetivo sigue creando su propio
  run (trazabilidad y auditoría intactas).
- `nexus_core/agent/react.py`: parámetro opcional `conversation_id`; el
  bookkeeping de reanudación (action log + cursor de iteración) se limita al run
  actual, y los objetivos previos se exponen al modelo en el contexto de sesión.
- `nexus_core/cli/commands.py`: `cmd_ask` persiste en la sesión de trabajo;
  `cmd_clear` rota (`/history --archive` consulta las sesiones archivadas);
  `cmd_history` gana `--archive`.
- `nexus_core/agent/prompts.py`: el prompt explica que el historial puede
  contener objetivos, `/ask` y aclaraciones de la misma sesión.

### Ejemplo multi-objetivo

Antes:

```text
> objetivo A   → run_1  + conversación react:run_1
> objetivo B   → run_2  + conversación react:run_2   (el LLM NO ve A)
> /ask "..."   → ask_history local (no persiste, no comparte)
```

Después:

```text
> objetivo A   → run_1 ┐
> objetivo B   → run_2 ┤→ conversación work:eng-1 (misma)
> /ask "..."   →        ┘  (append con metadata source=ask)
```

Verificado por `test_e2e_multi_objective_context.py`: el prompt del segundo
objetivo contiene `Escanea el host 10.0.0.5` (objetivo previo) y
`Ahora enumera SMB en ese host` (objetivo actual), y una sola conversación
`work:` acumula ambos.

## Fase 2 — optimización de contexto (hallazgo #8)

- Eliminada la segunda aparición del catálogo en `REACT_SYSTEM_PROMPT`.
- `render_tool_catalog` emite una línea compacta por tool
  (`- id: desc | args[name:type*…] | riesgo:X | scope:field`) sin el JSON schema.
- Presupuesto por run: `NEXUS_RUN_BUDGET_TOKENS` (0 = sin límite) leído por
  `execute_react` y por `run_react_loop`; al agotarse, el run termina con estado
  `budget_exceeded` y registra un `react.budget_exceeded` con tokens usados.
  Los tokens de cada respuesta se contabilizan en `kernel_usage_ledger`.
- `.env.example` documenta `NEXUS_RUN_BUDGET_TOKENS=0`.

Medición real:

```text
catalog chars: 4880
prompt chars: 7105
nmap count: 1
```

## Fase 3 — reporte extendido (hallazgo #6)

Nueva representación por tool:

| Tool | Representación | Severidad |
|---|---|---|
| `nexus.web.sqlmap` | Finding (`sqli`) | high |
| `nexus.web.dalfox` | Finding (`xss`) | medium |
| `nexus.recon.gobuster` | Inventory | — |
| `nexus.recon.whatweb` | Inventory | — |
| `nexus.exploit.searchsploit` | Reference | — |
| `nexus.recon.netexec` | Surface | — |
| `nexus.recon.bloodhound_python` | Evidence | — |
| `nexus.attack.impacket_secretsdump` | Finding (`credentials`) | critical |
| `nexus.attack.impacket_getuserspns` | Finding (`kerberoast`) | high |
| `nexus.attack.impacket_psexec` | Finding (`remote_exec`) | critical |

- `models.py`: `ReportItem` (kind `inventory`/`reference`/`surface`/`evidence`)
  y `EngagementReport.inventories/references/surfaces/evidences`; `to_dict` y
  digest actualizados.
- `extractor.py`: builders por tool + `extract_report_items` (+ wrapper sync).
- `data/tool_ttp_map.json`: MITRE de las 10 tools.
- `data/mitre_techniques.json`: añadidas T1059.007, T1588.005, T1069, T1482,
  T1003.003, T1558.003, T1021.002.
- `markdown.py` / `html.py`: secciones Inventario, Referencias, Superficie
  expuesta y Evidencia adicional (HTML con color por tipo: verde inventario,
  azul referencia, amarillo superficie, gris evidencia). Schema `/2`.

Secciones del reporte generado (E2E `test_e2e_full_report_covers_all_tool_types`):

```text
## Hallazgos
## Inventario              → Rutas descubiertas / Stack tecnológico identificado
## Referencias             → Exploits disponibles
## Superficie expuesta     → Superficie smb observada
## Evidencia adicional     → Mapa de Active Directory recolectado
## Cronología
```

## Verificación

```text
10 imports OK
26 tools
NO_COLOR=1: 1391 passed, 30 skipped
sin NO_COLOR: 1391 passed, 30 skipped
tests nuevos + E2E: 41 passed
ruff check --select F,E9: All checks passed
subprocess/Popen/os.system/shell=True en agent/report: ninguno
prompt < 18000 chars (7105) y catálogo aparece 1 vez
```

Tests añadidos/actualizados:

- `test_work_session_persistence.py` (7), `test_react_loop_work_session.py` (3).
- `test_prompt_optimization.py` (7), `test_run_budget.py` (9).
- `test_report_extended.py` (12).
- E2E: `test_e2e_multi_objective_context.py` (2),
  `test_e2e_full_report_covers_all_tool_types.py` (1).

## Cambios de contrato (internos)

- `/ask` deja de usar `session.ask_history` local: ahora persiste en la sesión
  de trabajo (`test_cli_ask_command.py` adaptado).
- `/clear` rota la sesión de trabajo en vez de solo resetear el contexto local
  (`test_cli_commands.py` adaptado).
- Schema del reporte JSON `nexus.engagement_report/1` → `/2`
  (`test_report_render.py` adaptado).

No se tocaron PolicyEngine, ScopeValidator, AuditWriter, `sandbox.py` ni las
firmas públicas de ToolGateway/`execute_tool`/`execute_react`.
