# ÍNDICE DOCUMENTAL — OmniAgentCS

> Última revisión: 2026-10-21 · Commit documental: 1a96924 · Código auditado: 430dcfb
> Regla: solo UN documento por tema es VIGENTE. El resto es histórico o archivado.
> La reorganización que introduce este índice es el commit `docs: reorganize documentation into INDEX + archive, clean root`, aplicado sobre la línea base `363bba9`.
> Ubicaciones: `/` = raíz del repo · `docs/missions/` = misiones y resultados abiertos · `docs/archive/` = material superado, solo consulta.

---

## Verdad vigente por tema

| Tema | Documento VIGENTE | Ubicación | Notas |
|---|---|---|---|
| Producto, instalación y CLI | `README.md` | `/` | Verdad del producto v3.0.0: tools, comandos, gobernanza |
| Historial de versiones | `CHANGELOG.md` | `/` | v3.0.0 actual (rename a OmniAgentCS) |
| Deuda y backlog | `BACKLOG.md` | `/` | Ledger único de deudas V0/V1/V2 (P1-A/B/C) |
| Instrucciones de proyecto para el agente | `OMNI.md` | `/` | Contexto no confiable, delimitado y auditado |
| Guía de uso manual de las OMNI tools | `GUIA_MANUAL_1.md` | `docs/guides/` | 68 tools gobernadas paso a paso, sin LLM |
| Guía del agente autónomo y comandos `/` | `GUIA_AGENTE_1.md` | `docs/guides/` | ReAct, subagentes, playbooks y los 41 comandos `/` |
| Auditoría UX/CLI | `AUDIT_POTENCIA_CLI.md` | `docs/archive/audits/` | 8.3/10, sustituye a `AUD_OMNI_BW` |
| Auditoría técnica integral | `AUDIT_POT_XCLAUDE_CLI.md` | `docs/archive/audits/` | 6,0/10, segunda opinión; origen de Fase 0/1/2 |
| Auditoría del cuerpo | `FASE_V1_AUDITORIA_CUERPO_PROMPT.md` | `docs/missions/` | Prompt de auditoría V1; resultados en `audit-v1/` y clasificados en `MASTER_ROADMAP.md` |
| Resultado de la auditoría V1 | `docs/missions/audit-v1/00_DICTAMEN.md` | `docs/missions/audit-v1/` | 12 informes + `audit_v1.json` + `catalog.json` |
| **Plan maestro / roadmap** | **`MASTER_ROADMAP.md`** | **`docs/`** | **Documento único de verdad**: inventario de auditorías, matriz [HECHO]/[PENDIENTE]/[BLOQUEADO]/[DESCARTADO] y plan P0–P4 |
| Plan estratégico | `PLAN_OMNIAGENTCS_V4.md` | `docs/missions/` | Parcialmente ejecutado, ver §10; sus promesas se clasifican en `MASTER_ROADMAP.md` |
| Comparación manual/agente | `MANUAL_VS_AGENT.md` | `docs/missions/` | n=1, no concluyente |
| Fase 2 (cerrada) | `FASE2_ORQUESTACION_AVANZADA.md` | `docs/missions/` | Cerrada con límites declarados; deuda viva en `MASTER_ROADMAP.md` §3.4 |
| Auditoría MCP y PTY | `AUDITORIA_ARQUITECTONICA_MCP_PTY_2026-10-21.md` | `docs/missions/` | Veredicto y orden P0–P4; base de `MASTER_ROADMAP.md` §4 |
| Roadmap técnico post-auditoría | `roadmap_12/10.md` | `roadmap_12/` | **WIP no versionado — no forma parte del ledger oficial** |
| Cleanup de código legado | `CLEANUP_RESULT_V3.md` | `docs/missions/` | Resultado final; decisiones por archivo en `CLEANUP_DECISIONS.md` |
| Decisiones de arquitectura | `ADR-004-sandbox-modes.md`, `ADR-005-surface-coverage-ledger.md`, `ADR-006-blackbox-default-authorization.md` | `docs/adr/` | Aceptadas; modos de sandbox, ledger de cobertura (veredicto por servicio) y autorización Caja Negra por defecto (RoE como única restricción de técnica) |
| Último run E2E autónomo | `TEST_E2E_BOUNTY_HACKER_RUN6.md` | `docs/missions/` | Bounty Hacker; fuente de `MANUAL_VS_AGENT.md` |
| Último run manual | `TEST_MANUAL_BOUNTY_HACKER_RUN7.md` | `docs/missions/` | Bounty Hacker con `omni tool`; fuente de Fase 4.1 |
| Evidencia de salas | `RUN_sala02.md` … `RUN_sala13.md` | `docs/missions/salas/` | 12 salas V0 resueltas con las tools gobernadas |
| Campaña QA de laboratorio | `QA_RESULT.md` | `qa_runs/` | BUG-002/003/004/006/007/008 citados por `PLAN_OMNIAGENTCS_V4` §10 |
| Evidencia de runs (trazas) | `docs/missions/examples/` | `docs/missions/examples/` | NDJSON de los runs E2E + informes |
| Evidencia por fase | `docs/missions/evidence/phase0|phase1|phase2|phase2-close/` | `docs/missions/evidence/` | Capturas de validación por fase |

> `roadmap_12/` (auditoría `10.md`, informes Fase 2–5, `Auditoria_playbook_telemetria.md`, `UI_terminal_14_10.md` y su evidencia) es **WIP no versionado — no forma parte del ledger oficial**: se conserva sin commitear y no se cita como fuente de verdad.

---

## Histórico (se conserva por trazabilidad)

Informes de misión cerradas cuyos hallazgos ya están en el código o en un documento vigente. No se actualizan.

### Resultados de misión (raíz, movidos aquí en esta revisión)

- `docs/missions/A2_RESULT.md` — cancelación de sandbox y worker
- `docs/missions/CAPABILITIES_RESULT.md` — 5 tools web/recon
- `docs/missions/CAPABILITIES2_RESULT.md` — 3 fixes críticos + 5 tools AD
- `docs/missions/CONTEXT_RESULT.md` — continuidad conversacional y `/ask`
- `docs/missions/FIX_ENV_RESULT.md` — neutralidad del entorno de tests
- `docs/missions/FIX_LLM_RESULT.md` — selección de LLM, logging silencioso
- `docs/missions/MSF_EXPLOIT_RESULT.md` — `msf_exploit` + ciclo de sesiones
- `docs/missions/REPORT_RESULT.md` — capa de reporte de engagement
- `docs/missions/SESSION_INTERACT_RESULT.md` — write/read de sesiones y REPL stateful
- `docs/missions/SHELL_POLISH_RESULT.md` — banner, spinner, prompt
- `docs/missions/SINGLE_WRITER_RESULT.md` — frontera única de escritura
- `docs/missions/SLIVER_RESULT.md` — puente Sliver C2 por gRPC
- `docs/missions/TUI_RESULT.md`, `TUI_B3_RESULT.md`, `TUI_POLISH_RESULT.md`, `TUI_FIX_RESULT.md` — migración y pulido de la TUI
- `docs/missions/CLEANUP_DECISIONS.md` — ledger por archivo del cleanup (referenciado por `CLEANUP_RESULT_V3.md`)

### Resultados de misión (ya residentes en `docs/missions/`)

- `CLI_RESULT.md`, `REACT_RESULT.md`, `NMAP_RESULT.md`, `TOOLKIT_RESULT.md`, `SCOPE_RESULT.md`, `SCOPE_WIRE_RESULT.md`, `ONBOARDING_RESULT.md`, `PURGE_RESULT.md`, `RESIDUALS_RESULT.md`, `FIX_SANDBOX_RESULT.md`, `MSF_RESULT.md`, `MSF_DAEMON_RESULT.md`

### Fases completadas que son base de las vigentes

- `docs/missions/FASE0_HONESTIDAD_Y_SEGURIDAD.md` — cimiento de las garantías actuales
- `docs/missions/FASE1_UX_ELITE.md` — UX de élite (HUD, historial, permisos)

### Linaje NEXUS / BAJIOWARE (producto anterior)

- `docs/missions/AUDITORIA_NEXUS_2026-08-04.md` — línea base autodeclarada histórica
- `docs/missions/INFORME_ARQUITECTONICO_NEXUS_2026-08-08.md` — arquitectura NEXUS en transición
- `docs/missions/PLAN_IMPLEMENTACION_NEXUS.md` y `REPORTE_IMPLEMENTACION_NEXUS_2026-08-04.md` — plan y reporte de esa implementación
- `docs/missions/PLAN_MAESTRO_BAJIOWARE.md`, `docs/missions/PRICING.md` — estrategia y modelos de negocio
- `docs/missions/platform/**` — runbooks, ADRs y despliegue de la plataforma NEXUS (SCIM, mTLS, SLO, on-prem)

### Backlog histórico

- `docs/missions/BACKLOG.md` — ideas aparcadas; el ledger vigente es `BACKLOG.md` en la raíz
- `roadmap_12/Backlog_post_auditoria.md` — detalle técnico del backlog post-auditoría; el ledger vigente es `BACKLOG.md`

---

## Archivado

Material superado o ruido operativo. Se conserva solo por trazabilidad; **no es verdad actual**. Ver `docs/archive/`.

### `docs/archive/audits/` — auditorías

- `AUD_OMNI_BW.md` — auditoría UX/UI integral sustituida por `AUDIT_POTENCIA_CLI.md`
- `TUI_UX_AUDIT.md` — auditoría visual previa a B3, absorbida por `AUD_OMNI_BW.md`
- `potencializar_cli.md` — benchmark + plan por fases superado por las auditorías posteriores y la ejecución de Fase 0–2
- `AUDIT_POTENCIA_CLI.md` — **vigente del tema UX/CLI**: los informes de auditoría se almacenan en esta carpeta por convención (ver tabla superior)
- `AUDIT_POT_XCLAUDE_CLI.md` — **vigente del tema auditoría técnica integral**; misma convención de almacenamiento

### `docs/archive/fases-cerradas/` — fases ya entregadas

- `FASE1_UX_UI_BRANDING.md` — Fase 1 antigua, sucedida por `FASE1_UX_ELITE.md`
- `FASE2_AGENT_SECURITY.md` — Fase 2 antigua de seguridad, absorbida por la orquestación vigente
- `FASE3_OFFENSIVE_DEPTH.md`, `FASE3B_ECOSYSTEM.md`, `FASE3E_REPORT_ENRICHMENT.md` — Fases 3, 3B y 3E entregadas
- `FASE35_UNBLOCK_E2E.md`, `FASE36_CLOSE_E2E.md`, `FASE37_ENUMERATION_FIX.md`, `FASE38_MODEL_CHANGE.md` — reparaciones 3.5–3.8 del E2E
- `FASE40_PLAYBOOK_SELF_IMPROVEMENT.md`, `FASE41_MANUAL_FIXES.md` — Fases 4.0/4.1, hallazgos ya en el motor de tools

### `docs/archive/recon-superseded/` — reconocimientos superados por su `*_RESULT`

- `A2_RECON.md`, `CAPABILITIES_RECON.md`, `CAPABILITIES2_RECON.md`, `CONTEXT_RECON.md`, `FIX_LLM_RECON.md`, `MSF_EXPLOIT_RECON.md`, `REPORT_RECON.md`, `SESSION_INTERACT_RECON.md`, `SHELL_POLISH_RECON.md`, `SINGLE_WRITER_RECON.md`, `SLIVER_RECON.md`, `TUI_RECON.md`, `TUI_B3_RECON.md`, `TUI_POLISH_RECON.md` — medidas y bloqueos *antes* del cambio; el `*_RESULT` homónimo en `docs/missions/` es la verdad
- `CLI_RECON.md`, `REACT_RECON.md`, `NMAP_RECON.md`, `TOOLKIT_RECON.md`, `SCOPE_RECON.md`, `ONBOARDING_RECON.md`, `PURGE_RECON.md`, `FIX_SANDBOX_RECON.md`, `RESIDUALS_DIAG.md`, `MSF_DAEMON_DIAG.md` — mismo caso; eran el paso previo a su `*_RESULT`

### `docs/archive/qa-runs-old/` — runs E2E superados

- `TEST_E2E_BOUNTY_HACKER.md` — run #1, fallo por bloqueantes corregidos en Fases 3.5–3.8
- `TEST_E2E_BOUNTY_HACKER_RUN2.md`, `TEST_E2E_BOUNTY_HACKER_RUN3.md`, `TEST_E2E_BOUNTY_HACKER_RUN4.md`, `TEST_E2E_BOUNTY_HACKER_RUN5.md` — runs #2–#5; el vigente es `TEST_E2E_BOUNTY_HACKER_RUN6.md`

### `docs/archive/misc/` — sin tema propio

- `CAPABILITIES2_FIX_RESULT.md` — subsumido por `CAPABILITIES2_RESULT.md`
- `CLEANUP_AUDIT.md`, `CLEANUP_RECON_V2.md`, `CLEANUP_RESULT.md`, `CLEANUP_RESULT_V2.md` — iteraciones bloqueadas del cleanup; el cierre es `CLEANUP_RESULT_V3.md`
- `CODEBASE_MAP.md` — mapa técnico de NEXUS 2.0 (`/home/operator/NEXUS`, 2026-06-09); no describe este repositorio
- `OMNIAGENT_CONTEXT.md` — volcado estático del árbol antiguo (469 KB); obsoleto y engañoso
