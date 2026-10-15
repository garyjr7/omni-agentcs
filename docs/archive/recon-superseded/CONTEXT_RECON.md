# CONTEXT_RECON — medidas antes de los cambios

Fecha: 2026-10-01. Rama: `feat/context-continuity-report`.
Base: `90fb7f5` (`feat(tools): add NetExec, BloodHound, and impacket AD attack tools`).
26 tools durables. Suite base: **1350 passed, 30 skipped**.

## Hallazgo #7 — continuidad conversacional

Medido con un `ControlStore` real:

- `memory.ensure_conversation(store, tenant, run_id, "omni")` crea una
  conversación por **run**, con título `react:<run_id>`.
- `OmniSession.run_objective` llama a `ensure_conversation` con el run recién
  creado, así que cada objetivo abre una conversación nueva y **no ve** el
  historial del objetivo anterior.
- `cmd_ask` mantiene `session.ask_history` en memoria (20 pares) y llama a
  `_ask_messages`, que construye system + historial local + pregunta. **No
  persiste** ni comparte contexto con los objetivos.
- `cmd_clear` hace `session.reset_context()`, que pone `conversation_id=None`;
  no rota ninguna sesión de trabajo (no existe).

## Hallazgo #8 — tamaño y duplicación del prompt

Medido con `render_system_prompt(catalog=durable_tool_definitions("system"), ...)`:

| Métrica | Antes |
|---|---|
| Herramientas | 26 |
| Catálogo renderizado (`render_tool_catalog`) | **19 313** chars |
| Prompt de sistema completo | **40 523** chars |
| Veces que el catálogo aparece en el prompt | **2** |
| Veces que aparece `nexus.recon.nmap` | 3 (catálogo ×2 + ejemplo JSON) |

Causa: `REACT_SYSTEM_PROMPT` contiene `{tool_catalog}` (sección
`HERRAMIENTAS DISPONIBLES`) **y** `{catalog_text}` (sección `CATÁLOGO DE
HERRAMIENTAS`), ambos rellenados con el mismo `render_tool_catalog`. Además cada
tool emite su JSON schema completo (`argumentos (JSON schema): {...}`).

`Runtime.select_llm_client` no usa `ModelRouter`; `execute_react` no lee ningún
presupuesto de tokens.

## Hallazgo #6 — cobertura del reporte

`nexus_core/report/extractor.py` solo convierte en `Finding`:
`nmap`, `nuclei`, `subfinder`, `ffuf`, `msf_exploit`, `session.interact`.

Las 10 tools nuevas no tienen representación:
`sqlmap`, `dalfox`, `gobuster`, `whatweb`, `searchsploit`, `netexec`,
`bloodhound_python`, `secretsdump`, `getuserspns`, `psexec`.

`nexus_core/report/data/tool_ttp_map.json` tampoco incluye las tools nuevas
(sqlmap/dalfox/gobuster/whatweb/searchsploit/AD), por lo que su MITRE sale vacío.

El modelo `EngagementReport` solo tiene `findings` + `failed_attempts` +
`timeline`; no hay inventario, referencias ni superficie. El schema JSON es
`nexus.engagement_report/1`.

## Plan

1. Sesión de trabajo persistente por engagement, compartida por runs y `/ask`.
2. Catálogo compacto y sin duplicación; presupuesto de tokens por run.
3. Secciones nuevas (inventario/referencias/superficie/evidencia) + MITRE por
   tool + schema `/2`.
