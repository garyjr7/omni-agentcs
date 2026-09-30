# REPORT_RECON — capa de reporte de engagement

Rama `feat/report-generation` (creada desde `7e47fa7`). Reconocimiento hecho
sobre el **registro durable real** del proyecto: `kernel_audit_events`,
`kernel_messages` (conversación ReAct), `kernel_artifacts` y el `EngagementScope`.
Los ejemplos de payload de este documento se generaron ejecutando el toolkit
sembrado (`nexus_core/tests/report_support.py`), así que son el formato exacto
que el gateway y el loop escriben.

## 1. Fuentes y su forma real

### 1.1 `kernel_audit_events` (fuente de decisiones y orden)

Columnas: `sequence, event_id, tenant_id, trace_id, actor_id, action,
resource_type, resource_id, decision, payload, previous_hash, event_hash,
created_at`. `trace_id` = `run_id`. `AuditWriter.export(tenant_id, *,
trace_id=None, run_id=None)`; `verify_chain() -> (bool, first_bad_sequence)`.

Ejemplo real de un engagement de laboratorio (17 eventos, `run_25f56d…`):

```json
{"action": "tool.invoke",   "resource_type": "tool", "resource_id": "nexus.recon.nmap",      "decision": "allow", "payload": {"argument_keys": ["ports", "target"]}}
{"action": "tool.complete", "resource_type": "tool", "resource_id": "nexus.recon.nmap",      "decision": "allow", "payload": {"output_bytes": 937, "run_id": "run_25f56d…"}}
{"action": "tool.invoke",   "resource_type": "tool", "resource_id": "nexus.web.nuclei",      "decision": "allow", "payload": {"argument_keys": ["severity", "targets"]}}
{"action": "tool.complete", "resource_type": "tool", "resource_id": "nexus.web.nuclei",      "decision": "allow", "payload": {"output_bytes": 548, "run_id": "run_25f56d…"}}
{"action": "tool.invoke",   "resource_type": "tool", "resource_id": "nexus.exploit.msf_exploit", "decision": "allow", "payload": {"argument_keys": ["module", "target"]}}
{"action": "tool.invoke",   "resource_type": "tool", "resource_id": "nexus.session.interact","decision": "allow", "payload": {"argument_keys": ["command", "session_uuid"], "engagement_id": "eng-lab"}}
{"action": "scope.denied",  "resource_type": "tool", "resource_id": "nexus.recon.nmap",      "decision": "deny",  "payload": {"reason": "ScopeViolation(example.com): target is outside the engagement", "target_keys": ["target"]}}
```

**Hallazgo clave:** el audit guarda `argument_keys` (los *nombres*), **no los
valores**. Por tanto el objetivo real (`target`, `domain`, `url`) **no está en el
audit**; solo se recupera del `ToolResult` persistido. El texto del
`ScopeViolation(<target>): …` sí lleva el objetivo denegado (se parsea con
`ScopeViolation\(([^)]+)\)`).

### 1.2 `kernel_messages` (los ToolResults; aquí está el contenido)

Cada llamada del loop ReAct —y, desde MISIÓN 9, cada llamada del REPL vía
`OmniSession.record_tool_result`— deja una observación:

```
metadata = {"kind": "react.observation", "tool_id": "nexus.recon.nmap",
            "arguments": {"target": "203.0.113.10", "ports": "22,80"},
            "success": true,
            "tool_result": {"tool_id": ..., "success": true,
                            "verification_method": "nmap_xml_parsed"},
            "run_id": "run_25f56d…"}
body     = {"tool_id": ..., "success": true, "verification_method": "nmap_xml_parsed",
            "evidence": {"hosts_up": 1, "ports_open_total": 2, "raw_xml_sha256": "aaaa…"},
            "output": {"target": "203.0.113.10", "scan": {"hosts": [...]}}}
```

El cuerpo truncado del loop (`react.observation`) y las observaciones del REPL
comparten `kind`; el REPL añade `source="cli"` y mete `arguments` en metadata.
De ahí que el extractor lea los argumentos de `react.action` (loop) **o** del
`arguments` de la propia observación (REPL).

`kernel_artifacts` aporta la evidencia content-addressed:
`id, tenant_id, run_id, media_type, storage_uri, sha256, size_bytes, metadata,
created_at`.

### 1.3 `EngagementScope` (metadatos del cliente)

`EngagementStore.get(tenant_id, engagement_id)` → `engagement_id, name, client,
owner_id, valid_from, valid_until, cidrs, domains, urls, exclusions, notes,
signature`. El engagement real `eng-scanme` (tenant `system`) tiene cliente
`NEXUS`, owner `operator`, dominio `scanme.nmap.org` y dos CIDRs IPv4/IPv6.

## 2. Reglas de extracción decididas

| Evento / ToolResult | Resultado | Severidad base |
|---|---|---|
| `nexus.recon.nmap` OK | finding "superficie expuesta" con los puertos | `info`; `low`/`medium` si hay servicios legacy |
| `nexus.recon.subfinder` OK | finding "subdominios enumerados" con count | `info` |
| `nexus.web.nuclei` con hallazgos | **un finding por hallazgo** (template → CVE/CWE/tags) | la del template (mapeada) |
| `nexus.web.ffuf` 200/30x | finding "endpoints descubiertos" | `info` |
| `nexus.web.ffuf` 401/403 | finding "endpoint protegido" (enumeración reveló su existencia) | `low` |
| `nexus.exploit.msf_exploit` `session_opened` | finding "Acceso obtenido vía `<module>`" | `critical` |
| `nexus.exploit.msf_exploit` `timeout`/`failed`/`no_session` | **FailedAttempt**, nunca finding | — |
| `nexus.session.interact` (`ok`/`timeout`) | finding "Comando ejecutado en sesión: `<cmd>`" | `hashdump`/`getsystem`/`migrate`… `critical`; `id`/`whoami`… `info` |
| `scope.denied` | **FailedAttempt** (intento bloqueado), no finding | — |
| `tool.failed` | FailedAttempt | — |
| Dedup | mismo `(kind, title, targets)` dentro de **300 s** → 1 finding con `reproductions:N` | — |
| Atribución | solo entran runs con un target **dentro del scope**, o runs con un evento que lleve `engagement_id` (los `session.command` del REPL) | — |

El reporte **nunca inventa un hallazgo**: si el audit no lo verifica, no aparece.

## 3. Puntos de integración

- `nexus_core/cli/commands.py`: `COMMANDS` es `name -> fn(session, args)`; se
  añaden `/findings`, `/report` y `/timeline` (17 entradas).
- `OmniSession.invoke_tool(...)` devuelve `{"tool_id", "output": <ToolResult>}` y
  ya persiste la observación; `nexus.report.generate` se ejecuta por ahí mismo.
- `ToolGateway.invoke` exige aprobación para HIGH; `nexus.report.generate` es
  `READ_ONLY` y `scope_required=False`, así que no necesita scope ni aprobación.
- El gateway **no** persiste ToolResults (solo audita); el reporte lee la
  conversación durable.

## 4. Decisiones derivadas del reconocimiento

1. **El audit no basta**: hay que cruzar `kernel_messages`. El extractor carga la
   conversación completa del tenant una vez (`_collect`) y correlaciona cada
   observación con su `completion` de audit por `(run_id, tool_id)` y ordinal.
2. **Selección de runs explícita**: `matches_scope` sobre los argumentos
   recuperados + `engagement_id` en payload. Un run sin target y sin
   `engagement_id` no se atribuye al engagement.
3. **CVSS calculado localmente**: el score se deriva del vector con el cálculo
   3.1 (Roundup) en `nexus_core/report/cvss.py`; nunca se acepta un número del
   modelo. Origen declarado en `cvss_source ∈ {tool, llm, heuristic}`.
4. **Fail-safe**: sin LLM se usa la heurística determinista; el reporte se genera
   siempre, incluso con la cadena rota (se marca "NO VERIFICADA").
5. **Cero dependencias nuevas**: Markdown y HTML por string templates; el HTML
   lleva el CSS embebido y sin JS/CDN.
