# REPORT_RESULT — generación de reportes de engagement

Rama `feat/report-generation` (desde `7e47fa7`). Implementa la capa de reporte:
motor de extracción desde el audit trail + ToolResults, mapeo CVSS / MITRE
ATT&CK / OWASP, render Markdown + HTML + JSON, tool durable
`nexus.report.generate` (**16 tools**), comandos REPL `/findings`, `/report`,
`/report export`, `/timeline` y chain of custody con `sha256`.

El reconocimiento y los formatos reales del registro están en `REPORT_RECON.md`.

## 1. Resultado

| Criterio | Resultado |
|---|---|
| 7 imports OK | ✅ `report`, `report.extractor`, `report.markdown`, `report.html`, `handlers.report_generate`, `cli.commands`, `omni` |
| 16 tools registradas | ✅ `nexus.report.generate` incluida (`len(durable_tool_definitions()) == 16`) |
| 626 tests previos siguen pasando | ✅ **721 unit** (626 previos + 95 nuevos) |
| ≥14 tests del extractor | ✅ 22 |
| ≥6 tests de severidad | ✅ 10 |
| ≥6 tests de MITRE | ✅ 12 |
| ≥5 tests de CVSS | ✅ 12 |
| ≥10 tests de renderers | ✅ 11 |
| ≥8 tests del handler | ✅ 14 |
| ≥8 tests de comandos meta | ✅ 14 |
| ≥2 tests E2E (opt-in) | ✅ 2 (`NEXUS_E2E=1`) |
| ruff `--select F,E9` limpio | ✅ All checks passed |
| Cero TODOs/FIXME/HACK | ✅ grep vacío |
| Markdown incluye todas las secciones | ✅ 9 secciones (§4) |
| HTML self-contained (sin CSS/JS externos) | ✅ `style` embebido, sin `<script>`, sin `href/src="http` |
| Cada finding con evidencia `sha256` | ✅ tool_result + audit_event + artifacts |
| Cada finding con técnicas MITRE | ✅ |
| El reporte nunca inventa findings | ✅ un exploit fallido es `FailedAttempt`, no finding |
| Artifact durable con `sha256` | ✅ 3 artefactos content-addressed por generación |
| Cadena de auditoría verificada antes de generar | ✅ `verify_chain()`; si falla, el reporte se marca NO VERIFICADA |
| Ningún handler ejecuta subprocess | ✅ grep vacío en `nexus_core/report` |
| JSON serializable | ✅ schema `nexus.engagement_report/1` |

## 2. Ficheros

Nuevos (5 288 líneas):

| Fichero | Líneas | Qué |
|---|---|---|
| `nexus_core/report/extractor.py` | 1271 | Motor: `_collect`, `extract_findings`, `build_report`, dedup 300 s, evidencia |
| `nexus_core/report/html.py` | 316 | Render HTML autocontenido |
| `nexus_core/report/markdown.py` | 288 | Render Markdown + JSON |
| `nexus_core/report/models.py` | 216 | `Finding`, `FailedAttempt`, `Evidence`, `EngagementReport`, digest |
| `nexus_core/report/cvss.py` | 186 | CVSS 3.1 calculado local (Roundup), prompt LLM, heurística |
| `nexus_core/report/severity.py` | 170 | Heurística determinista de severidad |
| `nexus_core/report/mitre.py` | 159 | Mapeo ATT&CK por tool/comando |
| `nexus_core/report/__init__.py` | 34 | Re-exportaciones |
| `nexus_core/report/data/mitre_techniques.json` | 53 | 51 técnicas |
| `nexus_core/report/data/tool_ttp_map.json` | 18 | 16 tools mapeadas |
| `nexus_core/tools/handlers/report_generate.py` | 284 | Tool durable `nexus.report.generate` |
| `nexus_core/tests/report_support.py` | 492 | Builders compartidos (engagement sembrado) |
| `nexus_core/tests/unit/test_report_extractor.py` | 447 | 22 tests |
| `nexus_core/tests/unit/test_report_handler.py` | 274 | 14 tests |
| `nexus_core/tests/unit/test_cli_report_commands.py` | 232 | 14 tests |
| `nexus_core/tests/unit/test_report_render.py` | 180 | 11 tests |
| `nexus_core/tests/unit/test_report_cvss.py` | 151 | 12 tests |
| `nexus_core/tests/unit/test_report_mitre.py` | 108 | 12 tests |
| `nexus_core/tests/unit/test_report_severity.py` | 86 | 10 tests |
| `nexus_core/tests/integration/test_report_e2e.py` | 323 | 2 E2E opt-in |
| `REPORT_RECON.md` / `REPORT_RESULT.md` | — | Informes |

Modificados (+359/−6): `cli/commands.py` (+230), `cli/session.py` (+63),
`README.md` (+61), `tools/registry.py` (+8), `test_system_env_handler.py`
(conteo 15 → 16).

## 3. Fixes reales encontrados durante la implementación

1. **`_run_report_tool` leía el `ToolResult` en el nivel equivocado.**
   `session.invoke_tool` devuelve `{"tool_id", "output": <ToolResult>}` (igual
   que `_kill_one`), pero el comando hacía `result.get("success")` en la raíz.
   El `/report` real nunca habría encontrado el `output`/`evidence`. Corregido:
   se desenvuelve `result["output"]`.
2. **Título duplicado de severidad en nuclei.** El extractor generaba
   `title="[HIGH] Apache 2.4.49 path traversal"` y el renderer antepone otro
   `[HIGH]` → `### [HIGH] [HIGH] …`. Corregido a título plano + test de regresión.
3. **Semántica de `verified` con cadena rota.** El gateway convierte
   `verified=False` en `RuntimeError`, así que las rutas del reporte no llegaban
   al llamante. El post-condition de la tool es "entregables producidos desde el
   registro durable"; la validez de la cadena es un dato (`evidence.audit_chain_valid`)
   que se estampa como "NO VERIFICADA" en el cuerpo.
4. **`test_system_env_handler.py` fijaba `len(catalog) == 15`.** Añadir una tool
   necesariamente lo cambia; actualizado a 16.

## 4. Ejemplo de Markdown (engagement sembrado, con hallazgos)

```markdown
# Reporte de Pentesting — lab-engagement

**Cliente:** ACME
**Operador:** operator-1
**Engagement:** `eng-lab`
**Período:** 2026-09-30T01:27:01.774983+00:00 — 2026-09-30T01:27:01.819476+00:00
**Generado:** 2026-09-30T01:27:01.857295+00:00

## Resumen ejecutivo

- Hallazgos: **2 críticos**, **1 altos**, **0 medios**, **1 bajos**, 4 informativos (8 en total).
- Intentos sin hallazgo: 2.
- Sesiones abiertas y verificadas: 1.
- Eventos de auditoría considerados: 17.
- Cadena de auditoría: ✓ válida.

## Alcance

Resumen: 1 CIDR, 1 dominio, 0 URLs, 0 exclusiones.

- CIDRs: `203.0.113.0/24`
- Dominios: `scanme.example`
- URLs: (ninguno)
- Exclusiones: (ninguno)
- Ventana de autorización: 2026-09-29T01:27:01.769113+00:00 — 2026-10-01T01:27:01.769120+00:00
- Runs: `run_9ae47a6182bf4a42be9a97128539d3e6`

## Metodología

Herramientas durables utilizadas, todas a través del gateway (política, scope, aprobación humana y auditoría):

- `nexus.recon.nmap`
- `nexus.recon.subfinder`
- `nexus.web.nuclei`
- `nexus.web.ffuf`
- `nexus.exploit.msf_exploit`
- `nexus.session.interact`

## Hallazgos

### [CRITICAL] Acceso obtenido vía exploit/linux/http/apache_mod_cgi_bash_env_exec

**CVSS:** 9.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`, origen: heuristic)
**MITRE ATT&CK:** T1190, T1210
**OWASP Top 10:** A06:2021-Vulnerable and Outdated Components
**Afectados:** `203.0.113.10`
**Descubierto por:** `nexus.exploit.msf_exploit`
**Fecha:** 2026-09-30T01:27:01.797866+00:00
**Finding id:** `finding_a0cd9eae55da24b1`

**Descripción:**

El módulo `exploit/linux/http/apache_mod_cgi_bash_env_exec` abrió una sesión shell (abc12345) sobre 203.0.113.10 como `www-data`. El acceso está confirmado por el post-condition del handler, no por una afirmación del modelo.

**Evidencia (chain of custody):**

- `tool_result` message_a14729bd8f9b40df85ee089010febbf7 (sha256: `bbbb…bb`, 2026-09-30T01:27:01.797866+00:00)

  > {"duration_seconds": 3.2, "job_uuid": "job-uuid-1", "module": "exploit/linux/http/apache_mod_cgi_bash_env_exec", "raw_sha256": "bbbb…bb", "session": {"info": "Command shell", "session_host": "203.0.113.10", "session_port": 51234, "target_host": "203.0.113.10", "tunnel_local": "127.0.0.1:4444", "tunnel_peer": "203.0.113.10:51234", "type": "shell", "username": "www-data", "uuid": "abc12345", "via_exploit": "exploit/linux/http/apache_mod_cgi_bash_env_exec", "via_payload": "linux/x64/shell_reverse_tcp"}, "status": "session_opened", "target": "203.0.113.10"}

- `audit_event` audit_19cd6f7d7d874a21b67ec2f7a517d03c (sha256: `2349aa…ac`, 2026-09-30T01:27:01.800543+00:00)

  > {"output_bytes": 821, "run_id": "run_9ae47a6182bf4a42be9a97128539d3e6"}

**Reproducción:**

1. Ejecutar `nexus.exploit.msf_exploit` con module=`exploit/linux/http/apache_mod_cgi_bash_env_exec` y target=`203.0.113.10`
2. Comprobar la sesión con `nexus.session.list` (uuid abc12345)

### [CRITICAL] Comando ejecutado en sesión: hashdump

**CVSS:** 9.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`, origen: heuristic)
**MITRE ATT&CK:** T1003, T1059
**Afectados:** `abc12345`
**Descubierto por:** `nexus.session.interact`
**Fecha:** 2026-09-30T01:27:01.808166+00:00
**Finding id:** `finding_7908cdc40c841623`

**Descripción:**

Se ejecutó `hashdump` en la sesión abc12345 (estado `ok`) y devolvió 55 bytes. Salida: Administrator:500:aad3b435b51404eeaad3b435b51404ee:...

**Evidencia (chain of custody):**

- `tool_result` message_e7b8b6216b7241dba42f78c703db4c8d (sha256: `cccc…cc`, 2026-09-30T01:27:01.808166+00:00)

  > {"command": "hashdump", "duration_seconds": 0.4, "output": "Administrator:500:aad3b435b51404eeaad3b435b51404ee:...\n", "output_bytes": 55, "raw_sha256": "cccc…cc", "session_uuid": "abc12345", "status": "ok"}

- `audit_event` audit_1091f814fad44c04b445c85a39b481b4 (sha256: `eeb99d…fd`, 2026-09-30T01:27:01.811034+00:00)

  > {"output_bytes": 396, "run_id": "run_9ae47a6182bf4a42be9a97128539d3e6"}

**Reproducción:**

1. Adjuntar la sesión abc12345 (`/session attach abc12345`)
2. Enviar `hashdump` con `nexus.session.interact`

### [HIGH] Apache 2.4.49 path traversal
```

(El documento completo tiene 100+ líneas más con los 6 findings restantes, la
tabla de intentos fallidos, la cronología, el chain of custody y los anexos.)

## 5. Demo manual sobre el engagement real `eng-scanme`

El engagement real de la DB XDG no tiene actividad explotable (0 eventos de
auditoría atribuibles), así que el reporte sale sin hallazgos — **fail-safe
verificado**, con todas las secciones:

```
$ .venv/bin/python - <<'PY'   (extract_engagement_metadata + extract_findings + build_report)
Metadata: {'engagement_id': 'eng-scanme', 'name': None, 'client': 'NEXUS',
           'operator': 'operator',
           'scope_summary': '2 CIDRs, 1 dominio, 0 URLs, 0 exclusiones',
           'audit_events_total': 0, 'audit_chain_valid': True}
Findings: 0
Failed: 0
report bytes: 1846
sha256: 22db291e247754c7d9f1875b88044909fa4ba76f855f28f11561c55b4ef923a8
sections present: ['## Resumen ejecutivo', '## Alcance', '## Metodología',
                   '## Hallazgos', '## Intentos fallidos', '## Cronología',
                   '## Chain of custody', '## Anexos']
```

## 6. Verificación ejecutada

```bash
# imports (7)
nexus_core.report OK · report.extractor OK · report.markdown OK · report.html OK
handlers.report_generate OK · cli.commands OK · omni OK

# tools
16 tools

# suite
721 passed in 21.51s                 # nexus_core/tests/unit
95 passed                            # report + cli_report_commands
ruff --select F,E9 → All checks passed
residual TODO/FIXME/HACK → OK: no residual
subprocess en nexus_core/report → OK: no subprocess
```

Los E2E son opt-in (`NEXUS_E2E=1`): el primero requiere `nmap` y red hacia
`scanme.nmap.org`; el segundo requiere `msfrpcd` y mantiene todo en loopback
(handler + víctima bash `/dev/tcp`), verificando el finding "Acceso obtenido…",
el comando `id` en sesión, las secciones del Markdown y el `sha256` de artefactos.

## 7. Decisiones de diseño no cubiertas por la misión

1. **El audit no guarda valores de argumentos** → el objetivo de cada finding se
   recupera del `ToolResult` en `kernel_messages`; el extractor correlaciona
   observación y evento `tool.complete`/`tool.failed` por `(run_id, tool_id)` y
   ordinal, y atribuye runs por target en scope o por `engagement_id` en payload.
2. **CVSS calculado localmente** con el cálculo 3.1 (Roundup): el LLM solo
   propone el vector; el score nunca se confía al modelo. `cvss_source` declara
   `tool`/`llm`/`heuristic`.
3. **`verified=True` aunque la cadena no valide**: el post-condition es que el
   reporte se produjo del registro durable; la integridad de la cadena se expone
   en evidencia y en el cuerpo ("NO VERIFICADA"). Decisión forzada por el gateway
   (una `verified=False` aborta la llamada antes de devolver las rutas).
4. **Dedup con ventana de 300 s** por `(kind, title, targets)`, acumulando
   `reproductions` y evidencia, para no inflar el conteo en escaneos repetidos.
5. **`nexus.report.generate` es READ_ONLY y sin scope**: lee estado, no toca
   objetivos; escribe el entregable y lo registra como artefacto.
6. **HTML autocontenido**: CSS embebido, `<details>` colapsables, sin JS ni CDN,
   footer con el digest del reporte para atarlo a la copia impresa.
7. **Directorio de salida** `$XDG_DATA_HOME/omni/reports/<slug>-<timestamp>` con
   colisión resuelta por sufijo; `output_dir` lo overridea (usado por `/report export`).
8. **`/report export`** escribe `report.sha256` y `manifest.json` (con los hashes
   de los artefactos) para verificación del entregable.

## 8. Commit

```
git add -A && git commit -m "feat(report): engagement report generator with CVSS, MITRE and chain of custody"
```

No se hizo push.
