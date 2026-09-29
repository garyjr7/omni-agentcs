# TOOLKIT_RESULT — 4 tools nuevas (subfinder, httpx, nuclei, ffuf)

Rama: `feat/toolkit-recon` (desde `feat/cli-omni`). Sin push.

---

## 1. Entregado

### Parsers (`nexus_core/tools/parsers/`)
| Módulo | Qué hace |
| --- | --- |
| `_jsonl.py` | helpers tolerantes compartidos: parseo NDJSON línea a línea, `sha256`, coerción de tipos, conteos |
| `subfinder.py` | JSONL (`host`/`source`/`sources`) + fallback a líneas planas con forma de hostname |
| `httpx.py` | JSONL (`url`, `status_code`, `title`, `tech`, `content_length`, `webserver`, `cdn`, `cname`) |
| `nuclei.py` | JSONL (`template-id`, `info.name/severity/tags`, `host`, `matched-at`, `matcher-name`) con severidades ordenadas |
| `ffuf.py` | NDJSON de `-json` **y** sobre `{"results": [...]}` de `-of json` |

Los cuatro: dataclasses frozen con `to_dict()`, `raw_sha256` del payload crudo
(para auditoría) y `malformed_lines` (tolerancia a ruido). Raíces vacías son un
resultado válido ("nada encontrado"); un payload no vacío sin ningún registro
parseable lanza `ValueError`.

### Handlers (`nexus_core/tools/handlers/`)
| Tool | Riesgo | Ruido | Argv base |
| --- | --- | --- | --- |
| `nexus.recon.subfinder` | `READ_ONLY` | `low` (siempre, pasivo) | `subfinder -d <domain> -silent -json -nc -timeout <t>` |
| `nexus.recon.httpx` | `LOW` | ≤20 low · ≤100 medium · >100 high | `httpx -json -silent -nc -sc -title -cl -timeout 10 [-td] [-probe] -u t1 -u t2 …` |
| `nexus.web.nuclei` | `MEDIUM` | severidades: info/low→low · medium→medium · high/critical→high | `nuclei -jsonl -silent -nc -no-interactsh -timeout 10 -severity low,medium -exclude-tags … -u t1 …` |
| `nexus.web.ffuf` | `MEDIUM` | ≤2 low · ≤5 medium · >5 high (default 10 → high) | `ffuf -u <url> -w <wordlist> -json -s -t <n> -rate <r> -timeout 10 -X <m> [-e …]` |

`_exec.py` centraliza lo común: `RECON_ALLOWED_PROGRAMS =
("python3","git","rg","nmap","subfinder","httpx","nuclei","ffuf")`, la
normalización OCI/local del sandbox y el transporte de lotes por argv repetido.
**Ningún handler lanza procesos por su cuenta**: los tests parchean
`asyncio.create_subprocess_exec` para que falle si alguien lo intenta.

### Scope validator (Fase 3)
`nexus_core/scope/validator.py::make_scope_validator` acepta ahora un valor
`list`/`tuple`: valida cada elemento y exige que **todos** pasen; lista vacía →
`ValueError`. El camino de string queda idéntico. 4 tests nuevos en
`test_scope.py` (`ScopeValidatorBatchTargetTests`).

### Registro (Fase 4)
`durable_tool_definitions()` devuelve 7 tools:

```
nexus.system.status
nexus.workspace.search
nexus.recon.nmap
nexus.recon.subfinder
nexus.recon.httpx
nexus.web.nuclei
nexus.web.ffuf
```

`render_tool_catalog()` no necesitó cambios: ya expone descripción, riesgo,
timeout, campo de scope y JSON schema de cada tool (3.465 chars para las 7).

---

## 2. Verificación

### Imports (14/14 OK)
```
nexus_api.main OK · nexus_core.kernel.runtime OK · nexus_core.tools.registry OK
nexus_core.tools.parsers.{subfinder,httpx,nuclei,ffuf} OK
nexus_core.tools.handlers.{subfinder,httpx,nuclei,ffuf} OK
nexus_core.agent.react OK · nexus_core.cli OK · omni OK
```

### Tests
| Comando | Resultado |
| --- | --- |
| `pytest nexus_core/tests/unit -q` | **279 passed** (177 previos + 102 nuevos) |
| `pytest nexus_core/tests/unit/test_*_parser.py -q` | 62 passed (27 nmap/react + 35 nuevos: subfinder 9, httpx 8, nuclei 9, ffuf 9) |
| `pytest nexus_core/tests/unit/test_*_handler.py -q` | 76 passed (13 nmap + 63 nuevos: subfinder 10, httpx 10, nuclei 20, ffuf 23) |
| `test_scope.py` | 32 passed (28 previos + 4 nuevos de listas) |

Ningún test previo se modificó; el único archivo existente tocado en tests es
`test_scope.py`, y solo con **adiciones** (fase 3 lo pide explícitamente).

### Ruff / residual
```
ruff check nexus_core/tools nexus_core/scope test_*_parser.py test_*_handler.py --select F,E9
→ All checks passed!
grep -rnE "TODO|FIXME|XXX|HACK|raise NotImplementedError" nexus_core/tools/ nexus_core/agent/  → limpio
grep -rnE "subprocess|Popen|os.system|shell=True" nexus_core/tools/  → limpio
```

### E2E opt-in (`NEXUS_E2E=1`)
```
test_e2e_subfinder_against_nmap_org_in_scope            PASSED   (subfinder real contra nmap.org)
test_e2e_httpx_against_scanme_in_scope                  PASSED   (httpx real contra http://scanme.nmap.org)
test_e2e_nuclei_against_scanme_in_scope                  SKIPPED (templates no instalados)
test_e2e_ffuf_against_scanme_denied_when_out_of_scope    PASSED   (scope gating + audit scope.denied)
=================== 3 passed, 1 skipped in 72.85s ===================
```

### Demostración agente real (CLI `omni`, Groq + sandbox + scope reales)
Objetivo one-shot contra el engagement de scanme; el LLM eligió **solo** la tool
nueva y el stack completo la ejecutó:
```
💭 Ejecutar httpx contra http://scanme.nmap.org para obtener código de estado,
   título y detección de tecnologías, cumpliendo con el scope del engagement.
⚙️  nexus.recon.httpx
     targets: ['http://scanme.nmap.org']   tech_detect: True   probe: True   noise: low
✓ nexus.recon.httpx — ok | noise: low
• estado=completed iteraciones=2
```

---

## 3. Lo que NO se cumplió al 100% (reportado, no oculto)

**El E2E de `nuclei` se salta**: no hay templates instalados (`~/nuclei-templates`
no existe) y, sin ellos, nuclei intenta descargarlos y agota el timeout del
sandbox (`verification_method="nuclei_timeout"`). El test lo declara con
`skipif` y motivo accionable (`nuclei -update-templates`). Toda la lógica del
handler nuclei (allowlist, flags prohibidos, defaults no intrusivos, derivación
de ruido por severidad, parser) está cubierta por 20 tests unitarios
deterministas, pero **no hay evidencia E2E de nuclei**.

**`LocalSandbox` no propaga `HOME`** (limitación de entorno, no de las tools).
Medido:

| Binario | Efecto observado con el sandbox actual |
| --- | --- |
| `subfinder` | funciona igual; escribe `./subfinder/config.yaml` y `provider-config.yaml` en el cwd del sandbox |
| `httpx` | funciona; escribe `./httpx/config.yaml` en el cwd del sandbox |
| `nuclei` | resuelve el home por `/etc/passwd`, crea `~/nuclei-templates` y se cuelga intentando descargar templates |

Es decir: un run real deja basura de configuración en el workspace (el repo,
cuando `NEXUS_WORKSPACE_ROOT` no está fijado). Detecté y borré los artefactos
creados durante el reconocimiento (`.nuclei-config/`, `httpx/`, `subfinder/`,
`~/nuclei-templates` vacío) y los E2E fijan `NEXUS_WORKSPACE_ROOT` a un
`tmp_path`. **No lo he arreglado** porque implica tocar `kernel/sandbox.py`
(fuera del alcance de esta misión) y cambiar el `env` del hijo tiene dimensión
de seguridad (inyectar `HOME` en un proceso sandboxeado). Recomendación:

1. añadir `HOME` (o un `XDG_CONFIG_HOME` por run) al `env` de `LocalSandbox`, o
2. usar la imagen OCI, que ya trae sus assets, y un `HOME` efímero en contenedor.

---

## 4. Decisiones de diseño no cubiertas por el prompt

1. **Transporte por argv repetido, sin ficheros temporales.** `httpx -u` y
   `nuclei -u` son `string[]`; 500 targets ≈ 12 KB, muy por debajo de `ARG_MAX`.
   Evita fichero temporal + limpieza + acoplamiento al bind-mount `/workspace`.
   Por eso el handler de httpx conserva `maxItems: 500` del enunciado en lugar
   de recortar a 50.
2. **`ffuf` lee su JSON de stdout** (`-json`, NDJSON) en vez de
   `-of json -o <fichero>`; el parser acepta **ambos** formatos, así que la
   decisión es reversible sin tocar tests.
3. **Flags estructurales nunca vienen del LLM.** El scope se valida sobre
   `url`/`targets` *antes* del handler: si el modelo pudiera añadir `-u`, `-w`,
   `-l`, `-t`, `-of`, `-o`, `-x`, `-config` o (peor) `-input-cmd` / `-input-shell`
   / `-preflight` / `-postflight`, se saltaría el scope, leería ficheros
   arbitrarios o ejecutaría comandos. Están en la lista de prohibidos y solo se
   permiten flags inocuos (`-mc`, `-fc`, `-rate`, `-p`, `-s`, `-ac`, `-r` en ffuf;
   `-severity`, `-tags`, `-exclude-tags`, `-rl`, `-c`, `-timeout` en nuclei).
   `FFUF_STRUCTURAL_FLAGS` documenta el conjunto estructural (que el enunciado
   listaba como "allowed") sin exponerlo al modelo.
4. **Defaults conservadores en nuclei**: `-no-interactsh` (OAST desactivado),
   `-exclude-tags intrusive,fuzz,fuzzing,dos,brute-force`, severidades por
   defecto `low,medium`, `-timeout 10` por petición. El nivel de ruido se deriva
   de las severidades **efectivas** (incluido el default), no de la entrada vacía.
5. **`ffuf` siempre con rate limit**: `-rate` por defecto 50 req/s
   (ffuf por defecto es 0 = ilimitado), tope 200; `threads` tope 50. El ruido se
   calcula por threads y luego se toma el máximo con el de las flags.
6. **Wordlist de ffuf contenida en el workspace**: `resolve_wordlist()` exige
   ruta dentro de `NEXUS_WORKSPACE_ROOT` y que el fichero exista; si no, error.
   Sin esto, `wordlist=/etc/passwd` convertía la tool en un lector de ficheros.
7. **Un scan sin hallazgos es un éxito verificado** (`verified=True`, `count=0`)
   en httpx/nuclei/ffuf, igual que `nmap` con 0 hosts: la post-condición es "el
   binario corrió y su salida se parseó", no "encontró algo".
8. **Duplicados gestionados**: se quitan de las flags del modelo las que el
   handler fija (todas booleanas, así que no se huérfana ningún valor) y se
   de-duplican targets conservando el orden.
9. **Parser de informes**: un payload no vacío sin registros parseables devuelve
   `ValueError` → el handler responde `verified=False` con
   `verification_method="<tool>_parse_failed"`, en línea con el comportamiento
   de nmap con XML malformado.
10. **`risk` y `required_permissions`** siguen el patrón existente
    (`execute:tool:<tool_id>`); `ToolDefinition.timeout_seconds` es el límite del
    handler en el gateway (subfinder 300, httpx/nuclei/ffuf 600) y el
    `timeout_seconds` del argumento acota la ejecución en el sandbox.
