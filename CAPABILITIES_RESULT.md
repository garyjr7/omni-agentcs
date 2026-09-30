# CAPABILITIES_RESULT — 5 tools web/recon durables

Rama: `feat/capabilities-web-recon`. Estado: **completado y verificado**.
Catálogo durable: **16 → 21 tools**. Sin dependencias nuevas. Sin push.

## 1. Tools añadidas

| tool_id | Riesgo | Timeout | Scope | Ficheros |
|---|---|---|---|---|
| `nexus.web.sqlmap` | MEDIUM | 1800 s | `url` | `handlers/sqlmap.py`, `parsers/sqlmap.py` |
| `nexus.recon.gobuster` | MEDIUM | 1800 s | `target` | `handlers/gobuster.py`, `parsers/gobuster.py` |
| `nexus.recon.whatweb` | LOW | 600 s | `targets` (lista) | `handlers/whatweb.py`, `parsers/whatweb.py` |
| `nexus.exploit.searchsploit` | READ_ONLY | 30 s | — (sin scope) | `handlers/searchsploit.py`, `parsers/searchsploit.py` |
| `nexus.web.dalfox` | MEDIUM | 900 s | `target` | `handlers/dalfox.py`, `parsers/dalfox.py` |

Registradas en `nexus_core/tools/registry.py::durable_tool_definitions()`
(imports perezosos). Total: **21**.

## 2. Batería de verificación (salida real)

### Imports — 12/12 OK
```
nexus_core.tools.handlers.{sqlmap,gobuster,whatweb,searchsploit,dalfox} OK
nexus_core.tools.parsers.{sqlmap,gobuster,whatweb,searchsploit,dalfox} OK
nexus_core.tools.registry OK
omni OK
```

### Tools registradas
```
$ .venv/bin/python -c "from nexus_core.tools.registry import durable_tool_definitions; print(len(durable_tool_definitions()), 'tools')"
21 tools
```

### Tests
```
$ NO_COLOR=1 .venv/bin/python -m pytest nexus_core/tests/unit -q
1210 passed

$ env -u NO_COLOR .venv/bin/python -m pytest nexus_core/tests/unit -q
1210 passed

$ NO_COLOR=1 .venv/bin/python -m pytest nexus_core/tests -q
1220 passed, 23 skipped
```
Baseline previo: 1074 tests. Los nuevos: **~146** (10 ficheros unit +
1 integración + scope). Los tests existentes que fijaban el catálogo se
actualizaron (ver §5).

### Ruff
```
$ .venv/bin/ruff check nexus_core/tools <tests nuevos> --select F,E9
All checks passed!
```

### No subprocess
```
$ grep -rnE "subprocess|Popen|os\.system|shell=True" <los 5 handlers> | grep -v "#"
OK: no subprocess
```

### Demo manual `parse_searchsploit_json`
```
$ .venv/bin/python - <<'PY'
from nexus_core.tools.parsers.searchsploit import parse_searchsploit_json
r = parse_searchsploit_json('{"SEARCH":"apache","RESULTS_EXPLOIT":[],"RESULTS_SHELLCODE":[]}', "apache")
print(f"Entries: {r.total}")
PY
Entries: 0
```

### E2E opt-in (real, contra scanme.nmap.org + Exploit-DB local)
```
$ NEXUS_E2E=1 .venv/bin/python -m pytest nexus_core/tests/integration/test_capabilities_web_e2e.py -v
test_e2e_searchsploit_local_lookup PASSED      [ 20%]
test_e2e_whatweb_fingerprints_scanme PASSED    [ 40%]
test_e2e_gobuster_dir_against_scanme PASSED    [ 60%]
test_e2e_sqlmap_detection_only PASSED          [ 80%]
test_e2e_dalfox_handles_zero_findings PASSED   [100%]
======================== 5 passed in 177.61s (0:02:57) =========================
```
- sqlmap: detección sobre `http://scanme.nmap.org/?id=1`; `verified=True`,
  `vulnerable=False` (no inyectable), sin explotación.
- dalfox: 0 findings (correcto, scanme no tiene XSS).
- gobuster/whatweb/searchsploit: resultados reales parseados.

## 3. Seguridad implementada

- **Sandbox siempre**: los 5 handlers ejecutan vía `sandbox_for_environment` +
  `run_in_sandbox`. Cero `subprocess`/`Popen`/`os.system`/`shell=True`.
- **Allowlist por handler** con tuplas `(noise, takes_value)` y conjuntos
  `FORBIDDEN`. Rechazo de flags desconocidos.
- **sqlmap**: siempre `--batch --flush-session --output-dir --answers --no-cast
  --no-escape --threads=1`. **PROHIBIDOS** `--os-shell`, `--os-pwn`,
  `--os-smbrelay`, `--sql-shell`, `--sql-query`, `--file-read`, `--file-write`,
  `--file-dest`, `--priv-esc`, `--reg-read/add/del`. `--dump/--dbs/--tables/...`
  solo con `safe_mode=False`, limitados con `--stop=100`. Metacaracteres de shell
  rechazados en `dbms`/`tamper`; caracteres de control en `url`/`data`/`cookie`.
- **gobuster**: `-o/-of/-z/--proxy/-p/-c/--pattern/-m/-H/--header` prohibidos.
  Wordlist confinada al workspace con `resolve_wordlist()` de ffuf (rechaza
  `/etc/passwd` y el HOME efímero del sandbox).
- **whatweb**: `--log-json --no-errors --color=never --max-threads=10`; agresión
  4 forzada a 3 con advertencia.
- **searchsploit**: `--json` siempre; `-m/--mirror` y `-x/--examine` nunca se
  usan; disponibilidad con `-h`.
- **dalfox**: `--format json --no-color --silence --skip-bav`; **PROHIBIDOS**
  `--custom-payload`, `--found-action`, `--found-action-shell`,
  `--waf-evasion`, `--blind`/`-b`, `--grep`, `--mining-*`, `--mass`,
  `--remote-payloads`, `--remote-wordlists`, `--proxy`, `--payload`. Headers
  con `Host`/`X-Forwarded-For`/`Via` rechazados.
- **Scope gating**: `test_capabilities_scope.py` prueba in-scope/out-of-scope
  para sqlmap/gobuster/whatweb/dalfox contra `make_scope_validator` real;
  searchsploit no requiere scope.

## 4. Parsers deterministas

| Parser | Entrada | Notas |
|---|---|---|
| `sqlmap` | stdout (`[HH:MM:SS] [LEVEL] ...`, `\r`, ANSI) | No usa el log (vacío en no-inyectable); reconoce `the back-end DBMS is`, `parameter 'x' is vulnerable`, bloque `Parameter/Type/Title/Payload`, `do not appear to be injectable`. |
| `gobuster` | stdout (regex acotada) | Única excepción justificada; patrón `path (Status: N) [Size: M] [--> redir]`, tolera slash inicial opcional. |
| `whatweb` | `--log-json` (lista JSON) | `plugins` → fingerprints con `version`/`details`. |
| `searchsploit` | `--json` (objeto) | `RESULTS_EXPLOIT`/`RESULTS_SHELLCODE`; fecha `Date_Published`. |
| `dalfox` | `--format json` (array o NDJSON) | Filtra el `{}` de relleno; `type` real es `"V"`. |

Todos preservan `raw_*_sha256` y distinguen "vacío válido" de "malformado"
(que lanza `ValueError`).

## 5. Tests existentes actualizados

- `nexus_core/tests/unit/test_system_env_handler.py`: `len(catalog) == 16` →
  `21` y subconjunto con las 5 tools.
- `nexus_core/tests/unit/test_tui_stream_prefix.py`: la invariante "toda tool
  durable tiene prefijo" ya no aplica porque `nexus_core/cli/**` está fuera de
  alcance; ahora exige que todas resuelvan a un prefijo y que las 5 nuevas usen
  el genérico `[Tool]`.
- `nexus_core/tests/unit/test_recipes.py`: `len(recipes) == 10` → `13` y
  verificación de `searchsploit -h`.
- `README.md`: catálogo "16 → 21" y listado de tools.

## 6. install_recipes.json

Añadidas `whatweb`, `searchsploit`, `dalfox`. `sqlmap` y `gobuster` ya existían:
- **searchsploit**: `"verify": ["searchsploit", "-h"]` (no `--version`).
- **gobuster**: `"verify"` corregido de `["gobuster", "version"]` (exit 3) a
  `["gobuster", "--version"]` (exit 0) tras verificarlo empíricamente.

## 7. Decisiones de diseño no cubiertas por el prompt

1. **`gobuster verify`**: el prompt pedía `["gobuster", "version"]`, pero en el
   build 3.8.2 ese subcomando no existe (`No help topic`, exit 3). Se corrigió
   a `--version`; documentado en `CAPABILITIES_RECON.md` §1.
2. **`searchsploit -h` sale con exit 2**, no 0. El preflight acepta `{0,1,2}`
   como "disponible" para no dar falso negativo.
3. **sqlmap se parsea desde stdout**, no desde `--output-dir`: el fichero `log`
   del output-dir queda vacío cuando el target no es inyectable (verificado).
4. **gobuster emite rutas sin slash inicial**; el regex del prompt se relajó a
   slash opcional.
5. **dalfox `--format json` es un array** (con objeto `{}` de relleno), no
   NDJSON por finding; el parser acepta ambos y filtra los vacíos.
6. **`flags` extra**: los schemas publicados no exponen `flags` (como el prompt),
   pero los handlers aceptan `arguments["flags"]` validado contra la allowlist;
   así los tests pueden probar el rechazo de flags prohibidos sin abrir la
   superficie al LLM.
7. **dalfox `blind=True`** no añade `--blind` (requiere una URL de callback que
   el schema no ofrece): simplemente omite `--skip-bav`. La opción nunca añade
   flags prohibidos.
8. **Imágenes OCI** por defecto (`secsi/sqlmap`, `ghcr.io/oj/gobuster`,
   `secsi/whatweb`, `secsi/searchsploit`, `hahwul/dalfox`) configurables por
   `NEXUS_*_IMAGE`; no se ejercitan en E2E (sandbox local).

## 8. Fuera de alcance respetado

No se tocaron `kernel/`, `scope/`, `agent/`, `integrations/`,
`provisioner/**` (salvo `data/install_recipes.json`) ni `nexus_core/cli/**`.
