# CAPABILITIES_RECON — FASE 0: pre-flight de las 5 tools web/recon

Rama: `feat/capabilities-web-recon` (partiendo de `fix/single-writer-boundary`).
Fecha: 2026-09-30. Todos los datos de formato fueron capturados **empíricamente**
con los binarios instalados en este host; ninguno proviene de documentación.

## 1. Binarios y versiones

```
$ which sqlmap gobuster whatweb searchsploit dalfox
/usr/bin/sqlmap
/usr/local/bin/gobuster
/usr/bin/whatweb
/usr/local/bin/searchsploit
/usr/local/bin/dalfox
```

| Binario | Versión verificada | Comando de versión |
|---|---|---|
| sqlmap | `1.8.4#stable` | `sqlmap --version` (exit 0) |
| gobuster | `3.8.2` | `gobuster --version` (exit 0) |
| whatweb | `0.5.5` | `whatweb --version` (exit 0) |
| searchsploit | (Exploit-DB local en `/opt/exploitdb`) | `searchsploit -h` (ayuda; **exit 2**) |
| dalfox | `v2.13.0` | `dalfox version` (exit 0, imprime banner ASCII + `Dalfox v2.13.0`) |

### Discrepancias empíricas frente al prompt (decididas y documentadas)

1. **`gobuster version` NO funciona** en el build instalado:
   ```
   $ gobuster version ; echo $?
   No help topic for 'version'
   3
   ```
   Es un subcomando inexistente en 3.8.2 (el binario usa `--version`/`-v`).
   → En `install_recipes.json` **se corrige** a `["gobuster", "--version"]`. El
   detector (`provisioner/detector.py::check_tool`) exige `returncode == 0`
   para extraer la versión, así que `gobuster version` dejaría `version=None`.
   El resto de la receta (go/apt) se mantiene.

2. **`dalfox version` SÍ funciona** (exit 0) → la receta `["dalfox", "version"]`
   se mantiene tal cual pide el prompt.

3. **`searchsploit -h`** es el comando de disponibilidad correcto
   (`--version` devolvería `illegal option -- -`). Aplicado en
   `install_recipes.json` y en el handler.

4. **Gobuster imprime las rutas SIN slash inicial** (`index.html`, `shared`),
   mientras el regex del prompt asumía `^/\S+`. El parser acepta slash inicial
   opcional (`/?\S+`). Ver §4.

## 2. sqlmap — formatos verificados

- `--batch`, `--flush-session` presentes en `sqlmap --help`.
- `--output-dir`, `--answers`, `--no-cast`, `--no-escape`, `--threads`,
  `--stop`, `--time-sec`, `--tamper`, `--timeout` presentes en `sqlmap -hh`
  (help avanzado). Verificado con `sqlmap -hh | grep`.
- Flags de explotación (`--os-shell`, `--file-read`, `--file-write`) existen
  y por eso deben bloquearse en la allowlist del handler.

Run real contra `http://scanme.nmap.org/?id=1` (`--batch --level=1 --risk=1`):

```
[INFO] testing connection to the target URL
[INFO] the back-end DBMS is ... (solo si se identifica)
[INFO] testing if GET parameter 'id' is dynamic
[WARNING] GET parameter 'id' does not appear to be dynamic
[WARNING] GET parameter 'id' does not seem to be injectable
[ERROR] all tested parameters do not appear to be injectable. ...
```

**Hallazgo clave:** el fichero `<output-dir>/<host>/log` queda **vacío** cuando
el target no es inyectable; toda la señal está en **stdout** (con prefijo
`[HH:MM:SS]` y `\r`). El parser trabaja sobre stdout, no sobre el log.

Mensajes exactos extraídos del código instalado (`/usr/share/sqlmap`):

- DBMS: `lib/core/session.py:38` → `"the back-end DBMS is %s"`.
- Inyectable: `lib/controller/controller.py:637` →
  `"<place> parameter '<p>' is vulnerable. Do you want to keep testing the others (if any)? [y/N]"`.
- No inyectable (param): `controller.py:645` →
  `"<place> parameter '<p>' does not seem to be injectable"`.
- No inyectable (final): `controller.py:666` →
  `"all tested parameters do not appear to be injectable."`.
- Bloque de informe: `controller.py:163` → `Parameter: <p> (<PLACE>)`,
  `Type: <stype>`, más `Title:` y `Payload:`.

## 3. whatweb — formato verificado

```
$ whatweb --log-json=/tmp/whatweb.json --no-errors --color=never --quiet \
          --max-threads=10 --aggression=1 http://scanme.nmap.org/
```
JSON real (lista de objetos):
```json
[
{"target":"http://scanme.nmap.org/","http_status":200,
 "request_config":{"headers":{"User-Agent":"WhatWeb/0.5.5"}},
 "plugins":{
   "Apache":{"version":["2.4.7"]},
   "Country":{"string":["RESERVED"],"module":["ZZ"]},
   "Google-Analytics":{"version":["Universal"],"account":["UA-11009417-1"]},
   "HTML5":{},
   "HTTPServer":{"os":["Ubuntu Linux"],"string":["Apache/2.4.7 (Ubuntu)"]},
   "IP":{"string":["45.33.32.156"]},
   "Script":{},
   "Title":{"string":["Go ahead and ScanMe!"]}}}
]
```
Flags confirmados en `whatweb --help`: `--log-json=FILE`, `--no-errors`,
`--colour/--color=WHEN`, `--quiet/-q`, `--max-threads/-t` (default 25),
`--aggression/-a=LEVEL` (1..4). `--quiet` no imprime nada a stdout → el handler
lee el fichero JSON.

## 4. gobuster — formato verificado

```
$ gobuster dir -u http://scanme.nmap.org/ -w words.txt -t 5 -q --no-error
index.html           (Status: 200) [Size: 6974]
images               (Status: 301) [Size: 318] [--> http://scanme.nmap.org/images/]
shared               (Status: 301) [Size: 318] [--> http://scanme.nmap.org/shared/]
```
- `-q` elimina el banner y deja solo las líneas de hit (también en stdout).
- `-o FILE` escribe exactamente las mismas líneas.
- **Sin slash inicial** → regex tolerante `^(?P<path>/?\S+)\s+...`.
- Modos: `dir`, `dns`, `vhost` (y otros). En `dir`/`vhost` el target es `-u`;
  en `dns` es `-d`.
- Flags confirmados en `gobuster dir --help`: `-o/--output`, `-q/--quiet`,
  `--no-error`, `-w/--wordlist`, `-u/--url`, `-t/--threads`, `-x/--extensions`,
  `-s/--status-codes`, `-b/--status-codes-blacklist`, `-k`, `-r`,
  `-e/--expanded`, `--random-agent`, `-d/--delay`, `--exclude-length/--xl`,
  `-c/--cookies`, `-p/--pattern`, `-m/--method`, `-H/--headers`, `--proxy`.

## 5. searchsploit — formato verificado

`searchsploit --json apache` devuelve:
```json
{
  "SEARCH": "apache",
  "DB_PATH_EXPLOIT": "/opt/exploitdb",
  "RESULTS_EXPLOIT": [
    {"Title":"...","EDB-ID":"42283","Date_Published":"2017-06-29",
     "Author":"Metasploit","Type":"remote","Platform":"java",
     "Path":"/opt/exploitdb/exploits/java/remote/42283.rb", ...},
    ...
  ],
  "RESULTS_SHELLCODE": []
}
```
- Campo de fecha real: **`Date_Published`** (el parser acepta `Date_Published`
  → `Date` → `Date_Published`).
- `searchsploit --cve CVE-2021-44228 --json` funciona.
- `-h` es el comando de disponibilidad; **imprime la ayuda y sale con exit 2**
  (no 0), por lo que el handler acepta `{0, 1, 2}` como "disponible".
  `--json`/`-j` confirmado en la ayuda.
- Prohibidos `-m/--mirror` y `-x/--examine` (no se usan).

## 6. dalfox — formato verificado

Run real contra un servidor local autorizado que refleja `q` (finding real):
```json
[
{"type":"V","inject_type":"inHTML-URL","poc_type":"plain","method":"GET",
 "data":"http://127.0.0.1:8765/?q=...",
 "param":"q","payload":"...","evidence":"1 line: ...",
 "cwe":"CWE-79","severity":"High","message_id":670,
 "message_str":"Triggered XSS Payload (found DOM Object): q=..."},
{}
]
```
- Con `--format json --output FILE`, dalfox escribe un **array JSON** (no NDJSON)
  y añade un objeto vacío `{}` de relleno incluso cuando hay un finding.
  El parser filtra los `{}` y admite también NDJSON/JSONL.
- **`type` es `"V"`**, no `"VULN"` como decía el prompt.
- Contra `scanme.nmap.org` (sin XSS) devuelve `[\n{}]` → 0 findings; el handler
  debe tratarlo como éxito con 0 hallazgos.
- Flags confirmados en `dalfox --help`: `--format` (plain/json/jsonl),
  `--no-color`, `--silence/-S`, `-o/--output`, `-w/--worker`, `--timeout`,
  `--skip-bav`, `--deep-domxss`, `-b/--blind`, y los avanzados que se
  bloquean (`--custom-payload`, `--found-action`, `--waf-evasion`, ...).

## 7. Infraestructura del repo relevante

- `registry.durable_tool_definitions()` hoy devuelve **16** tools.
- `scope/validator.py::make_scope_validator` acepta campo escalar **o lista**
  (`targets`), por lo que whatweb (`targets`) y el resto funcionan sin tocar
  scope.
- `provisioner/detector.py::check_tool` usa `verify` y exige exit 0 para
  extraer la versión.
- Tests que fijan el tamaño del catálogo y que **deben actualizarse**:
  - `nexus_core/tests/unit/test_system_env_handler.py` (`len(catalog) == 16`).
  - `nexus_core/tests/unit/test_tui_stream_prefix.py` (asumía que toda tool
    durable tiene prefijo en `PREFIXES`; las 5 nuevas usan el prefijo genérico
    `[Tool]` porque `nexus_core/cli/**` está fuera de alcance).
- `nexus_core/tests/unit/test_cli_banner.py` y `test_tui_visual_startup.py` usan
  un `tools_count=16` **literal** en el fixture, no leen el catálogo → no se
  ven afectados.

## 8. Decisión de ejecución

Todos los formatos anteriores cuadran con el diseño del prompt salvo las
correcciones §1 (gobuster `--version`) y §4 (slash opcional en gobuster),
aplicadas en la implementación. No se detectó ningún binario ausente.
