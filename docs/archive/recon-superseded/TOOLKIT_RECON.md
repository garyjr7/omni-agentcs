# TOOLKIT_RECON — subfinder / httpx / nuclei / ffuf

Misión: añadir 4 tools de recon/web al catálogo durable reusando **exactamente**
el patrón de `nexus.recon.nmap` (definición con `scope_target_field` +
`scope_required`, handler async con allowlist de flags y noise level, parser
determinista, registro explícito, tests parser + handler + E2E opt-in).

Rama: `feat/toolkit-recon` (desde `feat/cli-omni`). Working tree limpio.

---

## 1. Binarios disponibles

| Binario | Ruta | Versión observada |
|---|---|---|
| `subfinder` | `/usr/local/bin/subfinder` | v2.16.0 |
| `httpx` | `/usr/local/bin/httpx` | ProjectDiscovery httpx (banner ASCII, `-version`) |
| `nuclei` | `/usr/local/bin/nuclei` | v3.11.1 |
| `ffuf` | `/usr/local/bin/ffuf` | 2.1.0-dev |
| `nmap` | `/usr/bin/nmap` | (ya integrado) |

`httpx` aquí es el binario de ProjectDiscovery, **no** la librería Python
`httpx`. No hay colisión: son módulos de ruta absoluta distintos.

---

## 2. Verificación de los flags que pide la misión

| Pregunta | Respuesta | Flag exacto |
|---|---|---|
| ¿`httpx` soporta `-json` o `-jsonl`? | **Sí** | `-j, -json` → "store output in JSONL(ines) format" |
| ¿`subfinder` soporta `-json`? | **Sí** | `-oJ, -json` → "write output in JSONL(ines) format" |
| ¿`nuclei` soporta `-jsonl`? | **Sí** | `-j, -jsonl` → "write output in JSONL(ines) format" |
| ¿`ffuf` soporta `-of json`? | **Sí** | `-of` con formatos `json, ejson, html, md, csv, ecsv, all` |

Extra relevante: **`ffuf 2.1.0-dev` soporta `-json`** ("JSON output, printing
newline-delimited JSON records"). Eso permite leer el resultado del **stdout**
del sandbox y evitar fichero temporal + su limpieza.

### Diferencias con el enunciado (verificadas contra `--help`)

- `nuclei` moderno **no** tiene `-interactsh-url` / `-interactsh-token`. Los
  flags reales son `-iserver, -interactsh-server` y `-itoken,
  -interactsh-token`; el interruptor para desactivar OAST es
  `-ni, -no-interactsh`. Ambos nombres se prohíben en la allowlist del LLM.
- `ffuf` usa `-rate` para el rate limit (default `0` = ilimitado). Se impone un
  límite por defecto para cumplir el criterio "ffuf con `-rate` limitado por
  defecto".
- `nuclei` requiere `-u` repetido o `-l`; `-u` es `string[]` (acumulable).

---

## 3. Flags clave por binario

### subfinder v2.16.0
```
-d, -domain string[]      dominios objetivo
-dL, -list string         fichero de dominios
-silent                   solo subdominios
-oJ, -json                salida JSONL
-nc, -no-color            sin ANSI
-timeout int              segundos antes de timeout (default 30)
-max-time int             minutos máximos de enumeración (default 10)
-rl, -rate-limit int      peticiones/segundo (global)
```
Formato JSONL: una línea JSON por subdominio con `host` (+ `input`, `source`).

### httpx (ProjectDiscovery)
```
-u, -target string[]      targets (acumulable)
-l, -list string          fichero de targets
-j, -json                 salida JSONL
-silent                   modo silencioso
-nc, -no-color            sin ANSI
-td, -tech-detect         detección de tecnologías (wappalyzer)
-sc, -status-code         status code
-title                    título de la página
-probe                    estado del probe
-timeout int              timeout en segundos (default 10)
-t/-rl                    hilos / rate limit (default 50 / 150)
```
Formato JSONL: `{url, status_code, title, tech, content_length, ...}`.

### nuclei v3.11.1
```
-u, -target string[]      targets (acumulable)
-l, -list string          fichero de targets
-j, -jsonl                salida JSONL
-silent / -nc             sin ruido / sin ANSI
-s, -severity value[]     info, low, medium, high, critical, unknown
-tags / -etags            filtrar / excluir templates por tag
-rl, -rate-limit int      peticiones/segundo (default 150)
-c, -concurrency int      templates en paralelo (default 25)
-timeout int              timeout por petición (default 10)
-ni, -no-interactsh       desactiva interactsh (OAST)
-iserver/-itoken          servidor/token interactsh
-dast / -headless / -code modos peligrosos
```
Formato JSONL: `{template-id, info: {name, severity}, host, matched-at, type}`.

### ffuf 2.1.0-dev
```
-u             URL (con keyword FUZZ)
-w             wordlist (path[:KEYWORD])
-X             método HTTP
-e             extensiones (comma separated)
-t             hilos (default 40)
-rate          peticiones/segundo (default 0 = ilimitado)
-timeout       timeout HTTP en segundos (default 10)
-p             delay entre peticiones
-s             silent
-json          NDJSON en stdout
-o / -of       fichero y formato de salida
-mc / -fc      match / filter por status code
-input-cmd / -input-shell / -config    EJECUCIÓN ARBITRARIA → prohibido
-x / -replay-proxy / -postflight       proxy → prohibido
```
Formato `-json`: un objeto JSON por match (`{url, status, length, words, lines, ...}`).
Formato `-of json`: `{"results": [...]}`.

---

## 4. Patrón existente que se replica

1. **Definición** (`handlers/*.py::*_definition`): `ToolDefinition` con
   `input_schema` cerrado (`additionalProperties: False`),
   `required_permissions=["execute:tool:<tool_id>"]`,
   `scope_target_field=<campo>`, `scope_required=True`.
2. **Handler** async `(arguments, context) -> ToolResult`:
   - valida y canoniza flags contra una allowlist (`flag -> (noise, requiere_valor)`),
   - calcula el noise level agregado,
   - construye el argv canónico,
   - **nunca** usa `subprocess` directo: siempre `sandbox_for_environment(...)`,
   - parsea la salida con el parser determinista,
   - devuelve `ToolResult` con `verified`, `verification_method`, `evidence`,
     `exit_code`, `accepted_exit_codes`, `stdout`, `stderr`.
3. **Parser** (`parsers/*.py`): dataclasses frozen + `to_dict()`, sin regex sobre
   stdout cuando hay formato estructurado.
4. **Registro** explícito en `durable_tool_definitions()`.
5. `engagement_id` **no** lo toca el handler: lo propaga el bucle ReAct /
   `execute_tool` al `RunContext`, y `make_scope_validator` valida el target.

---

## 5. Hallazgo que obliga a extender el scope validator

`nexus.recon.httpx` y `nexus.web.nuclei` reciben **listas** de targets
(`targets: [...]`), pero `make_scope_validator` actual hace
`str(arguments[field])` y valida ese string. Con una lista eso produce un
target no reconocido → violación espuria (o, peor, un fallo de parseo).

Por eso la Fase 3 extiende `make_scope_validator` (aditivo): si el valor del
campo es `list`/`tuple`, valida **cada** elemento y exige que **todos** pasen;
si la lista está vacía, error. El camino de string no cambia.

---

## 6. Decisiones de transporte (sin ficheros temporales)

El sandbox `LocalSandbox.run` no soporta stdin (`stdin=DEVNULL`) y en OCI el
workspace se monta en `/workspace`. Opciones: fichero temporal en el workspace
+ limpieza, o argumentos repetidos.

Decisión: **argumentos repetidos** (`-u t1 -u t2 ...`) para httpx y nuclei.
- `httpx -u` y `nuclei -u` son `string[]` acumulables.
- 500 targets × ~25 bytes ≈ 12 KB, muy por debajo de `ARG_MAX` (~2 MB).
- Sin fichero temporal ⇒ sin carrera de limpieza, sin acoplamiento al
  bind-mount de OCI, y tests deterministas.
- Para `ffuf` se usa `-json` sobre stdout (soportado en esta versión) en lugar
  de `-of json -o <fichero>`; el parser tolera **ambos** formatos.

`ffuf` sí necesita un wordlist en disco: se resuelve contra
`NEXUS_WORKSPACE_ROOT` y se exige que quede **dentro** del workspace.

### Hallazgo de entorno: `LocalSandbox` no propaga `HOME`

`LocalSandbox.run` lanza el hijo con `env={"PATH": ..., "NEXUS_SANDBOX": "1"}`,
es decir **sin `HOME`**. Medido en este equipo:

- `subfinder` funciona igualmente (sus fuentes no necesitan caché) y devuelve
  JSONL real.
- `httpx` funciona, pero resuelve el home vía `/etc/passwd` y deja
  `./httpx/config.yaml` en el **cwd del sandbox** (el workspace).
- `subfinder` deja `./subfinder/config.yaml` y `./subfinder/provider-config.yaml`.
- `nuclei` crea `~/nuclei-templates` y, si no hay templates instalados, se queda
  intentando descargarlos hasta que vence el timeout del sandbox.

Estos directorios se detectaron y borraron tras la fase de reconocimiento; los
E2E fijan `NEXUS_WORKSPACE_ROOT` a un `tmp_path` para que cualquier artefacto
caiga en el temporal y no en el repo. Queda documentado en `TOOLKIT_RESULT.md`
como limitación de desarrollo (en OCI la imagen correspondiente ya trae sus
assets).

## 7. Allowlists: qué NO puede pasar el LLM (bypass de scope)

El scope se valida sobre los **argumentos estructurados** (`url`, `targets`),
antes de que corra el handler. Por eso los flags que fijan el target o el
fichero de entrada quedan **prohibidos** en las flags propuestas por el LLM:

- nuclei: `-u`, `-l`, `-targets-inline`, `-t`, `-turl`, `-w`, `-wurl`,
  `-iserver`, `-itoken`, `-dast`, `-headless`, `-code`, `-config`, `-H`, `-V`,
  `-o`, `-je`, `-jle`, `-me`, `-se`, `-rdb`, `-sresp`, `-srd`, `-ai`, `-sign`,
  `-file`, `-im`, `-proxy`, `-r`.
- ffuf: `-u`, `-w`, `-X`, `-e`, `-t`, `-o`, `-of`, `-od`, `-x`,
  `-replay-proxy`, `-config`, `-request`, `-input-cmd`, `-input-shell`,
  `-preflight`, `-postflight`, `-b`, `-d`, `-audit-log`, `-debug-log`.

Esos valores los fija **siempre** el handler a partir de los argumentos ya
validados por scope/policy.
