# Fase 3B — Ecosistema (MCP + Skills + OMNI.md) y Modo Headless

Documento de misión (docs-as-code) de la Fase 3B sobre la rama
`feat/ecosystem-phase-3b`, partiendo de `feat/offensive-depth-phase-3` (`1b32c01`,
Fase 3A completa).

> **Este documento explica el PORQUÉ de cada decisión, no solo el QUÉ.** Las
> desviaciones respecto al prompt maestro están en la §10 y las limitaciones
> honestas (lo que **no** se pudo verificar) en la §11.

---

## 0. Estado de partida (verificado en esta sesión)

| Comprobación | Comando | Resultado |
| --- | --- | --- |
| Rama base | `git log -1 --oneline feat/offensive-depth-phase-3` | `1b32c01 feat(agent): Fase 3A …` |
| Suite de partida | `.venv/bin/python -m pytest nexus_core/tests/unit -q` | **1901 passed, 1 skipped, 0 failed** |
| Escritorio de trabajo | `git branch --show-current` | `feat/ecosystem-phase-3b` (creada desde `1b32c01`) |

---

## 1. Alcance entregado y criterio de corte

El prompt maestro pedía 3D (ecosistema), 3E (reporte) y 3F (headless). Por
decisión explícita del usuario (`ask_user`) esta rama entrega **3D + 3F** y
**difiere 3E**. El criterio es de **dependencia**, no de comodidad: 3E (CVSS 4.0,
mapeos PTES/WSTG/NIST/D3FEND, SARIF, enriquecimiento CVE offline) no comparte
ninguna pieza con 3D/3F y su calidad exige su propia sesión (el mapeo de marcos
es un *catálogo* de cientos de técnicas y el enriquecimiento CVE quiere caché
propia).

```
Fase 3B (esta rama, entregada)
├── 3D.1 MCP cliente + registry + gateway_bridge   nexus_core/integrations/mcp/
├── 3D.2 Skills firmables (HMAC)                   nexus_core/agent/skills.py
├── 3D.3 OMNI.md / AGENTS.md / CLAUDE.md           nexus_core/agent/project_context.py
├── 3D.4 Fan-out read-only enganchado              nexus_core/cli/session.py
└── 3F  Modo headless (--json / --stream-json)     nexus_core/cli/headless.py

Fase 3E (diferida por decisión del usuario)
└── CVSS 4.0 · mapeos · SARIF 2.1.0 · CVE offline-first
```

**Gobernanza intacta.** No se ha cambiado la semántica del scope firmado (HMAC),
la cadena de auditoría por hash, las aprobaciones durables ni la regla de oro.
Los dos únicos cambios en la superficie de gobernanza son **correcciones de
fallo** (§8 y §9): el kill switch de RoE era inerte y su `show` miraba otro
fichero que el que escribe el CLI.

---

## 2. Dependencias nuevas (autorizadas por el usuario)

El usuario autorizó explícitamente instalar y declarar cuatro dependencias. Cada
una tiene un motivo y una alternativa descartada.

| Dependencia | Versión instalada | Destino | Por qué |
| --- | --- | --- | --- |
| `mcp` | 2.3.0 (`modelcontextprotocol.io`, MIT) | `[project.dependencies]` | **SDK oficial** del protocolo. Elegido frente a un cliente a mano porque el protocolo está versionado y evoluciona (stdio, streamable HTTP, SSE); reimplementarlo es deuda garantizada. Trae `httpx2`, `sse-starlette`, `starlette`, `jsonschema`, `pyjwt`, `python-multipart`, `uvicorn`. **`httpx==0.28.1` quedó intacto**: no hay conflicto con el cliente LLM. |
| `keyring` | 25.7.0 | `[project.dependencies]` | Backend de llavero del sistema para `config/secrets.py`. Sin él, la elección de backend degrada a fichero `0600`, que es correcto pero peor. |
| `mypy` | 2.4.0 | `[project.optional-dependencies].dev` | Verificación estática (deuda §8.3 de FASE3). Sólo dev: no entra en el runtime. |
| `pytest-cov` | 7.1.0 | `[project.optional-dependencies].dev` | Medir cobertura del código nuevo (deuda §8.1). `pytest-cov` ya estaba declarado en `dev`; se conserva. |

Declaradas en `pyproject.toml` (`mcp>=2.3,<3`, `keyring>=25.7,<26`,
`mypy>=1.11,<3`) y en `nexus_core/requirements.txt` (`mcp`, `keyring`), con
comentario de propósito en cada línea.

---

## 3. 3D.1 — Cliente MCP

### 3.1 Diseño en tres capas

```
nexus_core/integrations/mcp/
├── client.py          habla con el servidor (SDK oficial) — NO ejecuta nada
├── registry.py        allowlist TOML + descubrimiento cacheado
└── gateway_bridge.py  convierte cada tool MCP en una tool duradera gobernada
```

La idea que hace que todo lo demás sea gratis: **una tool MCP se registra como
una tool duradera** (`tools/registration.py`, `replace=False`). El bucle ReAct
sólo alcanza herramientas a través de `execute_tool → ToolGateway`, así que la
tool MCP hereda *sin código extra* policy, scope firmado, gate de RoE,
aprobaciones durables, sandbox y cadena de auditoría. No hay puerta lateral, y
`gateway_bridge.py` es precisamente lo que garantiza que no la haya: nunca llama
a `session.call_tool` fuera de un handler que el gateway invocó.

### 3.2 Allowlist (fail-closed por ausencia)

El fichero se resuelve en este orden: `$NEXUS_MCP_CONFIG` → `<XDG_CONFIG_HOME>/omni/mcp_servers.toml`.

```toml
# ~/.config/omni/mcp_servers.toml
[[servers]]
name          = "filesystem"
transport     = "stdio"
command       = "npx"
args          = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
allowed_tools = ["read_file", "list_directory"]   # [] ⇒ NINGUNA tool permitida
env           = { MCP_MODE = "1" }                 # se suma al entorno saneado
call_timeout  = 30.0
connect_timeout = 30.0

[[servers]]
name          = "github"
transport     = "http"
url           = "https://api.githubcopilot.com/mcp/"
allowed_tools = ["search_repositories"]
requires_approval = ["create_issue"]              # ⇒ RiskLevel.HIGH ⇒ aprobación durable
```

- **Fichero ausente ⇒ cero servidores.** No hay descubrimiento implícito.
- Un `[[servers]]` malformado **lanza** (`name`/`command`/`url`/`transport`
  inválidos, `env` no-tabla, nombres duplicados), en vez de saltarse la entrada:
  una errata no puede convertirse en "sin allowlist" y luego en un run permisivo.
- La allowlist se **re-comprueba en cada llamada** dentro del handler, así que un
  cambio de configuración no puede ampliar una sesión viva. La denegación se
  audita como `mcp.tool_denied` y lanza `PermissionError("mcp_tool_denied: …")`.

### 3.3 Todo output es dato no confiable

Dos canales distintos, ambos hostiles por construcción:

| Canal | Qué haría un servidor malicioso | Defensa |
| --- | --- | --- |
| **Descripción de la tool** | Llega al *system prompt* vía catálogo: inyectar ahí es lo más peligroso | `sanitize_description`: neutraliza delimitadores, aplana *whitespace* (mata transcripciones falsas), recorta a 400 chars y antepone `[mcp · no confiable]` |
| **Output de la tool** | Entra como observación en el bucle | Se devuelve como `ToolResult` normal; el bucle lo envuelve con `render_for_model` → `<<UNTRUSTED_TOOL_OUTPUT>> … <</UNTRUSTED_TOOL_OUTPUT>>` + señales de inyección |

El recorte de output es de 200 000 chars (`MAX_OUTPUT_CHARS`), aplicado tanto a
`output.text` como a `stdout` del resultado, para no reventar el presupuesto de
tokens con un servidor charlatán.

### 3.4 Fail-closed y timeouts

`MCPClient` envuelve el SDK con `asyncio.wait_for` en **todo** límite:

| Etapa | Default | Excepción |
| --- | --- | --- |
| connect + initialize | `connect_timeout` = 30 s | `MCPTimeout` |
| `tools/list` | 15 s | `MCPTimeout` |
| `call_tool` | `call_timeout` = 30 s (por servidor) | `MCPTimeout` |
| transporte caído / binario inexistente | — | `MCPUnavailable` |

El handler audita `mcp.timeout` / `mcp.unavailable` y **relanza**: un servidor
colgado nunca se convierte en un éxito silencioso ni en un salto de fase
invisible.

### 3.5 El niño nunca ve nuestros secretos

Un servidor stdio es un subproceso. Si le diéramos `os.environ` heredaría
`NEXUS_SCOPE_SIGNING_SECRET`, las claves de LLM y la URL de la base de datos
(regla 7). `sanitized_env` sólo deja pasar `BENIGN_ENV_KEYS`
(`PATH, HOME, LANG, TERM, TMPDIR, TMP, TEMP, USER, SHELL, PWD`) y descarta
cualquier nombre que contenga un marcador de secreto (`SECRET`, `TOKEN`,
`PASSWORD`, `API_KEY`, `CREDENTIAL`, `DATABASE_URL`, `DSN`, …). Encima se aplica
el `env` que el operador escribió en el TOML. `to_dict()` del config expone
`env_keys`, nunca los valores.

### 3.6 Riesgo y aprobación

- `requires_approval` ⇒ `RiskLevel.HIGH` ⇒ `PolicyEngine` exige aprobación
  humana **durable** (misma maquinaria de la Fase 1).
- Cualquier otra tool MCP es `MEDIUM`: un servidor MCP es una frontera de cadena
  de suministro, así que **nada** de lo que expone es `READ_ONLY` por defecto.
- `timeout_seconds` de la definición = `call_timeout + 5`, para que el gateway no
  mate la llamada antes de que el cliente pueda cerrarla limpiamente.

### 3.7 Los cinco casos de test obligatorios

`nexus_core/tests/unit/test_mcp_integration.py` (46 tests) cubre, entre otros:

1. **Payload malicioso no obedecido** — extremo a extremo con el bucle ReAct
   real: la salida hostil llega envuelta con los delimitadores, con cabecera
   "posible prompt-injection" y `injection_signals` persistidas; el modelo recibe
   datos, no instrucciones.
2. **Tool fuera de allowlist ⇒ `mcp_tool_denied` auditado** — re-chequeo en
   llamada, `PermissionError`, cadena de auditoría verificada.
3. **Servidor caído ⇒ timeout fail-closed auditado como `mcp.timeout`** — y
   también con el transporte stdio **real** (subproceso que no habla el
   protocolo).
4. **Output envuelto con `<<UNTRUSTED_TOOL_OUTPUT>>` + `injection_signals`**.
5. **Registro con `replace=False`** — un MCP no puede sombrear
   `nexus.recon.nmap`; el re-sync desregistra las tools que salen de la allowlist.

---

## 4. 3D.2 — Skills

Una skill es `.agents/skills/<nombre>/SKILL.md`: un procedimiento que el operador
puede activar (`/skills use <nombre>`, `--skill <nombre>`). Nada se activa de
forma implícita (fail-closed por defecto), porque el riesgo es exactamente el de
cadena de suministro: clonas un repo, trae un `SKILL.md` envenenado.

| Estado | Cuándo | Cómo la trata el agente |
| --- | --- | --- |
| `signed` | `SKILL.md.sig` coincide con el HMAC-SHA256 bajo `NEXUS_SCOPE_SIGNING_SECRET` | guía de confianza, **aún delimitada** (defensa en profundidad) |
| `unsigned` | no hay `.sig` | datos **no confiables** con aviso explícito y señales |
| `invalid` | hay `.sig` pero no verifica | **se rechaza**: nunca se renderiza, `usable=False` |

Se reutiliza el mismo secreto del scope (`scope.signing_secret`) en vez de
inventar otro: una sola raíz de confianza es más fácil de auditar y de rotar.

**Previsualización.** `/skills show <nombre>` imprime el contenido completo, el
grado de confianza, el `sha256` y las señales de inyección **antes** de activar.
Una skill con firma inválida no se previsualiza: se rechaza con mensaje explícito.

Todo el contenido llega al prompt por `wrap_untrusted_output` +
`scan_untrusted_text`, con procedencia y `sha256` en la cabecera.

**Ejemplo entregado:** `.agents/skills/example/SKILL.md` (barrido de puertos
solo-lectura) + `.agents/skills/README.md` con el procedimiento de firma. Ver §10
para por qué el ejemplo va **sin** `.sig`.

> `.agents/` está en `.gitignore` (es un directorio local del operador). El
ejemplo se incluye con `git add -f` como excepción deliberada: el prompt lo pide
como entregable. Las skills que escriba el operador seguirán ignoradas.

---

## 5. 3D.3 — OMNI.md (instrucciones de proyecto)

Precedencia: `OMNI.md` → `AGENTS.md` → `CLAUDE.md` (el primero que exista, en la
raíz del proyecto). Se lee una vez por run, se envuelve como dato no confiable y
se escanea.

**Procedencia en la auditoría.** Cuando hay instrucciones (o skills), el bucle
escribe una fila `project.context_loaded` con:

```json
{"project": {"path": "…/OMNI.md", "sha256": "…", "bytes": 1234,
             "signals": ["instruction_override"], "truncated": false},
 "skills": [{"name": "…", "sha256": "…", "trust": "signed", …}],
 "refused_skills": []}
```

Así los **bytes exactos** que dieron forma al run quedan demostrables después.
El tope es de 16 000 bytes (`MAX_PROJECT_BYTES`); un fichero ilegible o mal
codificado degrada a `None` — un `OMNI.md` roto no puede detener un engagement.

---

## 6. 3D.4 — `gather_readonly` enganchado a la orquestación

Deuda §8.5 de FASE3, resuelta con `OmniSession.fan_out_tool(tool_id, targets, …)`:

- El caso canónico es un CIDR: la misma enumeración sobre todos los hosts a la
  vez, en lugar de un turno por host.
- **Solo perfiles `parallel_safe`** (los read-only). `gather_readonly` lanza
  `ValueError` *antes* de programar nada si el perfil no lo es, así que una fase
  activa no puede paralelizarse por accidente.
- El límite de concurrencia se respeta y está capado en duro
  (`DEFAULT_MAX_PARALLEL = 4`), aunque el llamante pida más.
- Cada llamada pasa por `execute_tool`: policy, scope firmado, gate de RoE y
  auditoría se aplican **a cada target por separado**. Los resultados vuelven en
  el orden del llamante; un target que falla devuelve su excepción en su sitio en
  vez de descartar a sus hermanos.
- Se audita `fanout.started` con perfil, `read_only`, targets y concurrencia.

---

## 7. 3F — Modo headless

```bash
omni run "Escanea 10.0.0.1 y enumera servicios" --json          # un objeto al final
omni run "Escanea 10.0.0.1 y enumera servicios" --stream-json   # NDJSON en vivo
omni --objective "…" --stream-json                              # equivalente
```

- **Nunca abre la TUI.** `main.py` construye la sesión con `use_tui=False` cuando
  hay objetivo headless; no se instancia la aplicación de `prompt_toolkit` ni la
  pantalla alternativa.
- **`--json`**: un único objeto `run.complete` (con `duration_seconds`).
- **`--stream-json`**: NDJSON, un evento por línea, cada línea parseable por
  separado. Se emiten los run events (`react.step`, `orchestrator.subagent`, …) y
  las filas de auditoría relevantes (`tool.invoke`, `tool.complete`,
  `mcp.tool_denied`, `mcp.timeout`, `scope.denied`, `roe.denied`, …).
- **`subagent_id` en cada línea** cuando el productor lo conoce, para que un
  consumidor de CI atribuya cada paso a la fase que lo propuso.
- **Aprobaciones**: no hay humano, así que las tools que requieren aprobación se
  **deniegan** salvo `--trust-mode` (auto-aprobación auditada de alto riesgo,
  nunca destructivas).
- **Sin color.** La salida es JSON puro: `--no-color`/`NO_COLOR` se respetan
  (el modo headless no emite ANSI en ningún caso).
- **Exit code**: `0` para `completed`/`max_iterations`/`clarification`; `1` en
  cualquier otro estado; `2` si el objetivo está vacío; `130` en SIGINT.

**Shim `run`.** El CLI es argparse-por-flags, sin subparsers. `omni run "…"` se
implementa como un posicional oculto (`nargs="*"`, `SUPPRESS`) que el
despachador interpreta, en vez de introducir un subparser real que rompería
`--objective`, la selección de engagement y todos los flags existentes. Un
`command[0]` distinto de `run` es un error de uso (exit 2) sin arrancar nada.

---

## 8. Bug encontrado y corregido: el kill switch de RoE era inerte

Esta es la deuda #2 del prompt ("verificar `omni --roe arm` end-to-end con un
engagement real") y **la verificación encontró un fallo real**.

**Síntoma.** Con una RoE guardada y `omni --roe kill` ejecutado, una llamada a
`execute_tool` sobre un engagement real **se ejecutaba** y se auditaba como
`tool.invoke` + `tool.complete`. El kill switch no detenía nada.

**Causa.** `RoEEnforcer.stopped` sólo miraba `roe.kill_switch_file`, un campo del
JSON firmado. Pero `run_roe_action("kill")` escribe el centinela en
`kill_switch_path(engagement_id)` (`<XDG_STATE>/omni/roe/<eng>.kill`) y **no**
toca `kill_switch_file`. Como el campo venía vacío, `stopped` era siempre `False`:
el CLI y el runtime hablaban de ficheros distintos. El mismo desajuste hacía que
`omni --roe show` dijera "activa" con el kill switch puesto.

**Corrección** (`nexus_core/scope/roe.py`, `nexus_core/cli/roe_cli.py`):

- `RoEEnforcer` acepta un contexto `paths` opcional y `load_enforcer` se lo pasa.
- `_kill_switch_paths()` honra **ambos**: el `kill_switch_file` declarado en la
  RoE firmada *y* el centinela estándar del engagement, resueltos con el mismo
  contexto de paths. `stopped` es `any(exists(...))`.
- `run_roe_action("show")` construye el enforcer con el mismo `paths`, así que el
  estado que muestra es el fichero que el CLI escribe.

**Regresión cubierta** (`test_roe.py`, +3 tests): CLI kill → enforcer detenido;
`show` reporta `DETENIDA`; y un extremo a extremo
`engagement → RoE → kill → execute_tool denegado + auditado como roe.denied →
arm → la misma llamada pasa`.

**Verificado además a mano con el CLI real** (XDG temporal, engagement firmado):
`--roe path` → `--roe show` → `--roe kill` → `--roe arm` → `--roe arm`
(idempotente) devuelven lo esperado, y la ejecución gobernada con el centinela
activo se deniega auditando `roe.denied`.

> Nota: esto **corrige** la gobernanza, no la relaja. El kill switch pasa de ser
> un botón decorativo a detener de verdad toda acción.

---

## 9. Bug corregido: `keyring` y el test de fallback

Al instalar `keyring`, `test_config_secrets.py::test_select_backend_falls_back_to_file_without_keyring`
pasaba aislado pero fallaba en suite. El test simulaba "sin keyring" con
`monkeypatch.setattr(sys, "modules", {..., "keyring": None})`, que **deja de
simular un módulo ausente** una vez que `keyring` ya se importó en el proceso. La
corrección monkeypatchea `builtins.__import__` para lanzar `ImportError` en
`"keyring"`, que es la única simulación fiel de "no instalado".

---

## 10. Desviaciones conscientes respecto al prompt maestro

| # | Prompt | Implementado | Por qué |
| --- | --- | --- | --- |
| 1 | "**Todo** output de MCP pasa por `injection.render_for_model`; skills y OMNI.md también" | Output MCP **sí** lo atraviesa (llega como `react.observation`). Skills y OMNI.md usan `wrap_untrusted_output` + `scan_untrusted_text` **directamente** | `render_for_model` **sólo envuelve** mensajes de tipo `react.observation` y pasa el resto sin tocar. Aplicarlo a una cadena de proyecto sería un `no-op` que daría falsa sensación de protección. Se usan los mismos primitivos de frontera, que es la lectura honesta de la regla. Hay un test que lo documenta. |
| 2 | "Ejemplo de skill **firmado** HMAC" | El ejemplo va **sin** `.sig`; el `README.md` trae el procedimiento de firma | Una firma válida depende de *tu* `NEXUS_SCOPE_SIGNING_SECRET`. Firmar con un secreto público sería forjable; incluir el secreto real lo filtraría. Sin `.sig`, la skill se trata como dato no confiable, que es el modo seguro, y firmarla es un comando de una línea. |
| 3 | `omni run` como subcomando | Shim (posicional oculto) | Un subparser real rompería el diseño argparse-por-flags (`--objective`, `--engagement`, `--roe`, …). Ver §7. |
| 4 | 3E (CVSS 4.0, mapeos, SARIF, CVE) en esta entrega | Diferido | Decisión del usuario vía `ask_user`; criterio de dependencia en §1. |
| 5 | `omni --roe [ACCION]` como subcomando (FASE3 §7, fila 2) | Sigue como flag, ya documentado como desviación en FASE3 | Es el mismo diseño argparse-por-flags; no era el objetivo de esta fase y cambiarlo rompería compatibilidad. |

---

## 11. Limitaciones honestas (lo que **no** se pudo verificar)

1. **Servidor MCP real de terceros.** Los tests ejercitan la frontera con
   sesiones inyectadas y, además, el transporte stdio **real** contra subprocesos
   que fallan a propósito (silencio, binario inexistente). **No** se ha validado
   contra un servidor MCP publicado (p. ej. `@modelcontextprotocol/server-filesystem`):
   requiere red/npm y no se ejecutó.
2. **Transporte HTTP/SSE.** `streamable_http_client` está implementado y tipado,
   pero **no** cubierto por un test con servidor real (sólo se cubre la
   construcción del path HTTP por análisis estático). Queda como deuda.
3. **`mcp` 2.3.0.** La API del SDK se verificó por inspección y por los tests de
   transporte real; una futura major del SDK puede cambiar firmas. El adaptador
   (`_SDKSession`) está aislado justo para eso.
4. **Aprobación durable de MCP.** Se verifica que la definición resultante es
   `HIGH` (que es lo que dispara la aprobación de `PolicyEngine`), pero **no** un
   ciclo completo de aprobación humana contra un servidor MCP real.
5. **mypy.** No hay configuración de mypy en el repo; los **169** hallazgos
   preexistentes en `nexus_core` (con `--ignore-missing-imports`) siguen ahí. El
   código **nuevo** de 3B quedó limpio (§12). No se añadió un gate de CI.
6. **Cobertura.** Medida sólo sobre los módulos nuevos, ejecutando sus tests (§12);
   no se mide la cobertura global del proyecto.

---

## 12. Verificación reproducible

```bash
# Suite unitaria completa
.venv/bin/python -m pytest nexus_core/tests/unit -q
#   → 1987 passed, 1 skipped, 0 failed   (partida: 1901 passed)

# Tests nuevos/ampliados de 3B
.venv/bin/python -m pytest \
  nexus_core/tests/unit/test_mcp_integration.py \
  nexus_core/tests/unit/test_project_context.py \
  nexus_core/tests/unit/test_skills.py \
  nexus_core/tests/unit/test_headless_ndjson.py \
  nexus_core/tests/unit/test_fanout.py \
  nexus_core/tests/unit/test_cli_headless_shim.py -q    # → 110 passed

# Cobertura del código nuevo
.venv/bin/python -m pytest \
  nexus_core/tests/unit/test_mcp_integration.py \
  nexus_core/tests/unit/test_project_context.py \
  nexus_core/tests/unit/test_skills.py \
  nexus_core/tests/unit/test_headless_ndjson.py \
  nexus_core/tests/unit/test_fanout.py \
  --cov=nexus_core.agent.project_context --cov=nexus_core.agent.skills \
  --cov=nexus_core.integrations.mcp --cov=nexus_core.cli.headless \
  --cov-report=term -q

# Estática (F/E9) y compilación
.venv/bin/python -m ruff check <ficheros> --select F,E9
.venv/bin/python -m compileall -q <ficheros>

# mypy sobre el código nuevo
.venv/bin/python -m mypy nexus_core/agent/project_context.py \
  nexus_core/agent/skills.py nexus_core/integrations/mcp \
  nexus_core/cli/headless.py --ignore-missing-imports
```

### 12.1 Cobertura del código nuevo (medida, no estimada)

| Módulo | Stmts | Miss | Cobertura |
| --- | --- | --- | --- |
| `agent/project_context.py` | 44 | 1 | **98 %** |
| `agent/skills.py` | 92 | 3 | **97 %** |
| `cli/headless.py` | 90 | 3 | **97 %** |
| `integrations/mcp/__init__.py` | 4 | 0 | **100 %** |
| `integrations/mcp/client.py` | 173 | 16 | **91 %** |
| `integrations/mcp/gateway_bridge.py` | 68 | 0 | **100 %** |
| `integrations/mcp/registry.py` | 102 | 2 | **98 %** |
| **Total** | 573 | 25 | **96 %** |

Objetivo del prompt: ≥90 % en código nuevo. Cumplido (96 % global; **todos** los
módulos ≥91 %).

### 12.2 Tests nuevos/ampliados

| Fichero | Tests | Nota |
| --- | --- | --- |
| `test_mcp_integration.py` | 46 | 27 → 46 (+19 de ramas defensivas) |
| `test_project_context.py` | 12 | nuevo |
| `test_skills.py` | 27 | nuevo (incluye previsualización por `/skills`) |
| `test_headless_ndjson.py` | 10 | nuevo |
| `test_fanout.py` | 8 | nuevo |
| `test_cli_headless_shim.py` | 7 | nuevo |
| `test_roe.py` | 31 | 28 → 31 (+3 de regresión del kill switch) |
| `test_config_secrets.py` | — | corregido el fallback de `keyring` (§9) |

Total añadido a la suite: **+86 tests** (1901 → 1987).

### 12.3 Comprobación manual del CLI real (`--roe`)

Ejecutado contra un engagement firmado en un XDG temporal:

```
engagement creado: eng-b530a6ee923c · e2e-roe · cidrs=['127.0.0.1/32']
RoE: /tmp/…/state/omni/roe/eng-b530a6ee923c.json
sin RoE configurada para eng-b530a6ee923c
⛔ kill switch activado: toda acción se detiene de inmediato (…/eng-b530a6ee923c.kill)
✓ kill switch desarmado; el engagement puede continuar
✓ el kill switch ya estaba desarmado
```

Y con el centinela activo, `execute_tool` sobre `nexus.knowledge.record_fact`
deniega (`RoEKillSwitch`) auditando `roe.denied`; tras `arm`, la misma llamada
devuelve `success=True`.

---

## 13. Deuda restante

1. **3E completa** — CVSS 4.0 (fuente `tool|llm|heuristic` expuesta en el
   reporte), mapeos PTES/WSTG/NIST SP 800-115/D3FEND, export SARIF 2.1.0,
   enriquecimiento CVE offline-first (NVD/EPSS/CISA KEV con caché local y
   degradación elegante).
2. **Test de integración con servidor MCP real** por transporte (stdio con un
   servidor npm, y HTTP/SSE con un servidor de prueba).
3. **Ciclo completo de aprobación durable sobre una tool MCP real.**
4. **Gate de mypy en CI** (los 169 hallazgos preexistentes habría que abordarlos
   primero).
5. **Benchmark** de la Fase 3 (deuda §8.2 de FASE3).
