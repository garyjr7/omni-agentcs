# GUÍA DEL AGENTE 1 — Uso autónomo de OMNI con el agente interno

**Producto:** OmniAgentCS-CLI (`omni`) · BAJIOWARE / Team Red
**Versión cubierta:** `3.0.0`
**Alcance de esta guía:** lanzar el **agente autónomo** (bucle ReAct + planner +
subagentes + playbooks), controlarlo desde el REPL con **todos los comandos `/`**,
y usarlo en modo headless/CI. La ejecución manual paso a paso de una tool se cubre
en **[GUIA_MANUAL_1.md](GUIA_MANUAL_1.md)**.

---

## Índice

1. [Cómo funciona el agente](#1-cómo-funciona-el-agente)
2. [Requisitos y arranque](#2-requisitos-y-arranque)
3. [El planner por fases](#3-el-planner-por-fases)
4. [Subagentes (perfiles de capacidad)](#4-subagentes-perfiles-de-capacidad)
5. [Playbooks deterministas](#5-playbooks-deterministas)
6. [Skills](#6-skills)
7. [Modos de permisos y trust mode](#7-modos-de-permisos-y-trust-mode)
8. [Lanzar objetivos: REPL y headless](#8-lanzar-objetivos-repl-y-headless)
9. [Referencia COMPLETA de comandos `/`](#9-referencia-completa-de-comandos-)
10. [Atajos de teclado y control](#10-atajos-de-teclado-y-control)
11. [Flags de la CLI para el agente](#11-flags-de-la-cli-para-el-agente)
12. [Subcomandos del agente](#12-subcomandos-del-agente)
13. [Aprobaciones, resume y hooks](#13-aprobaciones-resume-y-hooks)
14. [Reporte y cierre del engagement](#14-reporte-y-cierre-del-engagement)
15. [Variables de entorno del agente](#15-variables-de-entorno-del-agente)
16. [Códigos de salida y eventos NDJSON](#16-códigos-de-salida-y-eventos-ndjson)

---

## 1. Cómo funciona el agente

El agente es un **bucle ReAct durable** sobre el proveedor LLM que elijas:

```
objetivo → system prompt (plan + playbooks + subagente + tools permitidas)
        → modelo emite { thought, action }   (el "💭 pensamiento" va en streaming)
        → gateway aplica policy/scope/aprobación/auditoría y ejecuta la tool
        → observación (resultado verificado) vuelve al modelo
        → repite hasta task_complete / max_iterations / cancelación
```

Regla de oro: **un modelo propone, nunca afirma éxito**. Todo hallazgo se clasifica
como `confirmed_finding`, `hypothesis` o `inventory`; `completion_verified`
significa que pasaron las compuertas deterministas, no que el objetivo se logró.

Elementos deterministas que enmarcan al modelo (no dependen del LLM):

- **Planner** por fases (kill chain) → §3.
- **Subagentes** que acotan el subconjunto de tools por fase → §4.
- **Playbooks** que sugieren el siguiente paso gated → §5.
- **Skills** curadas por el operador → §6.
- Toda tool sigue pasando por el gateway (scope, aprobación, auditoría).

---

## 2. Requisitos y arranque

```bash
source .venv/bin/activate
export PATH="$HOME/.local/bin:$PATH"

omni                                  # REPL con TUI (pantalla alternativa)
omni --no-fullscreen                  # modo inline (conserva scrollback)
omni --no-tui                         # readline
omni --engagement eng-xxxx            # fija el engagement
omni --continue eng-xxxx              # retoma engagement + conversación
```

El proveedor LLM se resuelve en un único sitio (`nexus_core/cli/llm_env.py`), que
comparten CLI, worker y bucle ReAct:

1. `NEXUS_LLM_DEFAULT_PROVIDER` explícito, si tiene credenciales.
2. `LLM_PROVIDER` o el de `config.toml`.
3. El primer proveedor real disponible.
4. `fake` (offline, determinista) si no hay ninguno.

Un `LLM_PROVIDER=fake` heredado **no** desplaza a un proveedor real configurado.

---

## 3. El planner por fases

Un **planner determinista** (sin LLM) deriva del blackboard la fase del kill chain
y la inyecta en cada prompt con su siguiente paso sugerido. Cada transición se
audita como evento `orchestrator.plan`.

| # | Fase (id) | Etiqueta | Evidencia que la completa |
|---|---|---|---|
| 1 | `recon` | Reconocimiento | `host` o `service` |
| 2 | `enumeration` | Enumeración | `endpoint`, `user`, `email`, `credential` o `vulnerability` |
| 3 | `exploitation` | Acceso inicial | `access` o `session` |
| 4 | `privilege_escalation` | Escalada de privilegios | `privilege` |
| 5 | `post_exploitation` | Post-explotación | `loot` o `artifact` |
| 6 | `lateral_movement` | Movimiento lateral (**opcional**) | `session` o `access` (≥ 2) |
| 7 | `reporting` | Reporte | solo lo cierra `task_complete` |

- El **movimiento lateral es opcional**: aparece en el pipeline pero nunca se
  convierte en la fase actual, así no bloquea el reporte.
- **Hechos sin verificar no avanzan el plan** (son *leads*): solo la evidencia de
  un parser determinista cuenta. Las *leads* sí influyen en qué subagente se usa.
- Salida del planner:
  - Barra de estado: `▸ <fase actual> <n>/<total>`.
  - `/plan` → imprime el plan completo + superficie de ataque + perfil táctico.
  - `/plan on|off` o **F2** → panel lateral superpuesto.
- Puedes forzar cambio de fase registrando hechos con `nexus.knowledge.record_fact`.

---

## 4. Subagentes (perfiles de capacidad)

Cada perfil define un **subconjunto de tools**, un **presupuesto de tokens** y un
**contexto**. Se elige de forma **determinista** (fase + hechos del blackboard);
el modelo nunca se autoasigna el perfil. Un subagente **no** es una frontera de
ejecución: solo encoge la superficie.

| id | Etiqueta | Fase | Modo | Tools | Iter. |
|---|---|---|---|---|---|
| `recon` | Reconocimiento | recon | read-only (paralelizable) | nmap, dns, subfinder, httpx, ftp, gobuster, whatweb, nikto + comunes | 8 |
| `services` | Enumeración de servicios | enumeration | activo | web + ftp, netexec, pwn.analyze, web.request/upload + comunes | 10 |
| `web` | Enumeración web | enumeration | read-only | httpx, gobuster, whatweb, nikto, nuclei, ffuf, dalfox, wp_enum, git_dump + comunes | 10 |
| `cred` | Credenciales | enumeration | activo | cred.bruteforce, wp_bruteforce, netexec, ftp + comunes | 6 |
| `exploit` | Acceso inicial | exploitation | activo | msf_search/auxiliary/exploit, searchsploit, netexec, pwn, wp_bruteforce, wp_exec, web.request/upload, git_dump + comunes | 8 |
| `postexploit` | Post-explotación | post_exploitation | activo | ssh_exec/upload, enum_system, shell_exec, job, pivots, ntlm_capture, dns_update, tftp, dpapi, changepasswd, nopac, winrm, wp_exec, session.*, sliver_sessions/exec/loot + comunes | 8 |
| `privesc` | Escalada de privilegios | privilege_escalation | activo | enum_system, privesc_hints, ssh_exec/upload, session.list, shell_exec, job + comunes | 10 |
| `lateral` | Movimiento lateral | lateral_movement | activo | netexec, bloodhound, secretsdump, getuserspns, psexec, changepasswd, nopac, cred.bruteforce, ssh_exec, pivots, session.*, sliver_sessions/pivot + comunes | 8 |
| `reporter` | Reporte | reporting | read-only | report.generate + comunes | 4 |

**Tools comunes a todos los perfiles:** `nexus.knowledge.record_fact`,
`nexus.knowledge.query_facts`, `nexus.workspace.search`, `nexus.workspace.read`,
`nexus.system.status`, `nexus.system.check_env`, `nexus.orchestrator.playbook`.

**Refinamiento automático:** en `enumeration`, si hay `credential`/`user` → perfil
`cred`; si hay `endpoint`/`vulnerability` → perfil `web`; si no, `services`.
Fase desconocida → falla cerrado al perfil más restrictivo (`recon`).

**Grace de fase:** durante las 2 primeras iteraciones de un perfil nuevo se
heredan las tools read-only del perfil anterior (nunca las activas).

**Alias de operador** (resuelven a un perfil existente; no crean paths nuevos):

| Alias | Perfil |
|---|---|
| `target-mapper` | `recon` |
| `tactical-planner` | `recon` |
| `deep-reasoning` | `recon` |
| `exploit-scripter` | `exploit` |
| `c2-operator` | `postexploit` |
| `stealth-validator` | `reporter` |

**Auto-spawn (`--autospawn`)**: al cambiar de *familia* de fase hacia un perfil
con presupuesto suficiente se delega a una **conversación hijo real**
(`AgentSupervisor`). Umbrales: `NEXUS_AUTOSPAWN_MIN_BUDGET` (def. 20 000 tokens) y
`NEXUS_AUTOSPAWN_MIN_ITERATIONS` (def. 4). Profundidad máxima 2; concurrencia
máxima 4; presupuesto global `--supervisor-budget`. Por defecto **desactivado**.

**Presupuesto por subagente:** `NEXUS_SUBAGENT_BUDGET_<ID>` (p. ej.
`NEXUS_SUBAGENT_BUDGET_RECON=150000`).

---

## 5. Playbooks deterministas

Un **playbook** es una secuencia ordenada de pasos gated cuya aplicabilidad se
decide **solo con el blackboard** (sin LLM). Ningún paso se ejecuta solo: el
gateway sigue aplicando scope, aprobación y auditoría.

### 5.1 Playbooks escritos a mano

| id | Título | Fase | Requiere | Pasos (tool) |
|---|---|---|---|---|
| `ftp_anon_to_cred` | FTP anónimo → credenciales | exploitation | servicio FTP con login anónimo | recon.ftp (list) → recon.ftp (download) → cred.bruteforce |
| `linux_privesc` | Post-explotación Linux → root | privilege_escalation | acceso a host Linux | post.enum_system → post.privesc_hints → post.ssh_exec |
| `lateral_movement` | Movimiento lateral con C2 | lateral_movement | acceso + otro servicio | sliver_generate → sliver_deploy → sliver_sessions |

### 5.2 Paquete declarativo `red_team_base`

`nexus_core/playbooks/red_team_base.yaml` define 4 fases LLM-free:

| Fase | Título | Perfil | Pasos (tool) |
|---|---|---|---|
| `stealth_recon` | Reconocimiento de bajo ruido | `recon` | subfinder → dns → nmap (perfil service) → httpx |
| `staging_and_interaction` | Frontera de aplicación | `services` | gobuster → git_dump → web.upload → web.request |
| `command_execution` | Comandos sobre sesión propia | `privesc` | session.list → shell_exec → job |
| `local_elevation_heuristics` | Heurísticas de elevación | `privesc` | enum_system → privesc_hints → shell_exec |

Cómo consultarlos sin ejecutar:

```text
/playbook                      # aplicables + siguiente paso
/playbook show linux_privesc   # detalle del playbook
```

o vía tool manual:

```bash
omni --engagement eng-x tool nexus.orchestrator.playbook
omni --engagement eng-x tool nexus.orchestrator.playbook '{"action":"list"}'
```

El **siguiente paso de cada playbook aplicable se inyecta en el system prompt**,
de modo que el agente prioriza el servicio que puede entrar.

---

## 6. Skills

Una **skill** es `.agents/skills/<nombre>/SKILL.md`: un procedimiento curado que
el operador activa para que el agente lo siga. Nada se carga implícitamente.

| Estado | Cuándo | Trato |
|---|---|---|
| `signed` | `SKILL.md.sig` coincide con HMAC bajo `NEXUS_SCOPE_SIGNING_SECRET` | guía de confianza (aún delimitada) |
| `unsigned` | no hay `.sig` | **datos no confiables** con aviso |
| `invalid` | hay `.sig` pero no verifica | **rechazada**, nunca llega al prompt |

```text
/skills list            # lista con estado de confianza y sha256
/skills show example    # previsualiza antes de activar
/skills use example     # activa para esta sesión
/skills off             # desactiva todas
```

Headless: `omni run "<objetivo>" --skill example --json`.

Firmar tu propia skill (fichero `.agents/skills/README.md`):

```bash
.venv/bin/python - <<'PY'
import os
from pathlib import Path
from nexus_core.agent.skills import sign_skill, SIGNATURE_SUFFIX, SKILL_FILENAME
body = Path(".agents/skills/example") / SKILL_FILENAME
body.with_name(SKILL_FILENAME + SIGNATURE_SUFFIX).write_text(
    sign_skill(body.read_bytes(), os.environ["NEXUS_SCOPE_SIGNING_SECRET"]))
PY
```

---

## 7. Modos de permisos y trust mode

El **modo operativo** se guarda en la conversación de trabajo (también entre
procesos); worker/headless lo heredan o usan su `session_id`.

- `interactive` — **default**.
- `plan` — el gateway permite **únicamente** `read_only`.
- `exec` — exige **aprobación durable por cada herramienta activa**.

```text
/mode show       # modo efectivo y sesión durable
/mode plan on    # gateway solo read_only
/mode plan off   # muestra la revisión y exige "aprobar <HASH>" para pasar a exec
```

`--trust-mode` **no** aprueba la transición del plan. Scope, RoE, política,
sandbox y aprobaciones siguen aplicándose. `/clear` crea otra conversación de
trabajo con su propio modo.

**Trust mode** (`--trust-mode` o `/trust on`) auto-aprueba tools de **alto riesgo**
del engagement sin pausar, salvo las de riesgo `DESTRUCTIVE`, que siguen pidiendo
confirmación. Cada auto-aprobación crea igualmente una aprobación durable y
escribe auditoría con `trust_mode=true` y `trusted_by=<usuario>`. Solo para
laboratorios controlados.

Niveles de riesgo y aprobación: `READ_ONLY`/`LOW`/`MEDIUM` (según política),
`HIGH` (aprobación humana o trust mode), `DESTRUCTIVE` (siempre humana).

---

## 8. Lanzar objetivos: REPL y headless

### 8.1 REPL (interactivo, TUI por defecto)

Cualquier línea que **no** empiece por `/` se envía como **objetivo al agente**:

```text
> Escanea scanme.nmap.org con nmap, puertos 22,80,443.
```

En modo sesión adjunta, el texto sin `/` va a la sesión y los comandos meta siguen
funcionando igual.

### 8.2 Headless (CI / scripts)

```bash
omni run "Escanea 10.0.0.1 y enumera servicios web" --json
omni run "<objetivo>" --stream-json          # NDJSON en vivo
omni --json "<objetivo>"                      # equivalente a run --json
omni --objective "<objetivo>"                 # one-shot sin REPL
```

En headless la TUI **no** arranca, el render se suprime (stdout solo JSON/NDJSON) y
las tools que requieren aprobación se **deniegan** salvo `--trust-mode`
(auto-aprobación auditada de `HIGH`, nunca `DESTRUCTIVE`). Cada línea lleva el
`subagent_id` activo. Límites:

```bash
omni run "<objetivo>" --stream-json --max-iterations 20 --trust-mode
```

---

## 9. Referencia COMPLETA de comandos `/`

Todos los comandos meta del REPL están en `nexus_core/cli/commands.py` (registro
`COMMANDS`: **41 claves = 40 comandos únicos**, porque `/quit` es alias de
`/exit`). Ninguno rompe la sesión y ninguno modifica la auditoría durable salvo
los que se indican.

### 9.1 Engagement y scope

| Comando | Qué hace |
|---|---|
| `/scope` | Muestra el engagement activo (scope firmado) y avisa si falta. |
| `/engage_current` | Igual que `/scope` (dispone de la variante de engagement activo). |
| `/engage_list` | Lista los engagements del tenant con `cidrs`, dominios y validez. |
| `/engage_create <nombre> <dominios/CIDRs> [--hours N]` | Firma un engagement nuevo y lo **activa**. `--hours` opcional (def. 24). |
| `/engage_use <id>` | Cambia el engagement activo en caliente, sin reiniciar. |
| `/engage [list\|create\|use\|current]` | Dispatcher por compatibilidad (prefiere los de primer nivel). |
| `/interview [show]` | Intake guiado: objetivo, cliente, targets, restricciones y RoE. Valida targets contra el scope (un target fuera no se registra) y guarda un hecho `hint` durable. `/interview show` imprime el brief. |

### 9.2 Plan, panel y presentación

| Comando | Qué hace |
|---|---|
| `/plan` | Imprime el plan por fases, la superficie de ataque y el perfil táctico. |
| `/plan on\|off` | Abre/cierra el panel lateral del plan (equivale a F2). |
| `/panel [on\|off]` | Muestra u oculta el panel lateral. Sin args, alterna. |
| `/expand [on\|off]` | Despliega/pliega todas las tarjetas de tool (clic = una tarjeta). |
| `/status [on\|off\|show]` | Muestra/oculta la barra de estado (preferencia persistente). |
| `/status show` | Imprime el estado completo como texto plano. |
| `/status fields ctx,tokens,provider,time` | Elige los campos del HUD (campos: `brand, scope, budget, status, alert, phase, provider, ctx, rate, tokens, cost, time, facts, engagement`; `alert` y `phase` están protegidos). |

### 9.3 Modo, trust y subagente

| Comando | Qué hace |
|---|---|
| `/mode show` | Modo efectivo y sesión durable. |
| `/mode plan on` | El gateway permite **solo** `read_only`. |
| `/mode plan off` | Muestra la revisión y exige escribir `aprobar <HASH>` para pasar a `exec`. |
| `/trust [on\|off]` | Consulta o cambia trust mode sin reiniciar. |
| `/subagent [ID\|auto]` | Fija o limpia el perfil de subagente del próximo run; sin args lista perfiles y alias. |

### 9.4 Memoria, historial y blackboard

| Comando | Qué hace |
|---|---|
| `/tools` | Lista las tools durables con riesgo y si exigen scope. |
| `/facts [tipo]` | Lista el blackboard del engagement; filtra por tipo de hecho. |
| `/findings` | Lista resumida de hallazgos verificados del engagement activo. |
| `/history [n]` | Muestra los últimos mensajes del run actual (máx. 500). |
| `/history --archive` | Lista las sesiones de trabajo archivadas (la primera es la activa). |
| `/approvals` | Lista las aprobaciones durables pendientes del tenant. |
| `/timeline [run]` | Cronología de acciones leída del audit trail. |
| `/export [archivo]` | Exporta la sesión actual a Markdown. |
| `/clear` | Rota a una **sesión de trabajo nueva** (archiva la anterior; mantiene engagement y auditoría). |

### 9.5 Playbooks, reporte y review

| Comando | Qué hace |
|---|---|
| `/playbook` | Muestra los playbooks aplicables y su siguiente paso. |
| `/playbook show <id>` | Detalle de un playbook (requisitos y pasos). |
| `/report` | Genera Markdown + HTML + JSON del engagement actual. |
| `/report --llm-cvss` | Pide al LLM un vector CVSS 3.1 (validado localmente; cae en heurística si no hay proveedor). |
| `/report --format sarif` | Emite SARIF 2.1.0 (GHAS, SonarQube, VS Code SARIF Viewer). |
| `/report export <dir>` | Escribe el entregable con `report.sha256` y `manifest.json`. |
| `/review [--deliver] [--llm-cvss] [--format markdown\|html\|both\|sarif]` | Valida evidencia, integridad y limpieza; entrega opcional. |

### 9.6 Sesiones y C2

| Comando | Qué hace |
|---|---|
| `/sessions` | Lista sesiones MSF activas (uuid, tipo, peer, vía, usuario). |
| `/sessions --sliver` | Lista las sesiones del team server Sliver (del engagement). |
| `/session attach <uuid>` | Adjunta a una sesión; el texto sin `/` se envía a ella. |
| `/session info` | Datos de la sesión adjunta. |
| `/detach` | Sale del modo sesión (la sesión sigue viva). |
| `/kill-session [uuid\|all]` | Termina una sesión o todas, con confirmación `Y/N/E`. |
| `/sliver` | Estado del team server (versión, operadores, jobs). |
| `/implants` | Lista builds y profiles de implants de Sliver. |
| `/loot` | Lista el loot del team server con su SHA256 (cadena de custodia). |
| `/exploit view-live <job_uuid>` | Vista de estado de un job MSF en otra terminal (solo lectura). Alias: `/exploit watch <job_uuid>`. |

### 9.7 Secretos, RoE y skills

| Comando | Qué hace |
|---|---|
| `/secrets list` | Lista el backend de secretos y los nombres guardados. |
| `/secrets set NOMBRE` | Guarda un secreto leyendo el valor **oculto** (nunca se imprime). |
| `/secrets rotate NOMBRE` | Rota un secreto (o lo crea si no existía). |
| `/secrets delete NOMBRE` | Elimina un secreto. |
| `/secrets import-env` | Importa al store las claves conocidas del entorno. |
| `/roe [show\|kill\|arm\|path]` | Muestra la RoE y controla su kill switch. |
| `/skills list` | Lista skills con estado de confianza y sha256. |
| `/skills show NOMBRE` | Previsualiza una skill (y señaliza inyecciones). |
| `/skills use NOMBRE` | Activa una skill para la sesión. |
| `/skills off` | Desactiva todas las skills. |

### 9.8 Conversación y control

| Comando | Qué hace |
|---|---|
| `/ask <pregunta>` | Consulta al LLM **sin ejecutar tools**, sin ReAct y sin tocar engagement/auditoría. Construye el system prompt con el estado real (comandos, tools, engagement, proveedor) y mantiene contexto local (últimos ~20 mensajes). Soporta streaming token a token. |
| `/chat` | Alias de `/ask`. |
| `/help` | Muestra la ayuda con todos los comandos. |
| `/exit` · `/quit` | Salen del REPL (la auditoría durable permanece). |

> **Cualquier otra línea** (que no empiece por `/`) se envía como **objetivo al
> agente**. En modo sesión, se envía a la sesión adjunta.

---

## 10. Atajos de teclado y control

| Tecla | Acción |
|---|---|
| Enter | Envía el objetivo completo. |
| Alt+Enter | Inserta una línea nueva (multi-línea, hasta 5 líneas). |
| Tab | Autocompleta comandos `/`, tools `nexus.`, argumentos, `@engagement` y rutas. |
| **F2** | Alterna el panel lateral del plan. |
| **F3** | Expande/edita un pegado (cursor junto al chip). |
| **F4** | Elimina un pegado (cursor junto al chip). |
| **F5** | Recupera el último borrador no vacío (entrada vacía). |
| **F6** | Recorre las tareas del panel de tareas. |
| **F7** | Cancela **solo** la llamada fan-out seleccionada. |
| PageUp/PageDown, rueda | Recorren el historial; al volver al final se reanuda el auto-scroll. |
| **Esc** | Interrumpe un run (registra `react.cancel_requested`) o cancela `/ask`/invocación. |
| **Ctrl+C** | Cancela la entrada actual; durante un run conserva la interrupción. |
| **Ctrl+D** | Sale del REPL (con el prompt vacío). |
| Clic en `▼ mostrar N líneas más` / `▲ mostrar menos` | Despliega/contrae esa tarjeta de tool. |

El scrollback muestra el **pensamiento** del agente en vivo (`💭 …`) y la respuesta
de `/ask` en streaming. Con la captura de ratón activa (alt-screen), para
seleccionar texto con el ratón hay que mantener **Shift**.

---

## 11. Flags de la CLI para el agente

| Flag | Efecto en el agente |
|---|---|
| `--engagement ID` / `--continue ID` | Engagement activo / retoma engagement + conversación. |
| `--tenant NOMBRE` | Tenant de trabajo. |
| `--objective TEXTO` | One-shot sin REPL. |
| `--stream-json` | Headless NDJSON. |
| `--skill NOMBRE` | Activa una skill (repetible). |
| `--max-iterations N` | Límite de iteraciones del bucle (def. 12). |
| `--subagent ID` | Fija el perfil de subagente del run. |
| `--trust-mode` | Auto-aprueba `HIGH` (nunca `DESTRUCTIVE`), auditado. |
| `--resume RUN_ID` / `--resume-policy approve\|skip\|fail` | Retoma un run y decide invocaciones `unknown`. |
| `--autospawn` / `--no-autospawn` | Delegación a subagente hijo al cambiar de familia de fase. |
| `--supervisor-budget TOKENS` | Presupuesto global del árbol de subagentes. |
| `--no-tui` / `--no-fullscreen` / `--no-color` | Presentación. |
| `--banner` / `--about` | Banner ASCII completo. |

Consulta el resto de flags globales, `--doctor`, `--setup`, `--config`,
`--new-engagement`, `--roe`, etc. en **[GUIA_MANUAL_1.md §9](GUIA_MANUAL_1.md#9-comandos-de-la-cli-omni)**.

---

## 12. Subcomandos del agente

| Subcomando | Uso |
|---|---|
| `omni run "<objetivo>" [--json\|--stream-json]` | Run headless con el bucle ReAct. |
| `omni report [--format FMT] [--output DIR]` | Entregable del engagement. |
| `omni cve update [CVE-...]` | Rellena caché NVD/EPSS/CISA KEV. |
| `omni tool <id> '<json>'` | Invocación manual gobernada (ver GUIA_MANUAL_1). |
| `omni hooks trust\|list\|revoke <path>` | Aprueba/revoca hooks de repo. |
| `omni resume <run_id> [--retry\|--skip ID]` | Resuelve invocaciones `unknown`. |

---

## 13. Aprobaciones, resume y hooks

**Aprobaciones.** Las tools que lo requieren piden `y/n/e/?` (o se auto-aprueban
con trust mode). En alt-screen aparece un **modal superpuesto** con tool, riesgo,
motivo y argumentos exactos. `/approvals` lista las pendientes. Sin humano
(headless), se **deniegan** salvo trust mode.

**Resume.** Tras un crash entre un efecto y su observación, el journal deja la
invocación en estado `unknown` y **no la re-ejecuta solo**:

```bash
omni resume <run_id>                 # lista las invocaciones unknown
omni resume <run_id> --retry <inv_id>   # registra aprobación humana ligada a esa invocación
omni resume <run_id> --skip <inv_id>    # marca "sin efecto" y permite continuar
```

En headless, `--resume-policy` elige: `approve` (solo consume una aprobación
previa; si falta, bloquea con exit 2), `skip` o `fail`.

**Hooks de repositorio** (`.agents/hooks.json`): son entrada cuasi-confiable y no
se cargan hasta que un humano los aprueba fuera de banda. `omni hooks trust <path>`
muestra el hash, pide confirmación y registra `path + sha256 + operador + fecha`;
cualquier cambio posterior revoca la confianza automáticamente. `list` y `revoke`
gestionan aprobaciones. Nunca ejecuta un hook.

---

## 14. Reporte y cierre del engagement

El agente cierra el engagement con `task_complete` (solo entonces se cierra la fase
`reporting`). `nexus.report.generate` es `READ_ONLY`, no exige scope y **nunca
inventa un hallazgo**: transcribe lo verificado.

```text
/report
/report --llm-cvss
/report --format sarif
/report export ./entregable
```

El reporte incluye: resumen ejecutivo (conteo por severidad), alcance firmado,
metodología, hallazgos (CVSS, MITRE ATT&CK, CWE/CVE, evidencia), intentos
fallidos, cronología completa y chain of custody (SHA256 de cada evidencia y del
reporte). Formatos: Markdown, HTML autocontenido, JSON y SARIF. Si la cadena de
auditoría no valida, el reporte se marca **NO VERIFICADA**.

---

## 15. Variables de entorno del agente

| Variable | Efecto |
|---|---|
| `NEXUS_LLM_DEFAULT_PROVIDER`, `LLM_PROVIDER` | Proveedor LLM a usar. |
| `NEXUS_ALLOW_MODEL_FALLBACK` | Permite cambiar de modelo/proveedor si falla. |
| `NEXUS_RUN_BUDGET_TOKENS` | Presupuesto de tokens por run (0 = sin límite). Superarlo termina el run con `budget_exceeded`. |
| `NEXUS_PHASE_TIMEOUT_SECONDS` | Timeout por fase. |
| `NEXUS_REACT_MAX_TOKENS` | Máximo de tokens por respuesta del bucle. |
| `NEXUS_SUBAGENT_BUDGET_<ID>` | Presupuesto de tokens de un perfil. |
| `NEXUS_AUTOSPAWN_MIN_BUDGET` | Umbral de tokens para auto-spawn (def. 20 000). |
| `NEXUS_AUTOSPAWN_MIN_ITERATIONS` | Umbral de iteraciones para auto-spawn (def. 4). |
| `NEXUS_PREFLIGHT_BINARIES` | Preflight de binarios (0 = desactivar). |
| `NEXUS_ALLOW_DEGRADED_TOOLS` | Permite un run degradado si falta un binario. |
| `NEXUS_WORKSPACE_ROOT` | Workspace efectivo del engagement. |
| `NEXUS_CONTEXT_WINDOW`, `NEXUS_CONTEXT_WINDOWS` | Ventana de contexto (`ctx NN% usado`). |
| `NEXUS_LOG_LEVEL` | `debug`\|`info`\|`warning`(def.)\|`error`. |
| `NEXUS_SCOPE_MODE` | `governed` (def.) o `lab`. |
| `NEXUS_SANDBOX_MODE` | `local`\|`local_strict`\|`oci`\|`oci_network`. |
| `NEXUS_OPERATOR_ID` | Identidad del operador. |

Además: las claves de proveedor (`GROQ_API_KEY`, `OPENAI_API_KEY`, …),
`MSF_*` y `SLIVER_*`. Lista completa en `.env.example` y en GUIA_MANUAL_1 §12.

---

## 16. Códigos de salida y eventos NDJSON

`omni run` publica `run.complete` en JSON y NDJSON con `termination_reason`,
`completion_verified`, `exit_code` y `exit_code_version: 1`:

| Código | Significado |
|---|---|
| `0` | `completed` **y** `completion_verified=true`. |
| `1` | Incompleto: `max_iterations`, `clarification`, `premature_completion`, final no verificado. |
| `2` | Bloqueado esperando aprobación humana. |
| `3` | Fallo de proveedor LLM/RPC o timeout externo. |
| `4` | Denegación de gobernanza (scope, RoE, policy o sandbox inválido). |
| `130` | Interrupción SIGINT/cancelación. |

En `--stream-json`, cada línea es un evento NDJSON con `type`, `run_id`,
`sequence`, `subagent_id` y `payload`. Se emiten eventos de run
(`react.step`, `tool.invoke`, `tool.complete`, `tool.failed`, `subagent.started`,
`subagent.ended`, …) y acciones de auditoría relevantes (`mcp.tool_denied`,
`mcp.timeout`, `mcp.unavailable`, `scope.denied`, `roe.denied`). El último evento
es `run.complete` con `exit_code`, `iterations`, `summary`, `findings`, `plan` y el
proveedor/modelo usados.

**Límites honestos:** un texto final sin pruebas **no** produce éxito CI;
`completion_verified` expresa que pasaron las compuertas deterministas
implementadas y existen assertions verificadas del run — no es una prueba
universal de cualquier objetivo en lenguaje natural.
