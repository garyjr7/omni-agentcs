# Potenciar OmniAgentCS — Auditoría, benchmark y plan de mejora

Fecha: 2026-10-02 · Rama: `feat/sliver-bridge` · Autor: auditoría técnica asistida (Buffy/Codebuff)

Este documento es una **auditoría honesta** del proyecto (lo bueno, lo malo y lo que
falta), un **benchmark** contra las CLIs de agentes modernas (Claude Code, Codex CLI,
Gemini/Antigravity, Cursor, Copilot CLI, Goose, OpenCode, Qwen Code, Aider, Freebuff)
y un **plan de potencialización por fases** para convertirlo en una CLI profesional
de pentesting autónomo con gobernanza verificable.

---

## 0. Resumen ejecutivo (TL;DR)

- **No estás empezando: ya tienes el esqueleto de un producto serio.** ~57.5k líneas
  Python en `nexus_core`, **160 archivos de test**, ~1.685 tests unitarios verdes, **42
  tools durables** y **29 comandos de REPL**. Lo diferencial —alcance firmado por HMAC,
  cadena de auditoría encadenada por hash, aprobaciones durables con separación de
  deberes, regla de oro "un modelo propone, no afirma éxito"— **no lo tiene casi nadie**
  en el nicho ofensivo. Eso es tu foso competitivo.
- **La cadena ofensiva ya está completa de punta a punta**: recon (nmap `-p-`,
  subfinder, httpx, ftp anónimo) → enumeración → credenciales (hydra) → explotación
  (msf, searchsploit, impacket, netexec) → post-explotación (ssh_exec, enum_system,
  privesc_hints) → C2 (**Sliver**: generate/deploy/loot/pivote/exec) → reporte con
  CVSS/MITRE/CWE/CVE y cadena de custodia. **Sí puede hacer una auditoría completa**;
  lo que falta es madurar producto y profundidad de cobertura.
- **Los 5 huecos que más te frenan** frente al estado del arte: **(1) extensibilidad
  (MCP + skills/hooks + instrucciones de proyecto)**, **(2) orquestación
  (subagentes + llamadas en paralelo)**, **(3) modo headless/CI con salida JSON**,
  **(4) seguridad del propio agente (keyring, defensa anti-inyección, undo/kill
  switch)**, y **(5) profundidad de pentest (OSINT/AD/cloud, CVSS 4.0, mapeo
  PTES/WSTG/NIST, SARIF, enriquecimiento CVE)**.
- **Opinión directa**: mereces apostar en serio por esto. Con 3–4 sprints enfocados en
  los puntos anteriores, esto deja de ser "un script potente" y pasa a ser una CLI de
  la liga de Claude Code/Codex, pero **en el nicho donde ellos no juegan**: pentesting
  autónomo con trazabilidad no repudiable.

---

## 1. Sobre el uso ético y legal (tu aclaración)

Tienes razón en el fondo, y la comparación con Metasploit es válida: **la herramienta es
dual-use, la intención y la autorización son humanas**. Metasploit, nmap, hydra, sqlmap,
impacket son open source y los usa todo el mundo; lo que separa un pentest de un delito
es **el permiso escrito y el alcance acordado**, no la existencia de la herramienta.

Lo importante: **tu diseño ya implementa esa filosofía mejor que la mayoría**. No es
retórica, está en el código:

- `nexus_core/scope/validator.py` — solo ejecuta contra objetivos dentro de un
  **engagement firmado por HMAC**, con **ventana temporal**, **exclusiones** y un
  **guardia de direcciones privadas**. Nada fuera del scope corre.
- `nexus_core/kernel/approvals.py` — las tools HIGH/DESTRUCTIVE exigen **aprobación
  humana durable**, con separación de deberes (quien pide no puede decidir) y
  consumo de un solo uso (no se puede reproducir un `approval_id`).
- `nexus_core/kernel/audit.py` — **cadena de auditoría encadenada por hash**: evidencia
  no repudiable de cada acción.
- `nexus_core/agent/react.py` — **la regla de oro**: ningún éxito sin post-condición
  determinista persistida. El agente no puede "creer" que explotó algo.

El modelo mental correcto —el que ya tienes— es el que describes:

> "Solo podemos tocar esta IP y su rango, y no puedes leer la base de datos" ⇒
> eso es un **engagement con scope firmado y exclusiones**. El agente lo respeta o el
> gateway lo deniega.
>
> "Nos dieron esta IP de punto pero podemos escanear la red interna, y la empresa
> **quiere** que probemos la fortaleza de los hashes" ⇒ eso es un **RoE (Rules of
> Engagement) explícito** ampliando el scope, con aprobaciones para lo destructivo.

**Recomendaciones para blindar el encuadre legal/profesional** (nada de esto existe hoy
y es barato de añadir):

1. **Atestación de autorización** en el wizard: declarar por escrito autorización del
   cliente, con nombre/rol/fecha/hash, guardada en el engagement. Es la prueba de
   permiso.
2. **`LICENSE`** con cláusula de uso autorizado + aviso en el banner y README
   ("Authorized use only. You must have written permission for every target").
3. **RoE como política de código**: timing (ventanas de ejecución), límites de
   intensidad (rate/threads), objetivos prohibidos, contacto de emergencia y
   **kill switch** ("para toda actividad ya").
4. **Modo "destructivo bloqueado"** a nivel de despliegue, para que en un cliente
   conservador ni siquiera se pueda aprobar (quita la tentación y el riesgo).
5. **Data-handling**: política de retención/borrado de loot y datos sensibles al cerrar
   engagement, con cadena de custodia (ya tienes el SHA256 en `sliver_loot`).

Con eso, el producto no solo es legítimo: **es defendible ante un cliente** (que es
exactamente lo que un equipo de red team paga por tener).

---

## 2. Retrato del proyecto hoy (inventario medido)

| Dimensión | Estado real |
|---|---|
| Código | ~**57.450** líneas Python en `nexus_core` (sin contar tests) |
| Tests | **160** archivos `test_*.py`, **1.685** unit tests verdes, 1 skipped (1 fallo preexistente de entorno) |
| Tools durables | **42** (recon, web, cred, exploit, post, c2, knowledge, report, system) |
| Comandos REPL | **29** (`/plan`, `/panel`, `/expand`, `/playbook`, `/loot`, …) |
| Providers LLM | OpenAI, **Groq**, OpenAI-compatible, Gemini, **Ollama (local)**, Anthropic, Fake |
| Kernel | policy, approvals, audit (hash-chain), scope (HMAC), sandbox (modos), artifacts (content-addressed), knowledge, blackboard, sessions, workflows (DAG resumable + compensación), packages, directory, connectors, model_router, telemetry (OTel), redaction |
| Agente | ReAct con presupuesto de tokens, cancelación cooperativa, **compactación de contexto**, **planner determinista** por fases, **playbooks** deterministas |
| TUI | prompt_toolkit: 4 regiones, panel lateral, **modal de aprobación**, **tool cards plegables**, `--fullscreen`, spinner, status bar |
| C2 | **Sliver** (gRPC): server, implants, sessions, exec, pivot, **generate, deploy, loot** |
| Explotación | Metasploit (msfrpcd, msgpack), searchsploit, impacket (secretsdump/getuserspns/psexec), netexec, bloodhound |
| Reporte | CVSS 3.1, severidad, **MITRE ATT&CK**, HTML autocontenido, Markdown, JSON, chain-of-custody SHA256 |
| Distribución | `pyproject.toml` (v3.0.0), `pipx`, `install.sh` (resuelve fuente→git→PyPI), shim npm |
| CI | `.github/workflows/ci.yml`: `make syntax lint test`, tests con **PostgreSQL** y **gitleaks** (escaneo de secretos) |
| Onboarding | `--setup` (21 componentes), `--install`, wizard de engagement, `--doctor`, `--json` |

**Conclusión del inventario:** madurez de *núcleo* alta; madurez de *producto/ecosistema*
media-baja. El 80% del valor diferencial ya está; el 20% que falta es justo lo que
"se siente" profesional.

---

## 3. Lo bueno (fortalezas reales, con evidencia)

1. **Gobernanza verificable — tu verdadero foso.** Scope firmado + aprobaciones
   durables + cadena de auditoría por hash + post-condiciones. Ninguna CLI de desarrollo
   (Claude Code, Codex, …) ofrece esto **para pentesting**. Es tu #1 y hay que
   **venderlo como tal**.
2. **Cadena ofensiva completa y real**, no de juguete: recon `-p-`, FTP anónimo,
   hydra dirigido, MSF end-to-end, impacket, C2 Sliver con movimiento lateral y loot.
   El pipeline de la sala THM "Red" está a tiro.
3. **Blackboard tipado y durable** (`kernel/blackboard.py`) como memoria del
   engagement: hosts/servicios/creds/accesos/privilegios/loot con procedencia y
   `verified`. Esto es lo que hace que el agente "recuerde" y no repita trabajo — y que
   un equipo humano retome el caso. Muy pocos lo tienen.
4. **Planner determinista** (`agent/planner.py`) y **playbooks deterministas**
   (`agent/playbooks.py`): la fase del kill chain y el siguiente paso **no dependen del
   LLM** ⇒ reproducible y auditable. Excelente decisión de diseño.
5. **Reporte sin alucinación**: solo lo observado entra; lo no verificado se marca. Con
   CVSS, MITRE, CWE/CVE y SHA256. Es un entregable que un cliente puede leer.
6. **Multi-proveedor + local-first** (Ollama): no mandas el engagement a un SaaS. Esto
   es un argumento comercial fuerte para clientes regulados.
7. **Disciplina de tests y contratos**: 160 archivos de test, tests de integración
   end-to-end, fixtures aisladas, `fail-closed` por diseño. La deuda de calidad está
   controlada.
8. **TUI por encima de la media**: modal de aprobación, tool cards, panel de plan,
   status bar con fase y coste. Ya no tiene la corrupción de logs que reportaba la
   auditoría.
9. **Onboarding real**: `omni --setup` verifica binarios **y servicios** (msfrpcd,
   Sliver team server) e instala con aprobación. Muy por encima de "git clone + reza".
10. **Provisioner de Sliver verificado con minisign**: integridad de supply-chain en la
    instalación del C2. Detalle profesional.

---

## 4. Lo malo (riesgos, límites y deuda — honesto)

### 4.1 Seguridad del propio agente (lo más urgente)
- **Secretos en claro**: API keys en config/`.env`. **Ya se expuso una key de Groq** en
  la sesión de QA: **rótala ya**. Falta `keyring` / gestor de secretos del SO.
- **El sandbox no ve `~/.local/bin`** (`SANDBOX_BASE_ENV PATH=/usr/local/bin:/usr/bin:/bin`),
  así que un binario "presente" puede no ser "ejecutable". Inconsistencia ya detectada.
- **`OCI_NETWORK` no implementado** (`sandbox_modes.py` lo deja explícito). El modo
  `local_strict` es allowlist + HOME efímero, pero **no aísla red**. Para herramientas de
  red esto importa.
- **Sin defensa explícita anti prompt-injection indirecta.** En pentesting, el agente
  *lee output de objetivos comprometidos* (banners, ficheros, respuestas HTTP): un
  atacante real puede intentar inyectar instrucciones en ese output. Es un vector de
  primera clase y hoy no hay capa dedicada (MCP lo empeora: ver §6).
- **Sin kill switch** ni compensación automática del ReAct loop (los workflows tienen
  saga/compensación, pero el bucle de agente no lo usa para deshacer acciones).

### 4.2 Extensibilidad
- **No hay MCP** (ni cliente ni servidor). Es *el* sustrato de extensión del ecosistema:
  sin él, cada integración es código dentro del core.
- **No hay skills/plugins/hooks**. Hay playbooks (bien) pero son del core, no cargables
  por el operador sin tocar código.
- **No hay instrucciones de proyecto** tipo `AGENTS.md`/`CLAUDE.md` (o tu propio
  `OMNI.md`): el operador no puede dar contexto/reglas por engagement desde un fichero.

### 4.3 Orquestación y autonomía
- **Sin subagentes** y **sin llamadas a tools en paralelo**: el bucle ReAct es
  secuencial de 12 iteraciones. Los subagentes son hoy estándar (Claude Code, Codex,
  Gemini, Copilot, Goose, OpenCode).
- **Sin checkpoints/undo/rewind**: en pentesting puede ser peligroso deshacer; pero
  falta al menos **checkpoint de estado del engagement** y "reanudar desde fase".
- **Sin presupuesto por fase**: `max_iterations` global de 12 es bajo para cadenas
  largas (recon completo → post-explotación).

### 4.4 Interfaz y producto
- **No hay modo headless con salida estructurada** del run del agente (existe
  `--objective` y `--json` solo para `--doctor/--setup`). Sin `omni run --json`/`--stream-json`
  no puedes meterlo en CI ni en pipelines.
- **Markdown incompleto** (tablas con wrap, listas anidadas) — pendiente reconocido.
- **Sin temas claro/oscuro** (ni en la TUI ni en el HTML del reporte) y **sin medición
  de latencia de teclado**.
- **Sin `omni update`/autoupdate** ni canal de versiones claro.

### 4.5 Cobertura de pentest (profundidad)
- **OSINT débil**: hay subfinder/httpx, pero no `theHarvester`/`amass`/enumeración de
  correos/formatos de usuario (`nexus.recon.email_users` estaba planeado y no está).
- **AD/cloud a medias**: netexec/bloodhound/impacket existen; falta AWS/Azure/GCP,
  contenedores/K8s.
- **CVSS solo 3.1**; CVSS **4.0** ya es estándar en muchos informes.
- **Sin mapeo explícito a marcos**: PTES, OWASP WSTG/MASTG, NIST SP 800-115, OSSTMM,
  D3FEND. Tienes MITRE ATT&CK; falta el resto.
- **Sin export SARIF** del propio hallazgo (nuclei puede, pero el agente no lo normaliza).
- **Sin enriquecimiento CVE** (NVD, EPSS, CISA KEV) ni "attack path graph".

### 4.6 Calidad/ingeniería
- **El CI existe y está bien pensado** (`syntax`, `lint` ruff F/E9, `test`, Postgres y
  **gitleaks**), pero: `mypy`, `pip-audit` y `pytest-cov` están declarados en
  `requirements-dev.txt` y **no se ejecutan** en CI ni en el `Makefile`; los tests
  **e2e van desactivados** (`NEXUS_E2E=0`). No hay cobertura publicada ni SAST más
  allá de gitleaks.
- **Sin versionado de esquema documentado** hacia el operador (hay migraciones
  aditivas, bien).
- **Idioma**: UI en español (bien para ti), pero sin i18n si quieres mercado global.

---

## 5. Benchmark: qué hace potente a una CLI de agente moderna

> Fuentes al final (§13). Comparativa de *factores*, no de precios.

| Capacidad | Claude Code | Codex CLI | Gemini/Antigravity | Cursor CLI | Copilot CLI | Goose / OpenCode | **OmniAgentCS hoy** |
|---|---|---|---|---|---|---|---|
| Open source | No | Sí (Apache-2.0) | Sí (Apache-2.0) | No | source-available | Sí | **Sí (tuyo)** |
| Instrucciones de proyecto | CLAUDE.md (+AGENTS.md) | AGENTS.md | GEMINI.md | AGENTS/rules | instrucciones | AGENTS.md | **❌** |
| **MCP** (cliente) | ✅ stdio+HTTP | ✅ +servidor | ✅ | ✅ | ✅ | ✅ (extensions) | **❌** |
| **MCP** (servidor) | — | ✅ `mcp-server` | — | — | — | — | **❌** |
| **Subagentes** | ✅ (Explore/Plan/custom) | ✅ | ✅ | ✅ | ✅ custom agents | ✅ Agents | **❌** |
| **Hooks / extensibilidad** | ✅ hooks+skills+plugins | ✅ hooks+skills | extensions | plugins | custom agents | extensions/plugins | **⚠️ solo playbooks** |
| **Headless / CI** | `claude -p` (+JSON) | `codex exec` | `gemini -p` | headless | `copilot -p` | `goose run` | **⚠️ `--objective`, sin JSON de agente** |
| Checkpoints / rewind | ✅ | ✅ | ✅ | ✅ | parcial | parcial | **❌** |
| Sandbox / aprobaciones | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | **✅ (tu fuerte)** |
| Multi-modelo | Bedrock/Vertex/Foundry | GPT/Codex | Gemini | muchos | muchos | muchos | **✅ (OpenAI/Groq/Gemini/Ollama/Anthropic)** |
| Gobernanza/auditoría de acciones | parcial | parcial | parcial | parcial | parcial | baja | **✅✅ (scope firmado + hash-chain + approvals)** |

**Lectura:** en lo que todo el mundo compite (MCP, subagentes, hooks, headless, UX)
**vas por detrás, pero no por arquitectura, sino por features no construidas** — y en lo
que casi nadie tiene (gobernanza verificable ofensiva) **vas por delante**. La estrategia
correcta no es "clonar" a Claude Code; es **construir la capa de extensibilidad/UX que
falta montada sobre tu foso de gobernanza**.

---

## 6. Brechas concretas (OMNI vs estado del arte)

| # | Brecha | Impacto | Esfuerzo | Prioridad |
|---|---|---|---|---|
| G1 | **MCP cliente** (stdio + HTTP) | Muy alto: reutiliza todo el ecosistema | M | **P1** |
| G2 | **MCP servidor** (exponer el agente/tools) | Alto: integrable con otros agentes | M | P2 |
| G3 | **Skills/plugins** cargables (`.agents/skills`) | Alto: el operador extiende sin fork | M | **P1** |
| G4 | **Hooks** de ciclo de vida (pre/post tool, pre-compact, session start/end) | Alto: automatización y política | M | **P1** |
| G5 | **Instrucciones de proyecto** (`OMNI.md`/`AGENTS.md`) | Alto: contexto y reglas por cliente | S | **P0** |
| G6 | **Subagentes** con subconjunto de tools y presupuesto | Alto: paraleliza y acota contexto | L | P2 |
| G7 | **Llamadas a tools en paralelo** (read-only) | Medio: velocidad real | M | P2 |
| G8 | **Modo headless + JSON/stream-json** | Alto: CI, pipelines, informes automáticos | S–M | **P0** |
| G9 | **Checkpoints / rewind del engagement** | Medio: recuperación y confianza | M | P2 |
| G10 | **Keyring + secretos** | Muy alto (seguridad) | S | **P0** |
| G11 | **Defensa anti prompt-injection** (sanitizar outputs/tools) | Muy alto (seguridad del agente) | M | **P0** |
| G12 | **Kill switch + egress control** | Alto (seguridad/legal) | S–M | P1 |
| G13 | **CVSS 4.0 + PTES/WSTG/NIST/D3FEND + SARIF** | Alto (calidad de informe) | M | P1 |
| G14 | **Enriquecimiento CVE (NVD/EPSS/KEV)** | Medio-alto (priorización) | S | P1 |
| G15 | **OSINT (correos/usuarios/theHarvester/amass)** | Medio (cobertura) | M | P2 |
| G16 | **Cloud/K8s/contenedores** | Medio (mercado) | L | P3 |
| G17 | **CI, cobertura, mypy/bandit** | Medio (confianza/equipo) | S | P1 |
| G18 | **Docker image + PyPI + `omni update`** | Medio (adopción) | S–M | P1 |
| G19 | **Markdown completo + temas + latencia** | Medio (UX percibida) | M | P2 |
| G20 | **i18n (es/en)** | Bajo-medio (alcance) | M | P3 |

---

## 7. Plan de potencialización (Propuesta V5)

Orden pensado para **máximo valor con mínimo riesgo**, respetando tu arquitectura (todo
pasa por el gateway: scope → policy → approval → audit).

### P0 — Quick wins de una semana (alto impacto, bajo esfuerzo)

1. **Instrucciones de proyecto** (`OMNI.md`, con fallback `AGENTS.md`/`CLAUDE.md`).
   - Cargar y concatenar al `render_system_prompt` (`agent/prompts.py`) con
     procedencia y hash; mostrar en el banner qué fichero se cargó.
   - Reglas del operador ("no toques X", "usa wordlist Y") se vuelven contexto real.
2. **Headless estructurado**: `omni run "<objetivo>" --json` y `--stream-json`.
   - Reusar `run_objective`; emitir eventos (`react.step`, `tool.complete`,
     `orchestrator.plan`) ya existentes como NDJSON. Habilita CI y dashboards.
3. **Secretos fuera del claro**: `keyring` (fallback a archivo 600 con aviso) +
   `omni secrets set/get`, y **rotar la key de Groq expuesta**.
4. **Defensa anti prompt-injection**: envolver todo output de tool/objetivo en un
   delimitador no confiable (`<<UNTRUSTED_TOOL_OUTPUT>>`) e instruir al modelo a
   tratar su contenido como datos, nunca como instrucciones; marcar en el prompt
   cualquier "action-like" hallado en output. (Ver §6 MCP-risks.)
5. **`LICENSE` + aviso "authorized use only" + atestación de autorización** en el
   wizard.

### P1 — Plataforma de extensibilidad y confianza (2–4 semanas)

6. **MCP cliente** (`nexus_core/integrations/mcp/`): stdio + Streamable HTTP.
   - Cada servidor MCP entra como **tools con scope/proxy**: la llamada MCP pasa por una
     capa que registra, redacta y audita, y (opcional) exige aprobación para clases
     peligrosas. **Nunca** un MCP salta el gateway.
   - Config en `~/.config/omni/mcp.json` (compatible con `.mcp.json`).
7. **Skills/plugins** (`.agents/skills/<name>/SKILL.md` + `playbook.yaml` opcional):
   - Cargables por nombre, con **firma opcional** (reutiliza HMAC del scope) y
     previsualización del contenido antes de activar.
8. **Hooks** de ciclo de vida (inspirados en Claude Code: pre/post tool use,
   user prompt submit, session start/end, pre-compact, stop):
   - `nexus_core/hooks/` con un registro y ejecución **fail-safe** (un hook que falla
     no rompe el bucle, se audita). Usos: notify Slack/Teams, política corporativa,
     auto-registrar hechos, bloquear tools por nombre.
9. **CVSS 4.0 + marcos + SARIF** (`report/`):
   - `cvss.py` a 4.0 (mantener 3.1 para compatibilidad), mapeo PTES/OWASP WSTG/NIST
     800-115/D3FEND en `report/mitre.py` o nuevo `report/frameworks.py`, y export
     **SARIF 2.1.0** para integración con plataformas de seguridad.
10. **Enriquecimiento CVE**: lookup NVD + **EPSS** + **CISA KEV** (opcional offline-first
    con caché), para priorizar hallazgos con datos, no a ojo.
11. **Egress/red**: implementar `OCI_NETWORK` o, como mínimo, documentar y **restringir
    por allowlist de destinos** las tools de red; añadir **kill switch** (`/stop`,
    señal, archivo-centinela) que corte herramientas en vuelo.
12. **CI + calidad (extender lo que ya hay)**: añadir al CI `mypy` incremental,
    `pip-audit`, cobertura (`pytest-cov`) con badge y un job e2e opcional; el resto
    (syntax/lint/test/Postgres/gitleaks) ya está montado.

### P2 — Orquestación y UX de clase mundial (1–2 meses)

13. **Subagentes** (`agent/subagents.py`): recon / web / cred / exploit / postexploit /
    lateral / reporter, cada uno con **subconjunto de tools**, **presupuesto propio** y
    contexto aislado; el planner decide y el gateway gobierna igual. Sube
    `max_iterations` a configurable con presupuesto por fase.
14. **Paralelismo seguro**: ejecutar en paralelo tools **read-only** independientes
    (subfinder + httpx + nmap sobre hosts distintos), con límite de concurrencia y
    cancelación. Nunca paralelizar DESTRUCTIVE.
15. **Checkpoints del engagement**: snapshot del blackboard + estado de sesiones/fase
    en el audit trail; `/rewind <checkpoint>` (solo estado, no "deshacer exploit").
16. **MCP servidor** (`omni mcp-server`): exponer tus 42 tools y el blackboard a otras
    CLIs/IDE, siempre tras el gateway.
17. **TUI**: Markdown completo (tablas con wrap, listas anidadas), temas, `--no-color`
    a fondo, medición de latencia/memoria, y **preview de reporte** dentro de la TUI.
18. **OSINT**: `nexus.recon.email_users`, `nexus.recon.theharvester`, opcional `amass`,
    y correlación usuarios↔correos en el blackboard.

### P3 — Cobertura y producto (continuo)

19. **Cloud/K8s**: AWS (prowler/ScoutSuite), Azure, GCP, contenedores (trivy/kubesec).
20. **Distribución**: imagen Docker, PyPI público, `omni update`, Homebrew tap,
    `apt`/repos, y un **benchmark reproducible** contra el informe manual (tu test de
    aceptación de la sala "Red").
21. **i18n** es/en y accesibilidad.
22. **Telemetría opt-in** con privacidad explícita (OTel ya está) para entender uso.

---

## 8. Arquitectura objetivo (V5)

```
┌───────────────────────────────────────────────────────────────────┐
│ UI: TUI (paneles, tool cards, approval modal, preview)  +         │
│     headless (`run --json`/`--stream-json`)                        │
├───────────────────────────────────────────────────────────────────┤
│ ORQUESTADOR: planner determinista + playbooks + HOOKS + SUBAGENTES │
│   recon · web · cred · exploit · postex · lateral · reporter       │
├───────────────────────────────────────────────────────────────────┤
│ ENGAGEMENT BLACKBOARD (facts tipados + procedencia + checkpoints)  │
├───────────────────────────────────────────────────────────────────┤
│ EXTENSIÓN: MCP cliente/servidor · Skills/Plugins · RoE policy      │
├───────────────────────────────────────────────────────────────────┤
│ TOOL GATEWAY: scope firmado → policy → approval durable → audit    │
├───────────────────────────────────────────────────────────────────┤
│ TOOLKIT (42+) · SANDBOX (OCI + egress) · SECRETS (keyring)         │
│ LLM ROUTER (multi-proveedor, local-first, failover)                │
└───────────────────────────────────────────────────────────────────┘
```

---

## 9. Métricas de éxito (KPIs a instrumentar)

- **Cobertura de cadena**: ≥ 90% de los pasos del informe manual automatizados.
- **Puertos**: `full_tcp` = 100% de puertos vs `nmap -p-`.
- **Autonomía**: pasos sin intervención / pasos totales.
- **Trazabilidad**: 100% de acciones con evidencia y cadena de auditoría válida.
- **Seguridad**: 0 secretos en claro; 0 acciones fuera de scope; 0 aprobaciones reusadas.
- **UX**: latencia de teclado < 50 ms; 0 discrepancias de render en PTY; primer valor < 30 s.
- **Extensibilidad**: tiempo de "añadir una capability sin tocar el core" < 30 min.
- **Distribución**: instalación en un comando en Kali limpio.
- **Informe**: % de hallazgos con CVSS + ATT&CK + marco (PTES/WSTG) + CVE enriquecido.

---

## 10. Checklist "¿es una CLI profesional?"

- [x] Instalación en un comando (`install.sh`, `pipx`, npm shim)
- [x] Onboarding con detección de entorno y autoprovisión
- [x] REPL con TUI, autocompletado, historial, status bar
- [x] Múltiples proveedores LLM incl. local
- [x] Aprobaciones humanas durables + auditoría no repudiable
- [x] Reporte reproducible y verificable
- [ ] **Instrucciones de proyecto** (`OMNI.md`/`AGENTS.md`)
- [ ] **MCP** (cliente y/o servidor)
- [ ] **Skills/plugins/hooks** cargables
- [ ] **Subagentes** y paralelismo seguro
- [ ] **Headless JSON** para CI
- [ ] **Keyring** / secretos gestionados
- [ ] **Defensa anti prompt-injection**
- [ ] **Kill switch / egress control**
- [ ] **CVSS 4.0 + marcos + SARIF + CVE enrich**
- [~] **CI** ya existe (ruff/pytest/Postgres/gitleaks); falta **cobertura, mypy/pip-audit, Docker, `omni update`**
- [ ] **LICENSE con uso autorizado + atestación de autorización**

---

## 11. Riesgos y decisiones abiertas

- **Dual-use / reputación**: documenta el uso autorizado y aplica "authorized use only".
  No cambies el diseño por miedo; hazlo **explícito**.
- **MCP amplía la superficie de ataque** (tool poisoning, rug-pull, inyección indirecta):
  por eso MCP debe entrar **detrás del gateway** con allowlist, firma y auditoría; y la
  defensa anti-inyección precede a MCP.
- **Paralelismo vs gobernanza**: paralelizar solo read-only, con límite y cancelación;
  jamás DESTRUCTIVE.
- **Coste LLM**: mantener presupuesto por fase y fallback local (Ollama) para no
  depender de un SaaS.
- **Mantenimiento**: cada integración nueva debe reusar el patrón handler→parser→test;
  no permitas atajos que salten el gateway.

---

## 12. Qué haría yo primero (si tuviera una sola semana)

1. Rotar la key de Groq y meter `keyring`.
2. `OMNI.md` (instrucciones de proyecto) + `run --json`.
3. Defensa anti prompt-injection en el prompt.
4. LICENSE + aviso de uso autorizado + atestación en el wizard.
5. Empezar MCP cliente tras el gateway.

Con esos cinco, la percepción del producto cambia de "script potente" a "CLI seria",
sin tocar lo que ya funciona.

---

## 13. Referencias (investigación web)

- Comparativa de CLIs de agentes (matriz de MCP, subagentes, hooks, headless):
  https://hidekazu-konishi.com/entry/cli_coding_agents_comparison.html
- Claude Code — best practices / plan mode:
  https://code.claude.com/docs/en/best-practices
- Claude Code — hooks (ciclo de vida):
  https://code.claude.com/docs/en/hooks
- Anthropic — autonomía y checkpoints:
  https://www.anthropic.com/news/enabling-claude-code-to-work-more-autonomously
- OpenAI Codex CLI — features y loop del agente:
  https://learn.chatgpt.com/docs/codex/cli · https://openai.com/index/unrolling-the-codex-agent-loop/
- Gemini CLI — extensibilidad y subagentes:
  https://github.com/google-gemini/gemini-cli · https://developers.googleblog.com/subagents-have-arrived-in-gemini-cli/
- Cursor CLI:
  https://cursor.com/blog/cli
- Freebuff (esta misma familia de producto):
  https://github.com/CodebuffAI/freebuff · https://freebuff.com/cli
- MCP — riesgos de seguridad (tool poisoning / prompt injection):
  https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks ·
  https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/ ·
  https://genai.owasp.org/ (OWASP GenAI Security)
- Marcos de pentesting (PTES, NIST SP 800-115, OWASP WSTG, MITRE ATT&CK):
  https://owasp.org/www-project-web-security-testing-guide/ ·
  https://www.nist.gov/privacy-framework/nist-sp-800-115

---

*Documento generado como auditoría técnica. No sustituye a un plan de proyecto
aprobado; prioriza según tu tiempo y tu mercado objetivo.*
