# Fase 4.0 — Entorno, informes de run y guía de playbook

**Autor:** BAJIOWARE · Team Red
**Rama:** `feat/playbook-self-improvement-phase-4-0` (desde `37c9360`, Fase 3.8)
**Estado:** implementado y verificado en este entorno
**Origen:** tras el E2E #5 (`TEST_E2E_BOUNTY_HACKER_RUN5.md`), el diagnóstico limpio
es que el bloqueo es **de entorno y de estrategia de herramientas**, no de modelo.
Esta fase ataca esos dos frentes.

---

## 0. Alcance acordado con el operador

Se propuso un "framework de auto-evolución" con 5 subsistemas
(`.agents/playbook/strategies|mistakes|patterns`, `analyze_runs.py`, loader,
`docs`, E2E #6). Tras verificar el repo y las fuentes, se acotó a:

1. **Entorno** (arreglar herramientas sin `sudo`).
2. **Informes de run** (`run_report.json`).
3. **Guía de playbook en el prompt** (reutilizando la infraestructura existente).

### Verificaciones previas (honestidad)

| Afirmación externa | Veredicto |
|---|---|
| Hace falta construir un playbook desde cero | **Falso en parte.** Ya existían `nexus_core/agent/playbooks.py` (`FTP_ANON_TO_CRED`, `LINUX_PRIVESC`, `LATERAL_MOVEMENT`), la tool `nexus.orchestrator.playbook`, `.agents/skills/` firmadas y `OMNI.md`. |
| `Qwen3.8-27B-Abliterated-Cyber` es la solución | **Fuera de alcance.** Es real, pero lo sirve el agregador **Infron**, no Groq; usarlo rompería la decisión vinculante "solo Groq". |
| "Qwen3.8-27B base emite 0% de tool-calls" | **Mal aplicado aquí.** Ese dato mide *native tool-calling*; el agente usa **JSON de texto** y el E2E #5 ya emitió tool-calls válidos (nmap, record_fact). |
| Tabla CyberGym (MiMo-V2.6, DeepSeek V4.1) | **Real pero irrelevante** mientras el proveedor sea Groq. |

---

## 1. Entorno: qué estaba roto y cómo quedó

Diagnóstico medido en este host (`command -v`): `grep`, `ffuf`, `gobuster`,
`nuclei`, `nmap`, `hydra`, `whatweb` **existen**; **`rg` (ripgrep) falta**.

| Problema (E2E #5) | Causa real | Arreglo |
|---|---|---|
| `workspace.search` → `No such file or directory: 'rg'` | `rg` hardcodeado y ausente | **Fallback a GNU grep**, mismo contrato (exit 1 = sin resultados) |
| `gobuster`/`ffuf` → `wordlist must live inside the workspace` | Las wordlists instaladas viven en `/usr/share/...`, fuera del workspace | **Allowlist de directorios de sistema de solo lectura** para la wordlist |
| `httpx` → `httpx_binary_mismatch` | `/usr/bin/httpx` es el CLI **de Python**, no el de ProjectDiscovery | **No se toca**: la comprobación es correcta. Requiere `go install` (entorno) |

Detalles:

- **`nexus_core/tools/handlers/workspace.py`**: nuevo `search_argv(query, program=…)`
  que prefiere `rg` y cae a `grep -rn -m 100`; el sandbox allowlistea ambos
  programas y, si el binario elegido desaparece entre la comprobación y el `exec`,
  reintenta con el otro.
- **`nexus_core/tools/handlers/ffuf.py`**: `system_wordlist_dirs()` (defaults
  `/usr/share/dirb/wordlists`, `/usr/share/seclists`, `/usr/share/wordlists`;
  override con `NEXUS_WORDLIST_DIRS`). `resolve_wordlist` acepta el workspace
  **o** esos directorios de solo lectura; **sigue rechazando** cualquier otra
  ruta, el traversal y el HOME del sandbox. Las descripciones de `ffuf` y
  `gobuster` ahora nombran una ruta válida de ejemplo.
- **`httpx`**: la verificación de identidad se mantiene intacta; el binario
  correcto es una tarea de provisión del entorno, no un cambio de código.

---

## 2. Informes de run

- **`scripts/analyze_runs.py`** (stdlib puro) pliega una traza NDJSON en
  `<traza>.report.json` con: `run_id`, `engagement`, `provider`, `model`,
  `status`, `iterations`, `duration_seconds`, `phase_reached`, `facts_total`,
  `facts_recorded`, `tools_used`, `blockers`, `failed_tool_calls`. Acepta una
  lista de trazas o el glob por defecto de `docs/missions/examples/*.ndjson`, y
  tolera líneas no-JSON (stderr intercalado).
- **`nexus_core/cli/headless.py`**: el evento `run.complete` ahora incluye
  `provider` y `model` (`llm_identity(session)`), que el NDJSON no registraba.
  Sin esto, el informe no podía atribuir una traza a un modelo.

---

## 3. Guía de playbook en el prompt (la pieza que faltaba)

Los playbooks deterministas **ya existían**, pero solo llegaban al modelo por una
tool que este tenía que *decidir* llamar. El E2E #5 entró en HTTP con la cadena
`ftp_anon_to_cred` sin usar.

- **`nexus_core/agent/playbooks.py`**: `render_playbook_matches()` renderiza cada
  playbook aplicable y su **siguiente paso** (tool_id incluido).
- **`nexus_core/agent/prompts.py`**: nueva sección `PLAYBOOKS APLICABLES` en
  `REACT_SYSTEM_PROMPT` + parámetro `playbook_summary` en `render_system_prompt`.
- **`nexus_core/agent/react.py`**: `_playbook_guidance()` lee los hechos del
  blackboard, selecciona los playbooks y los inyecta en el prompt de cada
  iteración (nunca lanza: la guía no puede tumbar un run).

Efecto: con un hecho `service` de FTP, el prompt pasa a decir
`- FTP anónimo → credenciales (fase exploitation) → SIGUIENTE PASO: Listar el FTP
anónimo [nexus.recon.ftp]`, que es exactamente la prioridad que faltaba.

---

## 4. Tests

| Fichero | Qué fija |
|---|---|
| `test_playbook_prompt_guidance.py` | El playbook FTP selecciona `nexus.recon.ftp`; el prompt lleva la guía |
| `test_workspace_search_fallback.py` | argv de `rg`/`grep` y fallback del handler ante `FileNotFoundError` |
| `test_wordlist_resolution.py` | Acepta workspace y dirs de sistema; rechaza fuera/traversal/inexistente |
| `test_analyze_runs_report.py` | El informe captura estado, fase, modelo y bloqueos; tolera ruido |

---

## 5. E2E #6

Informe completo: **`TEST_E2E_BOUNTY_HACKER_RUN6.md`**.

| | RUN #5 | **RUN #6** |
|---|---|---|
| Fase alcanzada | `enumeration` (1/6) | **`exploitation` (2/6)** |
| ¿Tocó el FTP? | **No** (se fue a HTTP) | **Sí** (`nexus.recon.ftp` list + download) |
| Estado | `subagent_budget_exceeded` | abortado por **TPD** del proveedor |

La guía de playbook en el prompt es lo que llevó al agente al FTP. El run **no
completó la sala**: el **presupuesto diario del tier gratis (200 000 TPD) se
agotó** (usado 192 969) tras varios E2E el mismo día.

### Límites del proveedor descubiertos (medidos)

`qwen/qwen3.8-27b` gratis impone **tres** presupuestos, y el run chocó con los tres:

| Límite | Valor | Arreglo en esta fase |
|---|---|---|
| OTPM (output/min) | 1 000 | **Sí**: el 429 por OTPM ahora encoge `max_tokens` (1536→768) |
| ITPM (input/min) | 7 000 | **Sí**: el 413 por input ahora recorta el contexto (`trim_oldest_messages`) |
| **TPD (tokens/día)** | **200 000** | **No**: es un tope de cuenta, irrecuperable dentro del día |

Consecuencia: **la cuenta gratuita da para ~un E2E completo al día**.

---

## 6. Limitaciones (honestidad)

1. **`httpx` sigue roto** por entorno; no se relajó la comprobación.
2. La red del entorno sigue siendo intermitente (`FASE38_MODEL_CHANGE.md` §8).
3. El playbook solo guía; **no** ejecuta ni sustituye la decisión del modelo.
4. El informe de run depende de que exista `run.complete`; una traza sin cierre
   final reporta `status: null`.

---

## 7. Atribución

BAJIOWARE · Team Red. Fase 4.0 sobre la Fase 3.8 (`FASE38_MODEL_CHANGE.md`).
