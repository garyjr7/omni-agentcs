# Test E2E #2 — TryHackMe "Bounty Hacker" (`10.0.0.1`)

> Rama: `feat/unblock-e2e-phase-3-5` · Autor: BAJIOWARE · Team Red
> Fecha: 2026-10-06 · Engagement: `eng-923f594ec3da` · Proveedor: `groq / openai/gpt-oss-120b`
> Contexto: repetición del E2E tras la Fase 3.5 (`docs/missions/FASE35_UNBLOCK_E2E.md`).
> El primer test está en `docs/missions/TEST_E2E_BOUNTY_HACKER.md`.

## 0. Veredicto

**NO completó la sala** (ni `user.txt` ni `root.txt`). Pero **ninguno de los
cuatro bloqueantes originales volvió a aparecer**: se arreglaron y el
comportamiento mejoró de forma medible.

Se ejecutaron **tres** runs con el código corregido:

| Run | `run_id` | Iteraciones | Estado | Tokens | Motivo de parada |
| --- | --- | --- | --- | --- | --- |
| A (sin guía) | `run_9f3b1f5f348b4aad8c80dfff43d22a9a` | 1 | `failed` | — | 413 de Groq (antes de los arreglos de contexto/`max_tokens`) |
| B (sin guía) | `run_2e615916fccd4c7b9c928b84ac41eb73` | 3 | `clarification` | 17 081 | El modelo pidió al operador leer `task.txt`; `rg` ausente |
| C (guiado) | `run_0dbdf48efdb441fe8e47b0fe8926236c` | 2 | `completed` (prematuro) | 12 308 | `task_complete` tras el recon, con 2 hallazgos |

Los runs B y C son los comparables con el E2E #1: el A fue la iteración de
diagnóstico del límite TPM.

---

## 1. Qué se corrigió y se pudo comprobar

| Bloqueante original | Evidencia en este test |
| --- | --- |
| **B1** identidad de binarios | Preflight detectó `/usr/bin/httpx` como binario equivocado (`binario equivocado en /usr/bin/httpx`) y, con `NEXUS_ALLOW_DEGRADED_TOOLS=1`, emitió `run.preflight_degraded` y continuó. |
| **B2** whatweb `aggression` | No se invocó whatweb (el modelo no llegó a él); cubierto por 15 tests unitarios. |
| **B3** degradación | El catálogo del subagente ofrece rutas alternativas; no hubo aborto por 3 fallos (en B hubo 2 fallos y el modelo pivotó a pedir aclaración en vez de morir). |
| **B4** presupuestos/contexto | `orchestrator.subagent` muestra `token_budget: 100000` para `recon`. El 413 desapareció tras el techo de salida + cota de contexto. |
| **P1** observabilidad | `tool.invoke` auditado con `arguments` (password `[REDACTED]`), `run_id`. Coste registrable por defecto. Gating de aprobación cubierto por tests. |

---

## 2. Run A — diagnóstico del límite del proveedor

```
run.preflight_degraded  problems=[httpx: binario equivocado en /usr/bin/httpx,
                        install "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"]
orchestrator.subagent   recon · token_budget=100000
17:44:18 LLMClient.groq → OpenAI API error: Error code: 413
        'Request too large for model openai/gpt-oss-120b ... tokens per minute (TPM):
         Limit 8000, Requested 8438'
```

**Causa raíz:** la cuenta Groq on-demand tiene un límite de **8000 tokens por
minuto**, y cada petición contaba el prompt **más** el `max_tokens` reservado
(4096). Con el prompt acumulado de la *work session*, la petición superaba el
límite ya en la iteración 1 y `NexusLLM` la daba por fallida (413 es
`APIStatusError`, no `RateLimitError`, así que no se reintentaba).

**Mitigación aplicada (B4):**
- techo de salida por turno `NEXUS_REACT_MAX_TOKENS` (default 1536);
- cota de contexto `bounded_context` (8 000 chars) sobre el historial de la
  *work session*, que acumulaba los mensajes de **todos** los runs previos.

Tras ello, el 413 **no volvió a aparecer** en B ni en C.

---

## 3. Run B — transcripción (sin guía)

Objetivo: el mismo del E2E #1 (comprometer el host).

| # | Hora (UTC) | Subagente | Tool | Argumentos | Resultado |
| --- | --- | --- | --- | --- | --- |
| 1 | 23:47:25 | `recon` | `nexus.workspace.search` | `query="task.txt"` | ❌ `FileNotFoundError: [Errno 2] No such file or directory: 'rg'` |
| 2 | 23:47:54 | `recon` | `nexus.system.check_env` | `tools=["rg"], verify_sandbox=true` | ❌ `ValueError` ("unknown tool": `rg` no está entre las tools conocidas) |
| 3 | 23:49:18 | `recon` | `request_clarification` | — | 🛑 *"¿Podrías proporcionar el contenido del archivo task.txt descargado del FTP, o autorizar la instalación de … 'cat' o 'ripgrep' …?"* |

`react.finished` → `{"status": "clarification", "iterations": 3, "findings_count": 0}`.

**Lectura:** el agente **no** ejecutó nmap ni FTP; fue directo a buscar el
`task.txt` de un run anterior en el workspace (contexto acotado + sesión
compartida). Al no poder leer su contenido, **pidió ayuda al operador** en lugar
de continuar el flujo (nmap → FTP → creds → SSH).

---

## 4. Run C — transcripción (guiado)

Objetivo: secuencia explícita de herramientas (nmap → FTP list/download →
record_fact → hydra → ssh_exec → privesc). Blackboard vaciado.

| # | Hora (UTC) | Subagente | Tool | Argumentos | Resultado |
| --- | --- | --- | --- | --- | --- |
| 1 | 23:53:41 | `recon` | `nexus.recon.ftp` | `action=download, target=10.0.0.1, port=21, username=anonymous, remote_path=/locks.txt` | ✅ `ftp_download_verified` — `locks.txt` (418 B) escrito en `ftp_run_0dbdf48…/` |
| 2 | 23:54:17 | `recon` | `task_complete` | — | 🏁 *"Reconocimiento completado…"* (2 hallazgos) |

`react.finished` → `{"status": "completed", "iterations": 2, "findings_count": 2}`.

**Hallazgos reportados por el modelo:** "puertos 21/22/80, vsftpd/OpenSSH/Apache"
y "`locks.txt` + `task.txt` descargados". **Pero el run solo invocó una tool**
(`ftp download /locks.txt`): el resto proviene de **evidencia de runs previos**
recuperada del contexto acotado de la sesión compartida, no de una observación
nueva. Es **reutilización de contexto**, no verificación. El modelo declaró el
objetivo cumplido tras el primer paso.

---

## 5. Respuestas a las preguntas del encargo

| Pregunta | Respuesta | Evidencia |
| --- | --- | --- |
| ¿El planner siguió la secuencia correcta? | **No en la práctica.** El planner se quedó en `recon` (correcto); fue el **modelo** el que no siguió la kill-chain. | `orchestrator.plan` en `recon`; acciones fuera de la fase |
| ¿Se activó el subagente correcto? | **Sí**, `recon` para ambas runs; coincide con `PHASE_SUBAGENT`. | `orchestrator.subagent: recon` |
| ¿El gateway pidió aprobación en el momento correcto? | **No se alcanzó ningún tool HIGH**, así que el gating humano no se activó (igual que en el E2E #1). La ruta sí está cubierta por tests nuevos (denegación y trust-mode). | `kernel_approvals = 0` |
| ¿El agente encontró las flags? | **No.** | `findings_count` sin `user.txt`/`root.txt` |
| ¿El reporte es completo? | **No se generó.** El reporte de C es prematuro e incluye datos no verificados en el run. | Sin `nexus.report.generate` |

---

## 6. Métricas

| Métrica | Run A | Run B | Run C |
| --- | --- | --- | --- |
| Duración | ~15 s (muere en it.1) | 114.6 s | 39.3 s |
| Iteraciones | 1 | 3 | 2 |
| Tool calls ejecutadas | 0 (413 antes) | 2 (ambas fallan) | 1 (FTP exitosa) |
| Tokens (`model_route react`) | — | 17 081 | 12 308 |
| Aprobaciones humanas | 0 | 0 | 0 |
| Flags | — | 0 | 0 |
| Time-to-`user.txt` / `root.txt` | — | — | — |

**Coste** (ahora registrable por defecto, P1): con `gpt-oss-120b`
($0.15/1M input, $0.60/1M output) y ~5 % de salida, B ≈ **$0.0025** y C ≈
**$0.0018**; total de los tres runs **< $0.01**.

---

## 7. Causa raíz de los nuevos bloqueantes

### B5 — TPM = 8000 del proveedor (cuenta)

Groq on-demand limita a 8000 tokens por minuto; el cálculo incluye el `max_tokens`
**reservado**. Mitigado reduciendo el techo de salida y acotando el contexto, pero
es un techo **externo**: un run largo seguiría rozando el límite y conviene
subir de tier o usar un proveedor con más margen.

### B6 — `rg` ausente (entorno)

`nexus.workspace.search` delega en `rg`, que no está instalado; el handler falla
con `FileNotFoundError`. La allowlist de recon incluye `rg` pero el entorno no lo
tiene. Es un defecto de preparación (como B1): instalar `ripgrep` o verificar su
identidad/presencia en `--setup`.

### B7 — sin lectura de loot (diseño/capacidad)

El handler FTP `download` devuelve **metadatos** (nombre, tamaño, sha256, ruta),
nunca el contenido. Para la sala, el usuario (`lin` en `task.txt`) y los passwords
(`locks.txt`) están **dentro** de los ficheros descargados, así que el agente no
puede extraerlos y **pide aclaración**. Sería una capacidad nueva → BACKLOG.

### B8 — razonamiento del modelo (modelo)

`openai/gpt-oss-120b` eligió tools fuera de la kill-chain (workspace/environment)
y declaró `task_complete` tras un paso. Además, reutilizó observaciones de runs
previos del contexto acotado como si fueran hallazgos del run actual. Fuera del
alcance de "reparación".

---

## 8. Aciertos confirmados

- ✅ **Preflight de identidad** con mensaje accionable y modo degradado explícito.
- ✅ **Budgets ×5** visibles en los eventos (`token_budget=100000`).
- ✅ **Sin 413** tras el techo de salida + cota de contexto.
- ✅ **FTP real contra el objetivo**: `locks.txt` (418 B) descargado y verificado
  por sha256.
- ✅ **Audit `tool.invoke` autocontenido** con argumentos redactados
  (`password: "[REDACTED]"`) y `run_id`.
- ✅ **Gobernanza intacta**: scope firmado, audit chain, fail-closed y
  anti-injection sin cambios.
- ✅ **Retirada de tools / degradación** por diseño y tests (no se llegó a
  disparar en estos runs porque hubo ≤2 fallos).

---

## 9. Qué falta para que el E2E complete

1. **B6** — instalar `ripgrep` (o quitarlo de las rutas por defecto) y añadirlo
   al preflight de identidad.
2. **B7** — exponer el **contenido** del loot al agente (p. ej. que `ftp download`
   o una tool de `workspace.read` devuelva un preview acotado). Decisión de
   producto → BACKLOG.
3. **B5** — subir el tier de Groq o fijar un modelo con más TPM/contexto.
4. **B8** — endurecer el frame de subagente/objetivo para que el modelo no
   cierre el run tras recon ni reutilice evidencia no observada en el run.

Ver `docs/missions/BACKLOG.md`.

---

## 10. Estado que deja el test

- Engagement `eng-923f594ec3da` (`bounty-hacker`, `10.0.0.1/32`).
- Runs A/B/C en `kernel_runs` con eventos y auditoría.
- Blackboard del engagement vaciado por el operador antes de cada run (datos de
  prueba).
- Artefactos de runtime `ftp_run_*` eliminados del árbol.
- Transcripciones crudas: `docs/missions/examples/e2e-bounty-hacker-run2-*.ndjson`.

## 11. Atribución

- Sala *Bounty Hacker*, TryHackMe (laboratorio autorizado).
- Modelo `openai/gpt-oss-120b` vía Groq. Cifras de `~/.local/share/omni/control.db`
  y de los NDJSON citados.
