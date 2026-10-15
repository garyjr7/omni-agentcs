# Test E2E — Bounty Hacker · RUN #5 (`qwen/qwen3.8-27b`)

**Autor:** BAJIOWARE · Team Red
**Fecha:** 2026-10-07
**Objetivo:** `10.0.0.1` (TryHackMe — Bounty Hacker)
**Engagement:** `bounty-hacker-5b` (`eng-a951627dd9ed`, scope firmado `10.0.0.1/32`)
**Run:** `run_1f1eba95c70e436fb28370d1e1b570b4`
**Modelo:** `groq/qwen/qwen3.8-27b` (nuevo default de la Fase 3.8)
**Traza:** `docs/missions/examples/e2e-bounty-hacker-run5.ndjson`

```
.venv/bin/python omni.py --engagement eng-a951627dd9ed \
  --objective "Compromete la sala Bounty Hacker ... consigue user.txt y root.txt ..." \
  --stream-json --trust-mode --max-iterations 20
```

---

## 1. Resultado

| Campo | Valor |
|---|---|
| Estado final | **`subagent_budget_exceeded`** |
| Iteraciones | 14 |
| Duración | 888 s (~14,8 min) |
| Fase alcanzada | **`enumeration`** (1/6 fases) |
| Hechos en el blackboard | **2** (`service`) |
| `user.txt` / `root.txt` | **No obtenidos** |

**No completó la sala.** Pero **mejoró de forma medible** sobre el RUN #4 con
`gpt-oss-120b` (ver §4).

---

## 2. Qué hizo el agente, iteración a iteración

| It | Tool | OK | Nota |
|---|---|---|---|
| 1 | `nexus.recon.nmap` (`full_tcp`) | ✅ | 3 puertos abiertos |
| 2 | `nexus.recon.nmap` (`service`) | ✅ | `21/tcp ftp` (**vsftpd 3.0.5**), `80/tcp` (tcpwrapped) |
| 3 | `nexus.knowledge.record_fact` | ✅ | `service/ftp_21` |
| 4 | `nexus.knowledge.record_fact` | ✅ | segundo `service` |
| — | **transición de subagente `recon` → `services`** | | plan: `recon` **done**, `enumeration` current |
| 5 | `nexus.recon.httpx` | ❌ | `tool post-condition was not verified (method=httpx_binary_mismatch)` |
| 6 | `nexus.recon.whatweb` | ✅ | |
| 7 | `nexus.recon.gobuster` | ❌ | `ffuf wordlist must live inside the workspace` |
| 8 | `nexus.workspace.search` | ❌ | `[Errno 2] No such file or directory: 'rg'` |
| 9 | `nexus.web.ffuf` | ❌ | `ffuf wordlist must live inside the workspace` |
| 10 | `nexus.workspace.read` | ❌ | `wordlists/dirb/common.txt` no existe |
| 11 | `nexus.workspace.read` | ❌ | `data/wordlists/dirb/common.txt` no existe |
| 12 | `nexus.web.nuclei` | ✅ | |
| 13 | `nexus.web.nuclei` | ✅ | |
| — | **`run.complete`** | | `subagent 'services' exceeded its iteration budget (10)` |

---

## 3. Causa raíz

**El modelo se quedó en la web (`:80`) y nunca enumeró el FTP**, que es la vía de
entrada real de la sala:

1. **Elección de servicio.** Tras identificar `vsftpd 3.0.5` en `:21`, el perfil
   `services` ofrece `nexus.recon.ftp`, pero el modelo prefirió explorar el
   puerto `80` (`httpx`, `whatweb`, `gobuster`, `ffuf`, `nuclei`). El puerto 80
   está identificado como `tcpwrapped` por nmap, así que esa vía no lleva a nada.
2. **Bloqueos de entorno** que consumieron el presupuesto de `services` (10
   iteraciones) con **6 de 9 fallos**:
   - `nexus.workspace.search` → **`rg` no está instalado**.
   - `nexus.recon.gobuster` / `nexus.web.ffuf` → la wordlist debe vivir dentro
     del workspace; no hay ninguna usable.
   - `nexus.recon.httpx` → `httpx_binary_mismatch` (post-condición no
     verificada).
3. Sin FTP no hay `locks.txt`, sin `locks.txt` no hay hydra SSH, y sin SSH no
   hay `user.txt`/`root.txt`.

---

## 4. Comparación con el RUN #4 (`gpt-oss-120b`) — la mejora es real

| | RUN #4 Run A (`gpt-oss-120b`) | **RUN #5 (`qwen3.8-27b`)** |
|---|---|---|
| Registra hechos | **0** | **2** (`service/ftp_21` con vsftpd) |
| El plan avanza | No (se quedó en `recon`) | **Sí** → `enumeration` (`services`) |
| `run.complete` | No | **Sí** (`subagent_budget_exceeded`, honesto) |
| Causa del bloqueo | *instruction-following* del modelo | **elección de servicio + entorno** |

El fix `with_kickoff_user_turn` (Fase 3.8) fue **requisito**: sin él,
`qwen/qwen3.8-27b` devolvía **HTTP 400** (*"No user query found in messages"*) en
la iteración 1 y el run moría de inmediato.

**Conclusión honesta:** el modelo nuevo **sí** corrige el eje que culpaba RUN #4
(*instruction-following* sobre esquemas y metodología: hechos registrados a la
primera y plan que avanza solo). **No basta** para cerrar la sala: falta que el
agente priorice el servicio por el que se entra y que el entorno tenga sus
herramientas/wordlists.

---

## 5. Hallazgos nuevos para el BACKLOG

1. **`rg` (ripgrep) no está instalado** → `nexus.workspace.search` falla siempre.
2. **No hay ninguna wordlist dentro del workspace** → `gobuster`/`ffuf` no pueden
   ejecutarse (los perfiles que las usan son inalcanzables en este entorno).
3. **`nexus.recon.httpx` no verifica su post-condición** (`httpx_binary_mismatch`).
4. **Presupuesto de subagente muy corto para `services` (10 iteraciones):** entre
   los 4 fallos de entorno y el barrido web se agota antes de llegar al FTP.
   Un servicio identificado con `nexus.recon.nmap` debería poder enumerarse sin
   gastar el presupuesto en herramientas rotas.
5. Sin cambios respecto a RUN #4: RPC de Metasploit sin configurar; al registrar
   un hecho `credential` la fase que lo valida se cierra (ver `BACKLOG.md`).

---

## 6. Limitaciones (honestidad)

1. **Un único run** con el nuevo default. No se midió reproducibilidad;
   `temperature` sin fijar.
2. **La red del entorno es intermitente** (ver `FASE38_MODEL_CHANGE.md` §8): cada
   llamada al proveedor cuesta varios segundos por el DNS mal configurado, lo que
   alarga el run (888 s) pero **no** es la causa del fallo.
3. El run **sí** emitió `run.complete`, con un estado que **no** es
   `completed`: el sistema no fingió un cierre.
4. El objetivo (`user.txt`/`root.txt`) **no se logró**. Esta fase cambia el
   modelo; no promete cerrar la sala.

---

## 7. Atribución

BAJIOWARE · Team Red. Fase 3.8 (`FASE38_MODEL_CHANGE.md`). Línea base:
`TEST_E2E_BOUNTY_HACKER_RUN4.md`.
