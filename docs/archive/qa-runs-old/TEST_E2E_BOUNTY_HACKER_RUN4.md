# Test E2E #4 — "Bounty Hacker" (TryHackMe) con OmniAgentCS 3.0.0

Informe del cuarto intento de completar la sala de forma autónoma, ejecutado con el
código de la Fase 3.7 (`feat/enumeration-fix-phase-3-7`).

> **Resultado**: **NO completó la sala.** El bloqueante P1 del E2E #3 (arquitectura
> de enumeración) **está arreglado y se verificó en vivo**: el agente enumeró el FTP,
> descargó y leyó el loot y registró credenciales. Lo que impidió el cierre fue el
> comportamiento del modelo `gpt-oss-120b` (no registrar hechos; inventar un
> `fact_type` fuera del vocabulario; gastar iteraciones en Metasploit sin RPC), no
> la arquitectura. Se documenta la causa raíz exacta y se propone el cambio de modelo
> (DeepSeek V4.1 Flash, ya preparado en la Fase 3.6) **sin seguir iterando sobre la
> arquitectura**, tal y como pedía el encargo.

## 0. Resumen ejecutivo

| | Run A | Run B |
| --- | --- | --- |
| Objetivo | `10.0.0.1` (Bounty Hacker) | `10.0.0.1` (Bounty Hacker) |
| Engagement | `eng-4d3a421e6284` (`bounty-hacker-4`) — **nuevo**, 0 hechos | `eng-3df61e81d9df` (el del E2E #3, con el hecho `service:21`) |
| Run | `run_1789543ee7e1451789adb4332a97f98b` | `run_9ee96f5c72194cc8b9fad91ff38e0a2b` |
| Modelo | Groq `openai/gpt-oss-120b` | Groq `openai/gpt-oss-120b` |
| Estado final | `subagent_budget_exceeded` (exit 1) · 9 iteraciones · 1057 s | **sin `run.complete`** (proceso terminado externamente) · 15 iteraciones |
| Plan alcanzado | `recon` (0 hechos) | `enumeration` → **`exploitation`** (2 hechos) |
| user.txt / root.txt | **no obtenidos** | **no obtenidos** |
| Artefacto | `examples/e2e-bounty-hacker-run4a.ndjson` | `examples/e2e-bounty-hacker-run4b-partial.ndjson` |

Lo esencial, en una línea: **la ruta que en el E2E #3 era imposible (FTP → loot →
credenciales) ahora funciona**; lo que falla es la disciplina metodológica del modelo.

## 1. Entorno y comandos exactos

```bash
export NEXUS_ALLOW_DEGRADED_TOOLS=1      # httpx de Python en /usr/bin/httpx (B1)
export NEXUS_WORKSPACE_ROOT=/tmp/e2e37   # /tmp/e2e37b en el run B
.venv/bin/python omni.py --engagement <ENG> --objective "<...>" \
  --stream-json --trust-mode --max-iterations 18   # 16 en el run B
```

Engagement **nuevo** para el run A (`omni --new-engagement bounty-hacker-4 --scope
10.0.0.1`): el scope firmado del engagement del E2E #3 no se amplió para
acomodar una IP nueva (gobernanza intacta). El run B reutiliza el engagement del
E2E #3 (mismo objetivo, mismo scope) para reproducir **exactamente** el escenario
que se bloqueó: plan ya en `enumeration` con un hecho `service`.

Entorno (idéntico al E2E #3): venv Python 3.14.7; nmap 7.99; whatweb 0.6.4; hydra,
nuclei, nxc presentes; **`rg` ausente**; **`httpx` de `/usr/bin` equivocado**;
`NEXUS_ENV` sin definir. **Corrección** de una nota del E2E #3: `sshpass` **no** hace
falta — `nexus.post.ssh_exec` usa `paramiko` dentro del sandbox y el `python3` del
sistema lo tiene (verificado). Novedad relevante del entorno: **el RPC de Metasploit
no está configurado**, así que `nexus.exploit.msf_*` falla siempre con
`msf_rpc_failed` (ver §4).

## 2. Qué arregló la Fase 3.7 (evidencia en vivo del run B)

| Fix | Evidencia | Veredicto |
| --- | --- | --- |
| **P0** (`services`) | `orchestrator.subagent → services` en la iteración 1 (15 tools, con `nexus.recon.ftp` y `nexus.recon.netexec`). El E2E #3 en la misma situación eligió `web` (6 tools, **sin** FTP) | arreglado |
| **P0** (cadena FTP) | iteraciones 2-5: `ftp list` → `ftp download locks.txt` → `workspace.read` → `ftp download task.txt`, **todo verificado** | arreglado |
| **P0** (avance determinista) | al registrarse el hecho `credential`, `orchestrator.subagent → exploit` (`previous=services`) y `orchestrator.plan → exploitation [2/6]` | arreglado |
| **P1** (gracia de fase) | en el run A la fase era `recon` todo el tiempo y nunca hubo transición; en el run B la transición `services → exploit` pasó por la gracia (tools read-only del perfil previo presentes las 2 primeras iteraciones). Cubierto además por test unitario determinista | implementado |
| **P3** (`tools` en el evento) | `orchestrator.subagent` lleva `tools` (13/15/19 según perfil): el bloqueante del E2E #3 (`web` sin `nexus.recon.ftp`) habría sido visible en vivo | arreglado |
| **P2** (`--subagent`) | presente y validado en la CLI (`--help`, y `invalid choice` con la lista de los 9 perfiles). No fue necesario para desbloquear, pero es la vía de retoma del operador | implementado |

Ninguno de los bloqueantes B1-B8.2 de las fases 3.5/3.6 reapareció: cero 413 (B5),
`rg` retirado antes de proponerse (B6), sin evidencia heredada (B8.2.1), sin
`task_complete` prematuro ni findings fabricados (B8.2.2/8.2.3).

## 3. Run A — cronología (engagement nuevo, desde cero)

```
14:05:06  run.preflight_degraded (httpx) + react.tool_unavailable (rg)
          orchestrator.subagent=recon (13 tools) · orchestrator.plan: recon [0/6]
 it.1  14:05:39  nexus.recon.nmap {profile: full_tcp}   → 21/22/80     ✓
 it.2  14:07:02  nexus.recon.nmap {profile: service}    → vsftpd 3.0.5 ✓
 it.3  14:10:14  nexus.recon.ftp {action: list, /}      → locks.txt, task.txt ✓
 it.4  14:11:44  nexus.recon.ftp {action: download, /locks.txt}          ✓
 it.5  14:13:08  nexus.workspace.read {locks.txt}                        ✓
 it.6  14:14:55  nexus.recon.ftp {action: download, /task.txt}           ✓
 it.7  14:17:17  nexus.recon.nmap {profile: full_tcp}   ← REPETICIÓN        ✓
 it.8  14:20:00  nexus.recon.nmap {profile: service}    ← REPETICIÓN        ✓
 it.9            subagent 'recon' exceeded its iteration budget (8)
14:22:40  run.complete status=subagent_budget_exceeded · 1057 s
```

**Nunca se registró un solo hecho** (`facts_total: 0`), así que el plan nunca salió
de `recon`. El agente hizo la cadena correcta de enumeración FTP (iteraciones 3-6)
pero **no la declaró**, y el propio prompt de la fase le siguió pidiendo el escaneo
de recon. Sus pensamientos de las iteraciones 7 y 8 (literal, del histórico):

> it.7 — "Ejecutar un escaneo completo de puertos TCP en el objetivo usando nmap con
> el perfil full_tcp **para cumplir con la fase de Reconocimiento** y descubrir todos
> los puertos abiertos **antes de pasar a la enumeración de servicios**."
>
> it.8 — "Ejecutar un escaneo de versiones y scripts (perfil *service*) contra los
> puertos abiertos descubiertos (21, 22, 80) **para obtener información detallada de
> los servicios antes de pasar a la enumeración y pruebas de credenciales**."

El guardarraíl de diseño (`subagent_budget_exceeded`, fail-closed) cortó el bucle:
mejor un run acotado que uno que quema tokens repitiendo el mismo escaneo.

## 4. Run B — cronología (el escenario del E2E #3, con el fix)

```
14:40:35  orchestrator.subagent=services (15 tools, previous=null, phase=enumeration)
          orchestrator.plan: enumeration [1/6]
 it.1  ftp {action: "LIST"}            ✗ $.action: value is not in enum (mayúsculas)
 it.2  ftp {action: "list", /}         ✓   (el modelo se autocorrige)
 it.3  ftp {action: "download", /locks.txt}                    ✓
 it.4  workspace.read {locks.txt}                              ✓
 it.5  ftp {action: "download", /task.txt}                     ✓
 it.6  record_fact {fact_type: "ftp_file_content", ...}  ✗ $.fact_type: value is not in enum
 it.7  query_facts {fact_type: "ftp_file_content"}       ✗ $.fact_type: value is not in enum
 it.8  record_fact {value: "<texto>"}                    ✗ $.value: expected object
 it.9  record_fact {fact_type: "credential", value:{passwords:[...]}}   ✓
          → orchestrator.plan: exploitation [2/6] · orchestrator.subagent=exploit (previous=services)
 it.10 msf_auxiliary {options:{PASSWORDS:[...]}}         ✗ unexpected fields / options must be scalar
 it.11 msf_auxiliary ...                        ✗
 it.12 msf_auxiliary {USERNAME: root, PASSWORD: ...}     ✗ msf_rpc_failed
 it.13 msf_search {query: "ssh login"}                   ✗ msf_rpc_failed
 it.14 msf_auxiliary ...                                 ✗ msf_rpc_failed
 it.15 check_env {tools: ["msf_auxiliary", ...]}         ✗ unknown tool
          (el proceso terminó externamente aquí; no hubo línea run.complete)
```

Hechos registrados por este run (**la prueba de que P0 desbloqueó la cadena**):

```
service    10.0.0.1:21   {product: vsftpd, version: 3.0.5, ...}   (del E2E #3)
credential ftp_locks         {passwords: [rEddrAGON, ReDdr4g0nSynd!cat3, ...]}
```

**Dos causas externas afectaron al run B** (documentadas para no atribuirles el
veredicto): (1) un primer intento murió a los 2 minutos con
`LLMClient.groq → OpenAI API error: Connection error` (corte transitorio de Groq;
la API respondía con HTTP 200 minutos después), y la excepción abortó el proceso sin
emitir `run.complete`; (2) el segundo intento (el de arriba) fue terminado
externamente por la plataforma en la iteración 15/16, también sin `run.complete`.
Ninguno de los dos es un defecto de la Fase 3.7; el primero sí revela una brecha de
robustez que se anota en `BACKLOG.md`.

## 5. ¿Completó la sala? No. Causa raíz

**No se obtuvo `user.txt` ni `root.txt`**. La causa raíz, por run:

1. **Run A — el modelo no registra hechos.** Hizo la cadena correcta (nmap, FTP,
   lectura del loot) y **cero** llamadas a `nexus.knowledge.record_fact`, pese a que
   el objetivo y el prompt se lo piden explícitamente (y pese a que el mismo modelo
   **sí** registró un hecho en el E2E #3, con el mismo prompt). Sin hechos, el
   planner — determinista — no puede avanzar: el frame se quedó en `recon` y le
   repitió la instrucción de escanear hasta agotar el presupuesto del subagente.
2. **Run B — el modelo usa mal los esquemas cerrados.** Necesitó **tres** intentos
   para registrar un hecho válido (`ftp_file_content` no existe en `FACT_TYPES`;
   `value` debe ser un objeto, no el texto del archivo). Lo consiguió en la cuarta
   (it.9) y entonces **P0 hizo su trabajo**: el plan avanzó a `exploitation`. A
   partir de ahí gastó 5 iteraciones en `nexus.exploit.msf_*` sabiendo (el error se
   lo dijo en la primera) que el RPC de Metasploit no está configurado, en vez de
   probar `nexus.recon.netexec` (presente en su subconjunto) o de volver a
   `nexus.cred.bruteforce` con el perfil adecuado.

**¿Es el modelo, la arquitectura o el objetivo?** Con la evidencia de los dos runs:

- **No es la arquitectura de enumeración.** El bloqueante del E2E #3 (perfil de
  `enumeration` incapaz de tocar el servicio hallado) está corregido y probado: el
  run B enumeró FTP, leyó el loot y registró credenciales, y el plan avanzó solo.
- **Es el modelo.** Los dos fallos son de *instruction-following* sobre esquemas y
  metodología que el propio prompt entrega literalmente (enum de `fact_type`, tipo
  de `value`, instrucción de registrar hechos, catálogo de tools disponibles). Un
  `gpt-oss-120b` que no registra hechos no puede cerrar ninguna cadena de fases;
  el sistema ya hizo todo lo que podía sin inventar progreso.
- **Tampoco es el objetivo**: la cadena de la sala (FTP anónimo → pistas → hydra SSH
  → `sudo tar`) está cubierta por tools existentes y el entorno las tiene
  (hydra, paramiko, nmap, whatweb).

Hallazgo arquitectónico **secundario** (no es la causa, pero contribuyó y queda
anotado para decisión del operador, **sin tocar en esta fase**): al registrar un
hecho `credential`, la fase `enumeration` se cierra y el plan pasa a `exploitation`,
cuyo perfil (`exploit`) **no** incluye `nexus.cred.bruteforce` (vive en `cred`, un
perfil de la fase `enumeration`). Es decir: registrar una *lista candidata* de
contraseñas cierra la fase en la que vive la herramienta que las *valida*. En el run
B esto empujó al modelo a Metasploit. La validación sigue siendo posible con
`nexus.recon.netexec` (en `exploit`), pero el camino "natural" (`cred.bruteforce`)
queda por detrás. Ver `BACKLOG.md`.

## 6. Consecuencia: decisión sobre el modelo

El encargo lo pedía explícitamente: si tras P0+P1+P2 el E2E #4 falla con
`gpt-oss-120b`, **es el modelo**. Es lo observado, con dos runs y causa raíz
identificada en cada uno.

**Propuesta (Fase 4, sin más iteraciones de arquitectura):** activar **DeepSeek
V4.1 Flash**, cuya infraestructura quedó lista en la Fase 3.6 (proveedor
`deepseek` en `create_from_env`, modelo `deepseek-v4.1-flash`, tarifas y TPM en
`pricing.py`/`limits.py`, backoff 413/429/503). Requiere únicamente la API key del
operador. Criterio de éxito sugerido para la Fase 4: repetir **este mismo E2E #4**
con el mismo código y el mismo objetivo, y comprobar si el nuevo modelo (a) registra
hechos válidos a la primera y (b) elige `nexus.recon.netexec`/`cred.bruteforce` en
vez de Metasploit sin RPC.

## 7. Limitaciones (honestidad)

1. **Un único run por configuración** (y el run A con 18 iteraciones de techo, no las
   necesarias para toda la cadena). No se midió reproducibilidad; `temperature` no se
   fijó.
2. **El run B no tuvo `run.complete`** (terminado externamente en 15/16). Su traza es
   completa hasta ahí (`run4b-partial.ndjson`, 56 líneas) y su estado de blackboard es
   verificable en la base (`credential ftp_locks`), pero su estado final no existe
   como artefacto del sistema. No se le atribuye ningún veredicto.
3. **El primer intento del run B** murió por un corte de red de Groq; el fallo de
   robustez que reveló (sin `run.complete` ni `run.error`) está en `BACKLOG.md`, fuera
   del alcance de la Fase 3.7.
4. **El RPC de Metasploit no está configurado** en este entorno, así que el perfil
   `exploit` está degradado por entorno, no por diseño. Se documenta porque el run B
   gastó ahí 5 de sus 15 iteraciones.
5. **P1 (gracia de fase) no se ejercitó en el run A** (nunca hubo transición) y en el
   run B la transición fue `services`→`exploit`; el caso exacto `recon`→`enumeration`
   está cubierto por un test unitario determinista
   (`test_first_service_fact_keeps_the_tools_that_enumerate_it`).

## 8. Atribución

BAJIOWARE · Team Red. Fix y verificación: Fase 3.7
(`docs/missions/FASE37_ENUMERATION_FIX.md`). Causa raíz del bloqueo original: E2E #3
(`TEST_E2E_BOUNTY_HACKER_RUN3.md` §5).
