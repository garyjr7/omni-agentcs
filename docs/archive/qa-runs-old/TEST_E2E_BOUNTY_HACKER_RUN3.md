# Test E2E #3 — "Bounty Hacker" (TryHackMe) con OmniAgentCS 3.0.0

Informe del tercer intento de completar la sala de forma autónoma, ejecutado con el
código de la Fase 3.6 (`feat/close-e2e-phase-3-6`).

> **Resultado**: **NO completó la sala.** El run terminó en
> `status=clarification` tras 4 iteraciones (279 s). Ninguno de los bloqueantes
> B1-B8.2 de las fases 3.5/3.6 se reprodujo; apareció **un bloqueante nuevo (P1)**
> de arquitectura, distinto de todos los anteriores. Este informe documenta
> exactamente por qué, y propone un plan alternativo (§7) **sin seguir iterando**
> sobre los mismos bloqueantes, tal y como pedía el encargo.

## 0. Resumen ejecutivo

| | |
| --- | --- |
| Objetivo | `10.0.0.1` (Bounty Hacker; la sala se reinició y cambió de IP — antes `10.0.0.1`) |
| Engagement | `eng-3df61e81d9df` · `bounty-hacker-3` · `cidrs=['10.0.0.1/32']` |
| Run | `run_d4a3f3a7604b459ebbc13763c204e4ed` |
| Conversación | `conversation_9eb6efb8b4d14e05943a05fd786f9278` |
| Modelo | Groq `openai/gpt-oss-120b` (sin cambios: sigue siendo el de desarrollo) |
| Estado final | `clarification` (exit code 0) · 4 iteraciones · 279 s |
| Subagente final | `web` |
| Hechos registrados | 1 (`service` → `10.0.0.1:21` vsftpd 3.0.5, verificado) |
| user.txt / root.txt | **no obtenidos** |

Lo que hizo el agente, en orden (todo verificado por herramienta):

1. `nexus.recon.nmap` `profile=full_tcp` → **21/tcp ftp, 22/tcp ssh, 80/tcp http**
   (49,7 s);
2. `nexus.recon.nmap` `profile=service` → vsftpd 3.0.5 en 21, OpenSSH en 22, http en 80
   (83,5 s);
3. `nexus.knowledge.record_fact` (`fact_type=service`, `10.0.0.1:21`) → el plan
   avanza de `recon` a `enumeration` y el subagente cambia a `web`;
4. `request_clarification`.

## 1. Entorno y comando exacto

```bash
export NEXUS_ALLOW_DEGRADED_TOOLS=1      # httpx de Python en /usr/bin/httpx (B1)
export NEXUS_WORKSPACE_ROOT=/tmp/e2e36
.venv/bin/python omni.py \
  --engagement eng-3df61e81d9df \
  --objective "Compromete el host 10.0.0.1 (Bounty Hacker): descubre TODOS los \
puertos TCP con nmap full_tcp y luego service, enumera el FTP anónimo (puerto 21) y \
descarga sus archivos; LÉELOS con nexus.workspace.read para extraer usuarios y \
contraseñas; valida las credenciales contra SSH (nexus.cred.bruteforce) para obtener \
acceso inicial; con el acceso, enumera la escalada local y demuestra sudo/SUID hasta \
poder leer /home/*/user.txt y /root/root.txt. Registra cada hallazgo verificado con \
nexus.knowledge.record_fact." \
  --stream-json --trust-mode --max-iterations 14
```

Entorno: venv Python 3.14.7; `nmap` 7.99; `whatweb` 0.6.4; **`rg` ausente**;
**`httpx` de `/usr/bin` es el cliente Python (equivocado)**; `go` ausente;
`NEXUS_ENV` sin definir (sandbox local). Engagement **nuevo** porque el anterior
(`eng-923f594ec3da`) estaba atado a `10.0.0.1/32`; el scope firmado no se toca
para acomodar una IP nueva (gobernanza intacta).

Artefactos: `docs/missions/examples/e2e-bounty-hacker-run3.ndjson` (23 líneas NDJSON,
NDJSON por evento) y `...-b7-check.txt` (verificación directa de B7, §4). `stderr`
vacío: ningún warning ni excepción en todo el run.

## 2. Qué arregló la Fase 3.6 (evidencia del run)

| Bloqueante | Evidencia en el run #3 | Veredicto |
| --- | --- | --- |
| **B6** (`rg` ausente) | primera línea tras el preflight: `react.tool_unavailable` con `tool_id=nexus.workspace.search`, `reason=binary_missing`, `iteration=0`. El modelo **nunca** propuso `nexus.workspace.search` (antes gastaba iteraciones hasta chocar con `FileNotFoundError`) | arreglado |
| **B1** (binario equivocado) | `run.preflight_degraded` con `httpx` → `/usr/bin/httpx` y el comando de instalación; el run arrancó en modo degradado sólo por el flag del operador | se mantiene |
| **B5** (413/TPM) | **cero** errores 413 en todo el run con el mismo modelo y proveedor que murió en el run #2. Sin inmiscuirse: las iteraciones se espaciaron ~48 s (pacing de TPM=8000) y el techo de salida (`NEXUS_REACT_MAX_TOKENS=1536`) mantuvo la reserva dentro del presupuesto | arreglado |
| **B8.2.1** (aislamiento por run) | el run usó una conversación nueva y el blackboard del engagement como único canal compartido. Un solo objetivo, sin evidencia heredada | arreglado (tests) |
| **B8.2.2** (anti-`task_complete` prematuro) | el agente **no** declaró la tarea completa tras el recon: pidió ayuda en su lugar. El gate no tuvo que intervenir (no hubo `react.premature_completion`) | activo, sin disparar |
| **B8.2.3** (evidencia del run) | no hubo `task_complete`, así que no hubo findings que contrastar. El agente citó solo lo que había observado | activo, sin disparar |
| **B7** (leer loot) | el agente no llegó a descargar/leer (ver §5), pero la capacidad se verificó **contra el objetivo real** en §4 | implementado y verificado |

Gobernanza (sin cambios, comprobada): scope firmado aplicado (el engagement nuevo
es el único autorizado), `tool.invoke` auditado con `run_id` y secretos redactados,
`sandbox_for_environment` para todo proceso, fail-closed en el preflight,
anti-injection en el límite del modelo.

## 3. Cronología del run

```
13:11:01  run.preflight_degraded (httpx equivocado)  +  react.tool_unavailable (rg ausente)
13:11:01  orchestrator.subagent=recon  ·  orchestrator.plan: recon [0/6]
          it.1  tool_call nexus.recon.nmap {profile: full_tcp}      → 49,7 s  (3 puertos)
          it.2  tool_call nexus.recon.nmap {profile: service}       → 83,5 s  (vsftpd 3.0.5)
          it.3  tool_call nexus.knowledge.record_fact (service:21)  →  2,8 ms
                orchestrator.subagent=web · orchestrator.plan: enumeration [1/6]
          it.4  request_clarification  →  react.finished (web)
13:15:40  run.complete  status=clarification  iterations=4  duration=278,9 s
```

Observación de calidad: las tres acciones fueron **productivas y verificadas**
(`nmap_xml_parsed`, `blackboard_fact_recorded`); no hubo ni una llamada fallida, ni
un parse error, ni un fallo de herramienta. El run no murió: **pidió ayuda**.

## 4. Verificación directa de B7 contra el objetivo real

El agente no llegó a usar B7, así que se verificó la capacidad **contra
`10.0.0.1`** ejercitando los handlers durables reales (sandbox + script FTP
embebido), sin agente:

```
LIST verified=True method=ftp_listing_parsed      names: ['/locks.txt', '/task.txt']
DOWNLOAD task.txt  verified=True size=68  sha256=e979be8aedf0 preview_bytes=68  truncated=False
   preview: '1.) Protect Vicious.\n2.) Plan for Red Eye pickup on the moon.\n\n-lin\n'
READ ftp_run_.../task.txt verified=True method=workspace_read_sha256 sha256_match=True lines=5
DOWNLOAD locks.txt verified=True size=418 sha256=900a3254f2f7 preview_bytes=418 truncated=False
   preview: 'rEddrAGON\nReDdr4g0nSynd!cat3\nDr@gOn$yn9icat3\n...'
READ ftp_run_.../locks.txt verified=True method=workspace_read_sha256 sha256_match=True lines=27
```

Es decir: el `preview` viaja en el propio resultado del `download` (los datos que
importan — usuarios `lin` y la wordlist `locks.txt` — están ya en la primera
observación), y `nexus.workspace.read` devuelve el contenido con el **mismo
`sha256`** que reportó la descarga, confinado al workspace del engagement.
Salida completa: `docs/missions/examples/e2e-bounty-hacker-run3-b7-check.txt`.

## 5. Causa raíz del no-completado (P1)

**La consecuencia más importante del run está en el pensamiento de la iteración 4**
(`subagent_id=web`), reproducido literalmente del histórico NDJSON:

> "Necesito enumerar el FTP anónimo en el puerto 21, pero la herramienta necesaria
> (nmap con script ftp-anon) no pertenece al subconjunto de herramientas del
> subagente web activo. Solicito cambiar al subagente adecuado o autorización para
> usar la herramienta requerida."

El modelo está describiendo con precisión un problema **del sistema**, no suyo:

1. El recon registra un hecho `service` (`10.0.0.1:21`) → el planner considera
   cerrada la fase `recon` (`Phase.evidence = ("host", "service")`) y pasa a
   `enumeration`.
2. `PHASE_SUBAGENT["enumeration"] = "web"`. Pero `_refine()` solo promociona a
   `cred` cuando ya existen hechos `user`/`credential`, y a `web` cuando existen
   `endpoint`/`vulnerability`. Con **solo** un hecho `service` (FTP), la fase cae al
   perfil `web` por defecto.
3. El perfil `web` = `{httpx, gobuster, whatweb, nuclei, ffuf, dalfox}` + comunes.
   **No tiene `nexus.recon.ftp`** (está en `recon` y en `cred`), ni
   `nexus.cred.bruteforce`.
4. La cadena que el objetivo necesita (FTP anónimo → leer `task.txt`/`locks.txt` →
   `lin`/`locks.txt` → hydra SSH) queda **inalcanzable**: para enumerar FTP haría
   falta tener FTP, y para que el planner asigne `cred` haría falta un hecho `user`
   que solo se obtiene... enumerando FTP. **Dependencia circular.**

El sistema, además, le había instruido explícitamente que hiciera esto ("Si crees
necesitar una tool fuera de tu subconjunto, cierra la fase y explica qué falta en
vez de insistir"), así que el agente obedeció el frame: escaló. La elección de
`request_clarification` (en vez de `task_complete`-con-explicación) **termina** el
run y exige al operador retomarlo a mano.

Nota honesta: el puerto 80 también estaba abierto y el perfil `web` **sí** tenía
herramientas para él. El agente eligió la ruta correcta para la sala (FTP) y no
pivotó a la web; un modelo distinto podría haber seguido por el 80 y quedarse
igualmente lejos de `user.txt`/`root.txt`, porque la ruta de la sala pasa por FTP→SSH.

## 6. ¿Es el modelo, la arquitectura o el objetivo?

Análisis pedido por el encargo, con la evidencia del run:

- **¿El modelo?** **No (al menos no como causa principal).** `gpt-oss-120b` hizo tres
  acciones correctas y verificadas, eligió el escaneo completo (`-p-`) como pide la
  metodología, registró un hecho verificado, **no alucinó evidencia** (el defecto del
  run #2) y **no falseó un cierre** (no hubo `task_complete` prematuro). Ante un
  bloqueo real, se detuvo y explicó exactamente cuál era. Un modelo más capaz
  probablemente habría pivotado al puerto 80 o habría pedido el perfil correcto con
  más insistencia, pero **no podía** completar la cadena FTP con el subconjunto
  asignado.
- **¿La arquitectura?** **Sí, aquí está la causa.** El planner determinista y el mapa
  fase→perfil (`PHASE_SUBAGENT` + `_refine`) asumen que "enumeración" = "enumeración
  web". Con un objetivo cuyo primer servicio enumerable no es web (FTP, SMB, SSH,
  RDP), el frame no tiene ninguna ruta hacia los tools correspondientes. Además, el
  hecho `service` cierra `recon` *demasiado pronto*: en la misma iteración en que se
  registra un servicio, el agente pierde las herramientas de recon que aún necesitaba.
- **¿El objetivo?** **No.** "Bounty Hacker" es una de las salas de entrada de
  TryHackMe: FTP anónimo con pistas + hydra SSH + escalada `sudo tar`. La cadena es
  corta y está enteramente cubierta por tools ya existentes (`nexus.recon.ftp`,
  `nexus.workspace.read`, `nexus.cred.bruteforce`, `nexus.post.ssh_exec`,
  `nexus.post.privesc_hints`). No hay que cambiar de objetivo.

**Conclusión: es un bloqueante de arquitectura, no de modelo ni de objetivo.** El
endurecimiento del frame (3.6) funcionó: el sistema prefirió parar y preguntar antes
que inventar. Es exactamente el comportamiento diseñado — y ahora deja ver el
siguiente cuello de botella real.

## 7. Plan alternativo propuesto (no implementado: requiere decisión del operador)

Por instrucción del encargo, **no he seguido iterando**. Propongo, en orden de
coste/beneficio:

1. **P0 — Enumeración consciente del servicio (≈30-60 líneas, riesgo bajo).**
   Que el perfil de `enumeration` incluya la enumeración no-web: la opción mínima es
   añadir `nexus.recon.ftp` al perfil `web` (que en realidad es "enumeración") y
   renombrarlo; la opción correcta es un perfil nuevo `services`
   (`nexus.recon.ftp`, `nexus.recon.netexec`, scripts de nmap) elegido cuando el
   board tenga un hecho `service` que no sea http/https. Gobernanza intacta: es solo
   reducir/redirigir el subconjunto.
2. **P1 — No cerrar `recon` con el primer servicio (≈20 líneas).** `Phase.evidence`
   de `recon` no debería bastar con un `service` sin haber enumerado ese servicio;
   alternativa pragmática: mantener las tools de recon disponibles durante las dos
   primeras iteraciones de `enumeration` (subconjunto = unión fase actual ∪ fase
   anterior para tools de solo lectura).
3. **P2 — Que el bloqueo de subagente no termine el run (≈10 líneas + 1 flag).** El
   bucle ya acepta `payload["subagent"]` como pin del operador, pero la CLI no lo
   expone: añadir `--subagent <id>` permite retomar (`--resume <RUN_ID>`) con el
   perfil correcto sin tocar el frame. Alternativa: que el propio bucle, ante un
   tool denegado por subconjunto, cierre la fase y **avance el plan** de forma
   determinista en vez de esperar a un humano.
4. **P3 — Observabilidad**: exponer el subconjunto del subagente activo en el NDJSON
   (`orchestrator.subagent` ya lleva `subagent_id`; añadir `tools`). Habría hecho
   este diagnóstico visible en vivo.

Con P0+P2 (≈90 líneas, sin tocar gobernanza) considero **probable** que la sala se
complete con `gpt-oss-120b`; si no, el siguiente candidato es el modelo (Fase 4,
DeepSeek V4.1 Flash, ya preparado en B8.2.4).

## 8. Entregables y trazabilidad

- NDJSON crudo del run: `docs/missions/examples/e2e-bounty-hacker-run3.ndjson`.
- Verificación de B7 contra el objetivo: `docs/missions/examples/e2e-bounty-hacker-run3-b7-check.txt`.
- Fase: `docs/missions/FASE36_CLOSE_E2E.md` (§9 resumen, §10 desviaciones).
- Runs anteriores: `TEST_E2E_BOUNTY_HACKER.md` (#1, B1-B4), `TEST_E2E_BOUNTY_HACKER_RUN2.md` (#2, B5-B8).

## 9. Limitaciones declaradas

1. El run **no completó** la sala: `user.txt` y `root.txt` no se obtuvieron.
2. El agente no llegó a ejercitar `nexus.workspace.read` ni `nexus.cred.bruteforce`
   en el run; B7 se verificó por separado contra el objetivo real (§4) y el resto por
   tests unitarios/de integración.
3. El TPM de Groq (8000) es el valor que el propio proveedor reportó en el 413 del
   run #2; se usa como referencia para espaciar peticiones, no como cuota
   consultada a la API.
4. Un único run por configuración: no se ha barrido `temperature` ni semillas
   (aparcado ya en BACKLOG).
5. El objetivo se alcanzó mediante una IP nueva; el engagement antiguo
   (`eng-923f594ec3da`) queda como archivo, no se amplió su scope.

## 10. Atribución

BAJIOWARE · Team Red. Fase 3.6, rama `feat/close-e2e-phase-3-6`.
