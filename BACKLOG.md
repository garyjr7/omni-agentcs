# Deuda explícita después de Fase 0

La implementación de Fase 0 se limita a las cinco grietas P0. El backlog
histórico se conserva en [docs/missions/BACKLOG.md](docs/missions/BACKLOG.md).
Estas P1 no se presentan como garantías disponibles:

| Prioridad / ID de auditoría | Trabajo pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| P1-A · A-01 | Completar journal durable por paso/intento y reconciliación tras crash | Fase 2 parcial ya registra prepared/running/succeeded/unknown y bloquea unknown no idempotente; identidad por hash no distingue toda intención, resume CLI y fencing de lease pendientes. **No** exactly-once. | Estado reservado/ejecutando/observado/reconciliado y pruebas de caída en cada frontera; ningún replay automático de efectos desconocidos. |
| P1-B · P2-3 | `oci_network` con egress validado por scope | El modo sigue indisponible y falla explícitamente. `oci` no tiene red; local no aísla egress. | Pruebas reales de rutas permitidas/denegadas, DNS/rebinding, IPv4/IPv6, cierre y cleanup sin degradación a local. |
| P1-C · A-05 | Sustituir el validador subset del gateway por JSON Schema completo | `minimum`, `maximum`, `pattern` y otras restricciones siguen sin validarse universalmente en entradas de herramientas. Los checks específicos de handlers siguen vigentes. | Suite por dialecto y constraints, errores compatibles, tratamiento explícito de `$ref`; no añadir dependencias sin autorización. MCP ya trae `jsonschema` transitivamente, utilizado para validar su outputSchema. |

Estimación orientativa: P1-A 3–5 días; P1-B 5–8 días; P1-C 1–2 días más
regresiones. Son trabajos separados, en ese orden, no parte del cierre P0.

## Límites explícitos del verificador

La promoción de hechos requiere un parser determinista específico. Una tool
sin parser semántico continúa devolviendo observaciones útiles, pero no puede
acreditar por sí sola una fase ni un hallazgo confirmado. Ampliar cobertura de
parsers exige casos positivos y negativos por tipo; no se permite volver a
confiar en `verified` o `source` proporcionados por el modelo.

Un outputSchema MCP describe estructura, no demuestra que un efecto remoto
ocurrió. Mantener `mcp_unverified` hasta disponer de un verificador independiente
es deliberado. La declaración de efectos del operador no es una barrera de
seguridad del sistema operativo para un servidor stdio malicioso en modo local.


## Fase 1 · UX pendiente

| Prioridad / ID | Pendiente e impacto | Criterio de cierre |
| --- | --- | --- |
| P1-UX-6 · U-05 | Transcript conserva todos los bloques y cola sin backpressure. El pegado compacto no limita la memoria de sesiones largas. La medición offline de 10.000 eventos retuvo 10.000 segmentos (~26,6 MB de pico trazado; ~1,539 s en la revisión final de este entorno). | Paginación de bloques a disco, ventana visible e índice/cola acotados; prueba de productor más rápido que renderer; medir memoria y latencia antes de cambiar renderer. |
| P1-UX-7 · U-06 | No hay estados separados de «enviar al terminar» e «interrumpir con instrucción», editor externo ni navegación por teclado de tarjetas individuales. Las teclas F3–F7 cubren chips/tareas, no esas funciones. | Máquina de estados explícita, prioridad de instrucciones/cancelación, editor seguro y navegación de tarjetas con pruebas PTY y sin perder entradas. |
| P1-3 · O-03 | Integrar AgentSupervisor a cambios de fase y cuotas raíz durables. La API de Fase 2 crea conversaciones aisladas, pero no hay auto-spawn ni árbol global verificado. | Ciclo de vida durable de agentes, contexto y presupuestos separados, resultados atribuibles y cancelación/reanudación sin contaminación del principal. |
| Calidad · Tipado TUI | Mypy incremental sobre ocho módulos UX conserva 23 errores preexistentes en `session.py` (atributos del layout dinámico, opcionalidad y anotaciones). El check no pasa; no se añadieron supresiones. | Contrato tipado de construcción del layout y sesión, cero hallazgos en esos módulos y pruebas de interfaz completas sin debilitar controles. Evidencia: `docs/missions/evidence/phase1/typecheck.txt`. |
| U-03 · Telemetría | Ventana depende de configuración/metadato conocido; el conteo previo al response es estimado. El aviso al 80% no cambia los umbrales existentes de compactación; tasa oculta sin dato. | Descubrimiento confiable por despliegue, tokenizer/usage consistente y telemetría de límites del proveedor. Cambiar la política de compactación requiere otra misión del orquestador. |

P1-A/A-01, P1-B/P2-3 (`oci_network`) y P1-C/A-05 permanecen con los criterios
anteriores. No se amplió esta fase para declararlas resueltas.

## Fase 2 · Cierre

Los tres pendientes críticos quedan **cerrados** con un test de regresión por
bloque. El detalle está en `docs/missions/FASE2_ORQUESTACION_AVANZADA.md`
(sección «Cierre de Fase 2») y la evidencia en
`docs/missions/evidence/phase2-close/`. 52 tests nuevos; la suite queda en
**2421 passed, 36 skipped**.

| ID | Estado | Resultado |
| --- | --- | --- |
| P2-A1 | CERRADO | `omni hooks trust/list/revoke`; la aprobación vive FUERA del repo (`hooks-trust.json` en XDG, `path+sha256+tenant+operador+fecha`); un byte distinto revoca la confianza. |
| P2-A2 | CERRADO | `HookRunner` recibe workspace/engagement explícitos y los publica; REPL, headless y worker pasan el `project_root` del engagement (nunca el cwd). |
| P2-A3 | CERRADO | `run_react_loop` emite `session_end` una vez (`status=exception` ante fallo) y nunca oculta la excepción del motor. |
| P2-C1/C2 | CERRADO | `kernel_budget_reservations` + `BudgetLedger`; reserva **antes** del proveedor, falla cerrado con `BudgetExceeded`, `settle`/`release` durables; la cuota global es por árbol. |
| P2-C3 | CERRADO | Auto-spawn opt-in solo en cambio de familia de fase, con umbrales `NEXUS_AUTOSPAWN_MIN_BUDGET`/`_ITERATIONS`; `web→services` y fases cortas no spawnean. |
| P2-C4 | CERRADO | `AgentSupervisor.root` ancla el árbol en `kernel_supervisor_roots`; la raíz es durable, compartida y sobrevive reinicios; profundidad se evalúa contra el árbol. |
| P2-D1 | CERRADO | `step_key` derivada por el gateway (`tool+args+phase+objective`); la reutilización de `succeeded` exige misma intención. |
| P2-D2 | CERRADO | Fencing por `lease_id`: un worker vivo no se toca; la propia lease recuperada pasa a `unknown` (sin replay), auditado. |
| P2-D3 | CERRADO | `omni resume` lista `unknown`; `--retry` exige aprobación durable y `--skip` marca `failed`; headless `--resume-policy approve\|skip\|fail`. |
| P2-D4 | CERRADO | `result_ref` = `artifact_id\|sha256` del `LocalArtifactStore`, con verificación de integridad al releer. |
| P2-D5 | CERRADO | Journal verificado contra PostgreSQL 18.6 real (esquema aislado): transiciones, migración aditiva, fencing y concurrencia. |

### Fase 2 · Límites que siguen abiertos (honestidad)

| ID | Pendiente | Criterio de cierre |
| --- | --- | --- |
| P2-A/B · OCI | Hooks/workspace se cierran a nivel de proceso; no se ejecutó un contenedor OCI real y `local_strict` no aísla host/red. | Procesos reales por las rutas del operador dentro de OCI, con egress validado por scope; sin degradar a local. |
| P2-D · FTP/efectos | Idempotencia FTP por operación y clasificación `failed` solo con ausencia de efecto **comprobada** (el skip actual es una aserción del operador). | Detectores deterministas por operación y reanudación GUI/headless que no dependan de la palabra del operador. |
| Global · exactly-once | No se promete exactly-once remoto; el journal evita replay automático y el fencing evita doble worker, pero no es una garantía distribuida. | Diseño distribuido explícito solo si un cliente lo exige; hoy no es requisito. |

Nota de cierre: la reserva es una estimación (chars/4) y es fail-closed a
propósito; un presupuesto global pequeño puede rechazar un request barato. La
deuda de tipado TUI de Fase 1 sigue vigente y no se presentan los tests verdes
como tipado estricto.

## Fase V0 · Validación con salas (deudas de RUN_sala02 · RootMe)

La sala #2 se completó con `omni tool` (ver `docs/missions/salas/RUN_sala02.md`).
Deudas concretas detectadas midiendo el motor:

| ID | Pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| V0-1 · Wordlists | `DEFAULT_SYSTEM_WORDLIST_DIRS` (`ffuf.py`) no incluye `/usr/share/dirbuster/wordlists`, y el symlink `/usr/share/wordlists/dirbuster` escapa del root resuelto. | gobuster/ffuf rechazan la wordlist estándar de dirbuster; hay que saber usar `/usr/share/dirb/wordlists/common.txt`. | Añadir el dir por defecto o resolver el symlink antes del `_inside`; prueba de path real de Kali + negatives. |
| V0-2 · Verificador de loot | No hay parser determinista que promueva hechos `loot`/`access`/`privilege`; quedan `asserted_by=agent`. | Los flags capturados salen como **hypothesis** en el reporte aunque el operador los verificó. | Parser determinista por tipo (p. ej. regex de flag + ubicación) que acredite el hallazgo; casos positivos/negativos. |
| V0-3 · Interacción post-explotación | **Parcialmente cerrado**: `nexus.post.listener` (HIGH, engagement-scoped, valida el peer contra el scope firmado, guarda transcripción+sha256 en el workspace) cubre un catch reverse-shell gobernado sin MSF. Falta `nexus.post.webshell_exec` de primera clase y una sesión interactiva multi-paso (hoy es un catch por vez). | Footholds con canal inverso ya son gobernados; el webshell sigue siendo una petición por comando. | `nexus.post.webshell_exec`/session manager con scope+auditoría; pruebas de reconexión. |
| V0-4 · Entorno MSF | **Cerrado**: `msfrpcd` operativo y verificado (`scripts/msf_verify.py`, core 6.5.3-dev). Pendiente menor: el instalador de servicio asume `/opt/metasploit-framework` (no el paquete apt de Kali). | Rutas MSF usables. | Preflight que valide el RPC o falle con mensaje accionable; installer compatible con apt. |
| V0-6 · Dump de `.git` | No hay `nexus.recon.git_dump` ni parser de git/index; en Sala #3 se hizo a mano (HTTP + `save_path` + zlib). | Exposición de `.git` se explota con pasos manuales, no gobernados de punta a punta. | Handler que recorre HEAD/refs/objects/packs y reconstruye con `git checkout`; parser de index; tests. |
| V0-5 · SARIF | `nexus.report.generate` con `format:both` reporta `sarif_size_bytes` > 0 pero `report_path_sarif` vacío y no escribe el `.sarif`. | Un consumidor de SARIF recibe ruta vacía y el archivo no existe. | Escribir el `.sarif` cuando se computa, o no reportar su tamaño; test de artifact existente. |

Cerradas en este run (no quedan como deuda): subida multipart con campos de
formulario (`nexus.web.request`), vector SUID de python en `privesc_hints`, y
lentitud de nmap (`-n` por perfil + `--min-rate`).

## Fase V0 · Validación con salas (deudas de RUN_sala04 · NahamStore)

Sala #4 **cerrada** con las 8 familias de bug explotadas (ver
`docs/missions/salas/RUN_sala04.md`). Deudas nuevas:

| ID | Pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| V0-7 · `Host` en recon | **Parcialmente cerrado**: `nexus.web.ffuf` ya acepta un `Host` estático en scope (además de la plantilla `FUZZ`) y admite subdominios de un dominio autorizado. Sigue faltando lo mismo en `gobuster` (modo vhost devuelve 0) y el CLI de scope rechaza `*.dominio`. | Enumerar contenido/vhosts sin DNS ya es posible con ffuf; gobuster no. | `--header`/vhost gobernado en gobuster; scope que acepte wildcards con validación de resolución. |
| V0-9 · Ejecución masiva de `omni` | Lanzar N procesos `omni` en paralelo (p. ej. 40 en un barrido SSRF) satura la CPU y congeló la máquina. Además, apuntar el SSRF al propio `localhost` de una app de un solo worker la deja en **deadlock** ~25 min. | Riesgo de tumbar el host del operador y la instancia objetivo. | Un cliente/cliente-batch que evite el arranque por petición (o un runner in-process) y una guía de concurrencia por tool; pruebas de carga. |
| V0-10 · DAST web (descubrimiento) | El motor no cubre XSS/SQLi/LFI/SSRF/XXE de forma automatizada. `super_scanner` (`/home/operator/super_scanner`) es un DAST modular con payloads, colaborador OOB local, DB CVE offline y SARIF; **probado contra el objetivo**: funciona, pero su *crawl* (Playwright) no acepta `Host` fijo (no ataca vhosts sin DNS), la `probe` excede el tiempo y su modelo es detectar/confirmar, no explotar. | Las salas web se resuelven a mano; sin verificación automatizada de clases de bug. | Tool gobernada `nexus.web.dast` que envuelva `super_scanner active-test/probe` con scope+sandbox+parser determinista y mapeo a `vulnerability`, **tras** arreglar el `Host` del crawl. |
| V0-11 · Explotación web gobernada | No hay tools de explotación: la sala #4 se explotó a mano (dump de BD, exfiltración, shells, XXE ciego). Faltan wrappers gobernados y un colaborador OOB propio. | Sin `sqlmap`/`dalfox`/`nuclei`/OOB, el agente no cierra clases de bug por sí solo. | `nexus.web.sqlmap` (SQLi), `nexus.web.dalfox` (XSS), `nexus.oob` (XXE/SSRF ciego con parser determinista) con scope, sandbox y casos positivos/negativos. |

## Fase V0 · Validación con salas (deudas de RUN_sala05 · Relevant/Windows)

Sala #5 **cerrada** (Windows Server 2016 / IIS; `user.txt` + `root.txt` por
explotación; 3 rutas a SYSTEM). Ver `docs/missions/salas/RUN_sala05.md`.
Engagement `eng-1faa46a8cc15`; **rehecha de punta a punta con `omni tool`** tras
añadir `nexus.recon.smb` y `nexus.post.smb_upload` (una primera pasada se hizo
con herramientas del sistema — error de proceso, corregido).

| ID | Pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| V0-12 · Cadena de ataque multi-paso | El motor resuelve **un vector a la vez**: no hay un planificador que (1) enumere, (2) puntúe vectores, (3) explote, (4) escale **y** (5) busque rutas alternativas encadenando las observaciones de cada fase. En sala #5 convivían un share SMB→webshell, `SeImpersonate`, un directorio escribible ejecutado como SYSTEM y MS17-010: el agente debía **elegir y encadenar**, no quedarse en el primer bug. | Las máquinas con más de un camino a root se resuelven manualmente y el agente se estanca en el primer hallazgo. | Orquestador de **kill-chain** con estados por vector (descubierto → probado → explotado / descartado), reutilización de credenciales/loot entre fases, y un *priority queue* que no cierre el engagement al primer éxito sino que enumere los demás caminos. Casos de prueba con una máquina de 3 rutas (como esta). |
| V0-13 · Post-explotación Windows gobernada | No hay `nexus.post.webshell_exec` interactivo (sigue V0-3), ni handlers de **escalada Windows** (`SeImpersonate`/Potato, permisos de directorio ejecutado como SYSTEM, `MS17-010`), ni captura de flags por parser determinista en Windows (`user.txt`/`root.txt` salen como *hypothesis*). | Un host Windows requiere encadenar comandos a mano por el webshell y la escalada no es reproducible por el motor. | `nexus.post.webshell_exec` (sesión multi-comando, scope+auditoría), `nexus.win.privesc` (chequeos `whoami /priv`, ACLs escribibles + tareas SYSTEM, parches MS17-010) y `nexus.win.loot` (parser de flags + rutas estándar). |
| V0-14 · Recon SMB/AD gobernado | **Parcialmente cerrada**: `nexus.recon.smb` (shares/list/get) y `nexus.post.smb_upload` ya cubren el *foothold* de esta sala (enumerar, leer `passwords.txt`, subir el `.aspx`) con scope+audit. Queda el **cleanup** (`del`/útil de borrado gobernado) y el `--script smb-vuln-*` (detección de MS17-010 desde la tool). | El agente ya no necesita `smbclient` a mano para el ataque; sí para borrar artefactos. | Añadir `action=delete` (destructive, con aprobación) y detección de vulnerabilidades SMB en la tool. |
| V0-15 · Binarios de explotación | `PrintSpoofer64.exe` se descargó de GitHub en tiempo de ejecución; `JuicyPotato` fue **eliminado por Defender**. No hay un catálogo local versionado/verificado de binarios de escalada ni manejo de la cuarentena del AV. | Dependencia de descarga en vivo, sin *hash*/procedencia y sin alternativa cuando el AV borra el binario. | Catálogo con *hash* y selección por versión de Windows; fallback entre técnicas (PrintSpoofer/GodPotato/RoguePotato); detección de cuarentena y reintento. |
| V0-16 · `nexus.recon.netexec` no verifica | En esta sala `nexus.recon.netexec` (fingerprint/manet SMB) falló la post-condición (`netexec_text_parsed`, exit fuera de {0,1}, salida no parseable) aunque `nxc` está presente y responde por `smbclient`/impacket. | La enumeración SMB/AD con NetExec no es fiable en Windows/EC2; el operador cae en `nexus.recon.smb`. | Diagnóstico del *exit code*/salida real de `nxc` en este entorno y ajuste del contrato de verificación (o fallo explícito con mensaje accionable). |

## Fase V0 · Validación con salas (deudas de RUN_sala06 · ret2libc / Pwn)

Sala #6 **cerrada** (Ubuntu 20.04; `exploit_me` setuid con `gets()`; ret2libc
para saltar ASLR). Ver `docs/missions/salas/RUN_sala06.md`. Engagement
`eng-117ca97cb4ec`. Es la primera sala **de caja blanca** (credenciales SSH
del cliente) y la primera de explotación de binarios: se añadieron
`nexus.pwn.analyze` y `nexus.pwn.ret2libc` (catálogo 47 → 49).

| ID | Pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| V0-17 · Pwn multiformato/defensas | El analizador cubre solo **ELF64 x86-64**. No hay ARM/ELF32, `one_gadget`, **bypass de canary**, de **PIE** (leak + partial overwrite) ni *format-string*. | Un binario con canary/PIE completo o de otra arquitectura no se resuelve solo con `nexus.pwn.ret2libc`. | Soporte ARM/ELF32, detección de canary/PIE con estrategia de bypass y `format-string` como vector de primera clase, con casos positivos/negativos. |
| V0-18 · Detección de offset | El offset del desbordamiento se infiere del patrón `lea rax,[rbp-disp]` antes de un `call gets@plt`. Otro compilador (`strcpy`, `read`, `scanf`, buffer en otro registro) no se detecta. | `nexus.pwn.ret2libc` puede no auto-resolver en binarios distintos y exige las constantes a mano. | Detección genérica de buffers en pila (o patrón cíclico ejecutado en el objetivo) y soporte de `strcpy`/`read`/`scanf`; pruebas con varios binarios. |
| V0-19 · Comando plantado | La explotación usa `gets(<writable>)` + `system(<comando>)` (canal no-TTY). Depende de que exista un segmento escribible y de la dirección de `.bss`. | Un binario sin región escribible útil o con binario PIE no tiene dónde plantar el comando. | Alternativa con shell interactiva sobre PTY cuando el canal lo permita, o `execve` con argv construido sin depender de `gets`. |
| V0-2/V0-13 · Verificador de loot (Linux pwn) | **Parcialmente cerrado**: `derive_assertions` ya promueve `privilege {uid:0}` y `loot` (flag) desde `nexus.pwn.ret2libc` con `asserted_by=verifier`. Sigue pendiente el parser de loot de Windows (V0-13). | En pwn, el `uid=0` y la flag dejan de ser `asserted_by=agent`. | Parser por tipo para Windows (`user.txt`/`root.txt`) y para rutas de loot arbitrarias. |
