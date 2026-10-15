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
| V0-29 · Detección de canary rota (bug medido en la puerta de lint) | `ruff check nexus_core omni.py nexus_worker.py --select F,E9` está **rojo en HEAD** con 4 hallazgos que **no** introduce este run: `_pwn.py:164 F841` (`canary = True` dentro de `_parse_symtab` asigna una variable **local** —falta `nonlocal`— y además la rama queda **detrás** del `continue` de símbolos indefinidos, así que `out["canary"]` es siempre `False`), `pwn.py:28 F401` (`re` sin usar), `smb.py:27 F401` y `test_smb_handler.py:99 F541`. | `nexus.pwn.analyze` puede reportar un binario con `__stack_chk_fail` como **sin canary** y llevar a una estrategia de explotación equivocada; el gate de lint está rojo y nadie lo mira. | Comprobar `__stack_chk_fail` **antes** del `continue` + `nonlocal`, limpiar los 3 restos, `make lint` verde y un test con un binario que tenga canary (la suite actual de 2563 no lo cubre). |

## Fase V0 · Validación con salas (deudas de RUN_sala07 · Internal / pivote interno)

Sala #7 **cerrada** (Ubuntu 20.04; WordPress 5.4.2 → `www-data` → `aubreanna` →
Jenkins en `127.0.0.1:8080` → `root`). Ver `docs/missions/salas/RUN_sala07.md`.
Engagement `eng-ed4eb06d55c4`. Se añadieron `nexus.post.pivot_bruteforce` y
`nexus.post.pivot_http` (catálogo 52 → 54) y se corrigió el transporte de
`nexus.web.wp_bruteforce`.

| ID | Pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| V0-20 · Sesión de pivote durable | Cada llamada al pivote repite *warm-up* + login (medido ≈4,6 s por petición en Jenkins) y solo habla **HTTP**. No hay handle de sesión reutilizable entre llamadas ni pivote a otros protocolos internos (SMB/MySQL/Redis en `127.0.0.1`). | Un flujo interno de N pasos paga N logins; un servicio interno que no sea HTTP no se alcanza. | Handle de sesión de pivote (crear/usar/cerrar) con cookie+token persistidos y expiración, más transporte de al menos un protocolo no-HTTP; pruebas de reutilización y de cierre. |
| V0-21 · Transferencia de ficheros por el pivote | `nexus.post.pivot_http` solo devuelve un cuerpo acotado (`max_body_bytes`); no hay *download*/*upload* a través del host interno (leer un binario, exfiltrar un fichero grande o subir un artefacto a un servicio interno). | El operador no puede sacar artefactos del segmento interno ni alimentar una tool que necesite fichero. | `nexus.post.pivot_transfer` (get/put por SFTP local vía el host autorizado) con límites, hash de integridad y limpieza de artefactos. |
| V0-22 · Vocabulario de post-condición en fuerza bruta | **CERRADA (2026-10-15)**: un barrido agotado sin acierto **completa** con `outcome=negative` (contrato de V0-22 en `kernel/models.py` + `kernel/tool_gateway.py`) en lugar de elevar `RuntimeError`, no deriva ninguna aserción y conserva en `evidence` los datos que se perdían (`tested`/`total`, `credentials_found=0` y el motivo). El vocabulario vive en `outcome` (`negative`/`denied`/`unsupported`), **no** en el nombre del método: `wp_credential_validated` se mantiene tal cual, por decisión del operador (2026-10-15). Fijada por `test_negative_outcomes_v0_22_31_36_38.py::test_wp_bruteforce_exhausted_sweep_completes_as_negative` (positivo: `::test_wp_bruteforce_validated_credential_is_verified`). | Un barrido sin acierto ya no retira la tool de la fase: queda como resultado negativo contabilizado. | Cumplido: negativo declarado (`negative`, sin aserciones) y positivo (`credential` + `access` en `derive_assertions`), con un caso de cada tipo. |
| V0-24 · Extracción de loot desde cuerpos HTTP | El verificador promueve `credential`/`access` del pivote, pero **no** extrae credenciales ni flags que aparezcan *dentro* de un cuerpo HTTP (`/opt/note.txt` lo leyó el operador; el verificador solo acredita el uso posterior por SSH). | Un loot leído de un servicio interno queda `asserted_by=agent` hasta que otra tool lo usa; una flag en un cuerpo HTTP no se promueve sola. | Parser determinista de loot para cuerpos de texto (`user:pass`, `flag{fake_flag}`) con reglas estrictas y casos positivos/negativos, integrado en `derive_assertions`. |

## Fase V0 · Validación con salas (deudas de RUN_sala08 · Frankesqwen / LLM local)

Sala #8 **cerrada** (Ubuntu 24.04; **caja blanca**; el objetivo era **extraer una
bandera memorizada en un LLM local**, no escalar privilegios). Ver
`docs/missions/salas/RUN_sala08.md`. Engagement `eng-627f37a6508c`. **Sin cambios
de código en el motor**: se usaron tools existentes (`nexus.post.ssh_exec`,
`nexus.recon.nmap`, `nexus.post.enum_system`, `nexus.web.request`) y las
carencias medidas quedan aquí, no como supuestos.

| ID | Pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| V0-25 · Consulta gobernada de modelos locales (LLM) | No hay tool para cargar/consultar un modelo Hugging Face **local en el objetivo**: la sala se resolvió con `nexus.post.ssh_exec` + un script `transformers` ad-hoc (modos `chat` y *raw completion*), sin schema, límites ni parser. | Un reto de *AI data extraction* no se cubre con el catálogo de tools; el operador escribe y ejecuta código a mano en el objetivo. | `nexus.ai.model_prompt` (ruta local `local_files_only`, modo `chat`/`raw`, lista de prompts, `max_new_tokens` acotado, CPU, salida confinada al workspace, HIGH) con scope+sandbox y casos positivos/negativos. |
| V0-26 · Artefactos desde el objetivo | El modelo (1,9 GB) vive en el objetivo y no hay tool para traerlo: cada sonda obliga a ejecutar *dentro* del host (relacionado con V0-21). | No se puede analizar el artefacto fuera del objetivo ni reutilizarlo entre salas. | `nexus.post.fetch` (descarga con `sha256`, límite de tamaño, confinada al workspace) y su reutilización por V0-25. |
| V0-27 · Loot en texto libre **no fiable** | La bandera aparece **dentro** de la respuesta de un LLM; ningún parser determinista la promueve, así que queda fuera de los hallazgos acreditados. Un LLM puede alucinar: promover texto generado sin más sería un falso positivo estructural. | La captura central de la sala no se acredita sola (sale solo como salida de tool). | Parser de loot de texto plano (regex estricta por formato, p. ej. `flag{fake_flag}`, `user:pass`) que exija **reproducibilidad** (≥2 prompts/muestras coincidentes) o la evidencia cruda adjunta, con casos positivos y negativos explícitos. |
| V0-28 · `ssh_exec`: timeout reportado como denegación + huérfanos | 9 de 117 invocaciones terminaron en `RuntimeError` y el wrapper devolvió `status=denied_or_failed` con resultado `null` y sin motivo; el proceso remoto **siguió vivo** (varios `python /tmp/ask_v7*.py` compitiendo por CPU hasta matarlos a mano). | El operador no distingue «denegado por política» de «se agotó el tiempo» y no puede cancelar el efecto remoto; quedan cargas de CPU huérfanas en el objetivo. | Clasificar timeout y fallo por separado, devolver el motivo y un identificador de cancelación, y terminar el grupo de procesos del sandbox al vencer (o documentar el canal de cancelación); prueba con un comando que excede el límite. |

Nota: `V0-5` (SARIF) **se reproduce** en esta sala — `sarif_size_bytes=17.321`
con `report_path_sarif` vacío — y sigue abierta.

## Fase V0 · Validación con salas (deudas de RUN_sala09 · WindCorp / AD)

Sala #9 **cerrada** (Windows Server 2019 · DC `FIRE` de `windcorp.thm`; web de
*password reset* → Openfire → NetNTLM de `buse` → WinRM → Account Operators →
`hosts.txt` → tarea SYSTEM → `tom` *domain admin*; 3 banderas). Ver
`docs/missions/salas/RUN_sala09.md`. Engagement `eng-059e4da8e9bc`. Se añadieron
`nexus.post.ntlm_capture` y `nexus.win.winrm_exec` (catálogo 54 → 56) y una rama
del verificador para `winrm_exec`.

| ID | Pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| V0-2/V0-13 · Verificador de loot (Windows) | **Parcialmente cerrado**: `derive_assertions` promueve `access`, `privilege` (dominio, desde `net (local)group <grupo admin> /domain` o un `whoami` que nombre grupo/SID administrativo) y `loot` (solo desde la lectura literal de **un** fichero) de `nexus.win.winrm_exec`. Con eso, los dos `domain-admin` y las 3 banderas pasan a `confirmed_finding` (10 tests nuevos). Sigue pendiente el loot que sale de un **bucle** (`Get-ChildItem … \| ForEach-Object { Get-Content $_.FullName }`, la forma que dio la bandera 3 en la primera pasada). | El *domain admin* y las banderas de un Windows ya se acreditan solos; una lectura envuelta en bucle queda en hipótesis. | Parser de loot por ruta cuando el comando enumera y lee (con atribución explícita de la ruta) o `nexus.win.loot` dedicada (V0-13). |
| V0-30 · Loot desde SMB y `workspace.read` | `nexus.recon.smb` en `get` devuelve `sha256` + `preview` y `smb_download_verified`, pero el verificador **no** promueve la bandera del fichero descargado; tampoco `nexus.workspace.read`. En esta sala las 3 banderas se bajaron por SMB (02:06:13, 02:51:42, 02:51:45) y solo se acreditaron al repetir la lectura por WinRM. | Una bandera obtenida por SMB queda en hipótesis hasta que otra tool distinta la vuelva a leer. | Rama `smb_download_verified` → `loot` con la ruta remota como clave, sha256 del fichero en el valor y casos positivos/negativos (fichero que *menciona* una bandera vs. fichero que *es* el loot). Depende de V0-33 para no duplicar claves. |
| V0-31 · Vocabulario de post-condición en SMB/AD | **CERRADA (2026-10-15)**: en `nexus.recon.smb`, listar una ruta que no existe completa con `outcome=unsupported` (`NT_STATUS_OBJECT_NAME_NOT_FOUND`) y una denegación con `outcome=denied`, sin `RuntimeError`, con `count`/`remote_path`/`nt_status` en la evidencia. En `nexus.recon.netexec`, el handler clasifica ahora la respuesta determinada que `nxc` imprime cuando cierra con un código fuera de `{0,1}` — medido en RUN_sala10: `0xc0000022`, `STATUS_USER_SESSION_DELETED`, `operationsError` ("bind must be completed") → `denied`/`unsupported` — y deja el token en `evidence.nt_status` con su `reason`; un token que el vocabulario no cubre **sigue fallando cerrado**. Fijada por `test_negative_outcomes_v0_22_31_36_38.py::test_smb_path_that_does_not_exist_completes_as_unsupported`, `::test_netexec_denied_answer_completes_as_denied`, `::test_netexec_ldap_bind_required_completes_as_denied` y `::test_netexec_unclassified_answer_still_fails_closed` (positivos: `::test_smb_share_listing_is_verified`, `::test_netexec_positive_run_is_verified`). | Un barrido de rutas produce un mapa de lo que hay y lo que no, contabilizado como resultado en vez de como fallo de motor. | Cumplido: `denied`/`unsupported` para el negativo, `netexec_text_parsed` para el positivo y el fail-closed documentado con su test. |
| V0-32 · Render del reporte: lista de `run_id` | «Alcance» imprime **todos** los `run_id` del engagement (≈133 en una sesión de 69 min) en una sola línea; `report.md` = 1.221.960 B y `report.html` = 1.940.383 B, dominados por ids. | El entregable al cliente es inmanejable y el tamaño crece linealmente con las llamadas, no con los hallazgos. | Resumen acotado (N ids + «y M más») o el propio `run_id` fuera del documento; test de tamaño con un engagement de >100 runs. |
| V0-33 · El blackboard no superpone hechos | `Blackboard.record` crea un documento nuevo por `(fact_type, key)`: cuando el verificador acredita el mismo hallazgo con **su** clave, la hipótesis del operador sobrevive con **otra** y el reporte lista el mismo dato dos veces (3 banderas + 2 `domain-admin` duplicados en esta sala). No hay operación de retirar ni de *supersede*. | El reporte infla hallazgos duplicados y no queda claro cuál es la versión acreditada. | Relación explícita entre un hecho acreditado y la hipótesis que lo anticipaba (o clave canónica compartida) con migración aditiva y test de no duplicación. |

Nota: `V0-5` (SARIF) **se reproduce** también aquí (`format=both` no escribe el
`.sarif` y reporta `sarif_size_bytes` > 0). `V0-12` (kill-chain) es el patrón
medido de esta sala: cinco saltos encadenados uno por **llamada**, sin planificador
que reutilice credenciales ni puntúe vectores.

Bug propio medido y **corregido** en esta sala (no queda como deuda): el catcher
`nexus.post.ntlm_capture` devolvía `status="no_ntlm"` **junto a** `captured=true`
porque etiquetaba el estado por conexión y ganaba la última (una sonda previa al
handshake). El estado es ahora monótono (`ok` → `challenged` → `captured`) y un test
ejecuta el **script realmente embarcado** (subprocess + handshake NTLM sintético):
`test_shipped_catcher_labels_a_probe_then_handshake_as_captured`.

## Fase V0 · Validación con salas (deudas de RUN_sala10 · RA2 / WindCorp)

Sala #10 **cerrada** (caja negra: `10.64.147.184` = FIRE, DC de `windcorp.thm`, 23
puertos, **sin WinRM**, IIS HTTPS autofirmado, Openfire 4.5.1, XMPP real y SOCKS5 sin
autenticación en `:7777`; después, **pase con credenciales Ra 2**). Ver
`docs/missions/salas/RUN_sala10.md`. Engagement `eng-ca20df309205`. **3 flags**: 1 por
**DNS TXT** (acreditada por el verificador, no tecleada) y 2 desde `C$` con
`smb_download_verified`. Seis cambios de motor aportados —TLS autofirmado, cookies de
sesión, la tool **`nexus.recon.dns`**, la tool **`nexus.post.dns_update`** (ADIDNS
gobernado), la tool **`nexus.attack.impacket_changepasswd`** (primitiva *Account
Operators*) y la tool **`nexus.attack.nopac`** (CVE-2021-42278/87 con cleanup
verificado)—, catálogo 56 → **60**, y **cinco deudas** (la última, V0-38, medida en el
pase con credenciales):

| ID | Pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| V0-34 · Tool DNS gobernada | **CERRADA**: `nexus.recon.dns` (consulta A/AAAA/CNAME/MX/NS/SOA/SRV/TXT/PTR/ANY por el sandbox, parser determinista de la sección ANSWER, `NXDOMAIN` como negativo válido, promoción a `loot` en `derive_assertions`; 19 tests) y **`nexus.post.dns_update`** (update dinámico RFC 2136 add/delete de UN registro, cliente embarcado porque el sandbox cierra `stdin`, post-condición = RCODE del servidor con id de transacción comprobado, apex de zona rechazado; 17 tests, 3 de ellos ejecutan el cliente real contra un servidor UDP local que guarda el paquete). Medido en el objetivo: `NOERROR` al crear, resolución verificada por la tool de consulta, borrado con cleanup verificado. | El vector que el TXT describe ya es gobernado (scope, aprobación, auditoría) y no depende de `nsupdate` a mano. El salto a *domain admin* no lo cierra el catálogo, sino el alcance (V0-37). | Cumplido: positivos (aceptado), negativos declarados (`refused`, `unanswered`), validación de nombre/tipo/apex y el invariante de *no-spawn*. |
| V0-35 · Tool XMPP gobernada | En sala09 el cebo NetNTLM por mensajería se hizo con `nexus.web.request` sobre **BOSH** (`:7070`). En esta sala BOSH **no está** (7070/7443 cerrados): el único canal es XMPP real (`5223/5262/5263/5269`) y ninguna tool lo habla. | Un objetivo sin BOSH no permite el cebo de captura NetNTLM, aunque el catcher (`nexus.post.ntlm_capture`) exista. | `nexus.post.xmpp` (login SASL PLAIN sobre TLS + envío de mensaje con marcador de éxito) con scope y casos positivos/negativos (credencial inválida). |
| V0-36 · Negativos legítimos elevados a fallo de motor | **CERRADA (2026-10-15)**: `nexus.recon.smb action=shares` sin shares completa con `outcome=negative` (`smb_shares_empty`, `count=0`, `nt_status=None`); `nexus.post.ntlm_capture` ya declaraba `negative` en `no_connection`/`no_hash`; y se extendió el mismo contrato al **otro catcher**, `nexus.post.listener`, cuyo `listener_no_connection` (el cebo se enlaza y nadie se conecta) completaba en `RuntimeError`: ahora completa con `outcome=negative` y `evidence` con `bound`/`listened_seconds`/`reason`. Un `listener_bind_failed` (no se pudo ofrecer el servicio) **sigue siendo un fallo del cuerpo**. Fijada por `test_negative_outcomes_v0_22_31_36_38.py::test_smb_empty_share_list_completes_as_negative` y `::test_listener_without_connection_completes_as_negative` (positivos: `::test_listener_catch_is_verified`; fail-closed: `::test_listener_bind_failure_still_fails_closed`). | La ausencia de acceso anónimo o de conexión al cebo queda registrada como resultado negativo con su motivo, no como fallo del motor. | Cumplido: `negative` para el cebo sin conexión y para el listado vacío, con casos positivos, negativos y de fallo real por handler. |
| V0-37 · El cebo ADIDNS provoca autenticación fuera del scope | En sala10, el envenenamiento ADIDNS gobernado (`nexus.post.dns_update`) hace que un host de la **red interna del DC** se autentique contra `nexus.post.ntlm_capture`; ese host está **fuera del `/32` firmado**, así que el catcher (correctamente) lo rechaza y la captura **nunca puede completarse** con este scope. Medido: `ntlm_capture_peer_out_of_scope`, y en una segunda ejecución el cebo ya no fue tomado (`connections=0`). **Acotada**: en el pase con credenciales el mismo cebo sobre `443` (WebDAV) **sí** capturó (peer dentro del `/32`) y, sobre todo, la sala ya no necesita ese vector: noPac escala desde cualquier usuario de dominio. | El vector que la sala nombra queda demostrado y gobernado; el pase de caja negra no se cerraba por una decisión de alcance, no por falta de tool. | Decidir el scope (incluir la red interna) o documentar el flujo del operador; el peer rechazado ya queda en la evidencia (§7.5 de RUN_sala10). |
| V0-38 · `bloodhound_python` sin salida se eleva a fallo de motor | **CERRADA (2026-10-15)**: el colector sin JSON completa con `outcome=negative` y registra el material recolectado de forma explícita (`evidence.collected=0`, `evidence.file_count=0`, `reason`, y `collected`/`file_count` también en el output) para que el reporte cuente el run como negativo en vez de perderlo en una excepción. El método se mantiene (`bloodhound_no_output`), por la misma decisión de vocabulario de V0-22; lo que faltaba era el dato, no el nombre. Fijada por `test_negative_outcomes_v0_22_31_36_38.py::test_bloodhound_without_output_completes_with_collected_zero` (positivo: `::test_bloodhound_collection_is_verified`). | El reporte distingue «no hay nada que colectar» (`collected=0`) de «la tool falló», y el perfil de reconocimiento no se retira de la fase. | Cumplido: `collected=0` explícito, negativo declarado y un test que fija que la rama vacía no es un fallo. |

Nota de este run: el gate `make lint` **no es ejecutable tal cual** en este entorno
(`make: ruff: No such file or directory`); el gate se corrió como
`.venv/bin/python -m ruff check … --select F,E9` → **mismos 4 hallazgos preexistentes**
de V0-29 (ninguno nuevo). Limpiar el gate (o documentar la invocación) queda como
tarea de mantenimiento, no como deuda de sala.

Bug propio medido y **corregido** en esta sala (no queda como deuda):
`nexus.web.request` **colapsaba las cabeceras repetidas** (un dict conserva solo la
última `Set-Cookie`), así que una respuesta de login que trae `JSESSIONID` **y**
`csrf` perdía el primero y **ninguna cadena multi-paso con sesión podía funcionar**
(el CVE de Openfire la exige). Ahora la tool expone `set_cookie: [...]` con todos los
valores y `evidence.set_cookie_count`; un test unitario y uno real (servidor local
que emite dos cookies) lo fijan. Igualmente corregido: **`insecure`** (opt-in por
petición para objetivos HTTPS con certificado autofirmado), con dos tests que
ejecutan el script embarcado contra un servidor TLS autofirmado local.

Dos defectos de **fidelidad de evidencia** medidos y **corregidos** en el cebo ADIDNS
(no quedan como deuda):

1. **El gateway descartaba la observación del handler al fallar la post-condición**
   (`kernel/tool_gateway.py`): el `RuntimeError` solo llevaba el `method` y el
   `tool.failed` solo `error_type`/`run_id`, así que un fallo quedaba sin causa
   observable — en la primera captura el catcher **sí sabía el host** que se autenticó y
   ese dato se perdía en la frontera. Ahora el error incluye el `output` redactado y
   acotado (≤480 chars) y el `tool.failed` persiste el mismo texto en `error`. 2 tests
   (`test_p1_observability.py`), incluido uno con 50 KB de output para fijar la cota.
2. **`nexus.post.ntlm_capture` confundía «nadie se conectó» con «rechacé un peer»**:
   ambos salían con `ntlm_capture_peer_out_of_scope` y el mismo mensaje, de modo que un
   run sin ninguna conexión era indistinguible de una denegación real. Se separaron
   (`ntlm_capture_no_connection` con `connections`/`status` en evidencia y output), con
   un test que fija que la rama «sin conexión» no consulta el scope.

### Pase con credenciales (Ra 2) — la sala se cierra

Cadena medida (todo gobernado salvo donde se indica): credencial de `edwardle`
capturada por el cebo **ADIDNS + WebDAV sobre 443** (peer **dentro** del `/32`) y
craqueada a `!Angelus25!` → enumeración SMB/LDAP con la tool → **primitiva Account
Operators** medida por LDAP (`edwardle` ∈ `IT` ∈ `Account Operators`; la víctima
`brittanycr` es **no protegida**: sin `memberOf` ni `adminCount`) → cebo de `hosts.txt`
en el home (subido y **releído** con sha256 idéntico) que **no dispara**: watchdog de
**40 ciclos** sin marcador y `Domain Admins` sigue siendo `{cert owner, Administrator}`
→ escalada a *domain admin* con **`nexus.attack.nopac`** verificada por DRSUAPI
(`nopac_domain_admin_dumped`, cuenta de máquina creada/renombrada/restaurada y
**borrada**; `ldapsearch "(sAMAccountName=OMNI*)"` devuelve **cero**) → loot con
pass-the-hash por SMB (`C$\flag2.txt`, `C$\flag3.txt`, `smb_download_verified` + sha256).

Evidencia nueva para las deudas abiertas: **13 `smb_listing_failed` + 2
`smb_shares_empty`** elevados a `RuntimeError` en este pase (V0-36 sigue siendo la
deuda más ruidosa) y 1 `bloodhound_no_output` (**V0-38**). Verificación del pase: suite
completa **2667 passed, 36 skipped, 0 failed**, `ruff check` **limpio** en los ficheros
nuevos y los **4 hallazgos preexistentes** de V0-29 sin cambios (comprobados contra
`HEAD`), catálogo **60** tools con el per-tool de siempre (195,7 chars/tool).

**Cierre del vocabulario (2026-10-15).** Las cuatro deudas de negativos legítimos
(V0-22, V0-31, V0-36 y V0-38) cierran juntas con el contrato ya commiteado en
`kernel/models.py` (`outcome`) y un fichero de tests nuevo que fija los dos casos por
handler: `nexus_core/tests/unit/test_negative_outcomes_v0_22_31_36_38.py`. Cambios de
motor de este cierre: `nexus.recon.netexec` (clasificación de la respuesta determinada
con exit fuera de `{0,1}`) y `nexus.post.listener` (`no_connection` → `negative`); en
`wp_bruteforce` y `bloodhound` solo se añade el dato que se perdía. `tool_gateway.py`
**no** se tocó. Verificación medida en este entorno: `pytest nexus_core/tests -q` →
**3112 passed, 53 skipped, 1 failed** preexistente (`test_ux_context`, TUI, ajeno a
estas deudas) y `ruff check nexus_core omni.py nexus_worker.py --select F,E9` → sin
hallazgos. `pytest -q` invocado desde la raíz **no** carga `nexus_core/tests/pytest.ini`
(por eso el modo `asyncio_mode=auto` no aplica y 129 tests async fallan con «async def
functions are not natively supported»): la invocación del gate es la de dentro del
árbol de tests.

## Fase V0 · Validación con salas (deudas de the synthetic run · the synthetic lab / WindCorp · endgame)

Sala #11 **cerrada** (caja negra: `10.66.173.92` = **the synthetic lab**, Windows 10 19041, unida
a `windcorp.thm`, **solo UDP/69 TFTP** — todos los TCP `filtered`; la entrada es un
*ducky* que se sube por TFTP y la víctima teclea ⇒ `alcrez`, y de ahí **SYSTEM** por
*unquoted service path* en el servicio `IVPN Client`). La **Flag 3** (KeePass/DPAPI de
`chajoh`) exigía el DC, así que se abrió un **segundo engagement firmado** que sí lo
incluye: escalada gobernada con `nexus.attack.nopac` y cadena DPAPI→KDBX verificada
offline. Ver `docs/missions/salas/the synthetic run.md`. Engagements `eng-e8074a112ecf`
(`the synthetic lab-osiris`) y `eng-da320a6df76f` (`the synthetic lab-flag3-dc`). **3 flags** (2 leídas en
disco + 1 en `Database.kdbx` de `chajoh`). **Dos cambios de motor** — **`nexus.post.tftp`**
(entrega de payload por TFTP, 19 tests) y **`nexus.post.dpapi`** (loot DPAPI/KeePass
offline, 26 tests + 1), catálogo 60 → **62** — que cierran la deuda medida en esta sala
(V0-39):

| ID | Pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| V0-39 · Loot DPAPI/KeePass sin tool gobernada | **CERRADA**: `nexus.post.dpapi` (`nexus_core/tools/handlers/dpapi.py` + cliente embarcado `nexus_core/tools/dpapi_client.py`, stdlib puro, **26 tests** + 1 que se omite cuando falta un lector de referencia). Offline, por el sandbox, `risk=MEDIUM`, `effect=credential_access`, `scope_required=False` (sin red: el dato ya está exfiltrado). Caso de aceptación = la cadena **real** de the synthetic run con los artefactos de `chajoh` (`ProtectedUserKey.bin`, `chajoh_masterkey.hex`, `Database.kdbx`): reproduce el material (sha256 `009e32…6c0d`) y la Flag 3, contrastado con **implementaciones de referencia** (dploot y pykeepass) cuando están presentes. El cliente se ejecuta como subprocess real (no se prueba contra sí mismo) y las primitivas se fijan contra vectores FIPS/eSTREAM. Catálogo 61 → **62**. | El loot final que vive en un almacén DPAPI (KeePass, Chrome, vault) queda **acreditado por el motor**: `verified` + promoción a `loot`/`credential` en `derive_assertions`, artefacto del material en el workspace gobernado y auditoría del paso. | Cumplido: `unwrap` prueba la **firma HMAC** del blob antes de devolver material (negativo declarado `dpapi_signature_invalid` con masterkey o entropía equivocadas); `open_kdbx` prueba `StreamStartBytes` y el hash de cada bloque (`kdbx_credentials_invalid` si el material no abre); los dos errores que costaron tiempo (entropía ausente, KDF con `master_seed`) son casos negativos; `test_definition_*` y el invariante de *no-spawn* (`asyncio.create_subprocess_exec` prohibido en el handler). |

## Fase V0 · Validación con salas (deudas de RUN_sala12 · Intrusion Detection / `idsevasion`)

Sala #12 **cerrada** (guía + CTF con **dos IDS reales evaluando el run**): `10.64.182.188`
= Ubuntu `reversegear` con 22 SSH, 80 Apache, **3000 Grafana 8.2.5** y **8000 CTFScore**
(el evaluador que puntúa cada alerta en vivo), más **Suricata** (NIDS) y **Wazuh** (HIDS
en el host con FIM sobre `/etc`). Cadena: LFI de Grafana (`CVE-2021-43798`) →
`grafana-admin:GraphingTheWorld32` → SSH (`grafana-admin` ∈ grupo `docker`) → *PE-assist*
subido con la tool nueva (el objetivo **no tiene salida a Internet**) → `docker run -v /:/mnt`
+ regla en `sudoers` → **`uid=0`** → flag `/root/root.txt` = `{SNEAK_ATTACK_CRITICAL}`, y
persistencia por `docker-compose` (`restart: always`) capturada con `nexus.post.listener`
y **retirada** después (lab restaurado y verificado). Ver `docs/missions/salas/RUN_sala12.md`.
Engagement `eng-7247bd3abc1e` (`sala12-idsevasion`). **Dos cambios de motor** —
**`nexus.post.ssh_upload`** (SFTP del workspace al objetivo, 8 tests) y **`nexus.recon.nikto`**
(escaneo web con `-Tuning`/`-evasion`/`-Pause` validados, 13 tests + parser), catálogo
62 → **64** — que cierran la deuda medida en esta sala (V0-40/V0-41):

| ID | Pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| V0-40 · Colocar un fichero en un host Linux sin salida a Internet | **CERRADA**: `nexus.post.ssh_upload` (modo `upload` del cliente paramiko de `ssh_post.py`). `risk=MEDIUM`, `effect=exploit`, `scope_required=True`, sandbox+audit; origen confinado al workspace (`resolve_workspace_path`), destino sin traversal, `file_mode` octal y `make_dirs`. **Post-condición real**: el cliente **relee el fichero remoto por SFTP y hashea en el objetivo**; el handler compara con el sha256 local (`ssh_upload_hash_mismatch` es el negativo declarado). Caso de aceptación = esta sala: `linpeas.sh` (1.783.754 B, sha256 `cc8f3805…5da2`) → `/tmp/pe.sh` con el **mismo sha256 leído del host**. Catálogo 62 → **63**. | Los pasos que necesitan *poner* un fichero (PE-assist, manifiesto de persistencia, payload) dejan de hacerse con heredocs a mano y quedan gobernados y auditados; el homólogo Windows (`nexus.post.smb_upload`) ya existía. | Cumplido: validación de origen/destino (`..`, NUL, caracteres de control, octal), `ssh_unavailable` si falta paramiko (`runtime_deps` lo declara), timeout clasificado, e invariante de *no-spawn* en el handler. |
| V0-41 · Recon web con evasión no gobernada | **CERRADA**: `nexus.recon.nikto` (`nexus_core/tools/handlers/nikto.py` + `nexus_core/tools/parsers/nikto.py`, **13 tests**). Args validados contra las tablas de nikto (`tuning` ∈ `0123456789abcx`, `evasion` ∈ `12345678ABR`, `pause` 0-30 s, `user_agent`, `request_timeout`, `maxtime_seconds`, `ports`, `ssl`) + flags de opsec fijados por el handler (`-nointeractive -nolookup -nocheck`). Parser determinista con `connected` derivado de la cabecera (sin cabecera ⇒ `nikto_no_target`) y hallazgos con `id`/`path`/mensaje. Catálogo 63 → **64**. | La sala exige bajar el ruido con `-Tuning`/`-evasion`; antes solo se podía hacer a mano, fuera del scope firmado y sin auditoría. | Cumplido: `noise_level` honesto (nikto siempre `high`) separado de `evasion`, con `warnings` cuando no hay `-Pause/-Tuning`; medido en la sala que `-evasion 6AB` **sube** el ruido (`SURICATA HTTP URI/METHOD terminated by non-compliant character` 2221029/2221030 y Wazuh 31101 ×659 + **31151 nivel 10** ×53). |
| V0-42 · La consola de scoring no correlaciona el HIDS | Medido en RUN_sala12: `ctflog` toma `dest_ip` de Suricata como el contenedor (`172.200.0.2x`) y de Wazuh como el **nombre del agente** (`/agent/name` = `dockerhost`), así que **ningún** evento de Wazuh se atribuye a la IP registrada por el operador. Toda la evidencia HIDS (rule 550 nivel 7 sobre `/etc/sudoers`, rule 554 nivel 5, 31151 nivel 10) hubo que leerla en el host. | El evaluador puntúa el paso ruidoso (NIDS) y silencia el paso grave (HIDS): un operador que solo mire la consola no ve la escalada. | Normalizar el campo de destino del agregador (o aceptar como alias los `agent.ip`/IPs de contenedor) y un test que pruebe que un evento HIDS con `agent.name` aparece bajo la cuenta del operador. |
| V0-43 · No hay tool para **traer** un artefacto del objetivo | `nexus.post.ssh_upload` cubre workspace → objetivo; el sentido contrario sigue sin tool (relacionado con V0-21/V0-26: el modelo de la sala #8, el `.kdbx` de la #11 y aquí los logs del HIDS). En esta sala el `alerts.json` de Wazuh se leyó con `docker cp` + un script subido a mano. | El *loot* que hay que analizar fuera del host (bases, modelos, logs) obliga a pasos manuales no gobernados (y a `save_path` de `nexus.web.request` cuando el dato sale por HTTP). | `nexus.post.ssh_download` (SFTP get confinado al workspace, con `sha256` remoto calculado en el objetivo, límite de tamaño y `risk=MEDIUM`), más el parser de loot que ya existe. |

### Huecos de numeración del ledger V0

Dos identificadores no tienen fila porque **nunca se abrieron como deuda**: se
declaran aquí para que el ledger sea continuo y verificable, y para que un hueco
no se confunda con una fila borrada. No se les atribuye título ni criterio de
cierre inventado; la consistencia inventario↔ledger↔artefactos se trata como
**V1-8** (no como deuda de sala).

| ID | Estado | Nota |
| --- | --- | --- |
| V0-8 | HUECO | Reservado, sin deuda asociada. La trazabilidad catálogo/ledger/versión de resultados es **V1-8**. |
| V0-23 | HUECO | Reservado, sin deuda asociada. |

Verificado por `test_audit_ledger_catalog_and_result_versions_consistent`
(`nexus_core/tests/unit/test_catalog_ledger_consistency.py`).

### Extensiones posteriores al ensayo de laboratorio

| Herramienta | Contrato |
| --- | --- |
| `nexus.web.upload` | POST multipart / PUT, streaming acotado |
| `nexus.post.shell_exec` | Sesiones registradas; aprobación de alto riesgo |
| `nexus.post.job` | Cola durable; gateway en el worker |
| `nexus.web.git_dump` | Recuperación de HEAD y objetos sueltos verificados |

## Fase V1 · Hallazgos del run de diagnóstico de Fase 3 (2026-10-15)

`run_abe04509c5064c6e8e475f46ba8f8c60` sobre `10.65.175.32` (11 iteraciones,
0 findings, cierre `subagent_budget_exceeded`) midió cuatro defectos del bucle
ReAct que no dependen de la sala: el catálogo ocultaba los enums válidos, el
planner no veía 10 turnos seguidos con `blackboard_delta = 0`, la enumeración
SMB/AD se agotó sin relevar a acceso inicial y el gateway dejó repetir dos
invocaciones idénticas. Se cerraron en **un solo commit**; los tres primeros son
hallazgos nuevos (no deuda de sala), de ahí que vayan al ledger **V1**.
IDs siguientes libres tras V1-14 (`docs/missions/audit-v1/`). V1-15/V1-16/V1-17
vienen del **rerun de Fase 3b** sobre la misma sala
(`run_434f5eeadb104b11ba0c80bce16f8d08`, `10.65.175.32`, 6 iteraciones, cierre
`provider_error`): el modelo propuso `options.RHOSTS` -clave que el handler
rechaza y el catálogo ocultaba- y `msfrpcd` sin escuchar abortó el run entero en
vez de degradar. V1-17 (segunda parte) y V1-18/V1-19 vienen del **rerun #3** de
Fase 3 (`run_02f8b99a5753469aa024905af4a25d7c`, commit `8de386b`): `msfrpcd` ya
escuchaba, pero `MSF_LHOST` no estaba en el `.env`, así que MS17-010 corrió
46,6 s sin callback, el subagente `exploit` agotó su presupuesto reintentando MSF
(`subagent_budget_exceeded`) y el hand-off `enumeration → exploitation` dejó el
plan con la fase que se abandonaba en `pending`.
V1-20/V1-21/V1-22 vienen del **rerun #4** de Fase 3
(`run_44b43bad8c5e4a998cf06b513c3eba60`, commit `a0e0194`, `MSF_LHOST` ya
configurado y doctor en verde): con el callback funcional MS17-010 se ejecutó 47 s
y falló en la fase SMB -fallo legítimo del exploit contra esa sala, no del arnés-,
pero el modelo quemó dos turnos en rechazos inevitables (`lhost` publicado como
ajustable) y el perfil `exploit` murió a los 8 turnos sin probar una alternativa.

| ID | Pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| V1-12 · Enums de tools no visibles en el system prompt | **CERRADA (2026-10-15)**: `nexus_core/agent/prompts.py` lista los valores legales de cada argumento con `enum` (`protocol∈{smb, ldap}`, `operation∈{fingerprint, …, delegation}`) y el argumento con enum va **antes** del resto: los 9 enums que quedaban detrás del tope de 5 argumentos ya se ven (ninguno se trunca nunca). Medido en el run: 3 de 11 turnos rechazados por contrato (`enum_shares`, `winrm`, `login`) = 30,6 % de los tokens del run. Catálogo 13.383 → 14.519 chars a 68 tools (**+8,5 %**, por debajo del 15 % de parada) y prompt revisado 20.883 → 22.028. | El modelo deja de adivinar los valores válidos y de quemar un turno completo (~8k tokens) en cada rechazo de `input_schema`. | Cumplido: `test_phase3_fixes.py::test_catalog_renders_enums` (parametrizado por tool), más `::test_catalog_never_lists_a_partial_enum` y `::test_catalog_keeps_every_required_argument_visible`. |
| V1-13 · El planner no detecta estancamiento ni releva de fase exhausta | **CERRADA PARCIALMENTE (2026-10-15)**: (a) el bucle cuenta `consecutive_no_progress` (queda en `react.turn_telemetry`), emite `react.stuck_detected` al umbral (`NEXUS_STUCK_THRESHOLD`, default 5, sin matar el run) e inyecta la línea de cambio de estrategia en el system prompt del turno siguiente; (b) en `planner.py` hay una regla determinista **sin LLM** (`enumeration_escalation`) que releva `enumeration → exploitation` / `services\|cred → exploit` cuando hay host + servicio SMB/AD, ninguna credencial ni acceso, y `no_progress ≥ 3`, con `reason: enumeration_exhausted_to_exploit` en el evento `orchestrator.plan` y transición de ida (no vuelve a `enumeration` mientras la evidencia no cierre la fase). Medido en el run: 10 turnos con delta 0 y enumeración agotada sin pivotar. **El planificador general de kill-chain (V0-12) sigue abierto**: aquí solo hay una regla de un caso (SMB), no puntuación ni encadenado de vectores. | Un bucle atascado deja de consumir presupuesto en silencio: el modelo recibe la señal y el perfil agotado deja el turno a `exploit` en vez de morir por presupuesto de subagente. | Cumplido: `test_phase3_fixes.py::test_loop_signals_stuck_at_the_threshold_and_warns_the_next_prompt`, `::test_no_progress_counter_resets_when_a_fact_arrives`, `::test_planner_hands_exhausted_smb_enumeration_to_exploit`, `::test_planner_does_not_escalate_outside_the_measured_case` (6 negativos) y `::test_loop_audits_the_hand_over_with_its_reason`. V0-12 permanece. |
| V1-14 · El gateway no deduplica invocaciones idénticas | **CERRADA (2026-10-15)**: la rama de reutilización del journal (`step_key` = tool + args + fase + objetivo, P2-D1) ya evitaba repetir el efecto, pero devolvía el resultado anterior **sin decirlo**; ahora lo marca (`verification_method=tool_already_invoked`, `evidence.previous_invocation_id`/`previous_outcome` y mensaje «esta misma invocación ya se ejecutó… considera cambiar de estrategia») conservando los datos previos, y lo audita en `invocation.reused`. Medido en el run: `netexec shares` (iters 3 y 8) y `netexec rid_brute` (iters 4 y 11) idénticos. El flujo de aprobación **no** se toca: la puerta sigue siendo de un solo uso y corre antes que el journal (`single-use` de V0-22/P2-D). | El modelo deja de leer la misma observación dos veces como si fuera nueva (dos turnos completos por par de repeticiones). | Cumplido: `test_phase3_fixes.py::test_gateway_deduplicates_identical_calls` (casos A/B/C/D), `::test_a_repeat_in_another_phase_is_a_new_intent_and_runs`, `::test_a_failed_call_keeps_its_retry_path`, `::test_idempotent_tools_are_never_deduplicated` y `::test_the_approval_flow_is_untouched`. |
| V1-15 · `FORBIDDEN_OPTIONS` de MSF invisibles en el catálogo | **CERRADA (2026-10-15)**: el render ya exponía los enums de `input_schema` (V1-12), pero no las restricciones que aplica cada handler. `ToolDefinition.forbidden_argument_values` (opcional, `{arg: [valores]}`) las publica y el catálogo las muestra con la misma forma de una sola pasada que un enum: `options:object ∉ {CHOST, CMD, …, RHOSTS, LHOST, LPORT, PROXIES, …}` (22 claves en `msf_auxiliary`, 21 en `msf_exploit`). El rechazo del handler ahora nombra la clave y lo que sí vale: `option 'RHOSTS' is forbidden; the handler sets the host from 'target'; safe extra options: RPORT, THREADS` (antes: `forbidden or duplicate auxiliary option`, que no decía cuál). Medido: iteración 6 con `options.RHOSTS`, que el modelo solo podía aprender por rechazo. Catálogo 14.519 → **14.976** chars a 68 tools (+457, +3,15 %; 220,2/tool; umbral de parada 15.500, no se cruzó) y prompt revisado 22.028 → 22.485. | El modelo deja de descubrir la restricción quemando un turno en el rechazo: sabe de antemano que está mal. | Cumplido: `test_phase3b_fixes.py::test_catalog_exposes_forbidden_options` (parametrizado por tool: exige `RHOSTS`/`LHOST` en la línea renderizada **y** que el mensaje nombre la opción prohibida), más `test_prompt_optimization.py::test_catalog_stays_compact_for_all_tools` con las cotas revisadas. |
| V1-16 · Un fallo de infraestructura del backend aborta el run en vez de degradar | **CERRADA (2026-10-15)**: `ProviderFailure` distingue `kind="unavailable"` (MSF RPC caído, credenciales RPC ausentes, binario ausente, timeout) de `kind="fatal"` (protocolo/invariante roto, **sigue** abortando con `provider_error`; es el valor por defecto para que nada se degrade en silencio). El gateway ya no lanza en el primer caso: reclasifica el resultado como `outcome="unavailable"` (`verification_method=<tool>_provider_unavailable`, `evidence.provider=msf_rpc`, causa original conservada en `evidence.cause`), la invocación se audita/journaliza como determinada (`tool.complete`) y deriva cero assertions. El bucle lo cuenta como fallo de tool: 3 consecutivos → `react.tool_unavailable`, retirada de la fase y el modelo lee «tool X is temporarily unavailable (reason: Y). Considera usar una alternativa o seguir con otras rutas». Medido: el run murió en la iteración 6 con cinco rutas aún disponibles. | Una tool cuyo backend no sirve deja de ser el final de la misión: el agente pivota a `searchsploit`/`impacket_*`/`web.*` según el subagente activo. | Cumplido: `test_phase3b_fixes.py::test_msf_auxiliary_returns_unavailable_when_rpc_down`, `::test_unavailable_tool_is_retired_after_three_failures`, `::test_unavailable_provider_failure_does_not_abort_the_run`, `::test_loop_suggests_alternative_when_tool_unavailable` y `::test_fatal_provider_failure_still_aborts`; `test_negative_outcomes.py::test_timeout_and_missing_infrastructure_keep_their_own_error` se reescribió al nuevo contrato (mismo propósito: «no pude mirar» nunca es `negative`). |
| V1-17 · `msfrpcd` no arranca por defecto y su config de callback no se valida | **CERRADA PARCIALMENTE (2026-10-15)**: la mitad *de código* está cerrada; el auto-arranque de `msfrpcd` sigue siendo entorno y no entra aquí. `omni --doctor` verifica ahora las **precondiciones de runtime** además de binarios y servicio: bloque `runtime_preconditions` en el JSON (`{service, missing_env, severity, action, observed}` por servicio) y línea humana con la acción (`msfrpcd: listening=true · MSF_LHOST=unset, MSF_LPORT=unset (WARNING: sin callback los payloads reverse quedan unavailable; exporta MSF_LHOST=<tu-IP-de-tun0> (y MSF_LPORT=4444))`); lo mismo para `SLIVER_LHOST/SLIVER_LPORT` cuando hay `SLIVER_OPERATOR_CONFIG` y para `NEXUS_NUCLEI_TEMPLATES` cuando el binario está presente. Nunca escala a error (correr solo las tools auxiliares sin callback es legítimo) y no altera el código de salida. La causa medida: `msfrpcd` escuchaba, `MSF_LHOST` no existía y nada lo dijo *antes* del run. Además `.env.example` publica `MSF_LHOST`/`MSF_LPORT` como líneas activas con comentario, el wizard de primer arranque autodetecta la IP de `tun0` (`ip -o -4 addr show tun0`) y la persiste en el `.env` del proyecto (`set_env_values`, escritura atómica 0600; sin `tun0` avisa y deja el campo vacío), y el README explica qué son y cómo obtenerlas. | Sin `msfrpcd` en marcha, toda la familia `nexus.exploit.msf_*` y `nexus.session.*` es inutilizable durante el engagement, aunque ya no mate el run; con `msfrpcd` arriba pero sin callback, cada payload reverse moría en el objetivo tras ~47 s quemando el presupuesto del subagente. | Cumplido (parcial): `test_phase3c_fixes.py::test_env_example_has_msf_lhost`, `::test_wizard_detects_tun0_ip`, `::test_doctor_reports_missing_msf_lhost` y `::test_doctor_json_includes_runtime_preconditions`. **Sigue abierto** el arranque de `msfrpcd` (criterio original: `omni --setup` con mensaje accionable) y la validación de `MSF_LPORT` más allá del aviso de higiene (el handler usa 4444 por defecto). |
| V1-18 · El hand-off deja la fase anterior en `pending` | **CERRADA (2026-10-15)**: toda transición deliberada pasa por `planner.hand_over_phase`, que marca `done` la fase que se abandona, `current` la destino, conserva en `done` lo que la evidencia ya cerró y **no inventa cierres** cuando la transición no avanza en la kill-chain (retroceso o mismo destino). `escalate_enumeration` (la regla determinista de V1-13) delega en él. Medido en el rerun #3 (7º hallazgo): el plan quedaba con `enumeration: pending` + `exploitation: current` y `progress=[1, 6]`, un estado que el gate de finalización no puede cerrar nunca (una fase obligatoria `pending` por detrás de la actual impide llegar a `reporting`); ahora el hand-off desde `enumeration` da `done=2` y `progress=[2, 6]`. | El plan que lee el modelo (y audita `orchestrator.plan`) es coherente con el gate: la fase abandonada deja de aparecer como trabajo pendiente y el avance se cuenta de verdad. | Cumplido: `test_phase3c_fixes.py::test_plan_marks_previous_phase_done_on_handoff`, parametrizado por las cuatro transiciones hacia delante (`recon→enumeration`, `enumeration→exploitation` vía `escalate_enumeration`, `exploitation→privilege_escalation`, `privilege_escalation→post_exploitation`): exige fase anterior `done`, destino `current`, ninguna obligatoria `pending` por detrás de la actual y el `progress`/`done` del payload auditado. |
| V1-19 · Config faltante del operador tratada como fallo de contrato | **CERRADA (2026-10-15)**: `kernel/models.py` añade `config_missing_result(tool_id, missing_env, detail=)`, que devuelve `outcome="unavailable"` (nunca `input_rejected` ni un fallo de contrato cualquiera), `verification_method=<tool>_config_missing`, `evidence={missing_env, tool_id, detail}` y `verified=False` con cero assertions: el gateway lo acepta como resultado **determinado** (no es `RuntimeError` de post-condición) y el bucle lo cuenta como fallo de tool, lo retira a los 3 intentos y le pasa al modelo la observación con el motivo y las alternativas del perfil. Solo se declaran variables que la tool *no puede* defaultear: `MSF_LPORT` tiene 4444, así que nunca aparece ahí (sí en el aviso del doctor). Aplicado a `nexus.exploit.msf_exploit` (payload reverse sin `MSF_LHOST`) y a `nexus.exploit.msf_auxiliary` en las familias que abren listener/relay (`auxiliary/server/`, `auxiliary/spoof/`, `auxiliary/relay/`; los scanners siguen corriendo sin callback), después de la validación de scope para que el gobierno siga denegando primero. Medido: `msf_lhost_missing` contaba como fallo normal y el perfil `exploit` reintentó MSF hasta agotar presupuesto. | El modelo recibe «qué variable falta» y pivota (`msf_search`, `searchsploit`, `impacket_*`, `web.*`) en vez de reintentar en bucle, y el operador tiene una línea accionable que arreglar. | Cumplido: `test_phase3c_fixes.py::test_msf_exploit_returns_unavailable_when_lhost_missing`, `::test_msf_auxiliary_returns_unavailable_when_callback_lhost_missing` y `::test_loop_suggests_alternative_on_config_missing` (outcome/unavailable, `evidence.missing_env`, retirada de la tool con las alternativas del subagente activo); `test_msf_exploit_handler.py::test_exploit_fails_closed_without_callback_for_reverse_payload` se reescribió al nuevo contrato conservando su propósito («sin callback no hay RPC»). |
| V1-20 · `lhost`/`lport` publicados como ajustables cuando el handler los rechaza | **CERRADA (2026-10-15)**: `kernel/models.py` añade `ToolDefinition.fixed_by_env` (opcional, `{argumento: variable}`) para los argumentos cuyo valor es *del operador* y llegan del entorno. `msf_exploit` declara `{"lhost": "MSF_LHOST", "lport": "MSF_LPORT"}` y `msf_auxiliary` `{"options.LHOST": "MSF_LHOST", "options.LPORT": "MSF_LPORT"}` (solo expone `options`, así que la clave se declara por ruta). El render (`agent/prompts.py`) añade una línea por tool **fuera** de `args[…]`: `lhost/lport fijos por env MSF_LHOST/MSF_LPORT (no ajustables)` en `msf_exploit` y `LHOST/LPORT fijos por env MSF_LHOST/MSF_LPORT (no ajustables)` en `msf_auxiliary`; la nota vive fuera del tope `CATALOG_MAX_ARGUMENTS` a propósito (una restricción truncada es exactamente la que el modelo repite) y el handler sigue rechazando el valor del modelo (publicar no autoriza). Medido en el rerun #4, iteración 11: el modelo propuso `lhost=10.65.175.1` (inventado, la puerta de enlace del objetivo) y el handler lo rechazó con `lhost is fixed by MSF_LHOST and cannot be set by the model` mientras el catálogo publicaba `lhost:string`: un turno perdido que el contrato podía evitar. Catálogo 14.976 → **15.104** chars a 68 tools (222,1/tool; umbral de parada 15.500, no cruzado), prompt revisado 22.485 → 22.613. | El modelo lee *de quién* es el callback antes de proponerlo, en vez de descubrirlo por rechazo. | Cumplido: `test_phase3d_fixes.py::test_catalog_marks_lhost_lport_fixed_by_env` (parametrizado por tool: exige la declaración `fixed_by_env`, la frase exacta en la línea renderizada fuera de `args[…]` y que el handler siga rechazando el valor del modelo). |
| V1-21 · Presupuesto del subagente `exploit` (8) insuficiente para probar alternativas tras un fallo legítimo | **BAJO EXPERIMENTO (2026-10-15)**: `agent/subagents.py` sube el presupuesto de iteraciones de `exploit` de 8 → **15** y nada más (token budget 60.000 intacto; ningún otro perfil tocado). Causa medida en el rerun #4: de los 8 turnos del perfil, 3 fueron de relleno (`record_fact` ×2 y la **misma** llamada `netexec fingerprint` repetida idéntica) y 2 rechazos evitables (RHOSTS y lhost) antes de llegar a MS17-010; con el exploit fallando a los 47 s el perfil murió con `subagent_budget_exceeded` y 27 iteraciones globales sin usar, sin haber probado `searchsploit`, `impacket_psexec` ni `msf_auxiliary` con otro módulo. | El agente dispone de espacio para 2-3 vectores más después de un fallo legítimo del exploit. | **Criterio de cierre definitivo**: fijar el valor tras el **rerun 5** según si pivota o no. Si con 15 iteraciones sigue sin pivotar, la causa es el prompt/planner y **no** el presupuesto (se revierte a 8 y se abre el hallazgo del prompt). Cumplido provisionalmente: `test_phase3d_fixes.py::test_exploit_subagent_budget_is_15` y `::test_other_subagent_budgets_unchanged`. |
| V1-22 · Verificar que `react.stuck_detected` cambia el prompt del turno siguiente | **CERRADA (2026-10-15, verificación)**: el vínculo ya existía (Fase 3 fixes, V1-13): `ContextBuilder.render` añade la línea `STUCK_PROMPT_LINE` al system prompt cuando `no_progress >= stuck_threshold`, la frase es «Detectado estancamiento: {iterations} turnos sin hechos nuevos. Cambia de estrategia o propón task_complete si ya no hay rutas viables.» y el evento se emite en el umbral. El rerun #4 lo emitió dos veces (iters 5 y 10) sin que el agente pivotase, así que quedaba la duda de si era solo auditoría: **llega al prompt** (el turno 5 no puede leerlo -ya se está respondiendo-, el 6 sí). No se cambió código ni el umbral (sigue en 5). | El aviso de estancamiento no es telemetría muerta: el modelo lo lee antes de decidir el turno siguiente. | Cumplido: `test_phase3d_fixes.py::test_stuck_signal_reaches_next_prompt` (re-verifica evento → prompt siguiente sobre la evidencia del rerun #4) y, desde la fase anterior, `test_phase3_fixes.py::test_loop_signals_stuck_at_the_threshold_and_warns_the_next_prompt`. |
