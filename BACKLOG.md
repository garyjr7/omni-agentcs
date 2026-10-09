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

Sala #4 en curso (ver `docs/missions/salas/RUN_sala04.md`). Deudas nuevas:

| ID | Pendiente | Impacto actual | Criterio de cierre |
| --- | --- | --- | --- |
| V0-7 · `Host` en recon | **Parcialmente cerrado**: `nexus.web.ffuf` ya acepta un `Host` estático en scope (además de la plantilla `FUZZ`) y admite subdominios de un dominio autorizado. Sigue faltando lo mismo en `gobuster` (modo vhost devuelve 0) y el CLI de scope rechaza `*.dominio`. | Enumerar contenido/vhosts sin DNS ya es posible con ffuf; gobuster no. | `--header`/vhost gobernado en gobuster; scope que acepte wildcards con validación de resolución. |
| V0-9 · Ejecución masiva de `omni` | Lanzar N procesos `omni` en paralelo (p. ej. 40 en un barrido SSRF) satura la CPU y congeló la máquina. Además, apuntar el SSRF al propio `localhost` de una app de un solo worker la deja en **deadlock** ~25 min. | Riesgo de tumbar el host del operador y la instancia objetivo. | Un cliente/cliente-batch que evite el arranque por petición (o un runner in-process) y una guía de concurrencia por tool; pruebas de carga. |
| V0-10 · DAST web | El motor no cubre XSS/SQLi/LFI/SSRF/XXE de forma automatizada. `super_scanner` (`/home/operator/super_scanner`, DAST modular con payloads, colaborador OOB y DB CVE local) es candidato natural, pero no está integrado. | Las salas web se resuelven a mano; sin verificación automatizada de clases de bug. | Tool gobernada que envuelva `super_scanner scan/probe` con scope+sandbox+parser determinista, y mapeo de hallazgos a `vulnerability`. |
