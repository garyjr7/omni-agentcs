# Blueprint arquitectónico — OmniAgentCS

**Tipo de revisión:** auditoría estática del checkout, sin ejecutar el agente ni sus herramientas.  
**Fecha:** 2026-10-30.  
**Alcance:** puntos de entrada, agente ReAct, runtime durable, gateway, herramientas, sandbox, scope/RoE, LLM, memoria y persistencia.  
**Estado del checkout:** había cambios locales sin commit, incluidos handlers nuevos. El documento describe el árbol presente durante la revisión; no presupone que todos esos cambios formen parte de una release.

## 1. Resumen ejecutivo

OmniAgentCS es una aplicación Python 3.12+ con CLI interactiva y worker durable. El agente usa un bucle ReAct propio: el modelo produce acciones JSON, el coordinador las valida y convierte en llamadas a herramientas, y cada herramienta durable pasa por un `ToolGateway` que aplica contrato, scope firmado, autorización, aprobaciones, journal y auditoría. Los handlers encapsulan herramientas externas, APIs RPC o lógica Python; no se delega el control general del agente a LangChain, AutoGen o CrewAI.

La arquitectura prioriza trazabilidad y continuidad: SQLite/PostgreSQL guardan tareas, conversaciones, resultados, hechos del engagement, aprobaciones, artefactos y auditoría. Hay memoria conversacional resumible y un blackboard tipado con procedencia. Las llamadas externas a LLM se hacen mediante una abstracción intercambiable y pueden tener fallback/routing.

El principal límite de seguridad es que «sandbox» no significa lo mismo en todos los modos. `local`/`local_strict` usan allowlist del ejecutable, cwd de workspace, HOME efímero, límites de salida/tiempo y grupos de procesos; el propio código declara que **no** aíslan filesystem, red ni procesos del host. OCI aplica aislamiento de contenedor, pero hoy ejecuta con `--network none`; `oci_network`, el modo que permitiría herramientas de red con filtrado, falla explícitamente porque aún no existe. Además, `nexus.shell.exec` abre un shell genérico y depende de filtros y validación de destinos sobre texto de comandos; esos controles son defensa en profundidad, no un límite equivalente a una política de sistema operativo.

## 2. Árbol de directorios y archivos principales

```text
.
├── omni.py                      Entrada del CLI instalado (`omni`)
├── nexus_worker.py              Worker de tareas durable
├── nexus_core/
│   ├── agent/                    ReAct, planificación, contexto y subagentes
│   ├── cli/                      REPL, comandos, wizard, approvals, TUI
│   ├── config/                   TOML, entorno, XDG y secretos
│   ├── hooks/                    Extensiones de lifecycle y tool hooks
│   ├── integrations/             Clientes Metasploit, Sliver y MCP
│   ├── kernel/                   Runtime, gateway, stores, policy, sandbox
│   ├── llm/                      Abstracción, selección y límites de modelos
│   ├── playbooks/                Playbooks declarativos YAML
│   ├── provisioner/              Detección, readiness e instalación aprobada
│   ├── report/                   Extracción de hallazgos y formatos de salida
│   ├── scope/                    Engagement firmado, resolución y RoE
│   ├── tools/
│   │   ├── handlers/             Adaptadores de herramientas y lógica ofensiva
│   │   └── parsers/              Normalización de salidas de herramientas
│   ├── tests/                    Pruebas unitarias, integración y contratos
│   └── utils/                    Logging y utilidades comunes
├── docs/                         ADR, auditorías, guías y misiones
├── scripts/                      CLI auxiliares, probes y soporte operativo
├── packaging/npm/                Wrapper npm para instalar/lanzar el CLI
├── roadmap_12/                   Diseño, bitácoras y evidencia de fases
├── bench/                        Benchmarks/evaluaciones
├── install.sh                    Instalador del producto
├── pyproject.toml                Paquete, dependencias y entry point
├── requirements-prod.in          Dependencias runtime declaradas
├── requirements-dev.lock         Lock reproducible de desarrollo
├── README.md                     Instalación, operación y comandos
└── SECURITY.md                   Política y contexto de seguridad
```

### Módulos que forman el camino de ejecución

| Zona | Archivos representativos | Responsabilidad |
|---|---|---|
| Entrada y operación | `omni.py`, `nexus_core/cli/main.py`, `nexus_core/cli/engage.py`, `nexus_core/cli/session.py`, `nexus_core/cli/headless.py` | Inicializa el CLI, configura o selecciona el engagement y presenta sesiones interactivas/headless. |
| Worker/runtime | `nexus_worker.py`, `nexus_core/kernel/runtime.py`, `nexus_core/kernel/workflows.py`, `nexus_core/kernel/batch.py` | Reclama tareas, construye contexto de ejecución, invoca ejecutores y emite eventos durables. |
| Agente | `nexus_core/agent/react.py`, `react_coordinator.py`, `react_services.py`, `parser.py`, `parallel.py` | Bucle ReAct; construcción del prompt, decodificación de acciones, coordinación, batching y límites de progreso. |
| Gobierno de herramientas | `nexus_core/kernel/tool_gateway.py`, `policy.py`, `approvals.py`, `invocation_journal.py`, `audit.py` | Valida y autoriza llamadas, requiere aprobaciones según riesgo, deduplica/reconcilia efectos y deja auditoría. |
| Catálogo de herramientas | `nexus_core/tools/registry.py`, `registration.py`, `handlers/`, `parsers/` | Define contratos (`ToolDefinition`) y conecta IDs de herramienta con handlers y parsers. Permite registro aditivo y entry points. |
| Scope y reglas | `nexus_core/scope/models.py`, `validator.py`, `roe.py`, `kernel/scope_loader.py` | Verifica HMAC/ventana temporal, resuelve targets y puede aplicar reglas adicionales de engagement. |
| Ejecución externa | `nexus_core/kernel/sandbox.py`, `sandbox_modes.py`, `tools/handlers/_exec.py` | Lanza argv bajo el ejecutor local u OCI, limita salida/tiempo y limpia grupos de procesos. |
| Persistencia y evidencia | `kernel/control_store.py`, `postgres_store.py`, `store_factory.py`, `artifacts.py`, `knowledge.py`, `blackboard.py` | Store relacional; tareas, mensajes, hechos, aprobaciones, eventos, artefactos y evidencias. |
| Modelos | `nexus_core/llm/abstraction.py`, `dynamic_selector.py`, `limits.py`, `anthropic_client.py` | Contrato común de cliente, proveedores, fallback, selección de modelo y presupuestos/reintentos. |
| Informes y provisión | `nexus_core/report/`, `nexus_core/provisioner/` | Extrae y representa hallazgos; detecta herramientas externas y ejecuta planes de instalación sujetos a autorización. |

`nexus_core/tools/handlers/` contiene muchas capacidades (Nmap, DNS, HTTP, SMB/AD, Hydra, Impacket, SQLMap, Nuclei, Metasploit, Sliver, SSH, pivot, shell, entre otras). La lista concreta vive en `registry.py` y puede ampliarse mediante `registration.py`; no todas las capacidades usan el mismo mecanismo de ejecución.

## 3. Stack tecnológico

### Lenguaje y frameworks

- **Python 3.12+**, async/await y `asyncio` para el loop, handlers, procesos y clientes de red.
- **Pydantic** para contratos/DTOs y estructuras de acciones; **jsonschema** para validar schemas de herramientas.
- CLI: **prompt_toolkit** para interacción y **Rich** para presentación.
- Configuración: TOML (`tomllib`), variables de entorno y `python-dotenv`; directorios XDG.
- Paquetes de integración: **httpx**, **msgpack**, **mcp** (SDK oficial), **sliver-py**, **paramiko**, **psycopg** y `keyring`.
- Playbooks: YAML con PyYAML y validación de schema.
- Telemetría: OpenTelemetry API/SDK/exporter, métricas locales del kernel.
- Construcción/empaquetado: setuptools/pyproject; además hay wrapper bajo `packaging/npm`.

No encontré LangChain, AutoGen ni CrewAI en el camino central. La orquestación ReAct, el router, el parser y el gateway son código propio.

### Proveedores LLM

La capa de `nexus_core/llm/` expone un contrato común y construye clientes para OpenAI, Gemini, Anthropic, Groq, DeepSeek y Ollama (además de Fake para offline/pruebas). `NexusLLM` centraliza retries/fallback; `dynamic_selector.py` puede enrutar tareas como planificación, ejecución, reflexión e informes a modelos diferentes. No hay memoria vectorial incorporada al camino principal.

### Herramientas externas

Las herramientas de pentest son binarios del sistema o dentro de imágenes OCI: Nmap, ffuf, gobuster, nuclei, nikto, sqlmap, searchsploit, Hydra, clientes Impacket, netexec, etc. Metasploit se integra por RPC (MessagePack o JSON sobre HTTP), Sliver mediante su cliente API, MCP por stdio/HTTP y SSH con Paramiko. Los handlers suelen construir `argv` directamente; no todos ejecutan un string shell.

### Persistencia

- **SQLite** como default local; **PostgreSQL** soportado vía `DATABASE_URL` y exigido por el selector del store cuando `NEXUS_ENV=production` (salvo override explícito de SQLite).
- Datos estructurados y JSON serializado en tablas relacionales; almacén de artefactos en filesystem configurable.
- No se observa una Vector DB. `KnowledgeStore.search` usa búsqueda SQL léxica `LIKE`, no embeddings.
- Secretos: keyring del sistema si está disponible; fallback `secrets.json` con permisos restrictivos según el bootstrap/config.

## 4. Flujo de ejecución (Execution Loop)

1. **Inicio y selección de contexto.** `omni.py` conduce a `nexus_core/cli`; se carga configuración, se abre el `ControlStore`, se selecciona/crea el engagement y se prepara la identidad, objetivo y workspace. El modo durable puede encolar trabajo para `nexus_worker.py`; CLI y worker comparten ejecutores del kernel.
2. **Creación/recuperación de ejecución.** `runtime.py` construye un `ExecutionContext` con store, tarea, worker y cancelación. Ante reintentos de tareas, valida lease y reconcilia invocaciones anteriores con `InvocationJournal` antes de reanudar.
3. **Preparación del turno.** `run_react_loop` crea/recupera conversación, emite hooks de sesión y limpia procesos/PTY residuales. `ReActCoordinator` obtiene historial, plan, facts, cobertura, scope, credenciales disponibles, playbook, skills y catálogo permitido; el selector elige el cliente/modelo aplicable.
4. **Decisión del LLM.** El prompt solicita una acción estructurada. La respuesta se extrae y valida por `parser.py`/DTOs: tool call, batch de llamadas, completar tarea o pedir aclaración. El coordinador aplica límites de iteración/tokens, filtros de perfil/subagente, coherencia con plan y frenos frente a repeticiones o cierres prematuros.
5. **Gobierno pre-ejecución.** El coordinador identifica aprobaciones necesarias. Después cada acción llega a `runtime.execute_tool`, que resuelve catálogo first-party y construye `ToolGateway`. El gateway verifica modo sandbox, operator mode, JSON schema, autenticidad/ventana/firma del scope, target dentro de scope, RoE si está configurado, PolicyEngine, aprobación durable y hooks `pre_tool_use`.
6. **Journal y handler.** Antes del efecto se calcula una clave de intención, se consulta/prepara el journal y se registra el inicio. Las llamadas repetidas de efectos no idempotentes pueden devolver el resultado previo; una invocación `unknown` no se repite silenciosamente. Luego se llama al handler con credenciales referenciadas resueltas solo para su copia de argumentos.
7. **Acción en Kali/servicio.** Un handler tipado valida/normaliza argumentos y construye `argv`, llama a una API (MSF/Sliver/MCP) o ejecuta lógica Python. Los handlers de procesos pasan por `sandbox_for_environment` y `_exec.run_in_sandbox`; el ejecutor usa `asyncio.create_subprocess_exec`, no `shell=True` como patrón universal. `nexus.shell.exec` es excepción intencional: ejecuta bash/sh con texto de comando, sujeto a guardas y scope checks propios.
8. **Captura y normalización.** El sandbox recoge stdout/stderr con límite de bytes, timeout y cancelación; la salida se convierte a `ToolResult`, parsea a datos estructurados y puede guardarse como artefacto. El gateway aplica redacción, post-condiciones/evidencia determinista y cierra el estado del journal. Algunos adaptadores RPC devuelven resultados estructurados directamente sin proceso local.
9. **Observación y memoria.** El coordinador persiste la acción y resultado sanitizados, añade evento de run/auditoría y los vuelve una observación del siguiente prompt. Los handlers/verificadores pueden registrar facts tipados en el blackboard con procedencia/verificación; plan y coverage se actualizan y guían la siguiente decisión. Las llamadas en batch se limitan por semáforo y generan una observación consolidada.
10. **Finalización.** La verificación de finalización evalúa evidencia y objetivo; el loop termina por completado, aclaración, bloqueo, cancelación, scope violation, presupuesto, fallo o máximo de iteraciones. Se limpian sesiones y procesos administrados y se emiten hooks de cierre.

**stdout/stderr:** en modo local el proceso tiene pipes separados y captura acotada. `stderr` se descarta (`DEVNULL`) en el camino interactivo `open_stdio`; en `run()` se captura por separado. El modelo suele recibir resultado parseado/resumido, no necesariamente la salida cruda completa. Nmap, por ejemplo, consume XML por stdout y limita el fragmento textual conservado.

## 5. Seguridad y sandboxing

### Controles presentes

- **Scope firmado:** `ScopeValidator` valida HMAC-SHA256, ventana de vigencia, tipo/canonicalización de target, exclusiones y resolución de IP/dominio. Los handlers declaran `scope_required` y/o `scope_target_field`; el gateway vuelve a validar en cada llamada.
- **RoE opcional:** si hay reglas cargadas, el enforcer puede estrechar el scope con ventanas horarias, límite de tasa/concurrencia, categorías/targets prohibidos y kill switch. La ausencia de RoE deja gobernando scope y políticas normales.
- **PolicyEngine:** aislamiento tenant, roles/permisos y aprobación para riesgo `HIGH` o `DESTRUCTIVE`; denegación por defecto si no hay permiso. Las aprobaciones tienen identidad, run/acción esperada y consumo de un solo uso.
- **Contratos de tool:** JSON Schema valida argumentos antes del handler. ToolDefinitions declaran riesgo, efecto, timeout, tamaño de salida, permisos y requisitos de scope/sandbox.
- **Auditoría/journal:** auditoría append-only encadenada por SHA-256 con saneado de campos sensibles; journal durable protege replay, reintentos y efectos de estado incierto.
- **Captura/terminación:** timeout, cancelación cooperativa, límites de salida, grupos de proceso y recolección de procesos huérfanos.
- **Secretos:** referencias a credenciales se resuelven en el gateway para el handler y se redactan de historial/auditoría; el cliente MCP también filtra entorno del proceso hijo.
- **Herramientas tipadas:** Nmap limita flags; Metasploit acota opciones/payload/target y fija callback desde configuración; handlers de instalación generan planes y piden aprobación.

### Garantías por modo

| Modo | Garantía efectiva del código | Límite operativo |
|---|---|---|
| `local` / `local_strict` | Allowlist de `argv[0]`, cwd dentro del workspace, HOME/XDG efímero, límite de captura, timeout/cancelación y grupos de proceso. | El propio `GUARANTEES` declara sin aislamiento de filesystem, red, procesos del host, recursos ni usuario. El proceso hijo conserva permisos del usuario que ejecuta Omni. |
| `oci` | Docker/Podman con filesystem read-only más workspace RW, sin red, usuario no root, capabilities eliminadas, no-new-privileges, límites de CPU/memoria/PIDs y tmpfs temporal. | Red desactivada impide que Nmap/HTTP/Hydra u otras herramientas alcancen objetivos externos desde ese contenedor. |
| `oci_network` | Modo conceptual para red filtrada por scope. | No implementado; la resolución lanza `SandboxModeNotImplemented`. |

Por defecto, desarrollo usa `local_strict`; `NEXUS_ENV=production` resuelve OCI si no se fuerza otro modo y rechaza modos locales. Por eso, la ejecución de red desde el mismo contenedor aislado no está resuelta hoy: habilitar red plena sería inseguro y dejarla desactivada rompe muchas herramientas. La arquitectura necesita una política de egress implementada (o una topología de ejecución controlada) antes de considerar OCI una configuración operativa general para pentesting remoto.

### Human-in-the-loop

Sí, según el nivel de riesgo: el gateway requiere aprobación durable para acciones de alto riesgo/destructivas, y CLI expone comandos para revisar/aprobar. Un job no interactivo sin aprobación puede terminar bloqueado. `--trust-mode` y `resume_policy` permiten automatizar ciertos reintentos de efectos inciertos; es una decisión explícita del operador y debe tratarse como un modo de mayor autonomía. No toda acción necesita aprobación individual: las herramientas de riesgo bajo/moderado pueden proceder bajo permisos, scope y política.

## 6. Integración de herramientas

- **Wrappers tipados propios:** cada handler ofrece definición/schema, valida parámetros y normaliza salida. `registry.py` centraliza el catálogo first-party, con registro extensible vía decoradores/entry points.
- **Comandos directos con argv:** Nmap y muchos scanners lanzan binarios externos mediante sandbox; `shell=True` no es el mecanismo general. Parsers en `tools/parsers/` convierten texto/XML/JSON a hallazgos consumibles por el agente.
- **Shell genérico:** `nexus.shell.exec` permite bash/sh para casos no cubiertos por wrappers, con riesgo alto y scope obligatorio. Hay denylist para operaciones destructivas y chequeo de targets reconocibles en comandos de fetch. La gramática arbitraria de shell es difícil de validar por regex; la protección fuerte debe venir del aislamiento del host y de limitar las capacidades.
- **Metasploit:** `integrations/metasploit/client.py` usa RPC HTTP JSON o MessagePack, no invoca `msfconsole` por shell para cada acción. Los handlers `msf_search`, `msf_auxiliary`, `msf_exploit` y `msf_session_*` separan búsqueda, ejecución y sesiones. El exploit tiene riesgo alto y parámetros target/callback restringidos.
- **Sliver:** integración cliente y handlers para servidor, generación/despliegue de implantes, sesiones, ejecución, pivot y loot.
- **MCP:** cliente SDK con transporte stdio/HTTP; lista de tools permitidas y capacidades declaradas. Stdio exige sandbox requerido; HTTP no puede garantizar sandbox local. Las tools descubiertas se adaptan al gateway, no lo eluden.
- **SSH/AD/pivot:** Paramiko e Impacket/netexec wrappers para post-explotación remota, extracción y movimiento lateral con contratos diferenciados.
- **Provisionamiento:** `provisioner/` detecta binarios, crea planes de instalación y verifica readiness; el handler central pasa por política y aprobación.

## 7. Memoria y contexto

La memoria consta de varias capas, no de una única conversación infinita:

1. **Historial ReAct durable:** mensajes user/assistant/tool se guardan en conversaciones del `ControlStore`; la conversación `react:<run_id>` facilita recuperar un run interrumpido. Las sesiones de trabajo por engagement pueden compartirse entre runs.
2. **Resumen de historial:** cuando el historial pasa el umbral (por defecto aproximado de tokens configurable por el constructor), `agent/memory.py` solicita una llamada de resumen y agrega un marcador lógico. Preserva el prompt de sistema y las últimas 10 entradas; la tabla append-only no se reescribe. La carga colapsa los mensajes reemplazados.
3. **Blackboard por engagement:** hechos estructurados (host, servicio, endpoint, usuario, credencial, acceso, vulnerabilidad, barrera, sesión, loot, ruta) con source URI, invocation y estado de verificación. Un fact solo se considera verificado con procedencia del verificador y método declarado.
4. **Contexto derivado:** plan por fases, cobertura de servicios, observaciones, barreras, hechos, playbook, skills y evidencia se vuelven a consultar para construir el prompt. Esto reduce dependencia del texto de chat para estado de engagement.
5. **Knowledge store:** documentos con clasificación, hash y cita; búsqueda léxica SQL. Puede dar contexto recuperado, pero no hay pipeline vectorial/embeddings en el diseño observado.
6. **Catálogo de skills:** `agent/skills.py` resuelve el directorio en este orden: `NEXUS_SKILLS_ROOT`, `<cwd>/.agents/skills` si existe, y si no `.agents/skills` de la instalación (padre del paquete `nexus_core`). El prompt (`render_skill_index`) y `nexus.skill.load` usan la misma resolución, y una skill que no existe nombra el catálogo real y el directorio leído; el bucle rechaza una segunda carga del mismo nombre inexistente (`branch_discipline.unknown_skill_refusal`). Las skills del repositorio van sin firma: se entregan como datos delimitados y con señales de inyección, nunca como instrucciones de confianza.
7. **Loot accionable:** los handlers de transferencia (`ftp`, `nfs`) resumen sus ficheros con procedencia, tamaño, `sha256`, tipo (`text`/`binary`) y truncamiento. Un fichero de líneas de un solo token se marca como lista de contraseñas y el resumen propone el siguiente eslabón (`nexus.cred.bruteforce` con `password_file` y usuario) junto a los demás servicios ya probados del mismo host; descargar un binario se reporta como descargado, nunca como analizado.
8. **Artefactos y journal:** salidas grandes, reportes y evidencia se almacenan fuera del prompt; el journal mantiene resultados y estados de invocación para auditoría/replay.
9. **Estado terminal:** agotar iteraciones o presupuesto persiste un resumen que declara el límite alcanzado, el número de hallazgos y las ramas que quedaron abiertas; nunca se informa éxito sin las condiciones del objetivo verificadas.

Los mensajes, metadata y argumentos guardados pasan por sanitización/redacción. Los resúmenes son otra salida del LLM, por tanto una compresión puede omitir detalles o arrastrar instrucciones maliciosas presentes en texto de salida. El estado verificable debe seguir viniendo de facts/evidencias estructuradas, no de confiar en un resumen narrativo.

## 8. Riesgos, cuellos de botella y mejoras

Prioridad basada en impacto potencial y evidencia del código; no equivale a una prueba de explotación.

### Prioridad alta

1. **Aislamiento local insuficiente para ejecutar comandos no confiables.** `local_strict` restringe el ejecutable inicial y el cwd, pero el proceso tiene acceso al filesystem/red y permisos del usuario; bash/python/binarios permitidos pueden ejecutar capacidades adicionales. Una denylist textual de `rm -rf /` no cubre todas las formas semánticas de causar daño. Para campañas con comandos elegidos por LLM, OCI/VM con mínimos privilegios debería ser requisito real, no una etiqueta.
2. **No hay modo OCI con egress gobernado.** OCI actual usa `--network none`, y `oci_network` falla cerrado. La opción local mantiene red completa sin aislamiento; esta tensión impide combinar disponibilidad de herramientas ofensivas y contención fuerte. Implementar filtrado de salida fuera del proceso (namespace/proxy/firewall) ligado a scope resuelto y DNS/IP, con pruebas contra DNS rebinding y redirects.
3. **Shell genérico amplía mucho la superficie.** `nexus.shell.exec` acepta lenguaje de shell y sus controles de comandos/destinos son necesariamente aproximados. La detección de URL/IP en comandos no equivale a controlar sockets: scripts, herramientas no parseadas, redirects, DNS, proxies, IPv6 y subprocesos pueden cambiar el destino real. Preferir wrappers estructurados para operaciones de red y mantener el shell deshabilitado o restringido en ejecución autónoma de alto impacto.
4. **Prompt injection por salidas de herramientas.** Los resultados externos y archivos consultados pasan al contexto del modelo; sanitización de secretos no neutraliza instrucciones adversariales. Etiquetar explícitamente el contenido no confiable, reducirlo a datos tipados, delimitarlo en prompt y evitar que texto de una página/archivo modifique decisiones de autorización.

### Prioridad media

5. **Compatibilidad operativa por entorno.** Debe documentarse y validarse la matriz de herramienta × modo: en OCI sin red las tools de red no pueden funcionar; en local funcionan con garantías débiles. Preflight debería advertir o rechazar una combinación incoherente antes de iniciar un engagement.
6. **Captura truncada y diagnósticos.** Límites de salida y resúmenes reducen costo/contexto pero pueden eliminar evidencia necesaria; algunos caminos descartan stderr. Asegurar manifest (hash, bytes descartados, truncamiento), artefacto completo con redacción y un fragmento diagnóstico útil para cada handler.
7. **Postura de secretos/artefactos.** Las referencias se protegen, pero contraseñas introducidas directamente en argumentos, outputs de herramientas o artefactos pueden filtrarse si no coinciden con reglas de redacción. Aplicar clasificación/retención y permisos estrictos al directorio de artefactos y evitar poner secretos en línea de comandos.
8. **MCP remoto y plugins son fronteras de confianza.** Una tool MCP HTTP ejecuta en un servicio externo sin sandbox local. Plugins/entry points son código Python con privilegios del proceso. Requerir firma/allowlist de paquetes, revisión de capability declarations y etiquetas de confianza por servidor/plugin.
9. **Scopes por nombre DNS y redirecciones.** La validación consulta DNS y handlers pueden volver a resolver al conectar. Confirmar que el IP conectado es uno de los IP validados y revalidar cada redirect/endpoint; una validación anterior no basta si el nombre cambia entre check y connect.

### Rendimiento y resiliencia

- Llamada serial al LLM por iteración domina latencia/costo; el batching ayuda solo para herramientas independientes y está acotado por concurrencia. Seguir monitorizando token usage, latencia de proveedor y presupuestos de subagentes.
- El summary usa una estimación de tokens por caracteres; idiomas, XML, JSON y tokens de proveedor varían. Preferir tokenizer por modelo o margen conservador; truncar por tamaño del request antes de proveedor.
- SQLite es apropiado para uso local, pero escritura de auditoría global y concurrencia de jobs pueden competir. PostgreSQL es el backend de operación multiworker.
- Dependencias de binarios y servicios (MSF RPC, Sliver, wordlists, templates) provocan degradación por disponibilidad/versión. El readiness check debe ser parte del runbook y reportar imagen/binario versionado.
- Cada handler debe mantener contrato común de timeout/cancelación, estado `unknown` para efectos de resultado incierto y evidencia determinista. Llamadas RPC de larga duración requieren detener jobs remotos cuando se cancela localmente.

### Recomendaciones arquitectónicas

1. Definir un perfil de ejecución soportado: modo aislado obligatorio para autonomía, red egress por proxy/firewall con allowlist derivada del scope y bloqueo de destinos privados no incluidos.
2. Tratar `nexus.shell.exec` como capability de administración explícita: aprobación por defecto, controles del host (usuario/container/VM efímero), límites de syscalls/CPU/memoria/FS y política de red independiente del parser.
3. Mantener el gateway como única ruta de efectos. Exigir en tests/contratos que herramientas nuevas declaren scope, riesgo, permisos, timeout, salida y mecanismo de ejecución; impedir side effects directos desde lógica del agente.
4. Normalizar outputs a evidencia tipada antes de volver al LLM; preservar el original saneado como artefacto con hash para revisión humana.
5. Separar y versionar confianza de facts (`agent assertion` vs `verifier`) y fuentes (`target`, `tool`, `external content`); no permitir que resumen o texto remoto eleve un hecho a verificado.
6. Hacer el preflight fail-fast cuando el modo y las capabilities no sean compatibles y mostrar garantías efectivas, no solo el modo solicitado.

## 9. Mapa de lectura recomendado para otro modelo

Para comprender o cambiar la arquitectura sin empezar por documentación histórica:

1. `nexus_core/agent/react.py` → entrada pública del loop.
2. `nexus_core/agent/react_coordinator.py` y `react_services.py` → transiciones, contexto y ejecución.
3. `nexus_core/kernel/runtime.py` → task/context y puente a herramientas.
4. `nexus_core/kernel/tool_gateway.py`, `policy.py`, `approvals.py`, `invocation_journal.py` → límites de autorización y efectos.
5. `nexus_core/tools/registry.py`, `tools/handlers/<capability>.py`, `tools/parsers/` → definición e implementación concreta.
6. `nexus_core/kernel/sandbox_modes.py` y `sandbox.py` → garantías que realmente se aplican.
7. `nexus_core/scope/validator.py`, `roe.py` → autorización del target y límites del engagement.
8. `nexus_core/agent/memory.py`, `kernel/blackboard.py`, `knowledge.py`, `control_store.py` → continuidad y persistencia.
9. `nexus_core/llm/abstraction.py`, `dynamic_selector.py` → inferencia, fallback y routing.

Las guías en `docs/archive/` y notas de `roadmap_12/` son útiles como historial de decisiones, pero deben contrastarse con código actual antes de inferir comportamiento runtime.
