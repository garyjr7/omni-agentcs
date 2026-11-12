# Auditoría del playbook declarativo y la telemetría por turno

## Dictamen

**No se puede certificar todavía el cumplimiento de los contratos solicitados.** La separación de módulos es razonable, el YAML utiliza un parser seguro y las invocaciones ordinarias mantienen el gateway. Sin embargo, hay tres hallazgos P1: pérdida del límite de capacidades al delegar jobs, publicación síncrona de telemetría en el event loop y progreso del playbook que puede completarse con hechos ajenos a sus pasos. También falta conectar la validación semántica del catálogo a la carga normal.

Además, `mypy --strict` **no pasa**: hay dos errores en `subagents.py`. Las **143 pruebas focalizadas pasan**, pero no cubren varios de los casos adversos reproducidos en esta auditoría. Pasar esas pruebas no acredita los invariantes adicionales solicitados.

Esta revisión genera informe y evidencia reproducible; no aplica parches a producción ni amplía capacidades ofensivas.

## Alcance y método

Se revisaron `playbooks/loader.py`, `playbooks/__init__.py`, `red_team_base.yaml`, `agent/turn_telemetry.py`, `react_coordinator.py`, `subagents.py` y `agent/playbooks.py`. Se siguieron sus conexiones con `react_services.py`, `react_support.py`, el handler de playbooks, `tools/handlers/jobs.py`, el runtime, el gateway, blackboard, eventos durables y telemetría del kernel.

Se ejecutaron pruebas locales de paquetes, telemetría, subagentes, efectos y scope. Los casos adicionales utilizan YAML en memoria, un directorio temporal, un sink simulado y una cola simulada. No realizan peticiones a objetivos ni ejecutan herramientas ofensivas.

Prioridades: **P1** requiere corrección antes de considerar estos contratos aptos para operación; **P2** afecta precisión, robustez o conformidad y debe entrar en la siguiente corrección. No se demostró una evasión de la autenticación de tenant, del scope firmado o de las aprobaciones del gateway.

## A. Salud del código y estructura

Aspectos sólidos:

- `yaml.safe_load` evita construir objetos Python arbitrarios mediante etiquetas YAML. El esquema Draft 2020-12 rechaza propiedades desconocidas y exige fases, gates, pasos y vocabularios reconocidos para perfiles, fases del planner, fact types y señales.
- Los paquetes y fases cargados usan dataclasses congeladas y tuplas. Hay límites declarados para número de fases/pasos y longitud de muchos campos.
- Cargar el paquete produce orientación; no dispara handlers, procesos o llamadas al LLM.
- El coordinador comprueba la pertenencia de la herramienta al perfil en la invocación directa. El worker ejecuta `tool.invoke` mediante el gateway, con validación de argumentos, políticas, scope, aprobación y journal.
- La telemetría guarda métricas y metadatos, no el texto del razonamiento del modelo. Su resultado por turno es una dataclass congelada. Las excepciones ordinarias de cada sink se capturan por separado.
- `append_run_event` valida un DTO de evento, sanea el payload y escribe mediante su propia transacción. La nueva telemetría no modifica directamente las filas de hechos del blackboard.
- El manifiesto de empaquetado incluye los YAML y declara PyYAML como dependencia.

Estas propiedades no equivalen a un workflow transaccional: el paquete se transforma en sugerencias de prompt. Sus declaraciones `verification`, `noise` y `telemetry` no se convierten en condiciones ejecutables del gateway.

## B. Hallazgos

### A01 — P1: los jobs pierden la restricción del perfil que los origina

**Referencias:** `agent/subagents.py:325`, `agent/subagents.py:366`, `agent/react_coordinator.py:855`, `tools/handlers/jobs.py:53`, `kernel/runtime.py:262`.

`privesc` y `postexploit` reciben `nexus.post.job`. El coordinador comprueba el ID externo del job, pero el handler acepta cualquier herramienta registrada salvo otro job. El payload encolado conserva identidad, permisos y engagement, pero no un conjunto de capacidades autorizado por el perfil. El worker no vuelve a comprobar ese perfil.

**Reproducción:** el perfil `privesc` permite el wrapper y rechaza directamente `nexus.web.upload`; aun así, el handler acepta encolar esa herramienta en una cola simulada. No se transmitió ningún archivo.

**Impacto:** el límite de especialización/capacidades del subagente no se mantiene a través de la delegación. No demuestra escalamiento a root ni evasión del gateway: las políticas y aprobaciones de la herramienta interna siguen aplicándose al ejecutarse.

**Corrección recomendada:** transportar una restricción de capacidades emitida por el coordinador/gateway, nunca confiada a argumentos del modelo. Comprobar la herramienta interna al encolar y otra vez al ejecutar, además de las políticas ordinarias. Considerar también el presupuesto del perfil que origina el trabajo. Añadir pruebas negativas de delegación fuera del perfil y de payload alterado.

### A02 — P1: la telemetría tolera excepciones, pero bloquea el event loop

**Referencias:** `agent/turn_telemetry.py:355`, `agent/turn_telemetry.py:379`, `agent/react_coordinator.py:1252`, `kernel/control_store.py:327`.

`finish()` llama directamente a `_publish()`. Span, métricas y `store.append_run_event()` son llamadas síncronas. La captura de excepciones no limita el tiempo que pueden tardar. SQLite está configurado con `timeout=10`, por lo que una contención de escritura puede retener el hilo mientras espera.

**Reproducción:** un sink local simulado que tarda 80 ms hace que `finish()` tarde aproximadamente 80 ms. La ejecución del coordinador llama a ese método dentro de su coroutine, sin desacoplarlo.

**Impacto:** puede retrasar cancelaciones, otros runs y la planificación de heartbeats. No se observó corrupción de tablas, pero el contrato «no bloqueante» no está implementado.

**Corrección recomendada:** separar construcción del registro y publicación mediante una cola acotada y un consumidor dedicado. Definir política de saturación, contador de registros perdidos, límites de espera de DB y cierre con plazo. No basta con lanzar threads sin límite ni con envolver I/O síncrono en `asyncio.wait_for`, que no interrumpe ese I/O.

### A03 — P2: el loader acepta herramientas inexistentes; la comprobación del catálogo sólo se usa en pruebas

**Referencias:** `playbooks/loader.py:342`, `playbooks/loader.py:435`, `agent/playbooks.py:213`.

El campo `tool_id` sólo se valida con un patrón de caracteres. `load_package_text()` y `load_packages(strict=True)` no llaman a `validate_against_catalog()`. La búsqueda de referencias encuentra esa comprobación en las pruebas y exports, no en la carga productiva.

**Reproducción:** sustituir un paso por `nexus.nonexistent` sigue produciendo un `LoadedPackage`. La llamada separada a `validate_against_catalog()` detecta el error.

**Impacto:** un paquete «estrictamente cargado» puede recomendar herramientas inexistentes o incompatibles con su perfil. El gateway rechaza una invocación inválida; el problema es degradación del plan, consumo de turnos y una promesa de validación incorrecta, no ejecución de un ID arbitrario.

**Corrección recomendada:** distinguir parsing estructural y compilación semántica, y exigir ambos antes de publicar un paquete. Inyectar un snapshot del catálogo para evitar ciclos de importación; validar ID, disponibilidad, compatibilidad de perfil y colisiones entre paquetes. Hacer visible el rechazo al operador.

### A04 — P1: los gates y el progreso no representan la ejecución verificada de los pasos

**Referencias:** `agent/playbooks.py:268`, `playbooks/loader.py:244`, `agent/react_support.py:95`, `playbooks/red_team_base.yaml:195`.

La finalización se decide por presencia global de un `fact_type`. No se liga a la invocación del paso, herramienta, objetivo o ejecución del playbook. Los pasos `produces: null` se consideran completos cuando aparece un hecho de un paso posterior; sin ese hecho, pueden quedar como primera sugerencia repetida.

Además, los gates y `_completion()` no filtran hechos con `is_verified_fact()`, mientras que la orientación del prompt recibe `Blackboard.list_facts()` directamente. Esto difiere del resumen verificado que usa el planner.

**Reproducción:** la fase `command_execution` figura completamente terminada con un hecho preexistente de tipo `session`, incluso sin metadatos de verificación. Ese tipo completa `durable_job_handoff`, y por arrastre los dos pasos anteriores. Encolar un job, además, no crea por sí mismo una sesión.

**Impacto:** etapas omitidas, progreso aparente o bucles de preparación repetidos. Los gates son orientación y no autorizan operaciones por sí mismos; no reemplazan el scope ni la aprobación.

**Corrección recomendada:** separar evidencia de elegibilidad y estado de ejecución del paso; filtrar evidencia verificada y relacionarla con objetivo, run e invocación. Si se requiere ejecución durable, persistir transiciones de pasos con CAS/idempotencia usando las primitivas existentes del kernel. No asignar al job un resultado de dominio que su contrato no produce. Validar los requisitos como datos estructurados, no como prosa.

### A05 — P2: varias métricas no describen fielmente el turno

**Referencias:** `agent/turn_telemetry.py:228`, `agent/turn_telemetry.py:280`, `agent/turn_telemetry.py:326`, `agent/turn_telemetry.py:389`, `agent/react_coordinator.py:1181`, `agent/react_coordinator.py:1219`.

Casos comprobados o visibles en el recorrido:

1. **Baseline:** `_previous_counts` empieza vacío. Un primer turno con ocho hechos existentes y ninguna incorporación informa `blackboard_delta=8`. La comparación correcta por turno debe partir del snapshot tomado al iniciarlo.
2. **Concurrencia:** los conteos abarcan el engagement. Un cambio escrito por otro worker puede atribuirse al turno actual. Una actualización de valor sin cambio de cantidad resulta invisible. Las bajas quedan ocultas por `max(0, delta)`.
3. **Snapshot vacío:** `if counts:` ignora un blackboard realmente vacío y lo trata igual que una lectura fallida.
4. **Outcome:** `self.status` comienza como `max_iterations`; `_turn_outcome()` lo devuelve durante turnos ordinarios. La reproducción devuelve ese estado para `NEXT_TURN`. La ruta de excepción también puede usar ese estado por defecto.
5. **Tiempo:** `turn_started` se toma después de construir contexto y seleccionar perfil, aunque `turn_ms` declara incluir esa preparación. `reasoning_ms` mide la llamada al proveedor, con sus esperas, no una medida interna de razonamiento. El span se abre y cierra al publicar: su duración nativa no es la del turno.
6. **Tokens:** cuando faltan ambos contadores, la estimación pasa a `prompt_tokens` y al contador total. En errores del proveedor esto puede etiquetar como consumo confirmado una estimación. Las llamadas de compactación del contexto tampoco están incluidas en ese registro.
7. **Fricción:** `CancelledError` se clasifica como `timeout`. Cuando un handler devuelve `success=false` sin lanzar excepción, el coordinador no pasa una clasificación detallada a `note_tool()`: puede perder la distinción entre timeout, indisponibilidad y negativa válida.

**Corrección recomendada:** snapshot inicial/final explícito con indicador de disponibilidad; distinguir delta agregado de evidencia atribuida por `invocation_id`; separar tokens observados/estimados/desconocidos; estados de turno independientes del estado terminal del run; reloj desde el inicio efectivo; clasificar el DTO de resultado y cancelación de forma explícita.

### A06 — P2: el contrato de aislamiento de errores no cubre el acumulador

**Referencias:** `agent/turn_telemetry.py:186`, `agent/turn_telemetry.py:321`, `agent/react_coordinator.py:1241`.

La protección se concentra en `_publish()`. Conversiones numéricas, cálculo de delta y construcción del registro pueden lanzar antes. `finish()` borra `_draft` antes de construir el registro. Un fallo en el cierre de telemetría dentro del manejador de una excepción puede reemplazar la excepción original del run.

**Reproducción adversa:** un contador inválido produce `ValueError`, y después `has_open_turn` es falso. El dato introducido viola el tipo declarado del contador; esta prueba verifica la promesa defensiva «nunca aborta», no demuestra que `Blackboard.summary()` produzca habitualmente datos inválidos. Las fronteras con `Any` y proveedores hacen relevante delimitar esa garantía.

**Corrección recomendada:** validar y normalizar entradas en el límite; producir primero un registro válido y después cerrar el draft; garantizar un cierre degradado que no oculte la excepción original. Contabilizar fallos de telemetría en lugar de descartarlos silenciosamente. Evitar capturar indiscriminadamente cancelaciones de la ejecución principal.

### A07 — P2: aceptación ambigua del YAML y degradación de todos los paquetes

**Referencias:** `playbooks/loader.py:76`, `playbooks/loader.py:254`, `playbooks/loader.py:357`, `playbooks/loader.py:418`.

- `safe_load` acepta claves repetidas; se conserva la última. La reproducción acepta un documento con dos `schema_version`.
- El gate permite combinar `always`, `any_fact_types` y `all_fact_types`; `always: true` descarta las demás condiciones. `any` y `all` se combinan como OR. Un `always: false` sin otra condición también es válido, aunque nunca abre el gate. Falta una semántica inequívoca.
- La comprobación de `produces` opera sobre todo el paquete, aunque el mensaje sugiere una fase. Una fase con todos sus pasos `produces: null` se acepta cuando otra fase sí produce hechos.
- Un archivo inválido provoca `()` para **todos** los paquetes en modo no estricto, en lugar de excluir sólo ese archivo como declara el docstring. Un archivo válido junto a uno inválido reproduce este comportamiento.
- Los máximos del esquema se aplican después del parseo: la lectura del archivo y el árbol YAML no tienen un límite previo de bytes/profundidad. No se realizó una prueba de agotamiento de memoria.

**Corrección recomendada:** loader seguro que rechace claves duplicadas; cuota de entrada antes del parseo; gate discriminado con `oneOf` o composición lógica explícita; validaciones por fase; carga y diagnóstico individual por archivo. Decidir si se conserva la última versión válida ante una edición defectuosa. Distinguir fallos de lectura/codificación de un directorio sin paquetes.

### A08 — P2: no hay conformidad total con `mypy --strict`

El comando aplicado a seis módulos de producción termina con código de error:

```text
nexus_core/agent/subagents.py:539: error: Function is missing a type annotation for one or more parameters [no-untyped-def]
nexus_core/agent/subagents.py:631: error: Missing type arguments for generic type "Future" [type-arg]
Found 2 errors in 1 file (checked 6 source files)
```

**Corrección recomendada:** tipar `definition` mediante un protocolo o unión de definición/entrada de catálogo/None y parametrizar el watcher como `asyncio.Future[None] | None`, de acuerdo con el retorno de `_watch()`. La presencia de `Any` y `follow_imports=skip` limita la garantía incluso después de corregir esos dos errores. No se atribuye necesariamente la introducción de ambos a este último cambio: sí afectan al cumplimiento del estado auditado.

## Mapeo de las capacidades solicitadas

| Perfil | web.request | web.upload | post.shell_exec | post.job | web.git_dump |
| --- | --- | --- | --- | --- | --- |
| web, read-only | — | — | — | — | Sí |
| services | Sí | Sí | — | — | Sí |
| exploit | Sí | Sí | — | — | Sí |
| postexploit | — | — | Sí | Sí | — |
| privesc | — | — | Sí | Sí | — |

Los otros perfiles no incluyen esas cinco herramientas en su conjunto base. La gracia entre fases puede heredar herramientas consideradas read-only, entre ellas Git dump; las cuatro activas constan en `ACTIVE_TOOLS` y no deben heredarse por esa vía. El catálogo actual y las pruebas focalizadas no muestran una asignación directa de upload/shell/job a un perfil read-only.

Hay una fragilidad adicional: para herramientas internas `permits()` consulta pertenencia al conjunto, no los efectos de la definición recibida. Si un plugin reemplaza una definición existente o cambia su efecto, el perfil read-only depende de mantener sincronizada la clasificación estática. Conviene comprobar también el efecto efectivo en tiempo de ejecución. Esto es un riesgo de extensión, no un reemplazo malicioso demostrado en el catálogo actual.

## Límites transaccionales y contrato del YAML

El registro de eventos usa una transacción distinta de la invocación/journal y de las escrituras del blackboard. OTel, métricas y DB tampoco forman una unidad atómica. Puede existir el resultado de la herramienta sin su evento de telemetría, o un contador publicado sin persistencia durable. Es compatible con observabilidad best-effort, pero no con una promesa de auditoría exacta o entrega exactamente una vez.

Los eventos carecen de una clave de idempotencia específica de turno/reanudación. Para correlación durable se recomienda una identidad estable de turno e intento y relación con `invocation_id`; para entrega garantizada, un outbox ligado a una transacción existente. No conviene introducir una transacción larga que abarque LLM, herramienta y exporters. Los eventos operativos tampoco sustituyen la cadena criptográfica de `AuditWriter`.

El archivo actual tiene cuatro fases, pero sus IDs son `stealth_recon`, `staging_and_interaction`, `command_execution` y `local_elevation_heuristics`. Los tres últimos no coinciden literalmente con los IDs del requerimiento original. No hay una etapa de persistencia implementada ni una verificación específica de Dirty COW; el texto menciona condiciones de carrera de forma general. `noise`, `notes` y `telemetry` no se conservan en `LoadedPhase`; `verification` se mezcla en un rationale truncado a 400 caracteres. No hay parámetros ejecutables que impongan el ruido declarado. Estas diferencias deben reflejarse en el contrato del producto, sin presentar la orientación textual como controles implementados.

## C. Orden recomendado de corrección y aceptación

1. **Autoridad y disponibilidad:** mantener las capacidades y presupuesto del perfil a través de jobs; desacoplar los sinks con cola limitada. Probar saturación, contención de DB y continuidad del heartbeat/cancelación.
2. **Carga y estado:** compilar contra el catálogo real antes de publicar; rechazar YAML ambiguo; asociar progreso a evidencias verificadas de cada paso y objetivo. Probar sesiones preexistentes, hechos sin verificar, otro target, varios paquetes y reanudación.
3. **Observabilidad fiel:** baseline por turno, tokens medidos separados de estimaciones, outcomes independientes, snapshot vacío frente a fallo de lectura y cierre seguro ante errores. Probar dos workers escribiendo al mismo engagement.
4. **Tipos e integración:** resolver los dos errores estrictos; reducir `Any` en store, proveedor y definición de herramienta; repetir las pruebas focalizadas y añadir integración de telemetría bajo contención tanto en SQLite como PostgreSQL.

## Evidencia y alcance de la validación

- `143 pruebas focalizadas aprobadas`, con una advertencia de deprecación de `google.genai`.
- `Resultado de mypy estricto`: dos errores.
- `Ruff F/E9`: sin errores.
- [Reproducciones mínimas](evidencia_auditoria_playbook/reproducir.py) y [resultados JSON](evidencia_auditoria_playbook/resultados.json).

Comandos reproducibles desde la raíz del repositorio:

```bash
.venv/bin/python -m mypy --strict nexus_core/playbooks/__init__.py nexus_core/playbooks/loader.py nexus_core/agent/turn_telemetry.py nexus_core/agent/react_coordinator.py nexus_core/agent/subagents.py nexus_core/agent/playbooks.py
NEXUS_ARTIFACT_ROOT=/tmp/playbook-audit-artifacts NEXUS_E2E=0 .venv/bin/python -m pytest nexus_core/tests/unit/test_playbook_packages.py nexus_core/tests/unit/test_turn_telemetry.py nexus_core/tests/unit/test_subagents.py nexus_core/tests/unit/test_effect_contract.py nexus_core/tests/unit/test_scope_wiring.py -q --tb=short
PYTHONPATH=. .venv/bin/python roadmap_12/evidencia_auditoria_playbook/reproducir.py
```

No se ejecutó la suite completa ni una nueva campaña de concurrencia PostgreSQL en esta auditoría. La prueba de delegación utiliza mocks, no ejecución end-to-end de una operación interna. El bloqueo del sink se mide de forma aislada; el impacto sobre leases bajo contención es un riesgo deducido del recorrido síncrono, no una pérdida de lease observada en estas pruebas. La auditoría deja esos límites explícitos y no certifica ausencia de regresiones fuera del alcance revisado.
