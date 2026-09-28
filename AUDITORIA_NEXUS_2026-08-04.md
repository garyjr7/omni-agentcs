# Auditoría de NEXUS hacia un Directorio Empresarial de Agentes

> Estado posterior: los hallazgos fueron tratados por la implementación descrita en
> `REPORTE_IMPLEMENTACION_NEXUS_2026-08-04.md`. Este documento se conserva como línea
> base histórica, no como descripción del runtime actual.

Fecha: 2026-08-04

## Dictamen ejecutivo

NEXUS sí iba parcialmente en la dirección correcta: ya contiene prototipos de registro y descubrimiento de agentes, registro de herramientas, orquestador, EventBus, estado, memoria, workflows, HITL, auditoría, proveedores de modelos, scheduler y API administrativa. Es una base de laboratorio útil, no todavía un kernel empresarial.

La visión actual está aproximadamente en estas etapas:

- 55% prototipo de fábrica/orquestador de agentes.
- 25% panel operativo y funciones departamentales.
- 10–15% de lo necesario para un verdadero directorio multiempresa de agentes.
- 0% de una capa MCP/A2A interoperable y endurecida para producción.

La brecha principal no es agregar más agentes. Es convertir piezas en memoria y SQLite, hoy estrechamente acopladas, en servicios con contratos durables, identidad verificable, autorización por política, aislamiento de ejecución y observabilidad.

## Lo que ya existe y se puede conservar

| Capacidad objetivo | Evidencia actual | Evaluación |
|---|---|---|
| Registro de agentes | `nexus_core/agents/registry.py` y tabla `agents` | Buen inicio, pero hay dos fuentes de verdad y el registro vive en memoria. |
| Descubrimiento | Búsqueda por `AgentCapability` y carga | Local y estática; faltan versiones, contratos, salud distribuida y metadatos de tenant. |
| Registro de herramientas | `nexus_core/skills/registry.py` y rutas `/tools` | Demasiado mínimo; no hay schemas, versiones, scopes, procedencia ni lifecycle. |
| Orquestación | `NexusOrchestrator`, reintentos, cola y checkpoints | Prototipo útil; la cola, tareas activas y semáforos viven en un proceso. |
| Workflows | DAG en `workflow_manager.py` | Buena dirección; falta persistencia durable, compensación, idempotencia, versionado y recuperación real. |
| Eventos | `EventBus` | Útil dentro de un proceso; no es un bus durable ni soporta consumidores distribuidos. |
| Memoria/vector | SQLite, memory manager y ChromaDB | Existe, pero no tiene gobierno, clasificación, retención, ACL por objeto ni defensa ante contaminación. |
| HITL/kill switch | Rutas y managers dedicados | Diferenciador valioso; debe unificarse con políticas y auditoría inmutable. |
| Model routing | abstracción OpenAI/Gemini y catálogo API | Parcial; dependencias duplicadas y no hay routing por coste, latencia, región, sensibilidad o evaluación. |
| Admin UI | React/Vite con páginas de agentes, RBAC, memoria, HITL, etc. | Es apropiado conservarla como plano de control, no como interfaz conversacional principal. |

## Hallazgos críticos

### P0 — Bloquean cualquier MCP o conector expuesto

1. **La frontera de autenticación no es segura ni única.** Existen dos árboles de auth (`nexus_api/auth/router.py` y `nexus_api/routes/auth.py`), varios módulos de dependencias y secretos JWT/admin por defecto. El sistema debe negarse a arrancar en producción si faltan secretos fuertes; nunca crear una cuenta conocida automáticamente.
2. **CORS permite cualquier origen junto con credenciales.** Debe configurarse por ambiente y origen explícito.
3. **Ejecución arbitraria sin sandbox real.** Hay `create_subprocess_shell`, `shell=True` y comandos formados desde parámetros en tareas, Junior, agentes generados, Docker, Git, nuclei y pentest. Regex/HITL no sustituyen aislamiento. Cada ejecución debe correr en un worker efímero sin privilegios, con filesystem, red, CPU, RAM y tiempo limitados.
4. **Autorización gruesa.** `admin/operator/viewer` no expresa `quién puede usar qué agente/herramienta, sobre qué recurso, desde qué conector, con qué finalidad y riesgo`. Faltan permisos por recurso y decisiones de política centralizadas.
5. **Estado no distribuido.** Registry, EventBus, HITL, StateManager, workflow state y colas dependen del proceso. El propio código advierte problemas con múltiples workers mientras Docker configura dos workers mediante otra variable distinta.
6. **Auditoría no demostrablemente inmutable.** Para empresa se requieren IDs correlacionados, actor humano y de workload, inputs/outputs redactados, decisión de política, aprobación, hashes de artefactos y retención protegida.

### P1 — Bloquean un producto empresarial

1. No existe multi-tenancy fuerte: `tenant_id` obligatorio, aislamiento de datos, claves, cuotas, límites y políticas.
2. No existe un modelo canónico de directorio para organizaciones, departamentos, usuarios, grupos, service accounts, agentes, tools, connectors, credentials, models, policies y relaciones.
3. SQLite y archivos JSON son adecuados para demo, no para control plane concurrente. Migrar a PostgreSQL con migraciones y restricciones.
4. No hay cola/workflow durable. Adoptar temporalmente Redis Streams/NATS JetStream o una plataforma de workflow durable; separar API, scheduler y workers.
5. Los agentes generados son archivos Python dentro del producto. Deben ser paquetes/versiones firmados o definiciones declarativas inmutables, promovidas dev → staging → prod.
6. No hay Vault/KMS real, rotación, credenciales delegadas ni tokens de corta duración para conectores.
7. No hay contratos de API versionados, idempotency keys, outbox, control de concurrencia o estrategia de compatibilidad.
8. No hay evaluaciones sistemáticas: datasets dorados, pruebas de tool selection, seguridad, calidad, coste, regresión y canary releases.

### P2 — Calidad y mantenibilidad

1. Dependencias Python sin lock y varias sin versión; `google-generativeai` está duplicado y convive con `google-genai`.
2. El checkout no instala las herramientas de prueba/build: `pytest` no está disponible, `vite` no está instalado y lint cae en ESLint global 6 aunque el proyecto declara ESLint 9.
3. Solo hay tres archivos unitarios de core; faltan pruebas API, auth/RBAC, workflows, persistencia, aislamiento, conectores y end-to-end.
4. El startup tolera imports rotos con `safe_include`; producción puede anunciarse healthy con módulos ausentes. Los componentes obligatorios deben fallar rápido.
5. Hay afirmaciones como “Military Grade”, “Zero Trust” y “superior a LangGraph” que hoy no están sustentadas. Deben retirarse de documentación y producto hasta tener controles y benchmarks verificables.
6. `data/` mezcla base de datos viva, WAL/SHM, logs, resultados de pentest, proyectos generados y reportes dentro de Git.

## Arquitectura objetivo

```text
ChatGPT / Claude / Gemini / Codex / CLI / n8n
                 │
       MCP Gateway + REST + A2A
                 │
       API Gateway / OAuth / OIDC
                 │
┌──────────────── Control Plane ────────────────┐
│ Directory │ Policy │ Registry │ Model Router │
│ Workflows │ Audit  │ Secrets  │ Evaluations  │
└──────────────────────┬────────────────────────┘
                       │ eventos/tareas durables
┌──────────────── Execution Plane ───────────────┐
│ Workers aislados │ Agent runtime │ Tool proxy │
│ Desktop/edge connectors con identidad propia  │
└──────────────────────┬─────────────────────────┘
                       │
             Sistemas y datos autorizados
```

### Principios

- **MCP es una puerta para tools/resources**, no el kernel.
- **A2A es la puerta opcional para delegar entre agentes independientes.**
- **El directorio y la política son la fuente de verdad.** Ningún cliente decide permisos.
- **Control plane separado del execution plane.** El API nunca ejecuta shell directamente.
- **Cada acción tiene identidad, autorización, límite, trazabilidad e idempotencia.**
- **Provider-neutral en contratos, no en el mínimo común denominador.** Conservar adaptadores por proveedor para capacidades avanzadas.

## Modelo mínimo de BAJIOWARE AI Directory

Entidades iniciales:

- `organizations`, `tenants`, `departments`, `environments`
- `users`, `groups`, `service_accounts`, `workload_identities`
- `agents`, `agent_versions`, `capabilities`, `agent_assignments`
- `tools`, `tool_versions`, `tool_schemas`, `connectors`
- `resources`, `credentials_refs`, `models`, `model_routes`
- `roles`, `permissions`, `policies`, `policy_bindings`
- `workflows`, `workflow_versions`, `runs`, `tasks`, `approvals`
- `memory_spaces`, `knowledge_bases`, `documents`, `retention_rules`
- `audit_events`, `artifacts`, `evaluations`, `budgets`, `quotas`

Toda entidad de negocio debe incluir tenant, versión, estado, propietario, clasificación, timestamps y etiquetas; las relaciones importantes deben tener vigencia y procedencia.

## Estándares y tecnología recomendados en 2026

1. **MCP:** implementar mediante SDK oficial, con HTTP remoto, OAuth/OIDC, schemas JSON completos y lifecycle/versiones. Mantener el protocolo detrás de adaptadores para absorber cambios; la revisión candidata 2026-07-28 introduce core stateless, extensiones, Tasks y endurecimiento de autorización.
2. **A2A:** ofrecer Agent Cards y delegación solo después del directorio. A2A y MCP son complementarios: agentes vs. herramientas.
3. **Identidad humana:** OIDC/OAuth 2.1 con un IdP externo; SCIM para provisionamiento empresarial. No construir contraseñas corporativas propias como producto principal.
4. **Identidad de workloads/conectores:** mTLS y, al crecer, SPIFFE/SPIRE para identidades cortas y verificables por proceso/nodo.
5. **Política:** motor PDP central (OPA/Rego, Cedar u otro) con decisiones registradas; RBAC + ABAC/ReBAC.
6. **Observabilidad:** OpenTelemetry para traces, logs y métricas; propagar `trace_id` desde cliente → MCP → workflow → agente → tool → modelo.
7. **Persistencia:** PostgreSQL para control plane; object storage S3-compatible para artefactos; vector search como índice derivado, no fuente de verdad.
8. **Ejecución:** contenedores/microVMs efímeros, seccomp/AppArmor, usuario no root, rootfs read-only, egress allowlist y credenciales scoped por ejecución.
9. **Supply chain:** SBOM, imágenes firmadas, provenance/SLSA, escaneo de dependencias y agentes/tools firmados.
10. **Model gateway:** Responses/Agents SDK u homólogos mediante adapters; routing por política, datos, región, SLA, coste y eval score; presupuestos y caching seguros.

Referencias primarias consultadas:

- https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
- https://a2a-protocol.org/latest/
- https://openai.com/index/new-tools-and-features-in-the-responses-api/
- https://opentelemetry.io/docs/specs/semconv/
- https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/
- https://www.rfc-editor.org/info/rfc7644/

## Roadmap propuesto

### Tramo 0 — Congelar y hacer reproducible (2–3 semanas)

- Definir ADRs, alcance y vocabulario; renombrar “agente/skill/tool/task” de forma consistente.
- Unificar auth y DB; eliminar defaults inseguros y proteger todas las rutas.
- Crear locks, migraciones, CI, unit/integration/e2e tests y una instalación reproducible.
- Sacar outputs de `data/` de Git y definir backup/retención.
- Deshabilitar ejecución shell directa hasta tener sandbox.

### Tramo 1 — Kernel v1 (4–8 semanas)

- PostgreSQL, modelo tenant-aware y repositorios únicos.
- Task/event backbone durable, workers separados e idempotencia.
- Registry versionado para agentes/tools y workflow engine durable.
- Audit envelope y OpenTelemetry de extremo a extremo.
- Policy Decision Point y approvals basadas en riesgo.

### Tramo 2 — AI Directory v1 (4–8 semanas)

- Organizaciones, grupos, departamentos, entornos y service accounts.
- RBAC + ABAC, scopes por tool/resource, budgets y quotas.
- OIDC/SCIM, secretos externos e identidad de conectores.
- Panel administrativo enfocado en control, no chat.

### Tramo 3 — Interoperabilidad (3–6 semanas)

- MCP Gateway con un conjunto pequeño y seguro de tools.
- REST/SDK estable; luego A2A para agentes remotos.
- Desktop Connector con enrolamiento, mTLS, actualización firmada, allowlists y revocación remota.

### Tramo 4 — Departamentos como paquetes

- Empezar por Marketing como cliente interno del kernel.
- Cada departamento aporta definiciones, tools, policies, knowledge, evals y dashboards; no forks del core.
- Promoción y rollback de paquetes con métricas de negocio.

## Estrategia competitiva realista

No conviene competir con OpenAI, Anthropic o Google entrenando un modelo fundacional ni copiando sus chats. La oportunidad defendible es el **control plane empresarial neutral**: gobierno multi-modelo, integración local, identidad de agentes y conectores, políticas, auditoría, ejecución segura y paquetes departamentales para PyMES/mercado latinoamericano.

El “moat” puede ser:

- instalación híbrida/on-prem y conectores de escritorio seguros;
- políticas y auditoría listas para empresas reguladas;
- catálogo de agentes/tools evaluados y firmados;
- metodología BAJIOWARE de ciberseguridad y operación;
- soporte en español, plantillas locales y despliegue administrado;
- evidencia medible de calidad, coste y seguridad por workflow.

## Limpieza realizada

Se eliminaron:

- 2 respaldos dentro de `.backups/`;
- 5 copias `.bak`/`.save` de módulos activos;
- 3 PID versionados;
- el archivo mal nombrado `nexus_api/services/__init_py`;
- 2 assets por defecto de Vite/React sin referencias;
- 19 scripts históricos `nexus_punto*`, `nexus_fix*`, `nexus_pages.sh`, `nexus_backend_complete.sh` y generadores de frontend no usados por runtime/instalación;
- 7 árboles `__pycache__` locales.

También se amplió `.gitignore` para PID, backups, WAL/SHM, logs, dist y caché de pytest.

No se borraron `data/reports`, `data/factory/projects`, `data/junior_workspace`, pentests ni la landing page: parecen outputs históricos o activos de negocio. Deben revisarse con el propietario y migrarse fuera del repositorio. Tampoco se tocaron las 36 modificaciones de código preexistentes ni los dos archivos nuevos encontrados al comenzar la auditoría.

## Criterio de salida para llamar a NEXUS “Kernel v1”

NEXUS será un kernel y no una demo cuando pueda demostrar en CI y staging que:

1. un tenant no puede ver ni ejecutar recursos de otro;
2. toda tool call es autorizada por política y queda auditada;
3. una caída durante un workflow permite reanudar sin duplicar efectos;
4. ningún agente ejecuta en el proceso del API ni obtiene credenciales globales;
5. un conector puede enrolarse, rotar identidad y revocarse;
6. MCP y REST usan el mismo servicio y las mismas políticas;
7. cada versión de agente/tool tiene schema, firma, evals y rollback;
8. trazas, coste, latencia, tokens, errores y aprobaciones se correlacionan de extremo a extremo.
