# Plan de implementación de NEXUS

Fecha base: 2026-08-04  
Documento de referencia: `AUDITORIA_NEXUS_2026-08-04.md`

Estado de ejecución: implementación terminada el 2026-08-04. La evidencia y las
validaciones externas pendientes están en `REPORTE_IMPLEMENTACION_NEXUS_2026-08-04.md`.

## Objetivo

Transformar NEXUS desde un prototipo de fábrica de agentes en un kernel y directorio empresarial de agentes, independiente de proveedor, consumible por MCP, REST, CLI y posteriormente A2A, con ejecución aislada y un laboratorio de automejora gobernada.

El desarrollo inicial debe funcionar sin GPU local y sin consumir APIs de pago.

## Regla de implementación

No se agregará otro departamento ni más agentes hasta estabilizar el kernel. Cada fase debe quedar funcionando, probada y documentada antes de comenzar la siguiente.

Prioridades:

1. Seguridad y reproducibilidad.
2. Contratos del kernel.
3. Persistencia y tareas durables.
4. Directorio, identidad y políticas.
5. Sandboxes y conectores.
6. MCP y clientes externos.
7. Evolution Lab.
8. Departamentos instalables.

## Desarrollo sin tokens

### Fake LLM determinista

Crear un proveedor `fake` compatible con la misma interfaz que OpenAI, Groq, Gemini, Ollama o vLLM. Debe responder desde fixtures JSON según el nombre del escenario.

Ejemplos:

- `planner.simple_success`
- `planner.invalid_json`
- `tool_call.safe`
- `tool_call.forbidden`
- `provider.timeout`
- `provider.rate_limited`
- `agent.prompt_injection`

Esto permite probar planificación, reintentos, tool calls, workflows, auditoría, políticas y UI sin llamar modelos reales.

### Record/replay

Cuando ocasionalmente se use una API real, guardar una respuesta sanitizada como fixture. Las siguientes pruebas reproducen esa respuesta localmente.

Nunca guardar API keys, datos de clientes, prompts confidenciales o respuestas sin sanitizar.

### Simuladores de herramientas

Las herramientas deben disponer de modo simulado:

- filesystem temporal;
- HTTP falso mediante servidor local;
- repositorios Git de fixture;
- reloj controlable;
- ejecución de comandos permitidos dentro de sandbox;
- APIs sociales, email y CRM simuladas.

### Uso de proveedores reales

Los proveedores gratuitos o promocionales se utilizarán solamente para smoke tests manuales y evaluaciones pequeñas. NEXUS no debe asumir que Groq, OpenAI, Gemini u otro proveedor conservará una cuota gratuita.

## Fase 0 — Preservación y línea base

Duración estimada: 2–3 días.

### Trabajo

- Crear una rama de estabilización.
- Etiquetar el estado actual antes de cambios estructurales.
- Separar las modificaciones preexistentes de la limpieza realizada.
- Documentar comandos oficiales de instalación, desarrollo, pruebas y arranque.
- Clasificar `data/` en datos activos, fixtures, ejemplos, reportes y basura.
- Respaldar fuera de Git proyectos y reportes que tengan valor.
- Crear ADR-001 con la visión: kernel independiente + gateways.

### Criterio de salida

- Existe un punto de recuperación verificable.
- Se conoce qué datos pueden eliminarse o migrarse.
- Hay un solo procedimiento oficial para arrancar NEXUS.

## Fase 1 — Build reproducible y seguridad inmediata

Duración estimada: 1–2 semanas.

### Backend

- Unificar `nexus_api/auth/router.py` y `nexus_api/routes/auth.py`.
- Unificar módulos de dependencias y bases de datos duplicados.
- Eliminar secretos y contraseñas predeterminados.
- Fallar al arrancar en producción si faltan secretos obligatorios.
- Configurar CORS mediante allowlist por ambiente.
- Proteger todas las rutas y WebSockets.
- Definir roles iniciales sin usar bypass implícito de desarrollo.
- Sustituir excepciones silenciosas y `safe_include` en módulos obligatorios.
- Deshabilitar temporalmente tools que ejecutan shell con entrada dinámica.

### Tooling

- Elegir un único gestor Python y generar lock reproducible.
- Eliminar dependencias duplicadas o abandonadas.
- Usar `npm ci` para frontend.
- Incorporar lint, format, type checking y tests a CI.
- Añadir escaneo de secretos y dependencias.
- Añadir migraciones de base de datos.

### Pruebas mínimas

- Login, refresh, logout y expiración.
- Acceso admin/operator/viewer.
- Rutas sin token y token inválido.
- CORS.
- Startup sin configuración insegura.
- Smoke test del frontend.

### Criterio de salida

- Un checkout limpio se instala y prueba con comandos documentados.
- No hay credenciales conocidas ni CORS global en producción.
- Ninguna ruta crítica queda abierta por accidente.
- CI bloquea errores de sintaxis, lint, tests y secretos.

## Fase 2 — Contratos del Kernel

Duración estimada: 1–2 semanas.

### Definir interfaces canónicas

- `ModelProvider`
- `AgentRuntime`
- `AgentRegistry`
- `ToolRegistry`
- `PolicyDecisionPoint`
- `MemoryStore`
- `ArtifactStore`
- `TaskQueue`
- `EventBus`
- `AuditSink`
- `SandboxRuntime`

### Modelos canónicos

- `AgentDefinition` y `AgentVersion`
- `ToolDefinition` y `ToolVersion`
- `Task`, `Run`, `Workflow` y `Artifact`
- `Identity`, `Resource`, `Permission` y `PolicyDecision`
- `ModelRequest`, `ModelResponse` y `Usage`

### Proveedores iniciales

- Implementar `FakeModelProvider` primero.
- Adaptar el código actual de OpenAI y Gemini a la interfaz.
- Crear adaptador compatible con APIs estilo OpenAI para Groq u otros.
- Reservar adaptadores Ollama/vLLM sin requerirlos para CI.

### Criterio de salida

- Los tests completos del kernel funcionan con `FakeModelProvider`.
- Cambiar de proveedor no modifica agentes ni workflows.
- Ningún agente importa directamente SDKs de proveedores.

## Fase 3 — Control plane persistente

Duración estimada: 2–4 semanas.

### Persistencia

- Introducir PostgreSQL para producción y mantener SQLite solamente para desarrollo pequeño si resulta útil.
- Añadir `tenant_id`, versión, propietario, estado y timestamps a entidades.
- Crear migraciones y repositorios; no usar SQL disperso en rutas.
- Añadir restricciones, índices y concurrencia optimista.
- Mover artefactos grandes a almacenamiento de objetos o filesystem abstraído.

### Entidades iniciales

- organizations, tenants, departments, environments;
- users, groups, service_accounts;
- agents, agent_versions, capabilities;
- tools, tool_versions, connectors;
- workflows, workflow_versions, runs, tasks;
- approvals, audit_events, artifacts;
- model_routes, budgets y quotas.

### Criterio de salida

- Existe una única fuente de verdad para agentes, tools y tareas.
- Reiniciar el API no pierde estado.
- Todas las consultas respetan tenant y ambiente.
- Migraciones forward y rollback se prueban automáticamente.

## Fase 4 — Ejecución durable

Duración estimada: 2–4 semanas.

### Trabajo

- Separar API, scheduler y workers.
- Reemplazar cola/eventos exclusivamente en memoria por un backend durable.
- Añadir idempotency keys y transactional outbox.
- Persistir transiciones de estado.
- Soportar cancelación, timeout, retry con backoff y dead-letter queue.
- Hacer workflows reanudables después de caídas.
- Añadir compensaciones para operaciones con efectos externos.
- Evitar duplicar publicaciones, pagos, emails o cambios de archivos.

### Criterio de salida

- Una tarea interrumpida continúa después de reiniciar workers.
- Repetir una solicitud idempotente no repite efectos.
- Los workflows muestran historial completo de transiciones.
- Los estados imposibles son rechazados.

## Fase 5 — AI Directory, identidad y políticas

Duración estimada: 3–5 semanas.

### Directory

- Organizaciones, departamentos, grupos, agentes, tools y recursos.
- Relaciones agente→departamento, tool→recurso y usuario→grupo.
- Ambientes dev/staging/prod.
- Inventario de conectores y workloads.

### Autorización

- Mantener RBAC para permisos generales.
- Agregar ABAC/ReBAC para tenant, departamento, clasificación, ambiente y riesgo.
- Centralizar decisiones en `PolicyDecisionPoint`.
- Registrar input, decisión, policy version y motivo.
- Implementar approvals de uno o dos responsables según riesgo.

### Identidad empresarial

- Preparar integración OIDC con un proveedor externo.
- Planificar SCIM para provisionamiento futuro.
- Representar service accounts y conectores como identidades, no como API keys anónimas.

### Criterio de salida

- Toda acción responde quién, qué, sobre cuál recurso y por qué fue permitida.
- Las pruebas demuestran aislamiento entre dos tenants.
- Un agente no puede otorgarse permisos ni aprobar su propia acción.

## Fase 6 — Sandbox y Tool Gateway

Duración estimada: 3–6 semanas.

### Tool Gateway

- Toda tool call pasa por validación de schema, política, cuota y auditoría.
- Versionar tools y sus JSON Schemas.
- Clasificar riesgo y efectos: read-only, reversible, external-write y destructive.
- Definir scopes por recurso.
- Añadir timeouts, límites de salida y redacción de secretos.

### Sandbox inicial

- Contenedor efímero sin privilegios.
- Usuario no root y root filesystem de solo lectura.
- Workspace temporal explícito.
- CPU, RAM, disco, procesos y tiempo limitados.
- Red deshabilitada por defecto y egress allowlist.
- Sin socket Docker del host.
- Credenciales cortas y específicas para la ejecución.
- Destrucción al terminar y exportación controlada de artefactos.

### Criterio de salida

- Ni Junior ni otro agente ejecutan shell dentro del proceso API.
- Escapar del workspace o acceder a secretos del host falla en pruebas.
- Cada tool call queda correlacionada con usuario, agente, tarea y aprobación.

## Fase 7 — Observabilidad, auditoría y Model Router

Duración estimada: 2–3 semanas.

### Observabilidad

- OpenTelemetry para API, MCP, workflows, modelos y tools.
- Propagar `trace_id`, `run_id`, `task_id` y `tenant_id`.
- Métricas de éxito, latencia, reintentos, coste y uso.
- Logs estructurados con redacción.

### Auditoría

- Eventos append-only.
- Hash de artefactos y versiones de agentes/tools/policies.
- Retención por tenant y clasificación.
- Exportación para investigaciones.

### Model Router

- Routing por disponibilidad, privacidad, coste, contexto y capacidad.
- Presupuestos por tenant, workflow y agente.
- Circuit breaker, retry y fallback explícito.
- Soportar proveedor local futuro sin cambiar contratos.
- Registrar estimación y uso real sin almacenar contenido sensible innecesario.

### Criterio de salida

- Una ejecución puede reconstruirse de extremo a extremo.
- Es posible conocer qué modelo, agente, tool y policy produjeron un resultado.
- Superar un presupuesto detiene o solicita aprobación.

## Fase 8 — MCP Gateway y clientes

Duración estimada: 2–4 semanas.

### Primera versión

- Exponer solo tools de bajo riesgo y lectura.
- Mapear identidad del cliente a identidad NEXUS.
- Aplicar exactamente las mismas políticas que REST/CLI.
- Añadir descubrimiento y schemas versionados.
- Implementar tareas largas sin mantener ejecución dentro de la petición.
- Crear CLI NEXUS para depuración sin depender de ChatGPT.

### Evolución

- OAuth/OIDC para MCP remoto.
- Resources y prompts únicamente si tienen gobierno claro.
- Compatibilidad por versión del protocolo.
- A2A después de estabilizar MCP, para delegación entre agentes remotos.

### Criterio de salida

- La misma operación produce la misma autorización desde REST, CLI y MCP.
- Desconectar ChatGPT no impide operar NEXUS.
- MCP no contiene lógica de negocio duplicada.

## Fase 9 — Desktop Connector

Duración estimada: 4–8 semanas.

### Primera versión

- Servicio pequeño con enrolamiento administrativo.
- Identidad propia por dispositivo/instalación.
- mTLS, rotación y revocación.
- Carpetas y comandos permitidos declarativamente.
- Ejecución local con sandbox y confirmación para acciones sensibles.
- Actualizaciones firmadas y rollback.
- Estado online/offline y health report.

### Criterio de salida

- Revocar el conector corta su acceso inmediatamente.
- No puede leer carpetas o ejecutar programas no permitidos.
- Una actualización inválida o no firmada es rechazada.

## Fase 10 — NEXUS Evolution Lab

Duración estimada: 4–8 semanas.

### Flujo

1. Observer detecta oportunidades desde métricas, incidentes y feedback.
2. Architect genera hipótesis y criterios de aceptación.
3. Developer implementa en una copia aislada.
4. Test y Evaluator comparan baseline contra candidato.
5. Guardian y Red Team buscan vulnerabilidades y abuso.
6. Release prepara artefacto, migración y rollback.
7. Un humano aprueba canary.
8. Métricas deciden promoción o rollback.

### Restricciones

- El laboratorio nunca edita producción.
- Los agentes no modifican tests baseline, políticas de aprobación ni evaluaciones protegidas.
- Ningún agente implementa, evalúa, aprueba y despliega el mismo cambio.
- Cada campaña tiene presupuesto, tiempo e iteraciones máximas.
- No existe ciclo infinito 24/7.
- Las mejoras se disparan por evidencia o ventanas programadas.

### Artefactos por propuesta

- problema y evidencia;
- cambio propuesto;
- patch y dependencias;
- threat model;
- resultados de tests/evals;
- comparación de coste, calidad y latencia;
- plan de migración y rollback;
- firmas y aprobaciones.

### Criterio de salida

- Una mejora puede recorrer sandbox → evaluación → canary → producción.
- Una regresión provoca rollback automático.
- Es imposible que Junior se conceda permisos o despliegue sin aprobación.

## Fase 11 — Departamentos instalables

Duración: incremental.

### Formato de paquete

Cada departamento incluye:

- agentes y versiones;
- tools requeridas;
- workflows;
- policies;
- knowledge sources;
- datasets de evaluación;
- dashboards y métricas de negocio;
- migraciones y compatibilidad.

### Orden recomendado

1. Marketing interno de BAJIOWARE.
2. Development.
3. SOC/Guardian.
4. Sales.
5. Otros departamentos después de medir resultados.

Marketing debe ser el primer cliente del kernel, no código especial dentro del kernel.

## Fase 12 — Preparación empresarial

Duración estimada: 4–8 semanas después de validar producto.

- Backups y disaster recovery probados.
- Alta disponibilidad y escalado de workers.
- SLO/SLI y alertas.
- SBOM, firma de imágenes y provenance.
- Gestión externa de secretos/KMS.
- Retención, borrado y exportación de datos.
- Runbooks de incidentes.
- Pentest independiente.
- Documentación de despliegue on-prem/híbrido.
- Licencias, soporte y estrategia de actualizaciones.

## Backlog que queda fuera del camino crítico

No implementar todavía:

- una interfaz conversacional competidora de ChatGPT;
- entrenamiento de modelos propios;
- decenas de agentes generados;
- marketplace público;
- Kubernetes antes de necesitar escalado real;
- A2A antes de estabilizar contratos internos y MCP;
- autonomía de despliegue sin aprobaciones;
- memoria ilimitada o aprendizaje directo de outputs no evaluados.

## Secuencia de entregas utilizables

### Release 0.1 — NEXUS reproducible

Fases 0–2. Kernel probado completamente con Fake LLM.

### Release 0.2 — NEXUS durable

Fases 3–4. Tareas y workflows sobreviven reinicios.

### Release 0.3 — AI Directory

Fase 5. Tenants, identidades, agentes, tools y políticas.

### Release 0.4 — Secure Execution

Fases 6–7. Sandbox, tool gateway, auditoría y observabilidad.

### Release 0.5 — NEXUS Everywhere

Fases 8–9. MCP, CLI y Desktop Connector.

### Release 0.6 — Evolution Lab

Fase 10. Mejoras propuestas y probadas por agentes.

### Release 1.0 — BAJIOWARE AI Platform

Fases 11–12 con Marketing como primer paquete validado.

## Primer sprint recomendado

Orden exacto para comenzar:

1. Preservar y etiquetar el estado actual.
2. Crear estructura de tests y comandos reproducibles.
3. Implementar `ModelProvider` y `FakeModelProvider`.
4. Crear fixtures para éxito, timeout, error, tool call y respuesta inválida.
5. Unificar autenticación.
6. Eliminar defaults inseguros y cerrar CORS.
7. Inventariar rutas protegidas/no protegidas.
8. Deshabilitar ejecución shell dinámica fuera de tests.
9. Añadir CI backend/frontend.
10. Redactar ADRs del kernel, directorio, gateways y sandbox.

Al terminar este sprint será posible desarrollar el nuevo NEXUS sin pagar tokens y sin depender de una GPU.
