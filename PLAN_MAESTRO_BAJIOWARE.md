# Plan Maestro de Evolución: NEXUS → BAJIOWARE

## Propósito

Construir un **IA-AD** (directorio activo para agentes de IA) y una red de
nodos de capacidad: agentes y personas actúan con identidades verificables,
políticas explícitas y evidencia auditable; los equipos ejecutan únicamente
las capacidades que les fueron delegadas.

La regla rectora es: **un modelo puede proponer una acción, pero nunca afirmar
su éxito**. El éxito sólo existe tras una post-condición determinista y
persistida.

## Principios no negociables

1. Separar control plane, data plane y ejecución en endpoint.
2. Denegar por defecto; permisos mínimos, de duración limitada y revocables.
3. Todo efecto debe ser idempotente o tener compensación declarada.
4. Toda mutación exige `ToolResult` verificable, artefacto/evidencia y auditoría.
5. El nodo no acepta órdenes sin identidad mTLS, tenant, policy decision y
   autorización de herramienta/recurso.
6. Las aprobaciones de alto riesgo son durables y fail-closed; su alcance se
   liga al run, herramienta, hash de argumentos y expiración.
7. Ningún conector recibe "control total" por defecto. `node.admin` es un scope
   excepcional, limitado en tiempo, auditado y normalmente aprobado por humano.

## Fase 1 — Core verificable y cero alucinaciones

**Objetivo:** retirar el legacy del camino productivo y convertir toda
observación de herramienta en evidencia estructurada.

- Estandarizar `ToolResult`: salida, exit code, stdout/stderr, timeout,
  verificación, método y evidencia.
- Requerir dicho contrato en `ToolGateway`; si no se verifica la post-condición,
  la invocación falla y el worker reintenta o llega a DLQ.
- Persistir resultados, transiciones y eventos por task/run; añadir artefactos
  content-addressed para evidencia grande.
- Trasladar al runtime durable el ciclo plan → acción autorizada → observación
  → evaluación → replanificación / pausa / fin.
- Mantener los módulos legacy sólo detrás de feature flags de desarrollo y
  eliminar llamadas directas de la ruta productiva. Ningún fallo codificado en
  un dict puede marcar la tarea como completada.

**Aceptación:** una escritura/ejecución no puede completar un run sin una
post-condición verificable; un exit code no aceptado, timeout o hash distinto
produce task failed/retry y evidencia consultable.

## Fase 2 — IA-AD y gobernanza

**Objetivo:** gobernar identidades, recursos y herramientas de manera
transaccional y multi-tenant.

- Directorios de agente, servicio, usuario, grupo, nodo, recurso y herramienta.
- Cada definición tiene scopes, clasificación, entorno, propietario, versión,
  límites, riesgo, timeout, contrato de verificación y compensación.
- RBAC + ABAC: tenant, rol, grupo, departamento, clasificación, entorno, nodo,
  recurso, horario y estado de dispositivo. La autorización se evalúa antes de
  cada tool call y no se confía en claims enviados por el agente.
- Vincular conectores a certificados mTLS, credenciales rotables y revocación.
- Usar `ApprovalService` durable con separación de deberes y expiración;
  indisponibilidad o timeout equivale a denegación.

**Aceptación:** un agente sólo puede invocar una herramienta asociada a un
recurso y nodo autorizados; un certificado/nodo revocado no puede leer ni
aceptar trabajo; el solicitante no puede aprobar su propia acción.

## Fase 3 — VEGA: nodos de capacidad y mensajería distribuida

**Objetivo:** convertir los conectores en ejecutores remotos, no en backdoors.

- NATS JetStream como transporte de comandos, resultados, heartbeats y eventos
  con subjects por tenant/nodo, ACLs, mensajes durables, ack y DLQ.
- `NEXUS Node` como daemon mínimo: enrolamiento, mTLS, inventario de
  capacidades, sandbox local, allowlist de roots/programas y actualización
  firmada con rollback.
- El control plane planifica; el nodo vuelve a autorizar localmente y ejecuta.
  Los resultados se firman, se correlacionan con run/task y se almacenan como
  artefactos.
- Sustituir el EventBus in-memory en la ruta distribuida; conservarlo sólo para
  eventos locales no críticos mientras se retira.

**Aceptación:** dos nodos activos pueden reclamar trabajo dirigido a sus
capacidades sin compartir filesystem, y un nodo desconectado no pierde ni
duplica un efecto tras recuperarse.

## Fase 4 — browser seguro y evolución gobernada

**Objetivo:** añadir interacción web y auto-mejora sin entregar el host al
navegador ni permitir cambios no revisados.

- Browser Playwright por tarea en contenedor efímero, perfiles segregados,
  secretos inyectados de corta duración, red/egress allowlisted y sin mount del
  host.
- Evidencia de navegación: URL final, trazas, screenshots y hashes como
  artefactos; no registrar secretos ni cookies.
- Pipeline de evolución: propuesta → sandbox OCI → tests/SAST/evaluaciones →
  artefactos SBOM/firmas → revisión dual → canary → promoción o rollback.
- El registro de una herramienta es un cambio versionado y firmado, no código
  dinámico ejecutable desde un prompt.

**Aceptación:** una herramienta propuesta por un agente no llega a producción
sin pruebas, evidencia, aprobación independiente y despliegue canary reversible.

## Orden de implementación

Fase 1 es prerequisito de las demás. Fase 2 puede aprovechar los repositorios
de directorio, políticas, aprobaciones y conectores ya presentes; Fase 3
conecta dichos contratos a equipos reales; Fase 4 se incorpora sólo sobre ese
canal gobernado.
