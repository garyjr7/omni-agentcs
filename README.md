# BAJIOWARE NEXUS

> **NEXUS Sovereign 3.0:** la consola propia y el runtime durable son ahora el
> camino principal. Consulte [la guía Sovereign](docs/NEXUS_SOVEREIGN.md).

NEXUS es un kernel y directorio empresarial de agentes. REST, CLI, MCP y A2A son gateways del mismo control plane; ChatGPT, Claude u otro cliente pueden servir como interfaz sin convertirse en dependencia arquitectónica.

## Capacidades

- AI Directory multi-tenant: organizaciones, departamentos, identidades, agentes, tools, recursos, ambientes y capacidades.
- RBAC más decisiones ABAC/ReBAC centralizadas, aprobaciones durables y auditoría append-only encadenada por hash.
- Tareas y workflows persistentes con idempotencia, leases, timeout, retry/backoff, DLQ, outbox, cancelación y compensaciones.
- Tool Gateway con schema, política, cuota, sandbox, límites y auditoría.
- Model Router intercambiable: Fake LLM, OpenAI, Google GenAI, OpenAI-compatible, y contratos preparados para Ollama/vLLM.
- Memoria durable y privada con tenant, clasificación, retención y búsqueda offline. Un vector store es un índice opcional.
- MCP 2.0, REST, CLI, A2A y Desktop Connector mTLS.
- Evolution Lab gobernado: workspace aislado, evaluador independiente, aprobación humana, canary y rollback.
- Marketing como primer departamento instalable, no como código especial del kernel.

## Desarrollo sin GPU, APIs ni tokens

Requiere Python 3.12. Las dependencias reproducibles se instalan desde el lock con hashes:

```bash
python3.12 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
cp .env.example .env
```

Configure un administrador explícito en `.env`; no existen credenciales predeterminadas. Mantenga `LLM_PROVIDER=fake` y ejecute:

```bash
PATH=.venv/bin:$PATH make lint typecheck test test-api test-mcp
.venv/bin/python nexus_cli.py fake-llm "hola" --scenario echo
.venv/bin/python nexus_cli.py enqueue-debug "hola" --idempotency-key demo-1
.venv/bin/python nexus_worker.py --once
```

Arranque local:

```bash
.venv/bin/uvicorn nexus_api.main:app --host 127.0.0.1 --port 8000
.venv/bin/python -m nexus_mcp.server
```

MCP por `stdio` permite depurar desde clientes compatibles sin publicar un puerto. Una cuenta gratuita de una interfaz no garantiza que esa interfaz permita MCP remoto: eso depende del producto, plan y soporte vigentes. NEXUS siempre puede operarse por CLI/REST y probarse con Fake LLM.

## Producción

Producción requiere PostgreSQL, secretos explícitos, TLS, workers separados y un sandbox OCI. SQLite es solamente para desarrollo pequeño. El backend de Compose se publica únicamente en loopback; MCP remoto exige OIDC/OAuth y el Desktop Connector entra por un gateway mTLS.

```bash
cp .env.example .env
# Definir POSTGRES_PASSWORD, JWT_SECRET_KEY, admin, CORS y URLs públicas.
docker compose up -d backend worker frontend
# Opcional: requiere PKI provisionado.
docker compose --profile connector up -d connector-gateway
```

No se instala Ollama ni se fuerza un proveedor cloud. Las rutas de datos confidenciales con `allow_cloud=false` se rechazan si no existe un proveedor privado disponible.

## Gateways y operación

- API: `/health`, `/docs` solo en desarrollo y `/system/metrics` autenticado.
- MCP: `python -m nexus_mcp.server`; Streamable HTTP requiere OIDC salvo loopback explícito.
- CLI: `python nexus_cli.py --help`.
- Worker: `python nexus_worker.py --help`.
- Backup SQLite: `./nexus_backup.sh --database data/nexus_pro.db`.
- Restore aislado: `./nexus_restore.sh ARCHIVO --database /ruta/nexus.db`.

Documentación clave:

- [Plan de implementación](PLAN_IMPLEMENTACION_NEXUS.md)
- [Auditoría base](AUDITORIA_NEXUS_2026-08-04.md)
- [Despliegue on-premise](docs/DEPLOYMENT_ON_PREM.md)
- [Desarrollo offline](docs/runbooks/DEVELOPMENT_OFFLINE.md)
- [Backup y restore](docs/runbooks/BACKUP_RESTORE.md)
- [Connector mTLS](docs/runbooks/CONNECTOR_MTLS.md)
- [SLO/SLI](docs/runbooks/SLO_SLI.md)
- [Gobierno de datos](docs/runbooks/DATA_GOVERNANCE.md)

## CLI interactivo omni

`omni` es la consola del bucle ReAct durable: el humano escribe un objetivo en
lenguaje natural, ve el razonamiento del agente en vivo y aprueba las acciones
de alto riesgo. El CLI nunca ejecuta herramientas por su cuenta: todo pasa por
el bucle ReAct y por el Tool Gateway (policy, scope, approval, sandbox y
auditoría).

Requisitos:

- `.env` con `GROQ_API_KEY` o `OPENAI_API_KEY` o `GEMINI_API_KEY` (con solo
  `fake` el bucle funciona, pero sin razonamiento real).
- un `EngagementScope` creado en el control store (sin scope, las herramientas
  que lo exigen se deniegan).

Uso básico:

```bash
./.venv/bin/python omni.py --engagement eng-scanme
```

Dentro del REPL:

```text
┌──(OmniAgentCS)─[scanme-test]
└─$ Escanea scanme.nmap.org en puertos 22, 80 y 443
```

Comandos meta:

| Comando | Descripción |
| --- | --- |
| `/scope` | muestra el engagement activo |
| `/tools` | lista las tools durables con su riesgo y si exigen scope |
| `/history` | historial (mensajes durables) del run actual |
| `/clear` | limpia el contexto local (mantiene el engagement y la auditoría) |
| `/export` | exporta la sesión a Markdown |
| `/approvals` | lista aprobaciones durables pendientes |
| `/help` | ayuda |
| `/exit` / `/quit` | salir |

One-shot (sin REPL):

```bash
./.venv/bin/python omni.py --engagement eng-scanme \
    --objective "Escanea scanme en puertos 22 y 80"
```

Listar engagements y ver los flags disponibles:

```bash
./.venv/bin/python omni.py --list-engagements
./.venv/bin/python omni.py --help
```

Ctrl+C interrumpe la línea de entrada sin matar la sesión; durante un run pide
cancelación cooperativa y el run se puede reanudar con
`omni --resume <run_id>`. Ctrl+D sale limpiamente. Las acciones de riesgo alto
piden aprobación explícita (`y` aprobar, `n` rechazar, `e` editar argumentos,
`?` ver la definición de la tool) y cada aprobación queda registrada como fila
durable en `kernel_approvals`, con separación de deberes entre el agente que
pide y el humano que aprueba.

## Seguridad

No exponga el API, MCP o conectores antes de configurar identidad, TLS y políticas. Las funciones heredadas de ejecución directa están deshabilitadas por defecto y siempre en producción. Un pentest independiente sigue siendo obligatorio antes de atender clientes o datos reales.
