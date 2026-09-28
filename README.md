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

## Seguridad

No exponga el API, MCP o conectores antes de configurar identidad, TLS y políticas. Las funciones heredadas de ejecución directa están deshabilitadas por defecto y siempre en producción. Un pentest independiente sigue siendo obligatorio antes de atender clientes o datos reales.
