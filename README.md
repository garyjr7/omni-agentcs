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

## Requisitos del sistema

- Python 3.12 y `.venv` del repo para todo lo demás.
- Los binarios de las tools que se vayan a usar, en `PATH`: `nmap`,
  `subfinder`, `httpx`, `nuclei`, `ffuf`.
- **Templates de nuclei en `/opt/nuclei-templates`** (o donde apunte
  `NEXUS_NUCLEI_TEMPLATES`). `nexus.web.nuclei` falla cerrado
  (`nuclei_templates_missing`) si el directorio no existe: nunca se queda
  descargando templates hasta agotar el timeout del sandbox.

```bash
# Instalar los templates una sola vez
nuclei -update-templates
sudo ln -s "$HOME/nuclei-templates" /opt/nuclei-templates   # o exporta NEXUS_NUCLEI_TEMPLATES
# Selección puntual por si el directorio vive en otro sitio:
#   NEXUS_NUCLEI_TEMPLATES=/srv/nuclei-templates
```

Nota: `nuclei` **no sigue un directorio symlinkeado**, por lo que el handler
pasa siempre la ruta canónica (`Path(...).resolve()`) aunque el default
configurado sea `/opt/nuclei-templates`.

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

## Tools durables

Todas se registran en `nexus_core/tools/registry.py::durable_tool_definitions()`,
se ejecutan dentro del sandbox (nunca `subprocess` directo) a través del Tool
Gateway y declaran `scope_target_field` + `scope_required` cuando tocan un
target. El `engagement_id` del run se propaga a cada llamada, así que el scope
se valida siempre, incluso cuando el LLM encadena varias tools.

| Tool | Riesgo | Ruido | Campo de scope | Descripción |
| --- | --- | --- | --- | --- |
| `nexus.system.status` | read_only | — (interno) | — | estado del kernel, cuotas y worker |
| `nexus.workspace.search` | read_only | — (local) | — | búsqueda en el workspace vía sandbox |
| `nexus.recon.nmap` | medium | calculado por flags (low→high) | `target` | escaneo de puertos/servicios con XML parseado |
| `nexus.recon.subfinder` | read_only | low (pasivo, sin tráfico al target) | `domain` | enumeración pasiva de subdominios (OSINT) |
| `nexus.recon.httpx` | low | low ≤20 targets · medium ≤100 · high >100 | `targets` (lista) | fingerprinting HTTP: status, título, tecnologías |
| `nexus.web.nuclei` | medium | según severidad: info/low→low · medium→medium · high/critical→high | `targets` (lista) | escaneo de vulnerabilidades con templates |
| `nexus.web.ffuf` | medium | threads ≤2→low · ≤5→medium · >5→high (default 10 = high) | `url` | fuzzing de rutas/directorios con wordlist |

Notas de seguridad de las tools nuevas:

- `nuclei` corre con `-no-interactsh -silent -nc -jsonl` por defecto y prohíbe
  interactsh/OAST, `-dast`, `-headless`, `-code` y cualquier flag que fije el
  target o redirija la salida. Las severidades por defecto son `low,medium` y se
  excluyen los tags `intrusive,fuzz,fuzzing,dos,brute-force`.
- `ffuf` **siempre** aplica `-rate` (default 50 req/s; ffuf por defecto es
  ilimitado) y exige que el wordlist viva dentro del workspace.
- `httpx` y `nuclei` reciben lotes de targets: el validador de scope exige que
  **todos** los elementos de la lista pasen; si uno falla, se deniega el lote
  completo.
- `subfinder` es pasivo (no genera tráfico al target) y por eso su ruido es
  siempre `low`.

Ejemplos en el REPL:

```text
└─$ Descubre subdominios de nmap.org y luego haz fingerprint HTTP de los que respondan
└─$ Haz fingerprint HTTP de http://scanme.nmap.org e intenta detectar tecnologías
└─$ Busca directorios comunes en http://scanme.nmap.org/FUZZ con el wordlist /workspace/words.txt, 5 threads
```

## Sandbox

Ninguna tool ejecuta binarios por su cuenta: todo pasa por
`sandbox_for_environment(...)`.

- **`LocalSandbox` (desarrollo)** lanza cada proceso con un entorno mínimo
  (`PATH`, `LANG`, `LC_ALL`, `TZ`, `NEXUS_SANDBOX=1`) y un **HOME efímero dentro
  del workspace**: `<workspace>/.sandbox_home`, con `XDG_CONFIG_HOME`,
  `XDG_CACHE_HOME` y `XDG_DATA_HOME` apuntando dentro. Así las CLIs que resuelven
  su configuración desde `$HOME` (httpx, subfinder, nuclei…) no ensucian el repo
  ni el home real del usuario. El directorio está en `.gitignore` y
  `resolve_workspace` bloquea su navegación: es fontanería del sandbox, no datos
  del agente.
- **`OCISandbox` (producción)** mantiene `--network none`, `--read-only`,
  `--cap-drop ALL`, `no-new-privileges` y `--user 65532:65532`, y añade un tmpfs
  efímero en `/home/sandbox` (`mode=1777`) con `HOME`/XDG apuntando ahí. Si el
  binario necesita una caché caliente (templates de nuclei) debe venir en la
  imagen o montarse de solo lectura.

## Seguridad

No exponga el API, MCP o conectores antes de configurar identidad, TLS y políticas. Las funciones heredadas de ejecución directa están deshabilitadas por defecto y siempre en producción. Un pentest independiente sigue siendo obligatorio antes de atender clientes o datos reales.
