# NEXUS Sovereign 3.0

NEXUS Sovereign es la interfaz y el runtime de primera parte de NEXUS. Los
clientes MCP, A2A y proveedores de modelos son adaptadores opcionales; la fuente
de verdad es el control plane durable.

## Flujo de ejecución

1. La consola crea una conversación o run en `/api/v1/sovereign`.
2. El API persiste el run, mensaje y evento antes de responder `202`.
3. Un worker reclama la tarea con lease e invoca un ejecutor registrado.
4. Modelos y tools registran uso, auditoría y eventos correlacionados.
5. La consola consulta el run o consume su stream SSE.

Tipos iniciales de tarea:

- `conversation.respond`
- `brain.run`
- `agent.run`
- `llm.complete`
- `tool.invoke`
- `memory.index`
- `evaluation.run`

El runtime rechaza cualquier tipo no registrado. El catálogo inicial de tools
contiene solamente `nexus.system.status` y `nexus.workspace.search`; ambas pasan
por Tool Gateway, política, cuota y auditoría. La segunda se ejecuta en el
sandbox correspondiente al ambiente.

## Arranque local

```bash
.venv/bin/uvicorn nexus_api.main:app --host 127.0.0.1 --port 8000
.venv/bin/python nexus_worker.py
npm --prefix nexus_frontend run dev
```

La consola requiere Node 22 o posterior. Para un entorno totalmente local puede
usarse `LLM_PROVIDER=fake` u Ollama. Un proveedor cloud solo se selecciona cuando
está configurado explícitamente; el fallback entre fronteras de datos requiere
`NEXUS_ALLOW_MODEL_FALLBACK=true`.

## Seguridad

- En producción se exponen `/health`, `/system/metrics` y `/api/v1`; los routers
  de ejecución heredados no se montan.
- `NEXUS_ENABLE_LEGACY_RUNTIME` solamente funciona en desarrollo.
- La ejecución durable de herramientas se realiza por `tool.invoke`.
- Conversaciones, conocimiento, memoria, runs y eventos están aislados por tenant.
- El conocimiento conserva URI y SHA-256 para generar citas verificables.

## Evidencia operativa

`GET /api/v1/sovereign/operations/summary` agrega estados de runs/tareas y uso.
`GET /api/v1/sovereign/runs/{id}/events` entrega el historial durable y
`/stream` ofrece SSE para la experiencia interactiva.

PostgreSQL es obligatorio en producción. SQLite se mantiene para desarrollo
mononodo y pruebas offline.
