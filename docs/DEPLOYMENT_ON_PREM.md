# Despliegue on-premise e híbrido

Producción requiere PostgreSQL, secretos externos, TLS en el borde y workers separados. SQLite y Fake LLM son modos de desarrollo. La API se liga a red privada; MCP remoto requiere OIDC/OAuth y MCP local se publica solo en loopback.

Orden: preparar `.env` desde `.env.example`; provisionar PostgreSQL y PKI; instalar locks con hashes; levantar backend y comprobar `/health`; levantar workers; ejecutar smoke REST/MCP; habilitar frontend; después habilitar connector/MCP remoto. Las credenciales de modelos son opcionales: el sistema arranca y se prueba con `LLM_PROVIDER=fake`.

En modo híbrido, datos `confidential/restricted` deben usar rutas con `allow_cloud=false` y un proveedor local futuro (Ollama/vLLM). Hasta disponer de capacidad local, esas solicitudes se rechazan: nunca se degradan silenciosamente hacia una nube.
