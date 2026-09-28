# Desarrollo offline

1. Copiar `.env.example` a `.env` y conservar `LLM_PROVIDER=fake`.
2. Ejecutar `make test-offline` para validar el Kernel sin red, GPU ni API keys.
3. Iniciar API/worker/MCP con Docker Compose cuando Docker esté disponible.
4. Enviar escenarios deterministas con `python3 nexus_cli.py fake-llm --scenario echo --message hola`.
5. Usar `python3 nexus_worker.py --once` para consumir una tarea durable.

Las respuestas reales solo se convierten en fixtures después de retirar secretos, datos personales y contenido confidencial.
