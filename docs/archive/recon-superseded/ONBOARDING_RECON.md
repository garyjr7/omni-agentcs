# Reconocimiento onboarding

2026-09-29. Rama feat/distribution-onboarding. Base: 373 tests correctos.

- omni.py carga .env junto al script con override=False antes de importar el CLI.
- nexus_core/config.py exporta rutas legacy resueltas al importar. NEXUS_ROOT
  apunta al repo; NEXUS_DATA_PATH usa data y NEXUS_DB_PATH usa nexus_pro.db.
  Varios agentes y store_factory importan esas constantes: se conservarán al
  migrar a paquete, corrigiendo la profundidad del directorio raíz.
- CLI main importa NEXUS_DB_PATH estáticamente; se resolverá la ruta efectiva
  al arrancar para permitir XDG/config/env sin depender del orden de imports.
- LLMFactory lee claves y modelos del entorno (OpenAI, Gemini, Groq, Ollama);
  fake siempre existe. El selector actual prioriza cualquier proveedor real.
  El proveedor elegido deberá respetarse explícitamente. La inspección detallada
  confirmó que Anthropic no tenía enum ni adaptador: se añade un adaptador de
  Messages con httpx, dependencia existente, y pruebas sin red.
- ToolGateway aplica policy, scope y ApprovalService; ReAct crea ApprovalDecision
  mediante el callback CLI. Las aprobaciones actuales enlazan tool/run, no
  argumentos: install_tool necesita una acción ligada al hash del plan mostrado.
- nmap usa sandbox; el provisioner será una excepción administrativa HIGH.
  Las llamadas a procesos (incluidas versiones) se centralizarán en installer.py.
- tomllib disponible. freedesktop_os_release devuelve Ubuntu 24.04.5 LTS,
  ID ubuntu, ID_LIKE debian, VERSION_ID 24.04. No se instalarán herramientas
  reales durante implementación o tests.
- XDG cubrirá config, DB por defecto, history/state y cache. .env/env explícitos
  conservan precedencia; no se moverá la DB existente silenciosamente.
- Instalaciones pip/npm publicadas se documentarán como futuras. Esta misión
  implementa onboarding desde el checkout, sin publicar paquetes externos.
