#!/bin/bash
set -e

echo "╔══════════════════════════════════════╗"
echo "║  NEXUS Sovereign — Backend Starting ║"
echo "╚══════════════════════════════════════╝"

# Verificar variables críticas
if [ -z "${OPENAI_API_KEY:-}" ] && [ -z "${GEMINI_API_KEY:-}" ]; then
  echo "[WARN] No cloud LLM key detected — Sovereign can use Fake LLM or Ollama"
fi

cd /nexus

# Iniciar FastAPI con uvicorn
echo "[INFO] Starting FastAPI on 0.0.0.0:8000..."
exec uvicorn nexus_api.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers ${NEXUS_API_WORKERS:-2} \
  --log-level ${LOG_LEVEL:-info} \
  --access-log
