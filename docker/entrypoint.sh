#!/bin/bash
set -e

echo "╔══════════════════════════════════════╗"
echo "║     NEXUS PRO — Backend Starting     ║"
echo "╚══════════════════════════════════════╝"

# Verificar variables críticas
if [ -z "${OPENAI_API_KEY:-}" ] && [ -z "${GEMINI_API_KEY:-}" ]; then
  echo "[WARN] No LLM API key detected — Junior will run in mock mode"
fi

# Crear DBs si no existen
DB_PATH="${NEXUS_DB_PATH:-/nexus/data/nexus_pro.db}"
if [ ! -f "$DB_PATH" ]; then
  echo "[INFO] Initializing database at $DB_PATH"
fi

# Iniciar nexus_core en background
echo "[INFO] Starting NEXUS Core orchestrator..."
cd /nexus
python -m nexus_core.main &
CORE_PID=$!
echo "[INFO] nexus_core PID: $CORE_PID"

# Esperar a que nexus_core levante
sleep 3

# Iniciar FastAPI con uvicorn
echo "[INFO] Starting FastAPI on 0.0.0.0:8000..."
exec uvicorn nexus_api.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers ${UVICORN_WORKERS:-2} \
  --log-level ${LOG_LEVEL:-info} \
  --access-log
