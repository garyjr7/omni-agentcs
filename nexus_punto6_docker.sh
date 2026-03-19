#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Punto 6: Docker + Instalador Limpio           ║
# ║  6A · Dockerfile Backend  6B · Dockerfile Frontend         ║
# ║  6C · docker-compose.yml  6D · .env.example  6E · install  ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

ROOT="/home/operator/NEXUS-PRO"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

cd "$ROOT"

# ══════════════════════════════════════════════════════════════
head "1/6 · Dockerfile — Backend (nexus_api + nexus_core)"
# ══════════════════════════════════════════════════════════════
cat > Dockerfile.backend << 'EOF'
# ── Stage 1: builder ──────────────────────────────────────────
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc libffi-dev libssl-dev git curl nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copiar requirements de ambos módulos
COPY nexus_api/requirements.txt  /build/req_api.txt
COPY nexus_core/requirements.txt /build/req_core.txt

# Instalar dependencias en venv limpio
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r /build/req_api.txt && \
    pip install --no-cache-dir -r /build/req_core.txt && \
    pip install --no-cache-dir \
        bandit safety python-jose[cryptography] \
        passlib[bcrypt] python-multipart slowapi

# ── Stage 2: runtime ──────────────────────────────────────────
FROM python:3.11-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl git sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Copiar venv del builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /nexus

# Copiar código fuente
COPY nexus_api/  /nexus/nexus_api/
COPY nexus_core/ /nexus/nexus_core/

# Datos persistentes — se montan como volumen
RUN mkdir -p /nexus/data/reports \
             /nexus/data/pentest \
             /nexus/data/junior_workspace \
             /nexus/data/junior_memory_db \
             /nexus/data/logs

# Script de arranque
COPY docker/entrypoint.sh /nexus/entrypoint.sh
RUN chmod +x /nexus/entrypoint.sh

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["/nexus/entrypoint.sh"]
EOF
log "Dockerfile.backend"

# ══════════════════════════════════════════════════════════════
head "2/6 · Dockerfile — Frontend (Vite build → nginx)"
# ══════════════════════════════════════════════════════════════
cat > Dockerfile.frontend << 'EOF'
# ── Stage 1: build Vite ───────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app
COPY nexus_frontend/package*.json ./
RUN npm ci --silent

COPY nexus_frontend/ ./

# Variables de build — se inyectan en tiempo de build
ARG VITE_API_URL=http://localhost:8000
ARG VITE_WS_URL=ws://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_WS_URL=$VITE_WS_URL

RUN npm run build

# ── Stage 2: nginx ────────────────────────────────────────────
FROM nginx:alpine AS runtime

# Configuración nginx con proxy_pass al backend
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

# Build del frontend
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=5s \
  CMD curl -f http://localhost/health || exit 1
EOF
log "Dockerfile.frontend"

# ══════════════════════════════════════════════════════════════
head "3/6 · docker/ — configs de soporte"
# ══════════════════════════════════════════════════════════════
mkdir -p docker

# entrypoint.sh
cat > docker/entrypoint.sh << 'EOF'
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
EOF
chmod +x docker/entrypoint.sh

# nginx.conf
cat > docker/nginx.conf << 'EOF'
upstream nexus_backend {
    server backend:8000;
    keepalive 32;
}

server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    # Gzip
    gzip on;
    gzip_types text/plain application/json application/javascript text/css;
    gzip_min_length 1024;

    # SPA — React router
    location / {
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    # Assets estáticos con cache largo
    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Proxy al backend FastAPI
    location /api/ {
        rewrite ^/api/(.*) /$1 break;
        proxy_pass http://nexus_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;
    }

    # WebSocket proxy
    location /ws/ {
        proxy_pass http://nexus_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Health check directo al backend
    location /health {
        proxy_pass http://nexus_backend/health;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        access_log off;
    }
}
EOF
log "docker/entrypoint.sh + nginx.conf"

# ══════════════════════════════════════════════════════════════
head "4/6 · docker-compose.yml — stack completo"
# ══════════════════════════════════════════════════════════════
cat > docker-compose.yml << 'EOF'
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — docker-compose.yml                            ║
# ║  Servicios: backend · frontend · chromadb                  ║
# ╚══════════════════════════════════════════════════════════════╝
version: "3.9"

x-logging: &default-logging
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"

services:

  # ── Backend FastAPI + nexus_core ─────────────────────────────
  backend:
    build:
      context: .
      dockerfile: Dockerfile.backend
    container_name: nexus-backend
    restart: unless-stopped
    env_file: .env
    environment:
      - NEXUS_DB_PATH=/nexus/data/nexus_pro.db
      - NEXUS_DATA_DIR=/nexus/data
      - CHROMA_HOST=chromadb
      - CHROMA_PORT=8001
      - UVICORN_WORKERS=2
      - LOG_LEVEL=info
    volumes:
      # Datos persistentes — surviven rebuilds
      - nexus_data:/nexus/data
      # Hot-reload del código en desarrollo
      # Comentar en producción:
      # - ./nexus_api:/nexus/nexus_api
      # - ./nexus_core:/nexus/nexus_core
    ports:
      - "${NEXUS_BACKEND_PORT:-8000}:8000"
    depends_on:
      chromadb:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 40s
    logging: *default-logging
    networks:
      - nexus_net

  # ── Frontend React → nginx ────────────────────────────────────
  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend
      args:
        - VITE_API_URL=${VITE_API_URL:-http://localhost:8000}
        - VITE_WS_URL=${VITE_WS_URL:-ws://localhost:8000}
    container_name: nexus-frontend
    restart: unless-stopped
    ports:
      - "${NEXUS_FRONTEND_PORT:-3000}:80"
    depends_on:
      backend:
        condition: service_healthy
    logging: *default-logging
    networks:
      - nexus_net

  # ── ChromaDB — Vector Memory ──────────────────────────────────
  chromadb:
    image: chromadb/chroma:latest
    container_name: nexus-chromadb
    restart: unless-stopped
    environment:
      - CHROMA_SERVER_AUTH_CREDENTIALS_FILE=/chroma/auth
      - IS_PERSISTENT=TRUE
      - PERSIST_DIRECTORY=/chroma/data
      - ANONYMIZED_TELEMETRY=FALSE
    volumes:
      - chroma_data:/chroma/data
    ports:
      - "${CHROMA_PORT:-8001}:8000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/heartbeat"]
      interval: 20s
      timeout: 5s
      retries: 5
      start_period: 20s
    logging: *default-logging
    networks:
      - nexus_net

  # ── Watchtower — Auto-updates (opcional) ─────────────────────
  # watchtower:
  #   image: containrrr/watchtower
  #   volumes:
  #     - /var/run/docker.sock:/var/run/docker.sock
  #   command: --interval 86400 nexus-backend nexus-frontend
  #   restart: unless-stopped

volumes:
  nexus_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${NEXUS_DATA_BIND:-./data}
  chroma_data:
    driver: local

networks:
  nexus_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
EOF
log "docker-compose.yml"

# ══════════════════════════════════════════════════════════════
head "5/6 · .env.example — todas las variables documentadas"
# ══════════════════════════════════════════════════════════════
cat > .env.example << 'EOF'
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Variables de Entorno                          ║
# ║  cp .env.example .env → editar con tus keys               ║
# ╚══════════════════════════════════════════════════════════════╝

# ── LLM API Keys ─────────────────────────────────────────────
# Al menos una es obligatoria para que Junior funcione
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=AIza...
ANTHROPIC_API_KEY=sk-ant-...

# Modelo por defecto para agentes
DEFAULT_LLM_MODEL=gpt-4o
FALLBACK_LLM_MODEL=gemini-pro

# ── NEXUS Core ───────────────────────────────────────────────
NEXUS_ENV=production           # development | production
NEXUS_SECRET_KEY=cambia-esto-por-una-cadena-aleatoria-larga-32chars
NEXUS_DB_PATH=/nexus/data/nexus_pro.db
NEXUS_DATA_DIR=/nexus/data
NEXUS_LOG_LEVEL=info           # debug | info | warning | error

# ── JWT Auth (Punto 7) ───────────────────────────────────────
JWT_SECRET_KEY=otro-secreto-muy-largo-para-firmar-tokens
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=480         # 8 horas

# ── Admin por defecto ────────────────────────────────────────
NEXUS_ADMIN_EMAIL=admin@nexuspro.io
NEXUS_ADMIN_PASSWORD=cambia-esto-urgente
NEXUS_ADMIN_NAME=Admin

# ── Puertos ──────────────────────────────────────────────────
NEXUS_BACKEND_PORT=8000
NEXUS_FRONTEND_PORT=3000
CHROMA_PORT=8001

# ── URLs para el frontend ────────────────────────────────────
# Producción: usar dominio real
# VITE_API_URL=https://nexus.tudominio.com/api
# VITE_WS_URL=wss://nexus.tudominio.com

# Desarrollo local
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000

# ── ChromaDB ─────────────────────────────────────────────────
CHROMA_HOST=chromadb
CHROMA_PORT_INTERNAL=8001

# ── Pentest ──────────────────────────────────────────────────
PENTEST_REPORTS_DIR=/nexus/data/reports
PENTEST_WORKSPACE=/nexus/data/pentest

# ── Rate Limiting ────────────────────────────────────────────
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_BURST=10

# ── Notificaciones (opcional) ────────────────────────────────
# SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
# TELEGRAM_BOT_TOKEN=...
# TELEGRAM_CHAT_ID=...

# ── Bind del volumen de datos ────────────────────────────────
NEXUS_DATA_BIND=./data
EOF
log ".env.example"

# ══════════════════════════════════════════════════════════════
head "6/6 · install.sh — instalador en un comando"
# ══════════════════════════════════════════════════════════════
cat > install.sh << 'INSTALL_EOF'
#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Instalador                                    ║
# ║  Un comando para instalar NEXUS en cualquier servidor      ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

log()     { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}▶ $1${NC}"; }

clear
echo -e "${BOLD}${GREEN}"
cat << 'BANNER'
╔═══════════════════════════════════════════════════╗
║                                                   ║
║         NEXUS PRO — Instalador v1.0               ║
║         AI Operations Platform                    ║
║                                                   ║
╚═══════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

# ── Verificar prerequisitos ──────────────────────────────────
section "Verificando prerequisitos"

command -v docker        >/dev/null 2>&1 || error "Docker no instalado. Visita https://docs.docker.com/get-docker/"
command -v docker-compose >/dev/null 2>&1 || docker compose version >/dev/null 2>&1 || error "Docker Compose no instalado"

DOCKER_V=$(docker --version | awk '{print $3}' | tr -d ',')
COMPOSE_V=$(docker compose version 2>/dev/null | awk '{print $NF}' || docker-compose version --short 2>/dev/null || echo "unknown")
log "Docker $DOCKER_V"
log "Docker Compose $COMPOSE_V"

# ── Preparar .env ────────────────────────────────────────────
section "Configuración"

if [ ! -f ".env" ]; then
  if [ ! -f ".env.example" ]; then
    error ".env.example no encontrado — ¿estás en el directorio correcto?"
  fi
  cp .env.example .env
  warn ".env creado desde .env.example"
  warn "IMPORTANTE: Edita .env con tus API keys antes de continuar"
  echo ""
  echo -e "  ${CYAN}nano .env${NC}  ← edita ahora y vuelve a ejecutar install.sh"
  echo ""
  read -p "¿Continuar con la configuración por defecto? [s/N]: " CONT
  [[ "$CONT" =~ ^[sS]$ ]] || exit 0
else
  log ".env encontrado"
fi

# Verificar que al menos una API key está configurada
if grep -q "^OPENAI_API_KEY=sk-\.\.\." .env 2>/dev/null; then
  warn "OPENAI_API_KEY no configurada — Junior correrá en modo mock"
fi

# Generar secrets aleatorios si están con valores por defecto
if grep -q "cambia-esto-por-una-cadena-aleatoria" .env 2>/dev/null; then
  NEW_SECRET=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))")
  sed -i "s/cambia-esto-por-una-cadena-aleatoria-larga-32chars/$NEW_SECRET/" .env
  log "NEXUS_SECRET_KEY generado automáticamente"
fi
if grep -q "otro-secreto-muy-largo-para-firmar-tokens" .env 2>/dev/null; then
  NEW_JWT=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))")
  sed -i "s/otro-secreto-muy-largo-para-firmar-tokens/$NEW_JWT/" .env
  log "JWT_SECRET_KEY generado automáticamente"
fi

# ── Crear directorios de datos ───────────────────────────────
section "Preparando directorios"
mkdir -p data/reports data/pentest data/junior_workspace data/junior_memory_db data/logs
log "data/ preparado"

# ── Build de imágenes ────────────────────────────────────────
section "Construyendo imágenes Docker"
echo -e "  ${CYAN}Esto puede tardar 3-5 minutos la primera vez...${NC}"
echo ""

docker compose build --no-cache 2>&1 | while IFS= read -r line; do
  if [[ "$line" == *"Successfully built"* ]] || [[ "$line" == *"naming to"* ]]; then
    log "$line"
  elif [[ "$line" == *"ERROR"* ]] || [[ "$line" == *"error"* ]]; then
    echo -e "  ${RED}$line${NC}"
  else
    echo -e "  ${NC}$line${NC}"
  fi
done

log "Imágenes construidas"

# ── Arrancar servicios ───────────────────────────────────────
section "Iniciando servicios"
docker compose up -d

# Esperar a que el backend levante
echo -e "  Esperando que NEXUS Backend levante..."
TRIES=0
MAX_TRIES=30
until curl -s http://localhost:8000/health > /dev/null 2>&1; do
  TRIES=$((TRIES+1))
  if [ $TRIES -ge $MAX_TRIES ]; then
    warn "Backend tardando más de lo esperado — revisa: docker compose logs backend"
    break
  fi
  printf "."
  sleep 2
done
echo ""

# ── Verificación final ───────────────────────────────────────
section "Verificación"

HEALTH=$(curl -s http://localhost:8000/health 2>/dev/null || echo '{"status":"unreachable"}')
STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "?")

if [ "$STATUS" = "ok" ] || [ "$STATUS" = "healthy" ]; then
  log "Backend: ONLINE ($STATUS)"
else
  warn "Backend: $STATUS — puede estar iniciando aún"
fi

FRONTEND_PORT=$(grep "^NEXUS_FRONTEND_PORT" .env 2>/dev/null | cut -d= -f2 || echo "3000")
BACKEND_PORT=$(grep "^NEXUS_BACKEND_PORT"  .env 2>/dev/null | cut -d= -f2 || echo "8000")

# ── Resumen ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO instalado correctamente ✓              ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Dashboard:${NC}  ${CYAN}http://localhost:${FRONTEND_PORT}${NC}"
echo -e "  ${BOLD}API:${NC}        ${CYAN}http://localhost:${BACKEND_PORT}${NC}"
echo -e "  ${BOLD}API Docs:${NC}   ${CYAN}http://localhost:${BACKEND_PORT}/docs${NC}"
echo -e "  ${BOLD}ChromaDB:${NC}   ${CYAN}http://localhost:8001${NC}"
echo ""
echo -e "  Comandos útiles:"
echo -e "  ${CYAN}docker compose logs -f backend${NC}    ← logs en vivo"
echo -e "  ${CYAN}docker compose ps${NC}                 ← estado servicios"
echo -e "  ${CYAN}docker compose down${NC}               ← detener todo"
echo -e "  ${CYAN}docker compose restart backend${NC}    ← reiniciar backend"
echo ""
echo -e "  ${YELLOW}Credenciales por defecto:${NC}"
echo -e "  Email:    $(grep NEXUS_ADMIN_EMAIL .env | cut -d= -f2)"
echo -e "  Password: $(grep NEXUS_ADMIN_PASSWORD .env | cut -d= -f2)"
echo -e "  ${RED}← Cambiar en .env antes de exponer a internet${NC}"
echo ""
INSTALL_EOF
chmod +x install.sh
log "install.sh"

# ══════════════════════════════════════════════════════════════
# Crear .dockerignore
# ══════════════════════════════════════════════════════════════
cat > .dockerignore << 'EOF'
# Python
**/__pycache__
**/*.pyc
**/*.pyo
**/venv
**/.env
**/*.egg-info

# Node
**/node_modules
nexus_frontend/.env
nexus_frontend/dist

# Git y backups
.git
.backups
**/*.bak
**/*.save
**/*.save.*

# Datos locales (se montan como volumen)
data/
*.db

# Dev
*.sh
.dockerignore
EOF
log ".dockerignore"

# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO — Punto 6: Docker ✓                    ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Archivos creados:"
echo -e "  ${CYAN}Dockerfile.backend${NC}   → python:3.11-slim multi-stage"
echo -e "  ${CYAN}Dockerfile.frontend${NC}  → node:20 build + nginx:alpine"
echo -e "  ${CYAN}docker/entrypoint.sh${NC} → arranque nexus_core + uvicorn"
echo -e "  ${CYAN}docker/nginx.conf${NC}    → SPA + proxy_pass + WS"
echo -e "  ${CYAN}docker-compose.yml${NC}   → backend + frontend + chromadb"
echo -e "  ${CYAN}.env.example${NC}         → todas las vars documentadas"
echo -e "  ${CYAN}install.sh${NC}           → instalador en un comando"
echo -e "  ${CYAN}.dockerignore${NC}        → build limpio sin basura"
echo ""
echo -e "  ${BOLD}Para probar ahora:${NC}"
echo -e "  ${CYAN}chmod +x install.sh && ./install.sh${NC}"
echo ""
echo -e "  ${BOLD}Siguiente — Punto 7: JWT Auth real${NC}"
echo -e "  Login page · tokens · rutas protegidas · RBAC"
echo ""
