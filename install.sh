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
