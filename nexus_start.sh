#!/usr/bin/env bash
# NEXUS PRO — Manager completo de servicios
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_API="$ROOT/.nexus_api.pid"
PID_FACTORY="$ROOT/.nexus_factory.pid"
PID_JARVIS="$ROOT/.nexus_jarvis.pid"
LOG_DIR="$ROOT/data/logs"
GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

mkdir -p "$LOG_DIR"

start_service() {
  local name="$1" cmd="$2" pid_file="$3" log_file="$4"
  if [ -f "$pid_file" ] && kill -0 "$(cat $pid_file)" 2>/dev/null; then
    echo -e "  ${CYAN}$name ya corriendo (PID $(cat $pid_file))${NC}"
    return
  fi
  cd "$ROOT" && source venv/bin/activate 2>/dev/null || true
  nohup bash -c "$cmd" >> "$log_file" 2>&1 &
  echo $! > "$pid_file"
  echo -e "  ${GREEN}✓ $name iniciado (PID $!)${NC}"
}

stop_service() {
  local name="$1" pid_file="$2"
  if [ -f "$pid_file" ]; then
    kill "$(cat $pid_file)" 2>/dev/null && echo -e "  ${GREEN}✓ $name detenido${NC}"
    rm -f "$pid_file"
  fi
}

start() {
  echo -e "${BOLD}Iniciando NEXUS PRO stack...${NC}"
  start_service "API Backend" \
    "uvicorn nexus_api.main:app --host 0.0.0.0 --port 8000 --workers 1" \
    "$PID_API" "$LOG_DIR/nexus_api.log"
  sleep 4
  start_service "Factory Runner" \
    "python3 $ROOT/factory_runner.py --daemon --interval 20" \
    "$PID_FACTORY" "$LOG_DIR/factory_runner.log"
  start_service "Junior JARVIS" \
    "python3 $ROOT/junior_jarvis.py --interval 60" \
    "$PID_JARVIS" "$LOG_DIR/jarvis.log"
  sleep 2
  echo ""
  status
}

stop() {
  echo -e "${BOLD}Deteniendo NEXUS PRO...${NC}"
  stop_service "API Backend"    "$PID_API"
  stop_service "Factory Runner" "$PID_FACTORY"
  stop_service "Junior JARVIS"  "$PID_JARVIS"
  pkill -f "uvicorn nexus_api" 2>/dev/null || true
  pkill -f "factory_runner.py"  2>/dev/null || true
  pkill -f "junior_jarvis.py"   2>/dev/null || true
}

status() {
  echo -e "${BOLD}Estado NEXUS PRO:${NC}"
  local api_ok=false
  if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    api_ok=true
    HEALTH=$(curl -s http://localhost:8000/health | python3 -c \
      "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null)
    echo -e "  ${GREEN}● API Backend${NC} — health: $HEALTH"
  else
    echo -e "  ${RED}○ API Backend${NC} — no responde"
  fi
  for name_pid in "Factory Runner:$PID_FACTORY" "Junior JARVIS:$PID_JARVIS"; do
    name="${name_pid%%:*}"
    pid_file="${name_pid##*:}"
    if [ -f "$pid_file" ] && kill -0 "$(cat $pid_file)" 2>/dev/null; then
      echo -e "  ${GREEN}● $name${NC} (PID $(cat $pid_file))"
    else
      echo -e "  ${RED}○ $name${NC} — detenido"
    fi
  done
  echo ""
  echo -e "  ${CYAN}Dashboard:  http://localhost:3000${NC}"
  echo -e "  ${CYAN}API:        http://localhost:8000${NC}"
  echo -e "  ${CYAN}API Docs:   http://localhost:8000/docs${NC}"
}

logs() {
  local service="${2:-api}"
  case "$service" in
    api)     tail -f "$LOG_DIR/nexus_api.log" ;;
    factory) tail -f "$LOG_DIR/factory_runner.log" ;;
    jarvis)  tail -f "$LOG_DIR/jarvis.log" ;;
    *)       tail -f "$LOG_DIR/nexus_api.log" ;;
  esac
}

case "${1:-start}" in
  start)   start ;;
  stop)    stop ;;
  restart) stop; sleep 2; start ;;
  status)  status ;;
  logs)    logs "$@" ;;
  *) echo "Uso: $0 [start|stop|restart|status|logs [api|factory|jarvis]]" ;;
esac
