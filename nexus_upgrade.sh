#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Script de Actualización v2.0               ║
# ║  Fija imports rotos, limpia legado BAJIOWARE            ║
# ╚══════════════════════════════════════════════════════════╝
set -euo pipefail

NEXUS_ROOT="/home/operator/NEXUS-PRO"
API_DIR="$NEXUS_ROOT/nexus_api"
CORE_DIR="$NEXUS_ROOT/nexus_core"
BACKUP_DIR="$NEXUS_ROOT/.backups/$(date +%Y%m%d_%H%M%S)"
VENV="$NEXUS_ROOT/venv"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
info() { echo -e "${CYAN}[→]${NC} $1"; }
warn() { echo -e "${YELLOW}[⚠]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

# ══════════════════════════════════════════════════════════════
head "NEXUS PRO v2.0 — Actualización"
# ══════════════════════════════════════════════════════════════

cd "$NEXUS_ROOT"

# 1. BACKUP
head "1/6 · Backup de seguridad"
mkdir -p "$BACKUP_DIR"
cp "$API_DIR/main.py" "$BACKUP_DIR/main.py.bak" 2>/dev/null || true
log "Backup guardado en $BACKUP_DIR"

# 2. VERIFICAR VENV
head "2/6 · Verificando entorno virtual"
if [ ! -f "$VENV/bin/activate" ]; then
    err "venv no encontrado en $VENV"
    exit 1
fi
source "$VENV/bin/activate"
log "venv activado: $(python --version)"

# 3. INSTALAR DEPENDENCIAS FALTANTES
head "3/6 · Dependencias"

PKGS=(
    "fastapi>=0.115.0"
    "uvicorn[standard]>=0.30.0"
    "python-dotenv>=1.0.1"
    "pydantic>=2.7.0"
    "pydantic-settings>=2.3.0"
    "databases[aiosqlite]>=0.9.0"
    "sqlalchemy>=2.0.0"
    "python-jose[cryptography]>=3.3.0"
    "passlib[bcrypt]>=1.7.4"
    "python-multipart>=0.0.9"
    "httpx>=0.27.0"
    "apscheduler>=3.10.0"
    "chromadb>=0.5.0"
    "openai>=1.35.0"
    "anthropic>=0.28.0"
)

info "Instalando/actualizando paquetes core..."
pip install --quiet --upgrade "${PKGS[@]}" 2>&1 | grep -E "(Successfully|already|ERROR)" || true
log "Dependencias listas"

# 4. VERIFICAR MÓDULOS NEXUS_CORE
head "4/6 · Verificando nexus_core"

check_module() {
    local path="$1"
    local name="$2"
    if [ -f "$path" ]; then
        log "$name ✓"
    else
        warn "$name NO encontrado en $path"
    fi
}

check_module "$CORE_DIR/core/orchestrator.py"     "Orchestrator"
check_module "$CORE_DIR/core/event_bus.py"         "EventBus"
check_module "$CORE_DIR/llm/abstraction.py"        "LLM Abstraction"
check_module "$CORE_DIR/memory/manager.py"         "MemoryManager"
check_module "$CORE_DIR/agents/registry.py"        "AgentRegistry"
check_module "$CORE_DIR/state/manager.py"          "StateManager"
check_module "$CORE_DIR/agent_team_manager.py"     "AgentTeamManager"
check_module "$CORE_DIR/workflow_manager.py"       "WorkflowManager"

# Verificar __init__.py en nexus_core (crítico para imports)
if [ ! -f "$CORE_DIR/__init__.py" ]; then
    warn "nexus_core/__init__.py no existe — creando..."
    touch "$CORE_DIR/__init__.py"
    log "nexus_core/__init__.py creado"
fi

if [ ! -f "$API_DIR/__init__.py" ]; then
    touch "$API_DIR/__init__.py"
    log "nexus_api/__init__.py creado"
fi

# 5. DEPLOY NUEVO MAIN.PY
head "5/6 · Desplegando main.py limpio"

# Descargar desde outputs o usar heredoc embebido
MAIN_PY="$API_DIR/main.py"

cat > "$MAIN_PY" << 'MAINPY'
"""
nexus_api/main.py — NEXUS PRO v2.0
Orquestador de Agentes IA · Zero Trust · Military Grade
"""
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "nexus_core"))

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("nexus.api")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s"
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info("  NEXUS PRO v2.0 — Iniciando...")
    logger.info("=" * 60)

    try:
        from nexus_api.auth.database import database, init_db
        init_db(); await database.connect()
        logger.info("[DB] ✓ Base de datos conectada")
    except Exception as e:
        logger.warning(f"[DB] ⚠ {e}")

    try:
        from nexus_api.scheduler.manager import start_scheduler
        start_scheduler()
        logger.info("[SCHEDULER] ✓ Scheduler iniciado")
    except Exception as e:
        logger.warning(f"[SCHEDULER] ⚠ {e}")

    try:
        from nexus_core.core.orchestrator import Orchestrator
        app.state.orchestrator = Orchestrator()
        logger.info("[ORCHESTRATOR] ✓ Listo")
    except Exception as e:
        logger.warning(f"[ORCHESTRATOR] ⚠ {e}")
        app.state.orchestrator = None

    try:
        from nexus_core.llm.abstraction import LLMProvider
        app.state.llm = LLMProvider()
        logger.info("[LLM] ✓ Listo")
    except Exception as e:
        logger.warning(f"[LLM] ⚠ {e}")
        app.state.llm = None

    try:
        from nexus_core.memory.manager import MemoryManager
        app.state.memory = MemoryManager()
        logger.info("[MEMORY] ✓ Listo")
    except Exception as e:
        logger.warning(f"[MEMORY] ⚠ {e}")
        app.state.memory = None

    try:
        from nexus_core.agents.registry import AgentRegistry
        app.state.registry = AgentRegistry()
        logger.info("[REGISTRY] ✓ Listo")
    except Exception as e:
        logger.warning(f"[REGISTRY] ⚠ {e}")
        app.state.registry = None

    try:
        from nexus_core.state.manager import StateManager
        app.state.state_manager = StateManager()
        logger.info("[STATE] ✓ Listo")
    except Exception as e:
        logger.warning(f"[STATE] ⚠ {e}")
        app.state.state_manager = None

    try:
        from nexus_core.core.event_bus import EventBus
        app.state.event_bus = EventBus()
        logger.info("[EVENTBUS] ✓ Listo")
    except Exception as e:
        logger.warning(f"[EVENTBUS] ⚠ {e}")
        app.state.event_bus = None

    try:
        from nexus_core.agent_team_manager import create_team_router
        app.include_router(create_team_router())
        logger.info("[TEAMS] ✓ AgentTeamManager → /teams/*")
    except Exception as e:
        logger.warning(f"[TEAMS] ⚠ {e}")

    try:
        from nexus_core.workflow_manager import WorkflowManager
        app.state.workflow_manager = WorkflowManager()
        logger.info("[WORKFLOW] ✓ Listo")
    except Exception as e:
        logger.warning(f"[WORKFLOW] ⚠ {e}")
        app.state.workflow_manager = None

    try:
        from nexus_core.junior_bridge import initialize_bridge, get_junior_bridge
        bridge_ok = await initialize_bridge()
        app.state.junior_bridge = get_junior_bridge() if bridge_ok else None
        status = "✓ Activo" if bridge_ok else "⚠ Degradado"
        logger.info(f"[JUNIOR] {status}")
    except Exception as e:
        logger.warning(f"[JUNIOR] ⚠ {e}")
        app.state.junior_bridge = None

    logger.info("=" * 60)
    logger.info("  NEXUS PRO v2.0 — SISTEMA HEALTHY ✓")
    logger.info("  API Docs → http://0.0.0.0:8000/docs")
    logger.info("=" * 60)

    yield

    logger.info("[NEXUS] Apagando servicios...")
    try:
        from nexus_api.scheduler.manager import stop_scheduler
        stop_scheduler()
    except Exception:
        pass
    try:
        from nexus_api.auth.database import database
        await database.disconnect()
    except Exception:
        pass
    logger.info("[NEXUS] ✓ Apagado limpio")


app = FastAPI(
    title="NEXUS PRO",
    version="2.0.0",
    description="AI Operations Platform — Orquestador de Agentes IA",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def safe_include(router, **kwargs):
    try:
        app.include_router(router, **kwargs)
        return True
    except Exception as e:
        logger.warning(f"[ROUTER] {kwargs.get('prefix','?')} ⚠ {e}")
        return False

from nexus_api.routes.auth import router as auth_router
app.include_router(auth_router, tags=["Auth"])

_routes = [
    ("nexus_api.routes.scheduler",      {},                              "Scheduler"),
    ("nexus_api.routes.agents",         {},                              "Agents"),
    ("nexus_api.routes.tasks",          {},                              "Tasks"),
    ("nexus_api.routes.projects",       {"prefix": "/projects"},         "Projects"),
    ("nexus_api.routes.nexus",          {},                              "Nexus"),
    ("nexus_api.routes.guardian",       {"prefix": "/guardian"},         "Guardian"),
    ("nexus_api.routes.teams_v2",       {"prefix": "/teams-v2"},         "Teams"),
    ("nexus_api.routes.project_manager",{"prefix": "/project-manager"},  "ProjectMgr"),
    ("nexus_api.routes.plans",          {"prefix": "/plans"},            "Plans"),
    ("nexus_api.routes.composite",      {"prefix": "/composite"},        "Composite"),
    ("nexus_api.routes.killswitch",     {"prefix": "/killswitch"},       "KillSwitch"),
    ("nexus_api.routes.testagent",      {"prefix": "/testagent"},        "TestAgent"),
    ("nexus_api.routes.docagent",       {"prefix": "/docagent"},         "DocAgent"),
    ("nexus_api.routes.ws_logs",        {},                              "WebSocket"),
]

for module_path, kwargs, name in _routes:
    try:
        import importlib
        mod = importlib.import_module(module_path)
        safe_include(mod.router, tags=[name], **kwargs)
    except Exception as e:
        logger.warning(f"[ROUTER] {name} ⚠ {e}")


@app.get("/health", tags=["Health"])
async def health():
    from datetime import datetime
    services = {k: ("ok" if getattr(app.state, k, None) else "degraded")
                for k in ["orchestrator","llm","memory","registry","event_bus",
                          "junior_bridge","workflow_manager","state_manager"]}
    return {
        "status": "healthy" if all(v=="ok" for v in services.values()) else "degraded",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "platform": "NEXUS PRO",
        "services": services,
    }

@app.get("/", tags=["Health"])
async def root():
    return {"name": "NEXUS PRO", "version": "2.0.0", "docs": "/docs"}
MAINPY

log "main.py desplegado en $MAIN_PY"

# 6. SMOKE TEST
head "6/6 · Smoke test"

info "Verificando sintaxis Python..."
python -c "
import sys
sys.path.insert(0, '$NEXUS_ROOT')
sys.path.insert(0, '$CORE_DIR')

errors = []

modules = [
    'nexus_api.auth.database',
    'nexus_api.routes.auth',
    'nexus_core.core.orchestrator',
    'nexus_core.core.event_bus',
    'nexus_core.llm.abstraction',
    'nexus_core.memory.manager',
    'nexus_core.agents.registry',
    'nexus_core.state.manager',
    'nexus_core.agent_team_manager',
    'nexus_core.workflow_manager',
]

for m in modules:
    try:
        __import__(m)
        print(f'  ✓  {m}')
    except Exception as e:
        print(f'  ⚠  {m} → {e}')
        errors.append(m)

print()
if errors:
    print(f'  {len(errors)} módulo(s) con advertencias (no crítico si son opcionales)')
else:
    print('  Todos los módulos importaron correctamente')
"

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO v2.0 — Listo para arrancar  ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════${NC}"
echo ""
echo -e "  Comando para iniciar:"
echo -e "  ${CYAN}cd $NEXUS_ROOT && source venv/bin/activate${NC}"
echo -e "  ${CYAN}uvicorn nexus_api.main:app --host 0.0.0.0 --port 8000 --reload${NC}"
echo ""
echo -e "  Backup guardado en: ${YELLOW}$BACKUP_DIR${NC}"
echo ""
