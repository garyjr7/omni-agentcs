"""
nexus_api/main.py — NEXUS PRO v2.0
Orquestador de Agentes IA · Zero Trust · Military Grade
"""
import logging
import sys
import warnings
logging.getLogger('passlib').setLevel(logging.ERROR)
warnings.filterwarnings('ignore', message='.*bcrypt.*')
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "nexus_core"))

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
# ── Security Headers Middleware ────────────────────────────────
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"]   = (
            "default-src 'self'; "
            "connect-src 'self' ws: wss: http://192.168.220.134:8000 ws://192.168.220.134:8000; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline';"
        )
        # Solo HSTS en producción con HTTPS
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("nexus.api")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s"
)

# ══════════════════════════════════════════════════════════════
# LIFESPAN
# ══════════════════════════════════════════════════════════════
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info("  NEXUS PRO v2.0 — Iniciando...")
    logger.info("=" * 60)

    # ── DB ────────────────────────────────────────────────────
    try:
        from nexus_api.auth.database import database, init_db
        init_db()
        await database.connect()
        logger.info("[DB] ✓ Conectada")
    except Exception as e:
        logger.warning(f"[DB] ⚠ {e}")

    # ── NEXUS PRO DB ──────────────────────────────────────────
    try:
        from nexus_api.db.database import init_nexus_db
        init_nexus_db()
        logger.info("[NEXUS-DB] ✓ Base de datos PRO inicializada")
    except Exception as e:
        logger.warning(f"[NEXUS-DB] ⚠ {e}")

    # ── Scheduler ─────────────────────────────────────────────
    try:
        from nexus_api.scheduler.manager import start_scheduler
        start_scheduler()
        logger.info("[SCHEDULER] ✓ Iniciado")
    except Exception as e:
        logger.warning(f"[SCHEDULER] ⚠ {e}")

    # ── EventBus — base de todo, primero ─────────────────────
    try:
        from nexus_core.core.event_bus import EventBus
        app.state.event_bus = EventBus()
        logger.info("[EVENTBUS] ✓ Listo")
    except Exception as e:
        logger.warning(f"[EVENTBUS] ⚠ {e}")
        app.state.event_bus = None

    # ── StateManager ──────────────────────────────────────────
    try:
        from nexus_core.state.manager import StateManager
        app.state.state_manager = StateManager()
        logger.info("[STATE] ✓ Listo")
    except Exception as e:
        logger.warning(f"[STATE] ⚠ {e}")
        app.state.state_manager = None

    # ── AgentRegistry ─────────────────────────────────────────
    try:
        from nexus_core.agents.registry import AgentRegistry
        app.state.registry = AgentRegistry()
        logger.info("[REGISTRY] ✓ Listo")
    except Exception as e:
        logger.warning(f"[REGISTRY] ⚠ {e}")
        app.state.registry = None

    # ── NexusOrchestrator (requiere state + registry + event_bus) ──
    # FIX: clase se llama NexusOrchestrator, no Orchestrator
    # FIX: requiere config, state_manager, agent_registry, event_bus
    try:
        from nexus_core.core.orchestrator import NexusOrchestrator, OrchestratorConfig
        if all([app.state.state_manager, app.state.registry, app.state.event_bus]):
            cfg = OrchestratorConfig()
            app.state.orchestrator = NexusOrchestrator(
                config=cfg,
                state_manager=app.state.state_manager,
                agent_registry=app.state.registry,
                event_bus=app.state.event_bus,
            )
            import asyncio
            asyncio.create_task(app.state.orchestrator.start())
            logger.info("[ORCHESTRATOR] ✓ NexusOrchestrator arrancado")
        else:
            logger.warning("[ORCHESTRATOR] ⚠ Dependencias incompletas — state/registry/eventbus requeridos")
            app.state.orchestrator = None
    except Exception as e:
        logger.warning(f"[ORCHESTRATOR] ⚠ {e}")
        app.state.orchestrator = None

    # ── LLM — NexusLLM con factory desde .env ─────────────────
    # FIX: LLMProvider es un Enum, no se instancia directamente
    # FIX: usar LLMFactory.create_from_env() que detecta keys del .env
    try:
        from nexus_core.llm.abstraction import LLMFactory, NexusLLM
        clients = LLMFactory.create_from_env()
        if clients:
            providers = list(clients.keys())
            primary  = clients[providers[0]]
            fallback = clients[providers[1]] if len(providers) > 1 else None
            app.state.llm = NexusLLM(primary=primary, fallback=fallback)
            msg = f"primary: {providers[0]}"
            if fallback:
                msg += f" · fallback: {providers[1]}"
            logger.info(f"[LLM] ✓ NexusLLM listo — {msg}")
        else:
            app.state.llm = None
            logger.warning("[LLM] ⚠ Sin API keys en .env — agrega OPENAI_API_KEY o GEMINI_API_KEY")
    except Exception as e:
        logger.warning(f"[LLM] ⚠ {e}")
        app.state.llm = None

    # ── MemoryManager ─────────────────────────────────────────
    try:
        from nexus_core.memory.manager import MemoryManager
        app.state.memory = MemoryManager()
        logger.info("[MEMORY] ✓ Listo")
    except Exception as e:
        logger.warning(f"[MEMORY] ⚠ {e}")
        app.state.memory = None

    # ── WorkflowManager — FIX: requiere event_bus como arg ────
    try:
        from nexus_core.workflow_manager import WorkflowManager
        if app.state.event_bus:
            app.state.workflow_manager = WorkflowManager(
                event_bus=app.state.event_bus,
                orchestrator=app.state.orchestrator,  # puede ser None, tiene fallback interno
            )
            logger.info("[WORKFLOW] ✓ WorkflowManager listo")
        else:
            logger.warning("[WORKFLOW] ⚠ EventBus no disponible")
            app.state.workflow_manager = None
    except Exception as e:
        logger.warning(f"[WORKFLOW] ⚠ {e}")
        app.state.workflow_manager = None

    # ── AgentTeamManager ──────────────────────────────────────
    try:
        from nexus_core.agent_team_manager import create_team_router
        app.include_router(create_team_router())
        logger.info("[TEAMS] ✓ AgentTeamManager → /teams/*")
    except Exception as e:
        logger.warning(f"[TEAMS] ⚠ {e}")

    # ── Registrar agentes — FIX: metadata explícita ──────────
    try:
        import importlib
        from nexus_core.agents.base import AgentMetadata, AgentCapability
        _agents_with_meta = [
            ("nexus_core.agents.generated.bashagent", "BashAgent",
             AgentMetadata(name="BashAgent", capabilities=[AgentCapability.FILE_OPERATIONS])),
            ("nexus_core.agents.generated.codeagent", "CodeAgent",
             AgentMetadata(name="CodeAgent", capabilities=[AgentCapability.CODE_GENERATION])),
            ("nexus_core.agents.generated.fileagent", "FileAgent",
             AgentMetadata(name="FileAgent", capabilities=[AgentCapability.FILE_OPERATIONS])),
        ]
        registered = []
        for mod_path, cls_name, meta in _agents_with_meta:
            try:
                mod = importlib.import_module(mod_path)
                AgentClass = getattr(mod, cls_name)
                agent = AgentClass(metadata=meta)
                if app.state.registry:
                    await app.state.registry.register(agent)
                registered.append(cls_name)
            except Exception as ae:
                logger.warning(f"[AGENTS] ⚠ {cls_name}: {ae}")
        if registered:
            logger.info(f"[AGENTS] ✓ Registrados: {', '.join(registered)}")
    except Exception as e:
        logger.warning(f"[AGENTS] ⚠ {e}")

    # ── HITL Manager — inicializar singleton ────────────────
    try:
        from nexus_core.hitl.manager import get_hitl_manager
        hitl = get_hitl_manager()
        app.state.hitl = hitl
        logger.info("[HITL] ✓ HITLManager activo — interceptando acciones críticas")
    except Exception as e:
        logger.warning(f"[HITL] ⚠ {e}")
        app.state.hitl = None

    # ── Registrar Junior Agent (estrella) ───────────────────
    try:
        from nexus_core.agents.junior_agent import JuniorAgent
        llm = getattr(app.state, 'llm', None)
        registry = getattr(app.state, 'registry', None)
        if registry:
            junior = JuniorAgent(llm=llm)
            await registry.register(junior)
            app.state.junior = junior
            logger.info("[JUNIOR-AGENT] ✓ Junior Agent registrado — autónomo y listo")
    except Exception as e:
        logger.warning(f"[JUNIOR-AGENT] ⚠ {e}")
        app.state.junior = None

    # ── Cargar agentes de DB al Registry ────────────────────
    try:
        from nexus_api.db.database import db_list_agents
        from nexus_core.agents.dynamic_agent import DynamicAgent
        db_agents = db_list_agents()
        loaded = []
        llm = getattr(app.state, 'llm', None)
        registry = getattr(app.state, 'registry', None)
        if registry and db_agents:
            for agent_cfg in db_agents:
                try:
                    dyn_agent = DynamicAgent(agent_cfg, llm=llm)
                    await registry.register(dyn_agent)
                    loaded.append(agent_cfg['name'])
                except Exception as ae:
                    logger.warning(f"[DYNAMIC] ⚠ {agent_cfg['name']}: {ae}")
            if loaded:
                logger.info(f"[DYNAMIC] ✓ Agentes DB cargados: {', '.join(loaded)}")
    except Exception as e:
        logger.warning(f"[DYNAMIC] ⚠ Error cargando agentes DB: {e}")

    # ── JuniorBridge — FIX: módulo no existe, warning limpio ──
    try:
        from nexus_core.junior_bridge import initialize_bridge, get_junior_bridge
        bridge_ok = await initialize_bridge()
        app.state.junior_bridge = get_junior_bridge() if bridge_ok else None
        logger.info(f"[JUNIOR] {'✓ Activo' if bridge_ok else '⚠ Degradado'}")
    except ModuleNotFoundError:
        logger.warning("[JUNIOR] ⚠ nexus_core/junior_bridge.py no existe — se puede crear")
        app.state.junior_bridge = None
    except Exception as e:
        logger.warning(f"[JUNIOR] ⚠ {e}")
        app.state.junior_bridge = None

    logger.info("=" * 60)
    logger.info("  NEXUS PRO v2.0 — SISTEMA HEALTHY ✓")
    logger.info("  API Docs → http://0.0.0.0:8000/docs")
    logger.info("=" * 60)

    yield  # ← app corriendo

    # ── Shutdown ──────────────────────────────────────────────
    logger.info("[NEXUS] Apagando servicios...")
    try:
        if getattr(app.state, "orchestrator", None):
            await app.state.orchestrator.stop()
    except Exception:
        pass
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


# ══════════════════════════════════════════════════════════════
# APP
# ══════════════════════════════════════════════════════════════
app = FastAPI(
    title="NEXUS PRO",
    version="2.0.0",
    description="AI Operations Platform — Orquestador de Agentes IA · Zero Trust",
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

# ══════════════════════════════════════════════════════════════
# ROUTERS
# ══════════════════════════════════════════════════════════════
def safe_include(router, **kwargs):
    try:
        app.include_router(router, **kwargs)
        return True
    except Exception as e:
        logger.warning(f"[ROUTER] {kwargs.get('prefix', '?')} ⚠ {e}")
        return False

# Auth — obligatorio
from nexus_api.routes.auth   import router as auth_router
from nexus_api.routes.memory  import router as memory_router
from nexus_api.routes.factory import router as factory_router
from nexus_api.routes.jarvis  import router as jarvis_router
app.include_router(auth_router,   tags=["Auth"])
app.include_router(memory_router)
app.include_router(factory_router)
app.include_router(jarvis_router)

# Todos los demás — tolerantes a fallos
import importlib
_routes = [
    ("nexus_api.routes.scheduler",       {},                              ["Scheduler"]),
    ("nexus_api.routes.agents",          {},                              ["Agents"]),
    ("nexus_api.routes.tasks",           {},                              ["Tasks"]),
    ("nexus_api.routes.nexus",           {},                              ["Nexus"]),
    ("nexus_api.routes.guardian",        {"prefix": "/guardian"},         ["Security"]),
    ("nexus_api.routes.teams_v2",        {"prefix": "/teams-v2"},         ["Teams"]),
    ("nexus_api.routes.project_manager", {"prefix": "/project-manager"},  ["ProjectMgr"]),
    ("nexus_api.routes.plans",           {"prefix": "/plans"},            ["Plans"]),
    ("nexus_api.routes.composite",       {"prefix": "/composite"},        ["Composite"]),
    ("nexus_api.routes.killswitch",      {"prefix": "/killswitch"},       ["KillSwitch"]),
    ("nexus_api.routes.testagent",       {"prefix": "/testagent"},        ["TestAgent"]),
    ("nexus_api.routes.docagent",        {"prefix": "/docagent"},         ["DocAgent"]),
    ("nexus_api.routes.ws_logs",         {},                              ["WebSocket"]),
    ("nexus_api.routes.projects",        {"prefix": "/projects"},         ["Projects"]),
    ("nexus_api.routes.tools",           {},                              ["Tools"]),
    ("nexus_api.routes.models",          {},                              ["Models"]),
    ("nexus_api.routes.junior",          {},                              ["Junior"]),
    ("nexus_api.routes.pentest",         {},                              ["Pentest"]),
    ("nexus_api.routes.hitl",            {},                              ["HITL"]),
]

for module_path, kwargs, tags in _routes:
    try:
        mod = importlib.import_module(module_path)
        safe_include(mod.router, tags=tags, **kwargs)
    except Exception as e:
        logger.warning(f"[ROUTER] {module_path.split('.')[-1]} ⚠ {e}")

# ══════════════════════════════════════════════════════════════
# ENDPOINTS BASE
# ══════════════════════════════════════════════════════════════
@app.get("/health", tags=["Health"])
async def health():
    from datetime import datetime

    def svc(key):
        return "ok" if getattr(app.state, key, None) is not None else "degraded"

    hitl_count = 0
    try:
        hitl = getattr(app.state, 'hitl', None)
        if hitl:
            hitl_count = hitl.count_pending()
    except Exception:
        pass

    services = {k: svc(k) for k in [
        "orchestrator", "llm", "memory", "registry",
        "event_bus", "junior_bridge", "workflow_manager", "state_manager"
    ]}

    # Core mínimo: event_bus + state + registry
    core_ok = all(services[k] == "ok" for k in ["event_bus", "state_manager", "registry"])

    return {
        "status": "healthy" if core_ok else "degraded",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "platform": "NEXUS PRO — AI Operations Platform",
        "services": services,
        "hitl_pending": hitl_count,
    }


@app.get("/", tags=["Health"])
async def root():
    return {
        "name": "NEXUS PRO",
        "version": "2.0.0",
        "status": "online",
        "docs": "/docs",
        "health": "/health",
    }
