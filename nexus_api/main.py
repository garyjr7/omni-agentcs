"""
nexus_api/main.py — NEXUS Sovereign 3.0
Orquestador de Agentes IA · Zero Trust · Military Grade
"""
import asyncio
import logging
import sys
import time
import uuid
import warnings
from collections import defaultdict, deque

logging.getLogger('passlib').setLevel(logging.ERROR)
warnings.filterwarnings('ignore', message='.*bcrypt.*')
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "nexus_core"))

# Load process-level settings before importing auth/provider modules that use
# os.getenv at import time. Pydantic's env_file does not populate os.environ.
from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ── Security Headers Middleware ────────────────────────────────
from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Frame-Options"] = "DENY"
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
                headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
                headers["Content-Security-Policy"] = (
                    "default-src 'self'; connect-src 'self' ws: wss:; "
                    "script-src 'self'; style-src 'self'; object-src 'none'; "
                    "base-uri 'self'; frame-ancestors 'none';"
                )
                if scope.get("scheme") == "https":
                    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestContextMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        supplied = Headers(scope=scope).get("X-Request-ID", "")
        try:
            trace_id = str(uuid.UUID(supplied)) if supplied else str(uuid.uuid4())
        except ValueError:
            trace_id = str(uuid.uuid4())
        scope.setdefault("state", {})["trace_id"] = trace_id
        started = time.monotonic()
        status_code = 500

        async def send_with_id(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                MutableHeaders(scope=message)["X-Request-ID"] = trace_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            from nexus_core.kernel.telemetry import metrics

            labels = {
                "method": scope.get("method", ""),
                "path": scope.get("route", {}).path
                if getattr(scope.get("route"), "path", None) else scope.get("path", ""),
                "status": str(status_code),
            }
            metrics.increment("nexus_http_requests_total", **labels)
            metrics.increment(
                "nexus_http_duration_ms_total", (time.monotonic() - started) * 1000,
                **labels,
            )


class RateLimitMiddleware:
    def __init__(self, app, requests_per_minute: int, burst: int):
        self.app = app
        self.limit = max(1, requests_per_minute + burst)
        self.requests = defaultdict(deque)
        self.lock = asyncio.Lock()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") == "/health":
            return await self.app(scope, receive, send)
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        now = time.monotonic()
        async with self.lock:
            history = self.requests[client_ip]
            while history and now - history[0] >= 60:
                history.popleft()
            if len(history) >= self.limit:
                response = JSONResponse(
                    {"detail": "rate limit exceeded"}, status_code=429,
                    headers={"Retry-After": "60"},
                )
                return await response(scope, receive, send)
            history.append(now)
        await self.app(scope, receive, send)


from nexus_api.auth.deps import require_admin
from nexus_api.config import settings

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

    from nexus_core.kernel.telemetry import configure_telemetry
    app.state.telemetry_enabled = configure_telemetry()
    logger.info("  NEXUS Sovereign 3.0 — Iniciando...")
    logger.info("=" * 60)

    import os
    if int(os.getenv("WEB_CONCURRENCY", "1")) > 1:
        import logging
        logging.getLogger("nexus").warning(
            "WARNING: Multiple workers detected. In-memory state (AgentRegistry, HITLManager, StateManager) is NOT shared between workers. Set WEB_CONCURRENCY=1 until Redis is integrated."
        )

    # ── NEXUS PRO DB ──────────────────────────────────────────
    try:
        from nexus_api.config import NEXUS_DB_PATH
        from nexus_core.kernel.store_factory import get_control_store
        app.state.control_store = get_control_store(NEXUS_DB_PATH)
        app.state.control_store.initialize()
        if not settings.is_production:
            from nexus_api.db.database import init_nexus_db
            init_nexus_db()
        logger.info("[NEXUS-DB] ✓ Control plane inicializado")
    except Exception as e:
        logger.error(f"[NEXUS-DB] ✗ {e}")
        raise

    # Production runs only the durable control plane. Legacy in-memory agents,
    # schedulers and orchestrators are development compatibility components.
    if settings.is_production or not settings.NEXUS_ENABLE_LEGACY_RUNTIME:
        app.state.orchestrator = None
        app.state.event_bus = None
        app.state.state_manager = None
        app.state.registry = None
        app.state.llm = None
        app.state.memory = None
        app.state.workflow_manager = None
        app.state.junior_bridge = None
        logger.info("[NEXUS] Control plane durable listo; workers son servicios separados")
        yield
        logger.info("[NEXUS] Control plane detenido")
        return

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

        from nexus_core.agents.base import AgentCapability, AgentMetadata
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
        from nexus_core.junior_bridge import get_junior_bridge, initialize_bridge
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
    logger.info("  NEXUS Sovereign 3.0 — SISTEMA HEALTHY ✓")
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
    logger.info("[NEXUS] ✓ Apagado limpio")


# ══════════════════════════════════════════════════════════════
# APP
# ══════════════════════════════════════════════════════════════
app = FastAPI(
    title="NEXUS Sovereign",
    version="3.0.0",
    description="Plataforma soberana de ejecución durable de agentes",
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(
    RateLimitMiddleware,
    requests_per_minute=settings.RATE_LIMIT_PER_MINUTE,
    burst=settings.RATE_LIMIT_BURST,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
)

# ══════════════════════════════════════════════════════════════
# ROUTERS
# ══════════════════════════════════════════════════════════════
# Auth — obligatorio
from nexus_api.routes.auth import router as auth_router
from nexus_api.routes.factory import router as factory_router
from nexus_api.routes.jarvis import router as jarvis_router
from nexus_api.routes.memory import router as memory_router

app.include_router(auth_router, prefix="/api/v1", tags=["Auth v1"])
app.include_router(memory_router, prefix="/api/v1")
if settings.NEXUS_ENABLE_LEGACY_RUNTIME and not settings.is_production:
    app.include_router(factory_router, prefix="/api/v1")
    app.include_router(jarvis_router, prefix="/api/v1")

# Los routers del producto son obligatorios: un import roto debe impedir el arranque.
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
    ("nexus_api.routes.directory",       {},                              ["Directory"]),
    ("nexus_api.routes.evolution",       {},                              ["Evolution"]),
    ("nexus_api.routes.connectors",      {},                              ["Connectors"]),
    ("nexus_api.routes.packages",        {},                              ["Packages"]),
    ("nexus_api.routes.a2a",             {},                              ["A2A"]),
    ("nexus_api.routes.approvals",       {},                              ["Approvals"]),
    ("nexus_api.routes.policies",        {},                              ["Policies"]),
    ("nexus_api.routes.workflows",       {},                              ["Workflows"]),
    ("nexus_api.routes.audit",           {},                              ["Audit"]),
    ("nexus_api.routes.sovereign",       {},                              ["Sovereign"]),
]

_legacy_route_modules = {
    "nexus_api.routes.scheduler", "nexus_api.routes.agents",
    "nexus_api.routes.tasks", "nexus_api.routes.nexus",
    "nexus_api.routes.guardian", "nexus_api.routes.teams_v2",
    "nexus_api.routes.project_manager", "nexus_api.routes.plans",
    "nexus_api.routes.composite", "nexus_api.routes.killswitch",
    "nexus_api.routes.testagent", "nexus_api.routes.docagent",
    "nexus_api.routes.ws_logs", "nexus_api.routes.projects",
    "nexus_api.routes.tools", "nexus_api.routes.models",
    "nexus_api.routes.junior", "nexus_api.routes.pentest",
    "nexus_api.routes.hitl",
}

for module_path, kwargs, tags in _routes:
    if module_path in _legacy_route_modules and (
        settings.is_production or not settings.NEXUS_ENABLE_LEGACY_RUNTIME
    ):
        continue
    mod = importlib.import_module(module_path)
    alias_kwargs = dict(kwargs)
    alias_kwargs["prefix"] = "/api/v1" + alias_kwargs.get("prefix", "")
    app.include_router(mod.router, tags=[f"{tag} v1" for tag in tags], **alias_kwargs)

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

    durable_ready = getattr(app.state, "control_store", None) is not None
    core_ok = durable_ready and (
        settings.is_production or not settings.NEXUS_ENABLE_LEGACY_RUNTIME or
        all(services[k] == "ok" for k in ["event_bus", "state_manager", "registry"])
    )

    return {
        "status": "healthy" if core_ok else "degraded",
        "version": "3.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "platform": "NEXUS Sovereign — Durable Agent Platform",
        "services": services,
        "durable_control_plane": "ok" if durable_ready else "degraded",
        "hitl_pending": hitl_count,
    }


@app.get("/", tags=["Health"])
async def root():
    return {
        "name": "NEXUS Sovereign",
        "version": "3.0.0",
        "status": "online",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/system/metrics", tags=["System"])
async def system_metrics(_=Depends(require_admin)):
    from nexus_core.kernel.telemetry import metrics

    return {"metrics": metrics.snapshot()}
