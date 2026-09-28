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
    from nexus_core.kernel.telemetry import configure_telemetry
    from nexus_api.config import NEXUS_DB_PATH
    from nexus_core.kernel.store_factory import get_control_store

    app.state.telemetry_enabled = configure_telemetry()
    app.state.control_store = get_control_store(NEXUS_DB_PATH)
    app.state.control_store.initialize()
    logger.info("[NEXUS] Control plane durable listo")
    yield
    logger.info("[NEXUS] Control plane detenido")


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
import importlib

_routes = [
    ("nexus_api.routes.auth", {}, ["Auth"]),
    ("nexus_api.routes.memory", {}, ["Memory"]),
    ("nexus_api.routes.agents", {}, ["Agents"]),
    ("nexus_api.routes.tasks", {}, ["Tasks"]),
    ("nexus_api.routes.nexus", {}, ["Nexus"]),
    ("nexus_api.routes.projects", {"prefix": "/projects"}, ["Projects"]),
    ("nexus_api.routes.tools", {}, ["Tools"]),
    ("nexus_api.routes.models", {}, ["Models"]),
    ("nexus_api.routes.directory", {}, ["Directory"]),
    ("nexus_api.routes.evolution", {}, ["Evolution"]),
    ("nexus_api.routes.connectors", {}, ["Connectors"]),
    ("nexus_api.routes.packages", {}, ["Packages"]),
    ("nexus_api.routes.a2a", {}, ["A2A"]),
    ("nexus_api.routes.approvals", {}, ["Approvals"]),
    ("nexus_api.routes.policies", {}, ["Policies"]),
    ("nexus_api.routes.workflows", {}, ["Workflows"]),
    ("nexus_api.routes.audit", {}, ["Audit"]),
    ("nexus_api.routes.sovereign", {}, ["Sovereign"]),
    ("nexus_api.routes.ws_logs", {}, ["WebSocket"]),
]

for module_path, kwargs, tags in _routes:
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

    durable_ready = getattr(app.state, "control_store", None) is not None
    return {
        "status": "healthy" if durable_ready else "degraded",
        "version": "3.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "platform": "NEXUS Sovereign — Durable Agent Platform",
        "durable_control_plane": "ok" if durable_ready else "degraded",
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
