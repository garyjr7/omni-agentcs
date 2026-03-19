import sys, logging, time
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

# ── añadir BW_ROOT al path ──
BW_ROOT = Path(__file__).parent.parent
if str(BW_ROOT) not in sys.path:
    sys.path.insert(0, str(BW_ROOT))

from nexus_api.config import settings
from nexus_api.services.nexus_service import NexusService
from nexus_api.services.project_service import ProjectService
from nexus_api.routes import nexus as nexus_router
from nexus_api.routes import agents as agents_router
from nexus_api.routes import tasks as tasks_router
from nexus_api.routes import projects as projects_router

# ── Servicios globales ──
nexus_svc   = NexusService(settings)
project_svc = ProjectService(settings)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logging.basicConfig(level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    await nexus_svc.initialize()
    yield
    # Shutdown
    await nexus_svc.shutdown()

app = FastAPI(
    title="BajioWare NEXUS API",
    description="Control API for NEXUS AI Operating System",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request timing middleware ──
@app.middleware("http")
async def timing_middleware(request: Request, call_next):
    t0 = time.time()
    response = await call_next(request)
    ms = (time.time() - t0) * 1000
    response.headers["X-Process-Time-Ms"] = f"{ms:.1f}"
    return response

# ── Global exception handler ──
@app.exception_handler(Exception)
async def global_error(request: Request, exc: Exception):
    return JSONResponse(status_code=500,
        content={"error": str(exc), "type": type(exc).__name__})

# ── Dependency injection helpers ──
def get_nexus():  return nexus_svc
def get_projects(): return project_svc

# ── Routes ──
app.include_router(nexus_router.router,    prefix="/api", tags=["NEXUS"])
app.include_router(agents_router.router,   prefix="/api", tags=["Agents"])
app.include_router(tasks_router.router,    prefix="/api", tags=["Tasks"])
app.include_router(projects_router.router, prefix="/api", tags=["Projects"])

@app.get("/", include_in_schema=False)
async def root(): return RedirectResponse("/docs")

@app.get("/health", tags=["Health"])
async def health():
    status = await nexus_svc.get_status()
    return {"api": "ok", "nexus": status["status"], "mode": status.get("mode","offline")}
