#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Punto 4: HITL Real                            ║
# ║  Agentes pausan · Dashboard notifica · Tú apruebas/niegas  ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

NEXUS="/home/operator/NEXUS-PRO"
CORE="$NEXUS/nexus_core"
API="$NEXUS/nexus_api"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

# ══════════════════════════════════════════════════════════════
head "1/4 · nexus_core/hitl/manager.py — Motor central HITL"
# ══════════════════════════════════════════════════════════════
mkdir -p "$CORE/hitl"
touch "$CORE/hitl/__init__.py"

cat > "$CORE/hitl/manager.py" << 'EOF'
"""
NEXUS PRO — HITL Manager v1.0
Human In The Loop — Motor central de aprobaciones.

Flujo:
  1. Agente detecta acción que requiere aprobación
  2. HITLManager.request() → crea pendiente + pausa agente
  3. WebSocket notifica al dashboard en tiempo real
  4. Usuario aprueba o deniega desde el dashboard
  5. Agente recibe la decisión y continúa o cancela

Modos HITL por agente:
  always      → toda acción pasa por HITL
  destructive → solo acciones destructivas (delete, deploy, exec)
  never       → completamente autónomo
"""
import asyncio
import json
import uuid
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("nexus.hitl")


class HITLRisk(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


class HITLStatus(str, Enum):
    PENDING  = "pending"
    APPROVED = "approved"
    DENIED   = "denied"
    TIMEOUT  = "timeout"
    AUTO     = "auto_approved"


# Acciones que SIEMPRE requieren HITL sin importar el modo
ALWAYS_HITL = {
    "rm -rf", "DROP TABLE", "DELETE FROM", "kubectl delete",
    "docker rm", "format", "mkfs", "dd if=",
    "deploy production", "push --force",
}

# Acciones destructivas (requieren HITL en modo 'destructive')
DESTRUCTIVE_ACTIONS = {
    "file_delete", "bash_exec", "docker_ops", "git_ops",
    "nmap_scan", "nuclei_scan", "sast_scan", "stride_model",
    "sql_query",
}

# Acciones siempre seguras (nunca requieren HITL)
SAFE_ACTIONS = {
    "file_read", "file_list", "http_request", "llm_call",
    "report_gen", "memory_search", "code_exec",
}


class HITLRequest:
    """Una solicitud de aprobación pendiente."""
    def __init__(self, agent_name: str, agent_id: str,
                 action: str, tool: str, params: dict,
                 risk: HITLRisk, context: str = ""):
        self.id          = f"HITL-{uuid.uuid4().hex[:6].upper()}"
        self.agent_name  = agent_name
        self.agent_id    = agent_id
        self.action      = action
        self.tool        = tool
        self.params      = params
        self.risk        = risk
        self.context     = context
        self.status      = HITLStatus.PENDING
        self.created_at  = datetime.utcnow().isoformat()
        self.resolved_at = None
        self.resolved_by = None
        self.reason      = None
        self._event      = asyncio.Event()

    def to_dict(self) -> dict:
        return {
            "id":           self.id,
            "agent_name":   self.agent_name,
            "agent_id":     self.agent_id,
            "action":       self.action,
            "tool":         self.tool,
            "params":       self.params,
            "risk":         self.risk,
            "context":      self.context,
            "status":       self.status,
            "created_at":   self.created_at,
            "resolved_at":  self.resolved_at,
            "resolved_by":  self.resolved_by,
            "reason":       self.reason,
        }


class HITLManager:
    """
    Motor central de Human In The Loop.
    Singleton — una instancia por servidor.
    """
    def __init__(self):
        self._pending:  Dict[str, HITLRequest] = {}
        self._history:  List[dict] = []
        self._listeners: List[Callable] = []  # WebSocket listeners
        self._timeout   = 300  # 5 minutos para decidir
        logger.info("[HITL] ✓ HITLManager iniciado")

    # ── Suscripción de listeners (WebSocket) ──────────────────
    def subscribe(self, listener: Callable):
        self._listeners.append(listener)

    def unsubscribe(self, listener: Callable):
        if listener in self._listeners:
            self._listeners.remove(listener)

    async def _notify(self, event: str, data: dict):
        """Notifica a todos los WebSocket conectados."""
        msg = {"type": "hitl", "event": event,
               "data": data, "timestamp": datetime.utcnow().isoformat()}
        dead = []
        for listener in self._listeners:
            try:
                await listener(msg)
            except Exception:
                dead.append(listener)
        for d in dead:
            self.unsubscribe(d)

    # ── Evaluación de riesgo ──────────────────────────────────
    @staticmethod
    def evaluate_risk(tool: str, params: dict, hitl_mode: str) -> Optional[HITLRisk]:
        """
        Decide si una acción requiere HITL y con qué nivel de riesgo.
        Retorna None si no requiere aprobación.
        """
        if hitl_mode == "never":
            return None

        params_str = json.dumps(params, ensure_ascii=False).lower()

        # Verificar comandos siempre bloqueados
        for blocked in ALWAYS_HITL:
            if blocked.lower() in params_str:
                return HITLRisk.CRITICAL

        # Modo 'always' — todo requiere aprobación
        if hitl_mode == "always":
            if tool in SAFE_ACTIONS:
                return HITLRisk.LOW
            return HITLRisk.MEDIUM

        # Modo 'destructive' — solo acciones destructivas
        if hitl_mode == "destructive":
            if tool in SAFE_ACTIONS:
                return None
            if tool in DESTRUCTIVE_ACTIONS:
                # Evaluar severidad por el contenido
                if any(x in params_str for x in ["delete", "remove", "drop", "destroy", "prod", "production"]):
                    return HITLRisk.HIGH
                if tool in {"nmap_scan", "nuclei_scan"}:
                    target = params.get("target", "")
                    # Externo = más riesgo
                    if not any(x in str(target) for x in ["localhost", "127.0.0.1", "192.168"]):
                        return HITLRisk.HIGH
                    return HITLRisk.MEDIUM
                return HITLRisk.MEDIUM

        return None

    # ── Solicitud de aprobación ───────────────────────────────
    async def request(self, agent_name: str, agent_id: str,
                      action: str, tool: str, params: dict,
                      risk: HITLRisk, context: str = "",
                      timeout: int = None) -> HITLStatus:
        """
        Pausa el agente y espera aprobación humana.
        Retorna HITLStatus.APPROVED o HITLStatus.DENIED.
        """
        req = HITLRequest(agent_name, agent_id, action,
                          tool, params, risk, context)
        self._pending[req.id] = req

        logger.warning(
            f"[HITL] ⏸ PAUSADO: {agent_name} quiere ejecutar "
            f"{tool} [{risk}] — ID: {req.id}"
        )

        # Notificar dashboard
        await self._notify("new_request", req.to_dict())

        # Esperar decisión humana
        wait_time = timeout or self._timeout
        try:
            await asyncio.wait_for(req._event.wait(), timeout=wait_time)
        except asyncio.TimeoutError:
            req.status = HITLStatus.TIMEOUT
            req.resolved_at = datetime.utcnow().isoformat()
            req.reason = f"Timeout después de {wait_time}s"
            logger.warning(f"[HITL] ⏰ Timeout: {req.id}")
            await self._notify("timeout", req.to_dict())

        # Mover a historial
        self._pending.pop(req.id, None)
        self._history.insert(0, req.to_dict())
        if len(self._history) > 100:
            self._history = self._history[:100]

        logger.info(
            f"[HITL] {'✓' if req.status == HITLStatus.APPROVED else '✗'} "
            f"{req.id}: {req.status} por {req.resolved_by or 'timeout'}"
        )
        return req.status

    # ── Resolución ────────────────────────────────────────────
    async def approve(self, hitl_id: str, approved_by: str = "admin",
                      reason: str = "") -> dict:
        req = self._pending.get(hitl_id)
        if not req:
            return {"success": False, "error": f"{hitl_id} no encontrado o ya resuelto"}
        req.status      = HITLStatus.APPROVED
        req.resolved_at = datetime.utcnow().isoformat()
        req.resolved_by = approved_by
        req.reason      = reason or "Aprobado"
        req._event.set()
        await self._notify("approved", req.to_dict())
        return {"success": True, "id": hitl_id, "status": "approved"}

    async def deny(self, hitl_id: str, denied_by: str = "admin",
                   reason: str = "") -> dict:
        req = self._pending.get(hitl_id)
        if not req:
            return {"success": False, "error": f"{hitl_id} no encontrado o ya resuelto"}
        req.status      = HITLStatus.DENIED
        req.resolved_at = datetime.utcnow().isoformat()
        req.resolved_by = denied_by
        req.reason      = reason or "Denegado por el usuario"
        req._event.set()
        await self._notify("denied", req.to_dict())
        return {"success": True, "id": hitl_id, "status": "denied"}

    # ── Consultas ─────────────────────────────────────────────
    def get_pending(self) -> List[dict]:
        return [r.to_dict() for r in self._pending.values()]

    def get_history(self, limit: int = 20) -> List[dict]:
        return self._history[:limit]

    def count_pending(self) -> int:
        return len(self._pending)

    async def approve_all(self, approved_by: str = "admin") -> dict:
        ids = list(self._pending.keys())
        for hid in ids:
            await self.approve(hid, approved_by, "Aprobación masiva")
        return {"approved": len(ids)}

    async def deny_all(self, denied_by: str = "admin") -> dict:
        ids = list(self._pending.keys())
        for hid in ids:
            await self.deny(hid, denied_by, "Denegación masiva")
        return {"denied": len(ids)}


# ── Singleton global ──────────────────────────────────────────
_hitl_manager: Optional[HITLManager] = None

def get_hitl_manager() -> HITLManager:
    global _hitl_manager
    if _hitl_manager is None:
        _hitl_manager = HITLManager()
    return _hitl_manager
EOF
log "hitl/manager.py"

# ══════════════════════════════════════════════════════════════
head "2/4 · Actualizar DynamicAgent — interceptar con HITL"
# ══════════════════════════════════════════════════════════════
python3 << 'PYFIX'
path = "/home/operator/NEXUS-PRO/nexus_core/agents/dynamic_agent.py"
with open(path) as f:
    content = f.read()

# Insertar import del HITLManager al inicio del execute
old_execute = '''    async def execute(self, task_id: str, payload: dict) -> dict:
        """
        Ejecuta la tarea con razonamiento LLM si está disponible,
        o ejecución directa si el payload especifica la tool.
        """
        task_name = payload.get("_task_name", f"task_{task_id[:8]}")
        task_desc = payload.get("_task_desc", "")'''

new_execute = '''    async def execute(self, task_id: str, payload: dict) -> dict:
        """
        Ejecuta la tarea con razonamiento LLM + interceptor HITL.
        Si la acción requiere aprobación, pausa y espera al humano.
        """
        task_name = payload.get("_task_name", f"task_{task_id[:8]}")
        task_desc = payload.get("_task_desc", "")'''

if old_execute in content:
    content = content.replace(old_execute, new_execute)

# Insertar HITL check antes de ejecutar la tool
old_exec_tool = '''        logger.info(f"[{self.name}] ⚡ Ejecutando: {tool_name} | task: {task_id}")

        # ── Ejecutar la tool ──────────────────────────────────
        tool_result = await ToolExecutor.execute_tool(
            tool_name, clean_payload, self._llm
        )'''

new_exec_tool = '''        logger.info(f"[{self.name}] ⚡ Ejecutando: {tool_name} | task: {task_id}")

        # ── HITL Check — ¿requiere aprobación humana? ─────────
        hitl_mode = self._config.get("hitl_mode", "destructive")
        if hitl_mode != "never":
            try:
                from nexus_core.hitl.manager import get_hitl_manager, HITLManager
                hitl = get_hitl_manager()
                risk = HITLManager.evaluate_risk(tool_name, clean_payload, hitl_mode)
                if risk is not None:
                    context = (
                        f"Agente {self.name} ({self._role}) quiere ejecutar '{tool_name}'.\\n"
                        f"Tarea: {task_name}\\n"
                        f"Params: {str(clean_payload)[:300]}"
                    )
                    logger.warning(
                        f"[{self.name}] ⏸ HITL requerido [{risk}] para {tool_name}"
                    )
                    status = await hitl.request(
                        agent_name=self.name,
                        agent_id=self.metadata.agent_id,
                        action=f"{task_name} → {tool_name}",
                        tool=tool_name,
                        params=clean_payload,
                        risk=risk,
                        context=context,
                        timeout=300,
                    )
                    from nexus_core.hitl.manager import HITLStatus
                    if status != HITLStatus.APPROVED:
                        return {
                            "agent": self.name,
                            "tool_used": tool_name,
                            "task_id": task_id,
                            "status": "hitl_denied",
                            "hitl_status": str(status),
                            "message": f"Acción bloqueada por HITL: {status}",
                        }
            except Exception as hitl_err:
                logger.warning(f"[{self.name}] HITL error (continuando): {hitl_err}")

        # ── Ejecutar la tool ──────────────────────────────────
        tool_result = await ToolExecutor.execute_tool(
            tool_name, clean_payload, self._llm
        )'''

if old_exec_tool in content:
    content = content.replace(old_exec_tool, new_exec_tool)
    print("  ✓ HITL interceptor agregado a DynamicAgent")
else:
    print("  ⚠ Bloque no encontrado exactamente — verificar manualmente")

with open(path, 'w') as f:
    f.write(content)
PYFIX

# ══════════════════════════════════════════════════════════════
head "3/4 · nexus_api/routes/hitl.py — API completa de HITL"
# ══════════════════════════════════════════════════════════════
cat > "$API/routes/hitl.py" << 'EOF'
"""
NEXUS PRO — HITL API v2.0
Human In The Loop — endpoints completos + WebSocket tiempo real
"""
import asyncio
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


def get_hitl():
    from nexus_core.hitl.manager import get_hitl_manager
    return get_hitl_manager()


# ── Schemas ───────────────────────────────────────────────────
class ApproveRequest(BaseModel):
    approved_by: str = "admin"
    reason: str = ""

class DenyRequest(BaseModel):
    denied_by: str = "admin"
    reason: str = "Denegado por el usuario"


# ── Endpoints REST ────────────────────────────────────────────

@router.get("/hitl/pending")
def get_pending():
    """Lista todas las solicitudes HITL pendientes."""
    hitl = get_hitl()
    pending = hitl.get_pending()
    return {
        "pending": pending,
        "total": len(pending),
        "timestamp": datetime.utcnow().isoformat(),
    }

@router.get("/hitl/history")
def get_history(limit: int = 20):
    """Historial de decisiones HITL."""
    hitl = get_hitl()
    return {
        "history": hitl.get_history(limit),
        "total": len(hitl.get_history(100)),
    }

@router.get("/hitl/count")
def get_count():
    """Número de HITL pendientes — para el topbar del dashboard."""
    hitl = get_hitl()
    return {"count": hitl.count_pending()}

@router.post("/hitl/{hitl_id}/approve")
async def approve(hitl_id: str, body: ApproveRequest):
    """Aprueba una solicitud HITL — el agente continúa."""
    hitl = get_hitl()
    result = await hitl.approve(hitl_id, body.approved_by, body.reason)
    if not result.get("success"):
        raise HTTPException(404, result.get("error", "HITL no encontrado"))
    return result

@router.post("/hitl/{hitl_id}/deny")
async def deny(hitl_id: str, body: DenyRequest):
    """Deniega una solicitud HITL — el agente cancela la acción."""
    hitl = get_hitl()
    result = await hitl.deny(hitl_id, body.denied_by, body.reason)
    if not result.get("success"):
        raise HTTPException(404, result.get("error", "HITL no encontrado"))
    return result

@router.post("/hitl/approve-all")
async def approve_all(body: ApproveRequest):
    """Aprueba todas las solicitudes pendientes."""
    hitl = get_hitl()
    return await hitl.approve_all(body.approved_by)

@router.post("/hitl/deny-all")
async def deny_all(body: DenyRequest):
    """Deniega todas las solicitudes pendientes."""
    hitl = get_hitl()
    return await hitl.deny_all(body.denied_by)


# ── WebSocket — notificaciones en tiempo real ─────────────────
@router.websocket("/ws/hitl")
async def hitl_websocket(ws: WebSocket):
    """
    WebSocket dedicado para HITL.
    El dashboard se suscribe y recibe notificaciones instantáneas
    cuando un agente pide aprobación.
    """
    await ws.accept()
    hitl = get_hitl()

    # Enviar estado actual al conectarse
    pending = hitl.get_pending()
    await ws.send_text(json.dumps({
        "type": "hitl",
        "event": "connected",
        "data": {"pending": pending, "count": len(pending)},
        "timestamp": datetime.utcnow().isoformat(),
    }))

    # Suscribir al manager
    async def on_hitl_event(msg: dict):
        try:
            await ws.send_text(json.dumps(msg, default=str))
        except Exception:
            pass

    hitl.subscribe(on_hitl_event)

    try:
        while True:
            try:
                data = await asyncio.wait_for(ws.receive_text(), timeout=30.0)
                # Procesar comandos desde el dashboard
                try:
                    cmd = json.loads(data)
                    if cmd.get("action") == "approve":
                        result = await hitl.approve(
                            cmd["hitl_id"],
                            cmd.get("by", "dashboard"),
                            cmd.get("reason", "")
                        )
                        await ws.send_text(json.dumps({
                            "type": "hitl_response", **result
                        }))
                    elif cmd.get("action") == "deny":
                        result = await hitl.deny(
                            cmd["hitl_id"],
                            cmd.get("by", "dashboard"),
                            cmd.get("reason", "")
                        )
                        await ws.send_text(json.dumps({
                            "type": "hitl_response", **result
                        }))
                    elif cmd.get("action") == "ping":
                        await ws.send_text(json.dumps({"type": "pong"}))
                except json.JSONDecodeError:
                    pass
            except asyncio.TimeoutError:
                # Heartbeat con conteo actual
                await ws.send_text(json.dumps({
                    "type": "hitl_heartbeat",
                    "count": hitl.count_pending(),
                    "timestamp": datetime.utcnow().isoformat(),
                }))
    except WebSocketDisconnect:
        pass
    finally:
        hitl.unsubscribe(on_hitl_event)
EOF
log "hitl.py routes"

# ══════════════════════════════════════════════════════════════
head "4/4 · Registrar HITL en main.py + inicializar singleton"
# ══════════════════════════════════════════════════════════════
python3 << 'PYFIX'
path = "/home/operator/NEXUS-PRO/nexus_api/main.py"
with open(path) as f:
    content = f.read()

# 1. Inicializar HITLManager en startup
old_junior = """    # ── Registrar Junior Agent (estrella) ───────────────────"""
new_junior = """    # ── HITL Manager — inicializar singleton ────────────────
    try:
        from nexus_core.hitl.manager import get_hitl_manager
        hitl = get_hitl_manager()
        app.state.hitl = hitl
        logger.info("[HITL] ✓ HITLManager activo — interceptando acciones críticas")
    except Exception as e:
        logger.warning(f"[HITL] ⚠ {e}")
        app.state.hitl = None

    # ── Registrar Junior Agent (estrella) ───────────────────"""

# 2. Agregar route
old_routes = '    ("nexus_api.routes.pentest",         {},                              ["Pentest"]),'
new_routes = '''    ("nexus_api.routes.pentest",         {},                              ["Pentest"]),
    ("nexus_api.routes.hitl",            {},                              ["HITL"]),'''

changed = False
if old_junior in content:
    content = content.replace(old_junior, new_junior)
    print("  ✓ HITLManager inicializado en startup")
    changed = True

if old_routes in content:
    content = content.replace(old_routes, new_routes)
    print("  ✓ Route /hitl/* + /ws/hitl registrado")
    changed = True

# También exponer el count en /health
old_health = '    services = {k: svc(k) for k in ['
new_health = '''    hitl_count = 0
    try:
        hitl = getattr(app.state, 'hitl', None)
        if hitl:
            hitl_count = hitl.count_pending()
    except Exception:
        pass

    services = {k: svc(k) for k in ['''

if old_health in content and 'hitl_count' not in content:
    content = content.replace(old_health, new_health)
    # También agregar hitl_count al return
    old_return = '"services": services,'
    new_return = '"services": services,\n        "hitl_pending": hitl_count,'
    content = content.replace(old_return, new_return, 1)
    print("  ✓ hitl_pending agregado al /health")
    changed = True

if changed:
    with open(path, 'w') as f:
        f.write(content)
PYFIX

# ── Rebuild frontend ──────────────────────────────────────────
cd "$NEXUS/nexus_frontend"
npm run build --silent 2>&1 | tail -2

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO — Punto 4: HITL Real ✓                 ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Nuevos endpoints:"
echo -e "  ${CYAN}GET  /hitl/pending${NC}            ← solicitudes pendientes"
echo -e "  ${CYAN}GET  /hitl/history${NC}            ← historial de decisiones"
echo -e "  ${CYAN}POST /hitl/:id/approve${NC}        ← aprobar acción"
echo -e "  ${CYAN}POST /hitl/:id/deny${NC}           ← denegar acción"
echo -e "  ${CYAN}POST /hitl/approve-all${NC}        ← aprobar todas"
echo -e "  ${CYAN}WS   /ws/hitl${NC}                 ← notificaciones tiempo real"
echo ""
echo -e "  Reinicia uvicorn y ejecuta las pruebas:"
echo ""
echo -e "  ${CYAN}# Prueba 1 — Crear tarea que TRIGGER HITL (DevOpsBot modo 'always')${NC}"
echo -e '  curl -s -X POST http://localhost:8000/tasks \'
echo -e '    -H "Content-Type: application/json" \'
echo -e '    -d '"'"'{"name":"Deploy staging","description":"Ejecutar deploy en servidor","task_type":"unique","priority":"alta","agent_id":"agt_3d4f1b9d","payload":{"tool":"bash_exec","command":"echo DEPLOY STAGING && ls /home/operator/NEXUS-PRO"}}'"'"' | python3 -m json.tool'
echo ""
echo -e "  ${CYAN}# Prueba 2 — Ver el HITL pendiente${NC}"
echo -e "  curl -s http://localhost:8000/hitl/pending | python3 -m json.tool"
echo ""
echo -e "  ${CYAN}# Prueba 3 — Aprobar desde CLI (en dashboard ya funciona con botones)${NC}"
echo -e "  curl -s -X POST http://localhost:8000/hitl/HITL_ID/approve \\"
echo -e '    -H "Content-Type: application/json" \'
echo -e '    -d '"'"'{"approved_by":"marcos","reason":"Revisado y aprobado"}'"'"' | python3 -m json.tool'
echo ""
