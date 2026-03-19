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
