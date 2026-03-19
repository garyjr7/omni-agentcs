"""
NEXUS PRO — WebSocket Logs
Transmite logs del sistema en tiempo real al dashboard
"""
import asyncio
import json
import logging
from datetime import datetime
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List

router = APIRouter()

# ── Manager de conexiones ────────────────────────────────────
class NexusLogManager:
    def __init__(self):
        self._connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)

    async def broadcast(self, msg: dict):
        dead = []
        for ws in self._connections:
            try:
                await ws.send_text(json.dumps(msg))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    async def send_log(self, level: str, source: str, message: str):
        await self.broadcast({
            "type": "log",
            "level": level.upper(),
            "source": source,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
        })

log_manager = NexusLogManager()

def get_log_manager() -> NexusLogManager:
    return log_manager


# ── Handler de logging para capturar logs reales ─────────────
class WSLogHandler(logging.Handler):
    def __init__(self, manager: NexusLogManager):
        super().__init__()
        self._manager = manager
        self._loop = None

    def emit(self, record):
        try:
            import asyncio
            msg = self.format(record)
            level = record.levelname
            source = record.name.replace('nexus.','').replace('uvicorn.','')

            # Solo emitir logs relevantes de nexus
            if not any(x in record.name for x in ['nexus','uvicorn','NexusOrchestrator','AgentRegistry','JuniorBridge','WorkflowManager']):
                return

            log_entry = {
                "type": "log",
                "level": level,
                "source": source[:20],
                "message": msg[:300],
                "timestamp": datetime.utcnow().isoformat(),
            }
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(self._manager.broadcast(log_entry))
            except Exception:
                pass
        except Exception:
            pass

# Registrar el handler
_ws_handler = WSLogHandler(log_manager)
_ws_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(_ws_handler)


# ── Endpoints WebSocket ───────────────────────────────────────

@router.websocket("/ws/logs")
async def websocket_global(ws: WebSocket):
    """Canal global de logs del sistema."""
    await log_manager.connect(ws)
    await log_manager.send_log("SUCCESS", "nexus-ws", "Dashboard conectado — NEXUS PRO v2.0")

    try:
        while True:
            # Heartbeat cada 15s + escucha comandos
            try:
                data = await asyncio.wait_for(ws.receive_text(), timeout=15.0)
                try:
                    payload = json.loads(data)
                    if payload.get("cmd") == "ping":
                        await ws.send_text(json.dumps({"type": "pong"}))
                except Exception:
                    pass
            except asyncio.TimeoutError:
                # Heartbeat
                await ws.send_text(json.dumps({
                    "type": "heartbeat",
                    "timestamp": datetime.utcnow().isoformat()
                }))
    except WebSocketDisconnect:
        log_manager.disconnect(ws)
    except Exception:
        log_manager.disconnect(ws)


@router.websocket("/ws/logs/{channel}")
async def websocket_channel(ws: WebSocket, channel: str):
    """Canal específico por agente o componente."""
    await log_manager.connect(ws)
    await log_manager.send_log("INFO", "nexus-ws", f"Canal '{channel}' conectado")
    try:
        while True:
            try:
                await asyncio.wait_for(ws.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                await ws.send_text(json.dumps({"type": "heartbeat"}))
    except WebSocketDisconnect:
        log_manager.disconnect(ws)
    except Exception:
        log_manager.disconnect(ws)
