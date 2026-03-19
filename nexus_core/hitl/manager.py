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
