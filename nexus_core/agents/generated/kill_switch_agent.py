"""
KillSwitchAgent v1.0 — Caja de Seguridad de BajioWare
Intercepta operaciones críticas y requiere aprobación humana.
"""
import sqlite3
import json
import uuid
from datetime import datetime
from pathlib import Path

BASE_DIR = Path("/home/operator/BW-AI")
DB_PATH = BASE_DIR / "nexus_api/database.db"

# Operaciones que SIEMPRE requieren aprobación humana
CRITICAL_OPERATIONS = {
    "modify_core": ["fase8b_junior.py", "fase8c_junior_tools.py", "nexus_api/main.py"],
    "modify_auth": ["auth/security.py", "auth/dependencies.py"],
    "deploy_production": ["systemctl", "gunicorn", "nginx"],
    "delete_data": ["DROP TABLE", "DELETE FROM", "rm -rf"],
    "modify_agents": ["nexus_core/agents", "nexus_core/llm"],
    "financial": ["payment", "billing", "stripe"],
}

# Operaciones que NUNCA se pueden ejecutar aunque se aprueben
BLACKLIST = [
    "rm -rf /",
    "DROP DATABASE",
    "DELETE FROM users",
    "mkfs",
    "dd if=",
]

_kill_switch_active = False


def is_blacklisted(operation: str) -> bool:
    """Verifica si una operación está en la lista negra."""
    op_lower = operation.lower()
    return any(b.lower() in op_lower for b in BLACKLIST)


def is_critical(operation_type: str, target: str = "") -> dict:
    """Determina si una operación es crítica y requiere aprobación."""
    if is_blacklisted(target):
        return {"critical": True, "blocked": True, "reason": "Operación en lista negra"}

    for category, patterns in CRITICAL_OPERATIONS.items():
        for pattern in patterns:
            if pattern.lower() in target.lower():
                return {
                    "critical": True,
                    "blocked": False,
                    "category": category,
                    "reason": f"Afecta componente crítico: {pattern}",
                }

    return {"critical": False, "blocked": False}


def request_approval(operation_type: str, description: str, payload: dict,
                     risk_level: str = "high") -> dict:
    """Registra una operación crítica para aprobación humana."""
    op_id = f"op_{uuid.uuid4().hex[:8]}"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO critical_operations
           (op_id, operation_type, description, payload, risk_level)
           VALUES (?,?,?,?,?)""",
        (op_id, operation_type, description, json.dumps(payload), risk_level)
    )
    conn.commit()
    conn.close()
    return {
        "op_id": op_id,
        "status": "pending_approval",
        "message": f"⚠️ Operación crítica registrada. Marcos debe aprobar con POST /killswitch/approve/{op_id}",
        "risk_level": risk_level,
    }


def approve_operation(op_id: str, approved_by: str = "marcos") -> dict:
    """Aprueba una operación crítica pendiente."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT * FROM critical_operations WHERE op_id=?", (op_id,)
    ).fetchone()
    if not row:
        conn.close()
        return {"success": False, "error": "Operación no encontrada"}
    if row[5] != "pending_approval":
        conn.close()
        return {"success": False, "error": f"Estado actual: {row[5]}"}
    conn.execute(
        "UPDATE critical_operations SET status='approved', approved_at=?, approved_by=? WHERE op_id=?",
        (datetime.utcnow().isoformat(), approved_by, op_id)
    )
    conn.commit()
    conn.close()
    return {"success": True, "op_id": op_id, "status": "approved", "approved_by": approved_by}


def reject_operation(op_id: str, reason: str = "") -> dict:
    """Rechaza una operación crítica."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE critical_operations SET status='rejected', result=? WHERE op_id=?",
        (reason, op_id)
    )
    conn.commit()
    conn.close()
    return {"success": True, "op_id": op_id, "status": "rejected"}


def get_pending_operations() -> list:
    """Obtiene operaciones pendientes de aprobación."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        """SELECT op_id, operation_type, description, risk_level, created_at
           FROM critical_operations WHERE status='pending_approval'
           ORDER BY created_at DESC"""
    ).fetchall()
    conn.close()
    return [{"op_id": r[0], "type": r[1], "description": r[2],
             "risk": r[3], "created_at": r[4]} for r in rows]


def activate_emergency_stop(reason: str, triggered_by: str = "system") -> dict:
    """Activa el Kill Switch de emergencia — detiene todas las operaciones."""
    global _kill_switch_active
    _kill_switch_active = True
    log_id = f"ks_{uuid.uuid4().hex[:8]}"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO kill_switch_log (id, action, triggered_by, reason) VALUES (?,?,?,?)",
        (log_id, "EMERGENCY_STOP", triggered_by, reason)
    )
    conn.execute(
        "UPDATE critical_operations SET status='cancelled' WHERE status='pending_approval'"
    )
    conn.commit()
    conn.close()
    return {
        "kill_switch": "ACTIVATED",
        "log_id": log_id,
        "reason": reason,
        "message": "🚨 KILL SWITCH ACTIVADO — Todas las operaciones detenidas",
    }


def deactivate_emergency_stop(authorized_by: str = "marcos") -> dict:
    """Desactiva el Kill Switch."""
    global _kill_switch_active
    _kill_switch_active = False
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO kill_switch_log (id, action, triggered_by, reason) VALUES (?,?,?,?)",
        (f"ks_{uuid.uuid4().hex[:8]}", "DEACTIVATE", authorized_by, "Manual deactivation")
    )
    conn.commit()
    conn.close()
    return {"kill_switch": "DEACTIVATED", "authorized_by": authorized_by}


def is_active() -> bool:
    return _kill_switch_active
