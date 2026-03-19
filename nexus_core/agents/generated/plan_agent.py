"""
PlanAgent v1.0 — Junior propone planes, Marcos aprueba UNA vez, Junior ejecuta todo.
Este es el núcleo de la libertad controlada.
"""
import sqlite3
import json
import uuid
import asyncio
import httpx
from datetime import datetime
from pathlib import Path

BASE_DIR = Path("/home/operator/BW-AI")
DB_PATH = BASE_DIR / "nexus_api/database.db"


def create_plan(title: str, objective: str, steps: list,
                risk_level: str = "low", affects_core: bool = False) -> dict:
    """Junior crea un plan completo para aprobación."""
    plan_id = f"plan_{uuid.uuid4().hex[:8]}"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO junior_plans
           (plan_id, title, objective, steps, risk_level, affects_core)
           VALUES (?,?,?,?,?,?)""",
        (plan_id, title, objective, json.dumps(steps),
         risk_level, 1 if affects_core else 0)
    )
    conn.commit()
    conn.close()

    # Si afecta core, también registrar en kill switch
    if affects_core:
        try:
            import httpx as _httpx
            _httpx.post(
                "http://127.0.0.1:8000/killswitch/request",
                json={"operation_type": "plan_execution",
                      "description": f"Plan: {title}",
                      "payload": {"plan_id": plan_id},
                      "risk_level": risk_level},
                timeout=5.0
            )
        except Exception:
            pass

    return {
        "plan_id": plan_id,
        "title": title,
        "objective": objective,
        "steps": steps,
        "risk_level": risk_level,
        "affects_core": affects_core,
        "status": "pending_review",
        "message": f"Plan registrado. Marcos debe aprobar: POST /plans/approve/{plan_id}",
        "preview_url": f"GET /plans/{plan_id}",
    }


def approve_plan(plan_id: str, approved_by: str = "marcos") -> dict:
    """Marcos aprueba un plan — Junior ejecutará todos los pasos."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT * FROM junior_plans WHERE plan_id=?", (plan_id,)
    ).fetchone()
    if not row:
        conn.close()
        return {"success": False, "error": "Plan no encontrado"}
    if row[7] != "pending_review":
        conn.close()
        return {"success": False, "error": f"Estado actual: {row[7]}"}
    conn.execute(
        "UPDATE junior_plans SET status='approved', reviewed_at=?, approved_by=? WHERE plan_id=?",
        (datetime.utcnow().isoformat(), approved_by, plan_id)
    )
    conn.commit()
    conn.close()
    return {
        "success": True,
        "plan_id": plan_id,
        "status": "approved",
        "message": "Plan aprobado. Junior puede ejecutar todos los pasos.",
    }


def reject_plan(plan_id: str, reason: str = "") -> dict:
    """Marcos rechaza un plan."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE junior_plans SET status='rejected', execution_log=? WHERE plan_id=?",
        (f"Rechazado: {reason}", plan_id)
    )
    conn.commit()
    conn.close()
    return {"success": True, "plan_id": plan_id, "status": "rejected"}


def get_plan(plan_id: str) -> dict:
    """Obtiene detalles de un plan."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT * FROM junior_plans WHERE plan_id=?", (plan_id,)
    ).fetchone()
    conn.close()
    if not row:
        return {"error": "Plan no encontrado"}
    steps = json.loads(row[3] or "[]")
    return {
        "plan_id": row[0], "title": row[1], "objective": row[2],
        "steps": steps, "risk_level": row[4],
        "affects_core": bool(row[5]), "status": row[6],
        "created_at": row[7], "approved_by": row[9],
        "execution_log": row[10],
        "total_steps": len(steps),
    }


def get_pending_plans() -> list:
    """Obtiene planes pendientes de aprobación."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        """SELECT plan_id, title, objective, risk_level, affects_core, created_at
           FROM junior_plans WHERE status='pending_review'
           ORDER BY created_at DESC"""
    ).fetchall()
    conn.close()
    return [{
        "plan_id": r[0], "title": r[1], "objective": r[2],
        "risk": r[3], "affects_core": bool(r[4]), "created_at": r[5]
    } for r in rows]


async def execute_approved_plan(plan_id: str) -> dict:
    """Ejecuta un plan aprobado paso a paso."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT * FROM junior_plans WHERE plan_id=?", (plan_id,)
    ).fetchone()
    if not row or row[6] != "approved":
        conn.close()
        return {"success": False, "error": f"Plan no aprobado o no encontrado"}

    steps = json.loads(row[3] or "[]")
    conn.execute(
        "UPDATE junior_plans SET status='executing' WHERE plan_id=?", (plan_id,)
    )
    conn.commit()
    conn.close()

    execution_log = []
    success_count = 0
    fail_count = 0

    async with httpx.AsyncClient(timeout=60.0) as client:
        for i, step in enumerate(steps):
            step_name = step.get("name", f"Step {i+1}")
            capability = step.get("capability", "file_operations")
            payload = step.get("payload", {})

            try:
                resp = await client.post(
                    "http://127.0.0.1:8000/junior/dispatch",
                    json={"task_name": step_name, "payload": payload,
                          "capability": capability}
                )
                result = resp.json()
                success = result.get("success", False)
                if success:
                    success_count += 1
                else:
                    fail_count += 1
                execution_log.append({
                    "step": step_name, "status": "ok" if success else "fail",
                    "result": str(result.get("result", ""))[:200]
                })
            except Exception as e:
                fail_count += 1
                execution_log.append({"step": step_name, "status": "error", "error": str(e)})

    final_status = "completed" if fail_count == 0 else "completed_with_errors"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE junior_plans SET status=?, execution_log=? WHERE plan_id=?",
        (final_status, json.dumps(execution_log), plan_id)
    )
    conn.commit()
    conn.close()

    return {
        "plan_id": plan_id,
        "status": final_status,
        "steps_total": len(steps),
        "steps_ok": success_count,
        "steps_failed": fail_count,
        "execution_log": execution_log,
    }


def list_plans(status: str = None) -> list:
    """Lista todos los planes."""
    conn = sqlite3.connect(DB_PATH)
    if status:
        rows = conn.execute(
            "SELECT plan_id, title, risk_level, affects_core, status, created_at FROM junior_plans WHERE status=? ORDER BY created_at DESC",
            (status,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT plan_id, title, risk_level, affects_core, status, created_at FROM junior_plans ORDER BY created_at DESC LIMIT 20"
        ).fetchall()
    conn.close()
    return [{"plan_id": r[0], "title": r[1], "risk": r[2],
             "affects_core": bool(r[3]), "status": r[4], "created_at": r[5]} for r in rows]
