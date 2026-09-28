"""
TeamOrchestrator v1.0 — Orquestador de equipos de producción BajioWare
Gestiona el ciclo de vida completo de equipos: crear, ejecutar, monitorear, destruir
"""
import asyncio
import json
import sqlite3
import subprocess
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional
from nexus_core.config import NEXUS_ROOT, LEGACY_DATABASE_PATH

BASE_DIR = NEXUS_ROOT
DB_PATH = LEGACY_DATABASE_PATH
TEMPLATE_PATH = BASE_DIR / ".nexus/production_team_template.json"


class TeamOrchestrator:
    """Orquesta equipos de producción para proyectos de clientes."""

    def __init__(self):
        self.template = json.loads(TEMPLATE_PATH.read_text()) if TEMPLATE_PATH.exists() else {}
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""CREATE TABLE IF NOT EXISTS teams (
            team_id TEXT PRIMARY KEY, team_type TEXT, name TEXT,
            status TEXT DEFAULT 'idle', project_id TEXT, config TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS team_agents (
            id TEXT PRIMARY KEY, team_id TEXT, role TEXT, agent_name TEXT,
            status TEXT DEFAULT 'idle', container_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS team_events (
            id TEXT PRIMARY KEY, team_id TEXT, agent_role TEXT,
            event_type TEXT, payload TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS team_lessons (
            id TEXT PRIMARY KEY, project_id TEXT, team_id TEXT,
            lesson TEXT, category TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        conn.commit()
        conn.close()

    def create_production_team(self, project_name: str, project_id: str = None, objective: str = "") -> dict:
        """Crea un equipo de producción para un proyecto."""
        project_id = project_id or f"proj_{uuid.uuid4().hex[:8]}"
        team_id = f"team_{uuid.uuid4().hex[:8]}"

        config = {
            "project_path": str(BASE_DIR / "projects" / project_id),
            "memory_namespace": f"project_{project_id}",
            "objective": objective,
            "project_name": project_name,
        }

        # Crear directorio del proyecto
        Path(config["project_path"]).mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO teams (team_id, team_type, name, status, project_id, config) VALUES (?,?,?,?,?,?)",
            (team_id, "production", f"Team-{project_name}", "created", project_id, json.dumps(config))
        )

        # Registrar agentes del equipo
        for agent_def in self.template.get("agents", []):
            agent_id = f"agent_{uuid.uuid4().hex[:8]}"
            agent_name = agent_def["name"].replace("Px", project_id[:4])
            conn.execute(
                "INSERT INTO team_agents (id, team_id, role, agent_name, status) VALUES (?,?,?,?,?)",
                (agent_id, team_id, agent_def["role"], agent_name, "created")
            )

        conn.commit()
        conn.close()

        self._emit_event(team_id, "system", "team_created", {
            "project_id": project_id,
            "project_name": project_name,
            "config": config,
        })

        return {
            "success": True,
            "team_id": team_id,
            "project_id": project_id,
            "project_name": project_name,
            "status": "created",
            "agents": len(self.template.get("agents", [])),
            "project_path": config["project_path"],
        }

    def get_team(self, team_id: str) -> Optional[dict]:
        """Obtiene información de un equipo."""
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT * FROM teams WHERE team_id=?", (team_id,)).fetchone()
        if not row:
            conn.close()
            return None
        agents = conn.execute(
            "SELECT role, agent_name, status FROM team_agents WHERE team_id=?", (team_id,)
        ).fetchall()
        events = conn.execute(
            "SELECT event_type, payload, created_at FROM team_events WHERE team_id=? ORDER BY created_at DESC LIMIT 10",
            (team_id,)
        ).fetchall()
        conn.close()
        config = json.loads(row[5] or "{}")
        return {
            "team_id": row[0], "team_type": row[1], "name": row[2],
            "status": row[3], "project_id": row[4], "config": config,
            "created_at": row[6], "agents": [{"role": a[0], "name": a[1], "status": a[2]} for a in agents],
            "recent_events": [{"type": e[0], "payload": json.loads(e[1] or "{}"), "at": e[2]} for e in events],
        }

    def list_teams(self, team_type: str = None) -> list:
        """Lista todos los equipos."""
        conn = sqlite3.connect(DB_PATH)
        if team_type:
            rows = conn.execute(
                "SELECT team_id, team_type, name, status, project_id, created_at FROM teams WHERE team_type=? ORDER BY created_at DESC",
                (team_type,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT team_id, team_type, name, status, project_id, created_at FROM teams ORDER BY created_at DESC"
            ).fetchall()
        conn.close()
        return [{"team_id": r[0], "team_type": r[1], "name": r[2], "status": r[3], "project_id": r[4], "created_at": r[5]} for r in rows]

    def update_team_status(self, team_id: str, status: str, agent_role: str = None) -> bool:
        """Actualiza el estado de un equipo o agente."""
        conn = sqlite3.connect(DB_PATH)
        if agent_role:
            conn.execute(
                "UPDATE team_agents SET status=? WHERE team_id=? AND role=?",
                (status, team_id, agent_role)
            )
        else:
            conn.execute(
                "UPDATE teams SET status=?, updated_at=CURRENT_TIMESTAMP WHERE team_id=?",
                (status, team_id)
            )
        conn.commit()
        conn.close()
        self._emit_event(team_id, agent_role or "system", "status_updated", {"status": status})
        return True

    def save_lesson(self, team_id: str, project_id: str, lesson: str, category: str = "general") -> str:
        """Guarda una lección aprendida del proyecto."""
        lesson_id = f"lesson_{uuid.uuid4().hex[:8]}"
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO team_lessons (id, project_id, team_id, lesson, category) VALUES (?,?,?,?,?)",
            (lesson_id, project_id, team_id, lesson, category)
        )
        conn.commit()
        conn.close()
        return lesson_id

    def get_lessons(self, project_id: str = None) -> list:
        """Obtiene lecciones aprendidas."""
        conn = sqlite3.connect(DB_PATH)
        if project_id:
            rows = conn.execute(
                "SELECT id, project_id, lesson, category, created_at FROM team_lessons WHERE project_id=? ORDER BY created_at DESC",
                (project_id,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, project_id, lesson, category, created_at FROM team_lessons ORDER BY created_at DESC LIMIT 50"
            ).fetchall()
        conn.close()
        return [{"id": r[0], "project_id": r[1], "lesson": r[2], "category": r[3], "created_at": r[4]} for r in rows]

    def destroy_team(self, team_id: str) -> dict:
        """Destruye un equipo y archiva sus datos."""
        team = self.get_team(team_id)
        if not team:
            return {"success": False, "error": "Team not found"}

        # Detener contenedores si existen
        conn = sqlite3.connect(DB_PATH)
        containers = conn.execute(
            "SELECT container_id FROM team_agents WHERE team_id=? AND container_id IS NOT NULL",
            (team_id,)
        ).fetchall()
        for (cid,) in containers:
            if cid:
                if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", cid):
                    raise ValueError("Invalid container identifier")
                subprocess.run(["docker", "stop", cid], capture_output=True, check=False)
                subprocess.run(["docker", "rm", cid], capture_output=True, check=False)

        conn.execute("UPDATE teams SET status='destroyed' WHERE team_id=?", (team_id,))
        conn.execute("UPDATE team_agents SET status='stopped' WHERE team_id=?", (team_id,))
        conn.commit()
        conn.close()

        self._emit_event(team_id, "system", "team_destroyed", {"project_id": team.get("project_id")})
        return {"success": True, "team_id": team_id, "status": "destroyed"}

    def _emit_event(self, team_id: str, agent_role: str, event_type: str, payload: dict):
        """Emite un evento al bus de eventos del equipo."""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                "INSERT INTO team_events (id, team_id, agent_role, event_type, payload) VALUES (?,?,?,?,?)",
                (f"evt_{uuid.uuid4().hex[:8]}", team_id, agent_role, event_type, json.dumps(payload))
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def get_events(self, team_id: str = None, limit: int = 20) -> list:
        """Obtiene eventos recientes."""
        conn = sqlite3.connect(DB_PATH)
        if team_id:
            rows = conn.execute(
                "SELECT team_id, agent_role, event_type, payload, created_at FROM team_events WHERE team_id=? ORDER BY created_at DESC LIMIT ?",
                (team_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT team_id, agent_role, event_type, payload, created_at FROM team_events ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        conn.close()
        return [{"team_id": r[0], "agent": r[1], "event": r[2], "payload": json.loads(r[3] or "{}"), "at": r[4]} for r in rows]


_orchestrator: TeamOrchestrator = None

def get_team_orchestrator() -> TeamOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = TeamOrchestrator()
    return _orchestrator
