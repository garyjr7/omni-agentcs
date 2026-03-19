import uuid, json, shutil, logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("workspace_manager")

VALID_TYPES = ["web-app","api","security-scan","data-analysis","devops","custom"]

class WorkspaceManager:
    """
    Gestiona workspaces Docker-ready para proyectos de BajioWare.
    Cada proyecto se aísla en su propio directorio con estructura estándar.
    AWS-ready: la misma estructura funciona en EC2 y S3.
    """
    def __init__(self, projects_root: str, docker_templates: str):
        self.root      = Path(projects_root)
        self.templates = Path(docker_templates)
        self.root.mkdir(parents=True, exist_ok=True)
        self._deleted  = self.root / ".deleted"
        self._deleted.mkdir(exist_ok=True)

    def create(self, name: str, project_type: str = "general") -> dict:
        if project_type not in VALID_TYPES:
            project_type = "custom"
        pid  = f"proj_{uuid.uuid4().hex[:8]}"
        base = self.root / pid
        # Estructura estándar
        for d in ["workspace","logs","docker","artifacts","reports"]:
            (base/d).mkdir(parents=True, exist_ok=True)
        # Copia templates Docker
        if self.templates.exists():
            for tpl in self.templates.glob("*"):
                shutil.copy2(str(tpl), str(base/"docker"/tpl.name))
        # .gitignore
        (base/"workspace"/".gitignore").write_text(
            "*.pyc\n__pycache__/\n.env\n*.key\n")
        # metadata
        meta = {
            "project_id": pid, "name": name, "type": project_type,
            "status": "created",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "workspace":  str(base/"workspace"),
            "logs":       str(base/"logs"),
            "docker":     str(base/"docker"),
            "agents":     [], "tasks_completed": 0,
        }
        (base/"metadata.json").write_text(json.dumps(meta, indent=2))
        logger.info(f"Workspace created: {pid} ({name}/{project_type})")
        return meta

    def list_all(self) -> list:
        result = []
        for d in sorted(self.root.iterdir()):
            if d.name.startswith("."): continue
            m = d/"metadata.json"
            if m.exists():
                try:
                    result.append(json.loads(m.read_text()))
                except Exception: pass
        return sorted(result, key=lambda x: x.get("created_at",""), reverse=True)

    def get(self, pid: str) -> Optional[dict]:
        m = self.root/pid/"metadata.json"
        return json.loads(m.read_text()) if m.exists() else None

    def update_status(self, pid: str, status: str) -> bool:
        m = self.root/pid/"metadata.json"
        if not m.exists(): return False
        meta = json.loads(m.read_text())
        meta["status"]     = status
        meta["updated_at"] = datetime.now(timezone.utc).isoformat()
        m.write_text(json.dumps(meta, indent=2))
        return True

    def delete(self, pid: str) -> bool:
        p = self.root/pid
        if not p.exists(): return False
        shutil.move(str(p), str(self._deleted/pid))
        logger.info(f"Workspace moved to .deleted: {pid}")
        return True