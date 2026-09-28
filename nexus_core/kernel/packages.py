"""Install versioned department packages without modifying kernel code."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict
from uuid import uuid4

from .control_store import ControlStore
from .models import AgentDefinition, utc_now


class PackageManager:
    def __init__(self, store: ControlStore, packages_root: str | Path):
        self.store = store
        self.packages_root = Path(packages_root).resolve()

    def load_manifest(self, package_path: str) -> tuple[Path, Dict[str, Any]]:
        root = (self.packages_root / package_path).resolve()
        if root != self.packages_root and self.packages_root not in root.parents:
            raise PermissionError("package path escapes package root")
        manifest_path = root / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        required = {"schema_version", "package", "version", "agents", "workflows", "policies"}
        missing = required - set(manifest)
        if missing:
            raise ValueError(f"package manifest missing: {sorted(missing)}")
        if not isinstance(manifest["agents"], list) or not manifest["agents"]:
            raise ValueError("package must define at least one agent")
        expected = manifest.get("manifest_sha256")
        unsigned = dict(manifest)
        unsigned.pop("manifest_sha256", None)
        calculated = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if expected and expected != calculated:
            raise ValueError("package manifest checksum is invalid")
        manifest["verified_sha256"] = calculated
        return root, manifest

    def install(
        self, package_path: str, tenant_id: str, installed_by: str
    ) -> Dict[str, Any]:
        root, manifest = self.load_manifest(package_path)
        package_id = f"package_{uuid4().hex}"
        department_id = f"department_{uuid4().hex}"
        now = utc_now()
        installed_agents = []
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT INTO kernel_departments(id,tenant_id,name,created_at)
                VALUES(?,?,?,?)""",
                (department_id, tenant_id, manifest["package"], now),
            )
            conn.execute(
                """INSERT INTO kernel_packages
                (id,tenant_id,package_name,version,manifest,status,installed_by,installed_at)
                VALUES(?,?,?,?,?,?,?,?)""",
                (package_id, tenant_id, manifest["package"], manifest["version"],
                 json.dumps(manifest, sort_keys=True), "installed", installed_by, now),
            )
            for agent_name in manifest["agents"]:
                definition = AgentDefinition(
                    name=f"{manifest['package']}.{agent_name}", tenant_id=tenant_id,
                    version=manifest["version"],
                    description=f"Agent installed from {manifest['package']}",
                    capabilities=list(manifest.get("required_capabilities", [])),
                    department_id=department_id,
                ).to_dict()
                conn.execute(
                    """INSERT INTO kernel_agents
                    (id,tenant_id,name,version,definition,status,created_at,department_id)
                    VALUES(?,?,?,?,?,'active',?,?)""",
                    (definition["agent_id"], tenant_id, definition["name"], definition["version"],
                     json.dumps(definition, sort_keys=True), now, department_id),
                )
                installed_agents.append(definition["agent_id"])
        return {
            "package_id": package_id,
            "package": manifest["package"],
            "version": manifest["version"],
            "tenant_id": tenant_id,
            "department_id": department_id,
            "agent_ids": installed_agents,
            "evaluation_suite": str(root / manifest.get("evaluation_suite", "")),
            "manifest_sha256": manifest["verified_sha256"],
        }

    def rollback(self, package_id: str, tenant_id: str, actor_id: str) -> Dict[str, Any]:
        now = utc_now()
        with self.store.connect() as conn:
            package = conn.execute(
                "SELECT * FROM kernel_packages WHERE id=? AND tenant_id=? AND status='installed'",
                (package_id, tenant_id),
            ).fetchone()
            if not package:
                raise KeyError("installed package not found")
            manifest = json.loads(package["manifest"])
            names = [f"{manifest['package']}.{name}" for name in manifest["agents"]]
            for name in names:
                conn.execute(
                    "UPDATE kernel_agents SET status='disabled' WHERE tenant_id=? AND name=? AND version=?",
                    (tenant_id, name, package["version"]),
                )
            conn.execute("UPDATE kernel_packages SET status='rolled_back' WHERE id=?", (package_id,))
            self.store._outbox(conn, tenant_id, "package", package_id, "package.rolled_back", {"actor_id": actor_id})
        return {"package_id": package_id, "status": "rolled_back", "disabled_agents": names, "at": now}

    def list_installed(self, tenant_id: str) -> list[Dict[str, Any]]:
        with self.store.connect() as conn:
            rows = conn.execute(
                """SELECT id,tenant_id,package_name,version,status,installed_by,installed_at
                FROM kernel_packages WHERE tenant_id=? ORDER BY installed_at""",
                (tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]
