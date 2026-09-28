"""Tenant-scoped AI Directory repositories and service identities."""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any, Dict, List, Optional
from uuid import uuid4

from .control_store import ControlStore
from .models import utc_now


class DirectoryRepository:
    def __init__(self, store: ControlStore):
        self.store = store

    def create_environment(self, tenant_id: str, name: str,
                           classification: str = "internal") -> Dict[str, Any]:
        if name not in {"development", "staging", "production"}:
            raise ValueError("environment must be development, staging or production")
        entity_id = f"env_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_environments
                (id,tenant_id,name,classification,created_at) VALUES(?,?,?,?,?)""",
                (entity_id, tenant_id, name, classification, utc_now()),
            )
        return {"id": entity_id, "tenant_id": tenant_id, "name": name, "classification": classification}

    def create_group(self, tenant_id: str, name: str) -> Dict[str, Any]:
        group_id = f"group_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                "INSERT INTO kernel_groups(id,tenant_id,name,created_at) VALUES(?,?,?,?)",
                (group_id, tenant_id, name, utc_now()),
            )
        return {"id": group_id, "tenant_id": tenant_id, "name": name}

    def create_department(self, tenant_id: str, name: str) -> Dict[str, Any]:
        department_id = f"department_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_departments(id,tenant_id,name,created_at)
                VALUES(?,?,?,?)""", (department_id, tenant_id, name, utc_now()),
            )
        return {"id": department_id, "tenant_id": tenant_id, "name": name}

    def create_capability(self, tenant_id: str, name: str,
                          description: str = "") -> Dict[str, Any]:
        capability_id = f"capability_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_capabilities
                (id,tenant_id,name,description,created_at) VALUES(?,?,?,?,?)""",
                (capability_id, tenant_id, name, description, utc_now()),
            )
        return {"id": capability_id, "tenant_id": tenant_id, "name": name,
                "description": description}

    def assign_agent_capability(self, tenant_id: str, agent_id: str,
                                capability_id: str) -> None:
        with self.store.connect() as conn:
            agent = conn.execute(
                "SELECT id FROM kernel_agents WHERE id=? AND tenant_id=?",
                (agent_id, tenant_id),
            ).fetchone()
            capability = conn.execute(
                "SELECT id FROM kernel_capabilities WHERE id=? AND tenant_id=?",
                (capability_id, tenant_id),
            ).fetchone()
            if not agent or not capability:
                raise KeyError("agent or capability not found in tenant")
            conn.execute(
                """INSERT OR IGNORE INTO kernel_agent_capabilities
                (agent_id,capability_id) VALUES(?,?)""", (agent_id, capability_id),
            )

    def bind_tool_resource(self, tenant_id: str, tool_id: str,
                           resource_id: str, scopes: list[str]) -> None:
        with self.store.connect() as conn:
            tool = conn.execute(
                "SELECT id FROM kernel_tools WHERE id=? AND tenant_id=?",
                (tool_id, tenant_id),
            ).fetchone()
            resource = conn.execute(
                "SELECT id FROM kernel_resources WHERE id=? AND tenant_id=?",
                (resource_id, tenant_id),
            ).fetchone()
            if not tool or not resource:
                raise KeyError("tool or resource not found in tenant")
            conn.execute(
                """INSERT OR IGNORE INTO kernel_tool_resources(tool_id,resource_id,scopes)
                VALUES(?,?,?)""", (tool_id, resource_id, json.dumps(sorted(set(scopes)))),
            )

    def add_member(self, tenant_id: str, group_id: str,
                   subject_type: str, subject_id: str) -> str:
        if subject_type not in {"user", "service_account", "agent"}:
            raise ValueError("unsupported group member type")
        membership_id = f"membership_{uuid4().hex}"
        with self.store.connect() as conn:
            group = conn.execute(
                "SELECT id FROM kernel_groups WHERE id=? AND tenant_id=?", (group_id, tenant_id)
            ).fetchone()
            if not group:
                raise KeyError("group not found")
            conn.execute(
                """INSERT INTO kernel_group_memberships
                (id,tenant_id,group_id,subject_type,subject_id,created_at) VALUES(?,?,?,?,?,?)""",
                (membership_id, tenant_id, group_id, subject_type, subject_id, utc_now()),
            )
        return membership_id

    def create_service_account(self, tenant_id: str, name: str,
                               roles: List[str], expires_at: Optional[str] = None) -> Dict[str, Any]:
        if not set(roles).issubset({"viewer", "operator"}):
            raise ValueError("service accounts cannot receive admin role")
        account_id = f"service_{uuid4().hex}"
        credential = secrets.token_urlsafe(48)
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_service_accounts
                (id,tenant_id,name,credential_hash,roles,expires_at,created_at)
                VALUES(?,?,?,?,?,?,?)""",
                (account_id, tenant_id, name, hashlib.sha256(credential.encode()).hexdigest(),
                 json.dumps(roles), expires_at, utc_now()),
            )
        return {"id": account_id, "tenant_id": tenant_id, "name": name,
                "roles": roles, "credential": credential, "expires_at": expires_at}

    def create_resource(self, tenant_id: str, kind: str, name: str,
                        classification: str, environment_id: Optional[str] = None,
                        owner_id: Optional[str] = None,
                        attributes: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        resource_id = f"resource_{uuid4().hex}"
        with self.store.connect() as conn:
            if environment_id and not conn.execute(
                "SELECT id FROM kernel_environments WHERE id=? AND tenant_id=?",
                (environment_id, tenant_id),
            ).fetchone():
                raise KeyError("environment not found in tenant")
            conn.execute(
                """INSERT INTO kernel_resources
                (id,tenant_id,environment_id,kind,name,classification,owner_id,attributes,created_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (resource_id, tenant_id, environment_id, kind, name, classification,
                 owner_id, json.dumps(attributes or {}), utc_now()),
            )
        return {"id": resource_id, "tenant_id": tenant_id, "kind": kind, "name": name,
                "classification": classification, "environment_id": environment_id}

    def list_kind(self, table: str, tenant_id: str) -> List[Dict[str, Any]]:
        allowed = {
            "kernel_environments", "kernel_groups", "kernel_service_accounts",
            "kernel_resources", "kernel_departments", "kernel_capabilities",
        }
        if table not in allowed:
            raise ValueError("unsupported directory entity")
        with self.store.connect() as conn:
            rows = conn.execute(f"SELECT * FROM {table} WHERE tenant_id=? ORDER BY created_at", (tenant_id,)).fetchall()
        values = [dict(row) for row in rows]
        for value in values:
            value.pop("credential_hash", None)
            for field in ("roles", "attributes"):
                if value.get(field):
                    value[field] = json.loads(value[field])
        return values
