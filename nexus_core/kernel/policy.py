"""Small deny-by-default PDP used until an external policy engine is configured."""

from __future__ import annotations

import json
from typing import Any, Iterable
from uuid import uuid4

from .models import Identity, PolicyDecision, Resource, RiskLevel, ToolDefinition


class PolicyEngine:
    """Central authorization point shared by REST, CLI, MCP and workers."""

    def __init__(self, store=None):
        self.store = store

    def decide(
        self,
        identity: Identity,
        action: str,
        resource: Resource,
        permissions: Iterable[str] = (),
        tool: ToolDefinition | None = None,
    ) -> PolicyDecision:
        if identity.tenant_id != resource.tenant_id:
            return PolicyDecision(False, "cross-tenant access denied", "tenant-isolation")

        explicit = self._explicit_decision(identity, action, resource)
        if explicit is not None:
            if (
                explicit.allowed
                and tool
                and tool.risk in {RiskLevel.HIGH, RiskLevel.DESTRUCTIVE}
                and not explicit.requires_approval
            ):
                return PolicyDecision(
                    True,
                    "explicit allow constrained by tool risk",
                    explicit.policy_id,
                    explicit.policy_version,
                    requires_approval=True,
                    obligations=("audit", "sandbox", "human-approval"),
                )
            return explicit

        roles = set(identity.roles)
        granted = set(permissions)
        if "admin" in roles:
            allowed = True
        elif action.startswith("read:") and roles.intersection({"viewer", "operator"}):
            allowed = True
        elif action.startswith(("execute:", "write:")) and "operator" in roles:
            allowed = True
        else:
            allowed = action in granted or "*" in granted

        if not allowed:
            return PolicyDecision(False, "identity lacks required permission", "role-and-permission")

        if tool and tool.risk in {RiskLevel.HIGH, RiskLevel.DESTRUCTIVE}:
            return PolicyDecision(
                True,
                "allowed after human approval",
                "risk-approval",
                requires_approval=True,
                obligations=("audit", "sandbox", "human-approval"),
            )

        obligations = ("audit",) if tool is None else ("audit", "sandbox")
        return PolicyDecision(True, "allowed", "role-and-permission", obligations=obligations)

    def _explicit_decision(
        self, identity: Identity, action: str, resource: Resource
    ) -> PolicyDecision | None:
        if not self.store:
            return None
        subjects = [("identity", identity.subject_id)] + [
            ("role", role) for role in identity.roles
        ] + [("group", group) for group in identity.groups]
        matches: list[dict[str, Any]] = []
        with self.store.connect() as conn:
            for subject_type, subject_id in subjects:
                rows = conn.execute(
                    """SELECT p.* FROM kernel_policies p
                    JOIN kernel_policy_bindings b ON b.policy_id=p.id
                    WHERE p.tenant_id=? AND p.enabled=1
                      AND b.subject_type=? AND b.subject_id=?""",
                    (identity.tenant_id, subject_type, subject_id),
                ).fetchall()
                matches.extend(dict(row) for row in rows)
        applicable = []
        for policy in matches:
            actions = json.loads(policy["actions"])
            resource_kinds = json.loads(policy["resource_kinds"])
            conditions = json.loads(policy["conditions"])
            if action not in actions and "*" not in actions:
                continue
            if resource.kind not in resource_kinds and "*" not in resource_kinds:
                continue
            if conditions.get("classification") not in (None, resource.classification):
                continue
            if conditions.get("environment") not in (None, resource.environment):
                continue
            applicable.append(policy)
        denies = [policy for policy in applicable if policy["effect"] == "deny"]
        if denies:
            policy = denies[0]
            return PolicyDecision(False, "explicit policy deny", policy["id"], policy["version"])
        allows = [policy for policy in applicable if policy["effect"] == "allow"]
        if allows:
            policy = allows[0]
            approval = bool(policy["requires_approval"])
            return PolicyDecision(
                True, "explicit policy allow", policy["id"], policy["version"],
                requires_approval=approval,
                obligations=("audit", "human-approval") if approval else ("audit",),
            )
        return None


class PolicyRepository:
    def __init__(self, store):
        self.store = store

    def create(
        self,
        *,
        tenant_id: str,
        name: str,
        effect: str,
        actions: list[str],
        resource_kinds: list[str],
        conditions: dict | None = None,
        requires_approval: bool = False,
        version: str = "1.0.0",
    ) -> dict:
        if effect not in {"allow", "deny"}:
            raise ValueError("policy effect must be allow or deny")
        policy_id = f"policy_{uuid4().hex}"
        from .models import utc_now
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_policies
                (id,tenant_id,name,version,effect,actions,resource_kinds,conditions,
                 requires_approval,enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (policy_id, tenant_id, name, version, effect, json.dumps(actions),
                 json.dumps(resource_kinds), json.dumps(conditions or {}),
                 int(requires_approval), 1, utc_now()),
            )
        return {"id": policy_id, "tenant_id": tenant_id, "name": name, "version": version}

    def bind(self, tenant_id: str, policy_id: str, subject_type: str, subject_id: str) -> str:
        if subject_type not in {"identity", "role", "group", "agent"}:
            raise ValueError("unsupported policy subject type")
        from .models import utc_now
        binding_id = f"binding_{uuid4().hex}"
        with self.store.connect() as conn:
            policy = conn.execute(
                "SELECT id FROM kernel_policies WHERE id=? AND tenant_id=? AND enabled=1",
                (policy_id, tenant_id),
            ).fetchone()
            if not policy:
                raise ValueError("policy not found in tenant")
            conn.execute(
                """INSERT INTO kernel_policy_bindings
                (id,tenant_id,policy_id,subject_type,subject_id,created_at)
                VALUES(?,?,?,?,?,?)""",
                (binding_id, tenant_id, policy_id, subject_type, subject_id, utc_now()),
            )
        return binding_id
