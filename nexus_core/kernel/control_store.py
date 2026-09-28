"""Durable SQLite control store for development and single-node deployments.

The repository contract deliberately avoids SQLite-specific types so a PostgreSQL
implementation can replace it without changing gateways or agents.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from uuid import uuid4

from .models import utc_now

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kernel_tenants (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kernel_organizations (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kernel_environments (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    classification TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL, UNIQUE(tenant_id,name)
);
CREATE TABLE IF NOT EXISTS kernel_groups (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    created_at TEXT NOT NULL, UNIQUE(tenant_id,name)
);
CREATE TABLE IF NOT EXISTS kernel_group_memberships (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, group_id TEXT NOT NULL,
    subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, created_at TEXT NOT NULL,
    UNIQUE(group_id,subject_type,subject_id)
);
CREATE TABLE IF NOT EXISTS kernel_service_accounts (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    credential_hash TEXT NOT NULL, roles TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT, created_at TEXT NOT NULL, UNIQUE(tenant_id,name)
);
CREATE TABLE IF NOT EXISTS kernel_resources (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, environment_id TEXT,
    kind TEXT NOT NULL, name TEXT NOT NULL, classification TEXT NOT NULL,
    owner_id TEXT, attributes TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL, UNIQUE(tenant_id,kind,name)
);
CREATE TABLE IF NOT EXISTS kernel_capabilities (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    description TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(tenant_id,name)
);
CREATE TABLE IF NOT EXISTS kernel_agent_capabilities (
    agent_id TEXT NOT NULL, capability_id TEXT NOT NULL,
    PRIMARY KEY(agent_id,capability_id)
);
CREATE TABLE IF NOT EXISTS kernel_tool_resources (
    tool_id TEXT NOT NULL, resource_id TEXT NOT NULL, scopes TEXT NOT NULL,
    PRIMARY KEY(tool_id,resource_id)
);
CREATE TABLE IF NOT EXISTS kernel_users (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, email TEXT NOT NULL,
    name TEXT NOT NULL, hashed_pw TEXT NOT NULL, role TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
    UNIQUE(tenant_id, email),
    FOREIGN KEY(tenant_id) REFERENCES kernel_tenants(id)
);
CREATE TABLE IF NOT EXISTS auth_refresh_sessions (
    jti TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at TEXT NOT NULL,
    revoked_at TEXT, created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES kernel_users(id)
);
CREATE TABLE IF NOT EXISTS auth_revoked_tokens (
    jti TEXT PRIMARY KEY, expires_at TEXT NOT NULL, revoked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kernel_departments (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    created_at TEXT NOT NULL, UNIQUE(tenant_id, name),
    FOREIGN KEY(tenant_id) REFERENCES kernel_tenants(id)
);
CREATE TABLE IF NOT EXISTS kernel_packages (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, package_name TEXT NOT NULL,
    version TEXT NOT NULL, manifest TEXT NOT NULL, status TEXT NOT NULL,
    installed_by TEXT NOT NULL, installed_at TEXT NOT NULL,
    UNIQUE(tenant_id, package_name, version),
    FOREIGN KEY(tenant_id) REFERENCES kernel_tenants(id)
);
CREATE TABLE IF NOT EXISTS kernel_policies (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    version TEXT NOT NULL, effect TEXT NOT NULL, actions TEXT NOT NULL,
    resource_kinds TEXT NOT NULL, conditions TEXT NOT NULL,
    requires_approval INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, UNIQUE(tenant_id,name,version),
    FOREIGN KEY(tenant_id) REFERENCES kernel_tenants(id)
);
CREATE TABLE IF NOT EXISTS kernel_policy_bindings (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, policy_id TEXT NOT NULL,
    subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, created_at TEXT NOT NULL,
    FOREIGN KEY(policy_id) REFERENCES kernel_policies(id)
);
CREATE TABLE IF NOT EXISTS kernel_agents (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, department_id TEXT,
    name TEXT NOT NULL, version TEXT NOT NULL, definition TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL,
    UNIQUE(tenant_id, name, version),
    FOREIGN KEY(tenant_id) REFERENCES kernel_tenants(id)
);
CREATE TABLE IF NOT EXISTS kernel_tools (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    version TEXT NOT NULL, definition TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL,
    UNIQUE(tenant_id, name, version),
    FOREIGN KEY(tenant_id) REFERENCES kernel_tenants(id)
);
CREATE TABLE IF NOT EXISTS kernel_runs (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, workflow_id TEXT,
    status TEXT NOT NULL, idempotency_key TEXT, context TEXT NOT NULL DEFAULT '{}',
    result TEXT, error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(tenant_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS kernel_tasks (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, run_id TEXT NOT NULL,
    task_type TEXT NOT NULL, status TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 5,
    payload TEXT NOT NULL, result TEXT, error TEXT, attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3, timeout_seconds INTEGER NOT NULL DEFAULT 300,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    available_at TEXT NOT NULL, lease_owner TEXT, lease_until TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES kernel_runs(id)
);
CREATE INDEX IF NOT EXISTS ix_kernel_tasks_claim
    ON kernel_tasks(status, available_at, priority);
CREATE TABLE IF NOT EXISTS kernel_task_transitions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL,
    from_status TEXT, to_status TEXT NOT NULL, reason TEXT,
    actor_id TEXT NOT NULL, created_at TEXT NOT NULL,
    FOREIGN KEY(task_id) REFERENCES kernel_tasks(id)
);
CREATE TABLE IF NOT EXISTS kernel_dead_letters (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, task_id TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL, error TEXT NOT NULL, attempts INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kernel_workflows (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    version TEXT NOT NULL, definition TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, UNIQUE(tenant_id,name,version)
);
CREATE TABLE IF NOT EXISTS kernel_workflow_steps (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, step_key TEXT NOT NULL,
    task_id TEXT, status TEXT NOT NULL, depends_on TEXT NOT NULL,
    compensation_type TEXT, compensation_task_id TEXT, result TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(run_id,step_key), FOREIGN KEY(run_id) REFERENCES kernel_runs(id)
);
CREATE TABLE IF NOT EXISTS kernel_outbox (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL, event_type TEXT NOT NULL, payload TEXT NOT NULL,
    published_at TEXT, attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kernel_run_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, event_type TEXT NOT NULL,
    payload TEXT NOT NULL, created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES kernel_runs(id)
);
CREATE INDEX IF NOT EXISTS ix_kernel_run_events
    ON kernel_run_events(tenant_id,run_id,sequence);
CREATE TABLE IF NOT EXISTS kernel_conversations (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, owner_id TEXT NOT NULL,
    title TEXT NOT NULL, agent_id TEXT, classification TEXT NOT NULL DEFAULT 'internal',
    status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_kernel_conversations_owner
    ON kernel_conversations(tenant_id,owner_id,updated_at);
CREATE TABLE IF NOT EXISTS kernel_messages (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL, conversation_id TEXT NOT NULL, run_id TEXT,
    role TEXT NOT NULL, content TEXT NOT NULL, metadata TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'internal', created_at TEXT NOT NULL,
    FOREIGN KEY(conversation_id) REFERENCES kernel_conversations(id)
);
CREATE INDEX IF NOT EXISTS ix_kernel_messages_conversation
    ON kernel_messages(tenant_id,conversation_id,sequence);
CREATE TABLE IF NOT EXISTS kernel_artifacts (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, run_id TEXT,
    media_type TEXT NOT NULL, storage_uri TEXT NOT NULL, sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL, metadata TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kernel_memories (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
    agent_name TEXT NOT NULL, session_id TEXT, role TEXT NOT NULL,
    content TEXT NOT NULL, classification TEXT NOT NULL DEFAULT 'internal',
    tokens_est INTEGER NOT NULL DEFAULT 0, expires_at TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_kernel_memories_context
    ON kernel_memories(tenant_id,agent_id,session_id,created_at);
CREATE TABLE IF NOT EXISTS kernel_memory_summaries (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
    session_id TEXT, summary TEXT NOT NULL, msg_count INTEGER NOT NULL DEFAULT 0,
    classification TEXT NOT NULL DEFAULT 'internal', expires_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kernel_knowledge_documents (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, title TEXT NOT NULL,
    source_uri TEXT NOT NULL, content TEXT NOT NULL, sha256 TEXT NOT NULL,
    classification TEXT NOT NULL, metadata TEXT NOT NULL,
    created_by TEXT NOT NULL, created_at TEXT NOT NULL,
    UNIQUE(tenant_id,source_uri,sha256)
);
CREATE INDEX IF NOT EXISTS ix_kernel_knowledge_documents
    ON kernel_knowledge_documents(tenant_id,classification,created_at);
CREATE TABLE IF NOT EXISTS kernel_usage_ledger (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, run_id TEXT NOT NULL,
    subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, metric TEXT NOT NULL,
    amount REAL NOT NULL, metadata TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_kernel_usage_budget
    ON kernel_usage_ledger(tenant_id,run_id,subject_type,subject_id,metric);
CREATE TABLE IF NOT EXISTS kernel_quotas (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL, metric TEXT NOT NULL, limit_value REAL NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
    UNIQUE(tenant_id,subject_type,subject_id,metric)
);
CREATE TABLE IF NOT EXISTS kernel_approvals (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, run_id TEXT NOT NULL,
    action TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
    requested_by TEXT NOT NULL, decided_by TEXT, reason TEXT,
    created_at TEXT NOT NULL, decided_at TEXT
);
CREATE TABLE IF NOT EXISTS kernel_audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL, trace_id TEXT NOT NULL, actor_id TEXT NOT NULL,
    action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL,
    decision TEXT, payload TEXT NOT NULL, previous_hash TEXT, event_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evolution_proposals (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, title TEXT NOT NULL,
    hypothesis TEXT NOT NULL, evidence TEXT NOT NULL, acceptance_criteria TEXT NOT NULL,
    risk TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'proposed',
    proposed_by TEXT NOT NULL, implementation_actor TEXT, evaluation_actor TEXT,
    approval_actor TEXT, baseline_version TEXT NOT NULL, candidate_version TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evolution_evaluations (
    id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL, evaluator_id TEXT NOT NULL,
    passed INTEGER NOT NULL, metrics TEXT NOT NULL, report_uri TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(proposal_id) REFERENCES evolution_proposals(id)
);
CREATE TABLE IF NOT EXISTS evolution_campaigns (
    proposal_id TEXT PRIMARY KEY, max_iterations INTEGER NOT NULL,
    iterations_used INTEGER NOT NULL DEFAULT 0, token_budget INTEGER NOT NULL,
    tokens_used INTEGER NOT NULL DEFAULT 0, deadline TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL,
    FOREIGN KEY(proposal_id) REFERENCES evolution_proposals(id)
);
CREATE TABLE IF NOT EXISTS evolution_canary_samples (
    id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL, success_rate REAL NOT NULL,
    error_rate REAL NOT NULL, latency_ms REAL NOT NULL, cost REAL NOT NULL,
    decision TEXT NOT NULL, created_at TEXT NOT NULL,
    FOREIGN KEY(proposal_id) REFERENCES evolution_proposals(id)
);
CREATE TABLE IF NOT EXISTS connector_enrollment_tokens (
    token_hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, expires_at TEXT NOT NULL,
    used_at TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kernel_connectors (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    device_id TEXT NOT NULL, credential_hash TEXT NOT NULL, status TEXT NOT NULL,
    capabilities TEXT NOT NULL, allowed_roots TEXT NOT NULL,
    certificate_fingerprint TEXT, credential_rotated_at TEXT,
    last_seen_at TEXT, revoked_at TEXT, created_at TEXT NOT NULL,
    UNIQUE(tenant_id, device_id)
);
"""


class ControlStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate_sqlite(conn)
            conn.execute(
                "INSERT OR IGNORE INTO kernel_tenants(id,name,created_at) VALUES(?,?,?)",
                ("system", "NEXUS System", utc_now()),
            )

    @staticmethod
    def _migrate_sqlite(conn: sqlite3.Connection) -> None:
        """Apply small forward migrations to pre-control-plane SQLite databases."""
        columns = {row[1] for row in conn.execute("PRAGMA table_info(kernel_tasks)")}
        additions = {
            "max_attempts": "INTEGER NOT NULL DEFAULT 3",
            "timeout_seconds": "INTEGER NOT NULL DEFAULT 300",
            "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
        }
        for name, definition in additions.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE kernel_tasks ADD COLUMN {name} {definition}")
        connector_columns = {row[1] for row in conn.execute("PRAGMA table_info(kernel_connectors)")}
        for name in ("certificate_fingerprint", "credential_rotated_at"):
            if name not in connector_columns:
                conn.execute(f"ALTER TABLE kernel_connectors ADD COLUMN {name} TEXT")
        workflow_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(kernel_workflow_steps)")
        }
        if "compensation_task_id" not in workflow_columns:
            conn.execute(
                "ALTER TABLE kernel_workflow_steps ADD COLUMN compensation_task_id TEXT"
            )
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,name,applied_at) VALUES(?,?,?)",
            (1, "durable_workflows", utc_now()),
        )

    def migrate_legacy_users(self) -> int:
        """One-way migration from the original SQLite nexus_users table."""
        migrated = 0
        with self.connect() as conn:
            exists = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='nexus_users'"
            ).fetchone()
            if not exists:
                return 0
            rows = conn.execute("SELECT * FROM nexus_users").fetchall()
            for row in rows:
                value = dict(row)
                tenant_id = value.get("tenant_id") or "system"
                conn.execute(
                    """INSERT OR IGNORE INTO kernel_users
                    (id,tenant_id,email,name,hashed_pw,role,active,created_at)
                    VALUES(?,?,?,?,?,?,?,?)""",
                    (f"legacy_user_{value['id']}", tenant_id, value["email"],
                     value["name"], value["hashed_pw"], value["role"],
                     value["active"], value["created_at"]),
                )
                migrated += 1
        return migrated

    def create_tenant(self, name: str, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        tenant_id = tenant_id or f"tenant_{uuid4().hex}"
        created_at = utc_now()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO kernel_tenants(id,name,created_at) VALUES(?,?,?)",
                (tenant_id, name, created_at),
            )
        return {"id": tenant_id, "name": name, "status": "active", "created_at": created_at}

    def create_organization(self, name: str, organization_id: Optional[str] = None) -> Dict[str, Any]:
        organization_id = organization_id or f"organization_{uuid4().hex}"
        created_at = utc_now()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO kernel_organizations(id,name,created_at) VALUES(?,?,?)",
                (organization_id, name, created_at),
            )
        return {"id": organization_id, "name": name, "status": "active",
                "created_at": created_at}

    def list_organizations(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM kernel_organizations ORDER BY created_at"
            ).fetchall()]

    def list_tenants(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM kernel_tenants ORDER BY created_at"
            ).fetchall()]

    def put_definition(self, table: str, definition: Dict[str, Any]) -> Dict[str, Any]:
        if table not in {"kernel_agents", "kernel_tools"}:
            raise ValueError("unsupported definition table")
        entity_id = definition.get("agent_id") or definition.get("tool_id")
        if not entity_id:
            raise ValueError("definition id is required")
        now = definition.get("created_at") or utc_now()
        columns = "id,tenant_id,name,version,definition,status,created_at"
        values: tuple[Any, ...] = (
            entity_id, definition["tenant_id"], definition["name"],
            definition.get("version", "1.0.0"), json.dumps(definition, sort_keys=True),
            "active" if definition.get("enabled", True) else "disabled", now,
        )
        placeholders = "?,?,?,?,?,?,?"
        if table == "kernel_agents":
            columns += ",department_id"
            placeholders += ",?"
            values += (definition.get("department_id"),)
        with self.connect() as conn:
            conn.execute(
                f"INSERT INTO {table}({columns}) VALUES({placeholders})",
                values,
            )
        return definition

    def list_definitions(self, table: str, tenant_id: str) -> List[Dict[str, Any]]:
        if table not in {"kernel_agents", "kernel_tools"}:
            raise ValueError("unsupported definition table")
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT definition FROM {table} WHERE tenant_id=? ORDER BY created_at",
                (tenant_id,),
            ).fetchall()
        return [json.loads(row["definition"]) for row in rows]

    def create_run(
        self,
        tenant_id: str,
        context: Dict[str, Any],
        idempotency_key: Optional[str] = None,
        workflow_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = utc_now()
        run_id = f"run_{uuid4().hex}"
        with self.connect() as conn:
            if idempotency_key:
                existing = conn.execute(
                    "SELECT * FROM kernel_runs WHERE tenant_id=? AND idempotency_key=?",
                    (tenant_id, idempotency_key),
                ).fetchone()
                if existing:
                    return self._decode_row(existing, ("context", "result"))
            conn.execute(
                """INSERT INTO kernel_runs
                (id,tenant_id,workflow_id,status,idempotency_key,context,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?)""",
                (run_id, tenant_id, workflow_id, "pending", idempotency_key,
                 json.dumps(context), now, now),
            )
        return {"id": run_id, "tenant_id": tenant_id, "status": "pending", "context": context}

    def get_run(self, run_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM kernel_runs WHERE id=? AND tenant_id=?", (run_id, tenant_id)
            ).fetchone()
        return self._decode_row(row, ("context", "result")) if row else None

    def append_run_event(self, tenant_id: str, run_id: str, event_type: str,
                         payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        event = {
            "event_id": f"event_{uuid4().hex}", "tenant_id": tenant_id,
            "run_id": run_id, "event_type": event_type,
            "payload": payload or {}, "created_at": utc_now(),
        }
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_run_events
                (event_id,tenant_id,run_id,event_type,payload,created_at)
                VALUES(?,?,?,?,?,?)""",
                (event["event_id"], tenant_id, run_id, event_type,
                 json.dumps(event["payload"]), event["created_at"]),
            )
        return event

    def list_run_events(self, tenant_id: str, run_id: str,
                        after: int = 0) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """SELECT * FROM kernel_run_events WHERE tenant_id=? AND run_id=?
                AND sequence>? ORDER BY sequence""", (tenant_id, run_id, after),
            ).fetchall()
        return [self._decode_row(row, ("payload",)) for row in rows]

    def create_conversation(self, tenant_id: str, owner_id: str, title: str,
                            agent_id: Optional[str] = None,
                            classification: str = "internal") -> Dict[str, Any]:
        if classification not in {"public", "internal", "confidential", "restricted"}:
            raise ValueError("unsupported data classification")
        now = utc_now()
        value = {"id": f"conversation_{uuid4().hex}", "tenant_id": tenant_id,
                 "owner_id": owner_id, "title": title[:120] or "Nueva conversación",
                 "agent_id": agent_id, "classification": classification,
                 "status": "active", "created_at": now, "updated_at": now}
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_conversations
                (id,tenant_id,owner_id,title,agent_id,classification,status,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)""", tuple(value.values()),
            )
        return value

    def list_conversations(self, tenant_id: str, owner_id: str) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(
                """SELECT * FROM kernel_conversations WHERE tenant_id=? AND owner_id=?
                AND status!='deleted' ORDER BY updated_at DESC""", (tenant_id, owner_id),
            ).fetchall()]

    def get_conversation(self, tenant_id: str, conversation_id: str,
                         owner_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        sql = "SELECT * FROM kernel_conversations WHERE tenant_id=? AND id=?"
        params: tuple[Any, ...] = (tenant_id, conversation_id)
        if owner_id:
            sql += " AND owner_id=?"
            params += (owner_id,)
        with self.connect() as conn:
            row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def append_message(self, tenant_id: str, conversation_id: str, role: str,
                       content: str, *, run_id: Optional[str] = None,
                       metadata: Optional[Dict[str, Any]] = None,
                       classification: str = "internal") -> Dict[str, Any]:
        if role not in {"system", "user", "assistant", "tool"}:
            raise ValueError("unsupported message role")
        message = {"id": f"message_{uuid4().hex}", "tenant_id": tenant_id,
                   "conversation_id": conversation_id, "run_id": run_id,
                   "role": role, "content": content, "metadata": metadata or {},
                   "classification": classification, "created_at": utc_now()}
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_messages
                (id,tenant_id,conversation_id,run_id,role,content,metadata,classification,created_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (message["id"], tenant_id, conversation_id, run_id, role, content,
                 json.dumps(message["metadata"]), classification, message["created_at"]),
            )
            conn.execute("UPDATE kernel_conversations SET updated_at=? WHERE id=? AND tenant_id=?",
                         (message["created_at"], conversation_id, tenant_id))
        return message

    def list_messages(self, tenant_id: str, conversation_id: str,
                      limit: int = 100) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """SELECT * FROM (SELECT * FROM kernel_messages WHERE tenant_id=?
                AND conversation_id=? ORDER BY sequence DESC LIMIT ?) ordered
                ORDER BY sequence""", (tenant_id, conversation_id, max(1, min(limit, 500))),
            ).fetchall()
        return [self._decode_row(row, ("metadata",)) for row in rows]

    def delete_conversation(self, tenant_id: str, conversation_id: str,
                            owner_id: str) -> bool:
        with self.connect() as conn:
            updated = conn.execute(
                """UPDATE kernel_conversations SET status='deleted',updated_at=?
                WHERE tenant_id=? AND id=? AND owner_id=? AND status!='deleted'""",
                (utc_now(), tenant_id, conversation_id, owner_id),
            )
        return updated.rowcount == 1

    def enqueue_task(
        self,
        *,
        tenant_id: str,
        run_id: str,
        task_type: str,
        payload: Dict[str, Any],
        priority: int = 5,
        max_attempts: int = 3,
        timeout_seconds: int = 300,
    ) -> Dict[str, Any]:
        task_id = f"task_{uuid4().hex}"
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_tasks
                (id,tenant_id,run_id,task_type,status,priority,payload,max_attempts,
                 timeout_seconds,available_at,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (task_id, tenant_id, run_id, task_type, "queued", priority,
                 json.dumps(payload), max(1, max_attempts), max(1, timeout_seconds), now, now, now),
            )
            self._transition(conn, task_id, None, "queued", "enqueued", "system")
            self._outbox(conn, tenant_id, "task", task_id, "task.queued", {"run_id": run_id})
            conn.execute(
                "UPDATE kernel_runs SET status='queued',updated_at=? WHERE id=? AND tenant_id=?",
                (now, run_id, tenant_id),
            )
        return {"id": task_id, "run_id": run_id, "status": "queued", "payload": payload}

    def claim_task(self, worker_id: str, lease_seconds: int = 60) -> Optional[Dict[str, Any]]:
        now = datetime.now(timezone.utc)
        now_value = now.isoformat()
        lease_until = (now + timedelta(seconds=lease_seconds)).isoformat()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """SELECT * FROM kernel_tasks
                WHERE cancel_requested=0 AND ((status='queued' AND available_at<=?)
                   OR (status='running' AND lease_until<?)
                )
                ORDER BY priority ASC, created_at ASC LIMIT 1""",
                (now_value, now_value),
            ).fetchone()
            if not row:
                return None
            updated = conn.execute(
                """UPDATE kernel_tasks SET status='running',lease_owner=?,lease_until=?,
                   attempts=attempts+1,updated_at=? WHERE id=? AND
                   ((status='queued' AND available_at<=?) OR (status='running' AND lease_until<?))""",
                (worker_id, lease_until, now_value, row["id"], now_value, now_value),
            )
            if updated.rowcount != 1:
                return None
            claimed = conn.execute(
                "SELECT * FROM kernel_tasks WHERE id=?", (row["id"],)
            ).fetchone()
            self._transition(conn, row["id"], row["status"], "running", "lease claimed", worker_id)
        return self._decode_row(claimed, ("payload", "result"))

    def complete_task(
        self,
        task_id: str,
        worker_id: str,
        *,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        status = "failed" if error else "completed"
        now = utc_now()
        with self.connect() as conn:
            row = conn.execute(
                """SELECT t.run_id,r.workflow_id FROM kernel_tasks t
                JOIN kernel_runs r ON r.id=t.run_id
                WHERE t.id=? AND t.lease_owner=? AND t.status='running'""",
                (task_id, worker_id),
            ).fetchone()
            if not row:
                raise PermissionError("worker does not own an active task lease")
            conn.execute(
                """UPDATE kernel_tasks SET status=?,result=?,error=?,lease_owner=NULL,
                   lease_until=NULL,updated_at=? WHERE id=?""",
                (status, json.dumps(result) if result is not None else None, error, now, task_id),
            )
            self._transition(conn, task_id, "running", status, error, worker_id)
            self._outbox(conn, conn.execute(
                "SELECT tenant_id FROM kernel_tasks WHERE id=?", (task_id,)
            ).fetchone()["tenant_id"], "task", task_id, f"task.{status}", result or {"error": error})
            run_status = "running" if row["workflow_id"] else status
            conn.execute(
                "UPDATE kernel_runs SET status=?,result=?,error=?,updated_at=? WHERE id=?",
                (run_status, json.dumps(result) if result is not None else None, error, now, row["run_id"]),
            )

    def fail_or_retry_task(self, task_id: str, worker_id: str, error: str) -> str:
        """Retry with exponential backoff, or atomically move an exhausted task to DLQ."""
        now = datetime.now(timezone.utc)
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM kernel_tasks WHERE id=? AND lease_owner=? AND status='running'",
                (task_id, worker_id),
            ).fetchone()
            if not row:
                raise PermissionError("worker does not own an active task lease")
            if row["attempts"] < row["max_attempts"]:
                delay = min(300, 2 ** max(0, row["attempts"] - 1))
                available = (now + timedelta(seconds=delay)).isoformat()
                conn.execute(
                    """UPDATE kernel_tasks SET status='queued',error=?,available_at=?,
                    lease_owner=NULL,lease_until=NULL,updated_at=? WHERE id=?""",
                    (error, available, now.isoformat(), task_id),
                )
                self._transition(conn, task_id, "running", "queued", "retry: " + error, worker_id)
                return "queued"
            conn.execute(
                """UPDATE kernel_tasks SET status='dead_letter',error=?,lease_owner=NULL,
                lease_until=NULL,updated_at=? WHERE id=?""",
                (error, now.isoformat(), task_id),
            )
            conn.execute(
                """INSERT INTO kernel_dead_letters
                (id,tenant_id,task_id,payload,error,attempts,created_at)
                VALUES(?,?,?,?,?,?,?)""",
                (f"dlq_{uuid4().hex}", row["tenant_id"], task_id, row["payload"], error,
                 row["attempts"], now.isoformat()),
            )
            conn.execute(
                "UPDATE kernel_runs SET status='failed',error=?,updated_at=? WHERE id=?",
                (error, now.isoformat(), row["run_id"]),
            )
            self._transition(conn, task_id, "running", "dead_letter", error, worker_id)
            self._outbox(conn, row["tenant_id"], "task", task_id, "task.dead_letter", {"error": error})
            return "dead_letter"

    def request_task_cancel(self, task_id: str, tenant_id: str, actor_id: str) -> bool:
        now = utc_now()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT status FROM kernel_tasks WHERE id=? AND tenant_id=?", (task_id, tenant_id)
            ).fetchone()
            if not row or row["status"] in {"completed", "failed", "dead_letter", "cancelled"}:
                return False
            if row["status"] == "queued":
                conn.execute(
                    "UPDATE kernel_tasks SET status='cancelled',cancel_requested=1,updated_at=? WHERE id=?",
                    (now, task_id),
                )
                self._transition(conn, task_id, "queued", "cancelled", "cancel requested", actor_id)
            else:
                conn.execute(
                    "UPDATE kernel_tasks SET cancel_requested=1,updated_at=? WHERE id=?", (now, task_id)
                )
            return True

    def list_task_transitions(self, task_id: str) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM kernel_task_transitions WHERE task_id=? ORDER BY sequence", (task_id,)
            ).fetchall()]

    def record_usage(self, tenant_id: str, run_id: str, subject_type: str,
                     subject_id: str, metric: str, amount: float,
                     metadata: Optional[Dict[str, Any]] = None) -> float:
        if amount < 0:
            raise ValueError("usage amount cannot be negative")
        with self.connect() as conn:
            quota = conn.execute(
                """SELECT limit_value FROM kernel_quotas WHERE tenant_id=? AND
                subject_type=? AND subject_id=? AND metric=? AND enabled=1""",
                (tenant_id, subject_type, subject_id, metric),
            ).fetchone()
            used = conn.execute(
                """SELECT COALESCE(SUM(amount),0) AS total FROM kernel_usage_ledger
                WHERE tenant_id=? AND run_id=? AND subject_type=? AND subject_id=? AND metric=?""",
                (tenant_id, run_id, subject_type, subject_id, metric),
            ).fetchone()["total"]
            if quota and float(used) + amount > float(quota["limit_value"]):
                raise PermissionError(f"{metric} quota exceeded")
            conn.execute(
                """INSERT INTO kernel_usage_ledger
                (id,tenant_id,run_id,subject_type,subject_id,metric,amount,metadata,created_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (f"usage_{uuid4().hex}", tenant_id, run_id, subject_type, subject_id,
                 metric, amount, json.dumps(metadata or {}), utc_now()),
            )
            return float(used) + amount

    def set_quota(self, tenant_id: str, subject_type: str, subject_id: str,
                  metric: str, limit_value: float) -> None:
        if limit_value < 0:
            raise ValueError("quota cannot be negative")
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_quotas
                (id,tenant_id,subject_type,subject_id,metric,limit_value,created_at)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant_id,subject_type,subject_id,metric)
                DO UPDATE SET limit_value=excluded.limit_value,enabled=1""",
                (f"quota_{uuid4().hex}", tenant_id, subject_type, subject_id,
                 metric, limit_value, utc_now()),
            )

    def usage_total(self, tenant_id: str, run_id: str, subject_type: str,
                    subject_id: str, metric: str) -> float:
        with self.connect() as conn:
            row = conn.execute(
                """SELECT COALESCE(SUM(amount),0) AS total FROM kernel_usage_ledger
                WHERE tenant_id=? AND run_id=? AND subject_type=? AND subject_id=? AND metric=?""",
                (tenant_id, run_id, subject_type, subject_id, metric),
            ).fetchone()
        return float(row["total"])

    @staticmethod
    def _transition(conn, task_id: str, old: Optional[str], new: str, reason: Optional[str], actor: str) -> None:
        conn.execute(
            """INSERT INTO kernel_task_transitions
            (task_id,from_status,to_status,reason,actor_id,created_at) VALUES(?,?,?,?,?,?)""",
            (task_id, old, new, reason, actor, utc_now()),
        )

    @staticmethod
    def _outbox(conn, tenant_id: str, aggregate_type: str, aggregate_id: str,
                event_type: str, payload: Dict[str, Any]) -> None:
        conn.execute(
            """INSERT INTO kernel_outbox
            (id,tenant_id,aggregate_type,aggregate_id,event_type,payload,created_at)
            VALUES(?,?,?,?,?,?,?)""",
            (f"evt_{uuid4().hex}", tenant_id, aggregate_type, aggregate_id,
             event_type, json.dumps(payload), utc_now()),
        )

    @staticmethod
    def _decode_row(row: sqlite3.Row, fields: Iterable[str]) -> Dict[str, Any]:
        value = dict(row)
        for field in fields:
            if value.get(field):
                value[field] = json.loads(value[field])
        return value
