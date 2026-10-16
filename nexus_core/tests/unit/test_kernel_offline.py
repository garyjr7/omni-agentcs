import asyncio
import json
import unittest
import tempfile
import os
from pathlib import Path

from nexus_core.kernel import (
    AgentDefinition,
    Identity,
    PolicyEngine,
    Resource,
    RiskLevel,
    ToolDefinition,
    ToolResult,
)
from nexus_core.kernel.policy import PolicyRepository
from nexus_core.llm.abstraction import LLMConfig, LLMFactory, LLMMessage, LLMProvider
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.kernel.models import RunContext
from nexus_core.kernel.model_router import ModelRouter, RoutePolicy
from nexus_core.kernel.connectors import ConnectorRegistry
from nexus_core.kernel.store_factory import get_control_store
from nexus_core.kernel.sandbox import OCISandbox
from nexus_core.kernel.packages import PackageManager
from nexus_core.kernel.approvals import ApprovalService
from nexus_core.tools.parsers import PARSERS_VERSION


class OfflineKernelTests(unittest.TestCase):
    def test_fake_provider_uses_fixture(self):
        client = LLMFactory.create(LLMConfig(provider=LLMProvider.FAKE, model="test"))
        response = asyncio.run(client.complete(
            [LLMMessage(role="user", content="hola")], scenario="echo"
        ))
        self.assertEqual(response.content, "hola")
        self.assertEqual(response.provider, LLMProvider.FAKE)

    def test_policy_denies_cross_tenant(self):
        decision = PolicyEngine().decide(
            Identity("user-1", "tenant-a", roles=("admin",)),
            "read:agent",
            Resource("agent-1", "tenant-b", "agent"),
        )
        self.assertFalse(decision.allowed)

    def test_directory_entities_are_tenant_scoped(self):
        from nexus_core.kernel.directory import DirectoryRepository

        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            store.create_tenant("A", "tenant-a")
            store.create_tenant("B", "tenant-b")
            repo = DirectoryRepository(store)
            department = repo.create_department("tenant-a", "marketing")
            environment = repo.create_environment("tenant-a", "production", "confidential")
            group = repo.create_group("tenant-a", "operators")
            account = repo.create_service_account("tenant-a", "publisher", ["operator"])
            repo.add_member("tenant-a", group["id"], "service_account", account["id"])
            repo.create_resource(
                "tenant-a", "social_account", "linkedin", "confidential",
                environment_id=environment["id"],
            )
            capability = repo.create_capability("tenant-a", "content.publish")
            agent = AgentDefinition(
                name="Publisher", tenant_id="tenant-a", department_id=department["id"]
            )
            store.put_definition("kernel_agents", agent.to_dict())
            tool = ToolDefinition(name="Publish", tenant_id="tenant-a", input_schema={})
            store.put_definition("kernel_tools", tool.to_dict())
            resource = repo.list_kind("kernel_resources", "tenant-a")[0]
            repo.assign_agent_capability("tenant-a", agent.agent_id, capability["id"])
            repo.bind_tool_resource("tenant-a", tool.tool_id, resource["id"], ["publish"])
            self.assertEqual(len(repo.list_kind("kernel_resources", "tenant-a")), 1)
            self.assertEqual(repo.list_kind("kernel_resources", "tenant-b"), [])
            with self.assertRaises(KeyError):
                repo.create_resource(
                    "tenant-b", "social_account", "other", "internal",
                    environment_id=environment["id"],
                )
            self.assertNotIn(
                "credential_hash", repo.list_kind("kernel_service_accounts", "tenant-a")[0]
            )

    def test_explicit_policy_deny_overrides_admin(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            repository = PolicyRepository(store)
            policy = repository.create(
                tenant_id="system", name="protect-production", effect="deny",
                actions=["execute:tool"], resource_kinds=["tool"],
                conditions={"environment": "production"},
            )
            repository.bind("system", policy["id"], "role", "admin")
            decision = PolicyEngine(store).decide(
                Identity("admin", "system", roles=("admin",)), "execute:tool",
                Resource("tool", "system", "tool", environment="production"),
            )
            self.assertFalse(decision.allowed)

    def test_high_risk_tool_requires_approval(self):
        tool = ToolDefinition("deploy", "tenant-a", {}, risk=RiskLevel.HIGH)
        decision = PolicyEngine().decide(
            Identity("user-1", "tenant-a", roles=("operator",)),
            "execute:tool",
            Resource(tool.tool_id, "tenant-a", "tool"),
            tool=tool,
        )
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.requires_approval)

    def test_control_store_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            first = store.create_run("system", {"goal": "test"}, "same-request")
            second = store.create_run("system", {"goal": "different"}, "same-request")
            self.assertEqual(first["id"], second["id"])
            self.assertEqual(second["context"], {"goal": "test"})

    def test_durable_task_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            run = store.create_run("system", {"goal": "test"})
            task = store.enqueue_task(
                tenant_id="system", run_id=run["id"], task_type="debug",
                payload={"scenario": "echo"},
            )
            claimed = store.claim_task("worker-1")
            self.assertEqual(claimed["id"], task["id"])
            self.assertIsNone(store.claim_task("worker-2"))
            with self.assertRaises(PermissionError):
                store.complete_task(task["id"], "worker-2", result={"ok": True}, lease_generation=claimed["lease_generation"])
            store.complete_task(task["id"], "worker-1", result={"ok": True}, lease_generation=claimed["lease_generation"])

    def test_durable_retry_dead_letter_and_history(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            run = store.create_run("system", {})
            task = store.enqueue_task(
                tenant_id="system", run_id=run["id"], task_type="fail",
                payload={}, max_attempts=2,
            )
            claimed = store.claim_task("worker")
            self.assertEqual(store.fail_or_retry_task(claimed["id"], "worker", "one", lease_generation=claimed["lease_generation"]), "queued")
            with store.connect() as conn:
                conn.execute(
                    "UPDATE kernel_tasks SET available_at=? WHERE id=?",
                    ("1970-01-01T00:00:00+00:00", task["id"]),
                )
            claimed = store.claim_task("worker")
            self.assertEqual(store.fail_or_retry_task(claimed["id"], "worker", "two", lease_generation=claimed["lease_generation"]), "dead_letter")
            self.assertEqual(
                [item["to_status"] for item in store.list_task_transitions(task["id"])],
                ["queued", "running", "queued", "running", "dead_letter"],
            )

    def test_durable_workflow_resumes_and_enqueues_dependencies(self):
        from nexus_core.kernel.workflows import DurableWorkflowEngine

        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            engine = DurableWorkflowEngine(store)
            workflow = engine.register("system", "two-step", "1.0.0", {"steps": [
                {"key": "research", "task_type": "debug.fake_llm"},
                {"key": "publish", "task_type": "debug.fake_llm", "depends_on": ["research"]},
            ]})
            run = engine.start("system", workflow["id"], {}, "same-request")
            self.assertEqual(sum(bool(step["task_id"]) for step in engine.history(run["id"], "system")), 1)
            first = store.claim_task("worker")
            store.complete_task(first["id"], "worker", result={"ok": True}, lease_generation=first["lease_generation"])
            DurableWorkflowEngine(store).reconcile(run["id"], "system")
            self.assertEqual(sum(bool(step["task_id"]) for step in engine.history(run["id"], "system")), 2)

    def test_failed_workflow_enqueues_compensation_once(self):
        from nexus_core.kernel.workflows import DurableWorkflowEngine

        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            engine = DurableWorkflowEngine(store)
            workflow = engine.register("system", "compensated", "1.0.0", {"steps": [
                {"key": "write", "task_type": "write", "compensation_type": "undo"},
                {"key": "notify", "task_type": "notify", "depends_on": ["write"],
                 "max_attempts": 1},
            ]})
            run = engine.start("system", workflow["id"], {}, "compensation-request")
            write = store.claim_task("worker")
            store.complete_task(write["id"], "worker", result={"external_id": "one"}, lease_generation=write["lease_generation"])
            engine.reconcile(run["id"], "system")
            notify = store.claim_task("worker")
            store.fail_or_retry_task(notify["id"], "worker", "provider rejected", lease_generation=notify["lease_generation"])
            engine.reconcile(run["id"], "system")
            compensation = store.claim_task("worker")
            self.assertEqual(compensation["task_type"], "undo")
            store.complete_task(compensation["id"], "worker", result={"undone": True}, lease_generation=compensation["lease_generation"])
            engine.reconcile(run["id"], "system")
            states = {item["step_key"]: item for item in engine.history(run["id"], "system")}
            self.assertEqual(states["write"]["status"], "compensated")

    def test_tool_gateway_requires_approval_and_audits(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            approvals = ApprovalService(store)
            gateway = ToolGateway(PolicyEngine(), AuditWriter(store), approvals)
            tool = ToolDefinition("deploy", "system", {}, risk=RiskLevel.HIGH)
            gateway.register(tool, lambda arguments, context: ToolResult(
                output={"ok": True}, verified=True,
                verification_method="test-observation",
            ))
            context = RunContext(
                "system", Identity("operator-1", "system", roles=("operator",))
            )
            with self.assertRaises(PermissionError):
                asyncio.run(gateway.invoke(tool.tool_id, {}, context))
            approval = approvals.request(context, f"execute:tool:{tool.tool_id}")
            with self.assertRaises(PermissionError):
                approvals.decide(approval["id"], "system", "operator-1", True)
            approvals.decide(approval["id"], "system", "admin-2", True)
            result = asyncio.run(gateway.invoke(
                tool.tool_id, {}, context, approval_id=approval["id"]
            ))
            self.assertEqual(result["output"], {"ok": True})
            with store.connect() as conn:
                count = conn.execute("SELECT COUNT(*) FROM kernel_audit_events").fetchone()[0]
            self.assertEqual(count, 3)
            self.assertEqual(AuditWriter(store).verify_chain(), (True, None))

    def test_tool_gateway_validates_schema_quota_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            gateway = ToolGateway(PolicyEngine(), AuditWriter(store))
            tool = ToolDefinition(
                "lookup", "system",
                {"type": "object", "required": ["query"], "additionalProperties": False,
                 "properties": {"query": {"type": "string", "minLength": 1}}},
                max_output_bytes=1_000,
            )
            gateway.register(tool, lambda arguments, context: ToolResult(
                output={"result": arguments["query"]}, verified=True,
                verification_method="test-observation",
            ))
            context = RunContext("system", Identity("admin", "system", roles=("admin",)))
            with self.assertRaises(ValueError):
                asyncio.run(gateway.invoke(tool.tool_id, {}, context))
            store.set_quota("system", "tool", tool.tool_id, "calls", 1)
            result = asyncio.run(gateway.invoke(tool.tool_id, {"query": "ok"}, context))
            self.assertTrue(result.pop("invocation_id"))
            self.assertEqual(result.pop("run_id"), context.run_id)
            self.assertEqual(result.pop("assertions"), [])
            self.assertEqual(
                result,
                {"success": True, "output": {"result": "ok"}, "verified": True,
                 "verification_method": "test-observation",
                 # V0-22: the result says which conclusion it reached, so a
                 # determinate negative is distinguishable from a failure.
                 "outcome": "success", "evidence": {},
                 "exit_code": None, "accepted_exit_codes": [0], "stdout": "",
                 "stderr": "", "timed_out": False,
                 # V1-8: the canonical result pins the contract and parser
                 # revision that produced it, so a replay can use them.
                 "tool_id": tool.tool_id, "contract_version": tool.version,
                 "parser_version": PARSERS_VERSION,
                 # A04: the result carries the engagement the gateway stamped it
                 # with, so playbook progress binds to verified execution.
                 "engagement_id": context.engagement_id},
            )
            with self.assertRaises(PermissionError):
                asyncio.run(gateway.invoke(tool.tool_id, {"query": "again"}, context))


    def test_model_router_enforces_budget(self):
        client = LLMFactory.create(LLMConfig(provider=LLMProvider.FAKE, model="test"))
        router = ModelRouter({"fake": client}, [RoutePolicy("default", ("fake",))])
        context = RunContext(
            "system", Identity("user", "system", roles=("operator",)), budget_tokens=2
        )
        response = asyncio.run(router.complete(
            "default", [LLMMessage(role="user", content="hola")], context,
            scenario="echo",
        ))
        self.assertEqual(response.content, "hola")
        with self.assertRaises(PermissionError):
            asyncio.run(router.complete(
                "default", [LLMMessage(role="user", content="otra")], context,
                scenario="echo",
            ))

    def test_connector_enrollment_is_one_time_and_revocable(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            registry = ConnectorRegistry(store)
            token = registry.create_enrollment_token("system", "admin")
            enrolled = registry.enroll(
                token, name="test-device", device_id="device-0001",
                capabilities=["filesystem.read"], allowed_roots=[directory],
                certificate_fingerprint="cert-a",
            )
            with self.assertRaises(PermissionError):
                registry.enroll(
                    token, name="other", device_id="device-0002",
                    capabilities=[], allowed_roots=[],
                )
            with self.assertRaises(PermissionError):
                registry.heartbeat(enrolled["connector_id"], enrolled["credential"], "cert-b")
            registry.heartbeat(enrolled["connector_id"], enrolled["credential"], "cert-a")
            replacement = registry.rotate_credential(
                enrolled["connector_id"], enrolled["credential"], "cert-a"
            )
            with self.assertRaises(PermissionError):
                registry.authenticate(enrolled["connector_id"], enrolled["credential"], "cert-a")
            registry.authenticate(enrolled["connector_id"], replacement, "cert-a")
            registry.revoke(enrolled["connector_id"])
            with self.assertRaises(PermissionError):
                registry.authenticate(enrolled["connector_id"], replacement, "cert-a")

    def test_production_rejects_implicit_sqlite(self):
        previous = os.environ.get("NEXUS_ENV")
        previous_override = os.environ.pop("NEXUS_ALLOW_SQLITE_PRODUCTION", None)
        os.environ["NEXUS_ENV"] = "production"
        try:
            with self.assertRaises(RuntimeError):
                get_control_store("unused.db", database_url="")
        finally:
            if previous is None:
                os.environ.pop("NEXUS_ENV", None)
            else:
                os.environ["NEXUS_ENV"] = previous
            if previous_override is not None:
                os.environ["NEXUS_ALLOW_SQLITE_PRODUCTION"] = previous_override

    def test_postgres_adapter_translates_placeholders_and_idempotent_insert(self):
        from nexus_core.kernel.postgres_store import _PostgresConnection

        translated = _PostgresConnection._query(
            "INSERT OR IGNORE INTO sample(id,value) VALUES(?,?)"
        )
        self.assertEqual(
            translated,
            "INSERT INTO sample(id,value) VALUES(%s,%s) ON CONFLICT DO NOTHING",
        )

    def test_legacy_users_are_migrated(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            with store.connect() as conn:
                conn.execute("""CREATE TABLE nexus_users (
                    id INTEGER PRIMARY KEY, email TEXT, name TEXT, hashed_pw TEXT,
                    role TEXT, active INTEGER, created_at TEXT)""")
                conn.execute(
                    "INSERT INTO nexus_users VALUES(?,?,?,?,?,?,?)",
                    (7, "legacy@example.test", "Legacy", "hash", "viewer", 1, "now"),
                )
            self.assertEqual(store.migrate_legacy_users(), 1)
            with store.connect() as conn:
                user = conn.execute(
                    "SELECT * FROM kernel_users WHERE id='legacy_user_7'"
                ).fetchone()
            self.assertEqual(user["email"], "legacy@example.test")

    def test_oci_sandbox_has_mandatory_isolation_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            sandbox = OCISandbox(directory, ["python:test"])
            argv = sandbox.build_argv("python:test", ["python", "-m", "unittest"])
            joined = " ".join(argv)
            self.assertIn("--network none", joined)
            self.assertIn("--read-only", argv)
            self.assertIn("--cap-drop ALL", joined)
            self.assertIn("no-new-privileges", argv)
            self.assertIn("--user 65532:65532", joined)
            with self.assertRaises(PermissionError):
                sandbox.build_argv("untrusted:latest", ["true"])

    def test_package_installs_without_kernel_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            packages = Path(directory) / "packages"
            package = packages / "fixture"
            package.mkdir(parents=True)
            (package / "manifest.json").write_text(json.dumps({
                "schema_version": 1, "package": "test.fixture", "version": "1.0.0",
                "agents": [f"agent-{i}" for i in range(7)],
                "workflows": [], "policies": [],
            }))
            manager = PackageManager(store, packages)
            installed = manager.install("fixture", "system", "admin")
            self.assertEqual(installed["package"], "test.fixture")
            self.assertEqual(len(installed["agent_ids"]), 7)
            agents = store.list_definitions("kernel_agents", "system")
            self.assertEqual(len(agents), 7)
            rolled_back = manager.rollback(installed["package_id"], "system", "admin")
            self.assertEqual(rolled_back["status"], "rolled_back")

    def test_artifact_store_is_tenant_scoped_and_detects_tampering(self):
        from nexus_core.kernel.artifacts import LocalArtifactStore

        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            artifacts = LocalArtifactStore(store, Path(directory) / "artifacts")
            artifact = artifacts.put("system", b"evidence", "text/plain")
            self.assertEqual(artifacts.get("system", artifact["id"]), b"evidence")
            with self.assertRaises(KeyError):
                artifacts.get("other", artifact["id"])
            path = artifacts.root / "system" / artifact["sha256"][:2] / artifact["sha256"]
            path.write_bytes(b"tampered")
            with self.assertRaises(RuntimeError):
                artifacts.get("system", artifact["id"])




    def test_memory_store_is_durable_scoped_and_searchable(self):
        from nexus_core.kernel.memory import MemoryStore

        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            memory = MemoryStore(store)
            memory.save_message(
                "system", "junior", "Junior", "user", "analiza la campaña",
                "session-1", retention_days=30,
            )
            memory.save_summary("system", "junior", "Campaña en análisis", "session-1", 1)
            self.assertEqual(len(memory.context("system", "junior", "session-1")), 1)
            self.assertEqual(len(memory.search("system", "junior", "campaña")), 1)
            self.assertEqual(memory.context("tenant-b", "junior"), [])
            self.assertEqual(
                memory.summary("system", "junior", "session-1"), "Campaña en análisis"
            )
            self.assertEqual(memory.clear("system", "junior", "session-1"), 1)

    def test_schema_migrations_upgrade_and_rollback(self):
        from nexus_core.kernel.migrations import Migration, MigrationRunner

        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            migration = Migration(
                50, "test_reversible", "CREATE TABLE migration_probe(id TEXT);",
                "DROP TABLE migration_probe;",
            )
            runner = MigrationRunner(store, (migration,))
            self.assertEqual(runner.upgrade(), [50])
            self.assertEqual(runner.upgrade(), [])
            with store.connect() as conn:
                self.assertIsNotNone(conn.execute(
                    "SELECT name FROM sqlite_master WHERE name='migration_probe'"
                ).fetchone())
            self.assertEqual(runner.downgrade(1), [50])
            with store.connect() as conn:
                self.assertIsNone(conn.execute(
                    "SELECT name FROM sqlite_master WHERE name='migration_probe'"
                ).fetchone())



if __name__ == "__main__":
    unittest.main()
