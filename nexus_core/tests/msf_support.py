"""Shared fixtures for RPC unit tests and durable gateway integration tests."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

from nexus_core.integrations.metasploit.client import MetasploitClient, MetasploitConfig
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.scope import EngagementScope
from nexus_core.scope.validator import make_scope_validator
from nexus_core.tools.registry import register_durable_tools


def scope(cidrs=("203.0.113.0/24",), domains=()):
    now = datetime.now(timezone.utc)
    return EngagementScope(
        engagement_id="eng-msf-test",
        tenant_id="system",
        name="MSF test",
        client="test",
        owner_id="operator",
        cidrs=cidrs,
        domains=domains,
        urls=(),
        exclusions=(),
        valid_from=(now - timedelta(hours=1)).isoformat(),
        valid_until=(now + timedelta(hours=1)).isoformat(),
        created_at=now.isoformat(),
    )


def context(engagement=None):
    return RunContext(
        "system", Identity("operator", "system", roles=("operator",)), scope=engagement
    )


def gateway(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    audit = AuditWriter(store)
    result = ToolGateway(PolicyEngine(), audit, scope_validator=make_scope_validator())
    register_durable_tools(result)
    return result, audit


class FakeClient:
    def __init__(self, config):
        self._config = config
        self._token = "fixture-token"
        self.authenticate = AsyncMock()
        self.aclose = AsyncMock()
        self.is_available = AsyncMock(return_value=True)
        self.search_modules = AsyncMock(
            return_value=[
                {
                    "fullname": "exploit/windows/smb/ms17_010_eternalblue",
                    "name": "EternalBlue",
                }
            ]
        )
        self.execute_module = AsyncMock(return_value={"job_id": 42, "uuid": "fixture-uuid"})
        self.get_module_results = AsyncMock(return_value={"status": "completed", "result": {}})
        self.stop_job = AsyncMock()
        self.get_module_options = AsyncMock(return_value={})
        self.list_sessions = AsyncMock(return_value={})
        self.stop_session = AsyncMock(return_value={"result": "success"})
        self.execute_exploit = AsyncMock(
            return_value={
                "status": "timeout",
                "module": "exploit/multi/handler",
                "job_id": 42,
                "job_uuid": "fixture-uuid",
                "duration_seconds": 0.5,
            }
        )

    async def __aenter__(self):
        await self.authenticate()
        return self

    async def __aexit__(self, *args):
        await self.aclose()

    redact = MetasploitClient.redact


def fake_client(monkeypatch, module):
    monkeypatch.setenv("MSF_RPC_PASSWORD", "fixture-credential")
    monkeypatch.setenv("MSF_RPC_TRANSPORT", "msgpack")
    client = FakeClient(MetasploitConfig.from_env())
    monkeypatch.setattr(module, "MetasploitClient", lambda config: client)
    return client
