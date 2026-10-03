"""Shared fixtures for the Sliver bridge unit and gateway tests.

No team server is required: the underlying :class:`SliverClient` is replaced by
an :class:`AsyncMock`-backed double, mirroring ``msf_support.FakeClient``.
"""

from __future__ import annotations

from dataclasses import replace
from unittest.mock import AsyncMock

from nexus_core.integrations.sliver.client import SliverClient, SliverConfig
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.sessions import SessionRegistry
from nexus_core.tests import msf_support

#: Valid operator config path used by the fakes (the file itself is never read).
OPERATOR_CONFIG = "/tmp/nexus-sliver-operator.cfg"

#: A minimal, well-formed operator config for tests that exercise real parsing.
VALID_CONFIG_JSON = (
    '{"operator": "nexus", "lhost": "127.0.0.1", "lport": 31337,'
    ' "ca_certificate": "CA", "certificate": "CERT", "private_key": "KEY",'
    ' "token": "TOKEN"}'
)

scope = msf_support.scope
gateway = msf_support.gateway
gateway_with_approvals = msf_support.gateway_with_approvals


def context(engagement=None):
    return msf_support.context(engagement)


def session_record(
    session_id: str = "sess-1",
    *,
    remote_address: str = "203.0.113.10:4444",
    hostname: str = "victim",
    kind: str = "session",
) -> dict:
    return {
        "ID": session_id,
        "Name": f"{hostname}-{kind}",
        "Hostname": hostname,
        "Username": "root",
        "OS": "linux",
        "Arch": "amd64",
        "RemoteAddress": remote_address,
        "PID": 4001,
        "Filename": "/usr/bin/implant",
        "Transport": "mtls",
        "LastCheckin": "1700000000",
    }


class FakeSliverClient:
    """Async double with the same surface as ``SliverClient``."""

    def __init__(self, config: SliverConfig | None = None):
        self._config = config or SliverConfig.from_env()
        self.connect = AsyncMock()
        self.disconnect = AsyncMock()
        self.version = AsyncMock(
            return_value={
                "Major": 1,
                "Minor": 6,
                "Patch": 2,
                "Commit": "abc123",
                "OS": "linux",
                "Arch": "amd64",
            }
        )
        self.operators = AsyncMock(
            return_value=[{"Name": "nexus", "Online": True}]
        )
        self.list_jobs = AsyncMock(
            return_value=[{"ID": 1, "Name": "mtls", "Port": 8888}]
        )
        self.list_sessions = AsyncMock(return_value=[])
        self.list_beacons = AsyncMock(return_value=[])
        self.session_info = AsyncMock(return_value=None)
        self.beacon_info = AsyncMock(return_value=None)
        self.kill_session = AsyncMock(return_value={"session_id": "sess-1", "killed": True})
        self.kill_beacon = AsyncMock(return_value={"beacon_id": "beac-1", "killed": True})
        self.interact_session = AsyncMock(return_value=None)
        self.interact_beacon = AsyncMock(return_value=None)
        self.list_implant_builds = AsyncMock(return_value={})
        self.list_implant_profiles = AsyncMock(return_value=[])
        self.list_pivots = AsyncMock(return_value=[])
        self.start_portfwd = AsyncMock(
            return_value={"Port": 1080, "Protocol": 6, "Host": "10.0.0.5:8080"}
        )
        self.start_socks5 = AsyncMock(return_value={"TunnelID": 7, "SessionID": "sess-1"})
        self.stop_pivot = AsyncMock(return_value={"forward_id": 1, "stopped": True})
        self.close_socks5 = AsyncMock(return_value={"tunnel_id": 7, "closed": True})
        self.execute_command = AsyncMock(
            return_value={
                "session_id": "sess-1",
                "kind": "session",
                "command": "id",
                "status_code": 0,
                "stdout": "uid=0(root) gid=0(root)\n",
                "stderr": "",
                "pid": 42,
                "duration_seconds": 0.3,
            }
        )
        self.generate_implant = AsyncMock(
            return_value=(
                {
                    "name": "implant",
                    "filename": "implant",
                    "size": 4,
                    "sha256": "d34db33f",
                    "format": "executable",
                    "os": "linux",
                    "arch": "amd64",
                    "beacon": False,
                    "persistent": False,
                },
                b"\x7fELF",
            )
        )
        self.upload_file = AsyncMock(return_value={"path": "/tmp/implant"})
        self.execute_path = AsyncMock(
            return_value={
                "path": "/tmp/implant",
                "status_code": 0,
                "stdout": "",
                "stderr": "",
                "pid": 123,
            }
        )
        self.loot_list = AsyncMock(return_value=[])
        self.loot_get = AsyncMock(return_value={"Loot": []})
        self.loot_add_file = AsyncMock(return_value={})
        self.loot_add_credential = AsyncMock(return_value={})
        self.is_available = AsyncMock(return_value=True)

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *args):
        await self.disconnect()

    redact = SliverClient.redact


def fake_client(monkeypatch, *, operator_config: str = OPERATOR_CONFIG) -> FakeSliverClient:
    """Patch the client factory used by every Sliver handler."""
    from nexus_core.tools.handlers import sliver_common

    monkeypatch.setenv("SLIVER_OPERATOR_CONFIG", operator_config)
    client = FakeSliverClient(SliverConfig.from_env())
    monkeypatch.setattr(sliver_common, "SliverClient", lambda config: client)
    return client


def owned_context(tmp_path, *, register=()):
    """RunContext backed by a real ControlStore, with optional owned sessions."""
    store = ControlStore(tmp_path / "sliver-control.db")
    store.initialize()
    base = context(scope())
    run_context = replace(base, store=store)
    registry = SessionRegistry(store)
    for item in register:
        registry.register(
            session_uuid=item["id"],
            tenant_id="system",
            engagement_id=item.get("engagement_id", run_context.scope.engagement_id),
            run_id=item.get("run_id", run_context.run_id),
            session_type=item.get("session_type", "sliver:session"),
            target_host=item.get("target_host", "203.0.113.10"),
            opened_by_tool=item.get("opened_by_tool", "fixture"),
        )
    return run_context, store
