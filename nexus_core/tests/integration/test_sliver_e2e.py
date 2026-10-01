"""Opt-in end-to-end tests for the Sliver bridge.

Gated behind ``NEXUS_E2E=1`` **and** a usable ``SLIVER_OPERATOR_CONFIG`` **and**
a team server actually listening on ``SLIVER_LHOST:SLIVER_LPORT``. Nothing is
installed or started here: if the server is absent every test skips with a
reason instead of failing.
"""

from __future__ import annotations

import asyncio
import os
import socket
from pathlib import Path

from dotenv import load_dotenv
import pytest

from nexus_core.integrations.sliver.client import SliverClient, SliverConfig
from nexus_core.tests.sliver_support import context
from nexus_core.tools.handlers import sliver_server, sliver_sessions

ENABLED = os.getenv("NEXUS_E2E") == "1"
if ENABLED:
    load_dotenv(Path(__file__).resolve().parents[3] / ".env", override=False)


def _config() -> SliverConfig | None:
    try:
        config = SliverConfig.from_env()
    except ValueError:
        return None
    if not config.operator_config or not Path(config.operator_config).is_file():
        return None
    return config


def _server_reachable() -> bool:
    config = _config()
    if config is None:
        return False
    try:
        with socket.create_connection((config.lhost, config.lport), timeout=0.5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not ENABLED or not _server_reachable(),
    reason="requires NEXUS_E2E=1, SLIVER_OPERATOR_CONFIG and a reachable team server",
)


def test_e2e_server_version():
    result = asyncio.run(sliver_server.sliver_server_handler({}, context()))
    assert result.success and result.verified
    assert result.verification_method == "sliver_server_ok"
    assert result.output["version"]


def test_e2e_list_sessions(tmp_path):
    from dataclasses import replace

    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.tests.sliver_support import scope

    store = ControlStore(tmp_path / "sliver-e2e.db")
    store.initialize()
    run_context = replace(context(scope()), store=store)
    result = asyncio.run(
        sliver_sessions.sliver_sessions_handler({"kind": "both"}, run_context)
    )
    assert result.success and result.verified
    assert result.verification_method == "sliver_sessions_listed"
    assert isinstance(result.output["sessions"], list)
    assert isinstance(result.output["beacons"], list)


def test_e2e_exec_against_local_session():
    config = _config()
    assert config is not None

    async def _run() -> dict | None:
        client = SliverClient(config)
        try:
            await client.connect()
            sessions = await client.list_sessions()
            beacons = await client.list_beacons()
            if not sessions and not beacons:
                return None
            kind, target = (
                ("session", sessions[0]["ID"])
                if sessions
                else ("beacon", beacons[0]["ID"])
            )
            return await client.execute_command(target, "whoami", kind=kind)
        finally:
            await client.disconnect()

    raw = asyncio.run(_run())
    if raw is None:
        pytest.skip("team server has no sessions or beacons to execute against")
    assert raw["status_code"] == 0
    assert raw["stdout"] or raw["stderr"]
