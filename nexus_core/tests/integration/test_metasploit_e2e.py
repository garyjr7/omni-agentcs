"""Opt-in real RPC tests. Only smb_version sends traffic to scanme.nmap.org."""

import asyncio
import os
from pathlib import Path
import socket

from dotenv import load_dotenv
import pytest

from nexus_core.integrations.metasploit.client import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitUnavailable,
)
from nexus_core.scope import ScopeViolation
from nexus_core.tests.msf_support import context, gateway, scope

ENABLED = os.getenv("NEXUS_E2E") == "1"
if ENABLED:
    load_dotenv(Path(__file__).resolve().parents[3] / ".env", override=False)

pytestmark = pytest.mark.skipif(
    not ENABLED or not os.getenv("MSF_RPC_PASSWORD"),
    reason="requires NEXUS_E2E=1 and MSF_RPC_PASSWORD",
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


def test_e2e_search_ms17_010_finds_eternalblue(tmp_path):
    gw, _ = gateway(tmp_path)
    result = asyncio.run(
        gw.invoke(
            "nexus.exploit.msf_search",
            {"query": "ms17-010", "limit": 100},
            context(),
        )
    )
    assert result["verified"]
    assert any("eternalblue" in module["fullname"] for module in result["output"]["modules"])


def test_e2e_auxiliary_smb_version_scanme(tmp_path):
    host = "scanme.nmap.org"
    # Authorize only addresses actually resolved for the explicitly requested test host.
    addresses = {info[4][0] for info in socket.getaddrinfo(host, 445, type=socket.SOCK_STREAM)}
    engagement = scope(tuple(f"{ip}/{'128' if ':' in ip else '32'}" for ip in addresses), (host,))
    gw, _ = gateway(tmp_path)
    result = asyncio.run(
        gw.invoke(
            "nexus.exploit.msf_auxiliary",
            {
                "module": "auxiliary/scanner/smb/smb_version",
                "target": host,
                "options": {"THREADS": 1, "RPORT": 445},
                "timeout_seconds": 60,
            },
            context(engagement),
        )
    )
    assert result["verified"]
    assert result["output"]["status"] == "completed"
    assert result["output"]["uuid"]
    # Completed does not assert that scanme offers SMB or is vulnerable.


def test_e2e_out_of_scope_denied_with_audit(tmp_path):
    gw, audit = gateway(tmp_path)
    with pytest.raises(ScopeViolation):
        asyncio.run(
            gw.invoke(
                "nexus.exploit.msf_auxiliary",
                {
                    "module": "auxiliary/scanner/smb/smb_version",
                    "target": "8.8.8.8",
                },
                context(scope()),
            )
        )
    denied = [event for event in audit.export("system") if event["action"] == "scope.denied"]
    assert len(denied) == 1 and denied[0]["decision"] == "deny"
