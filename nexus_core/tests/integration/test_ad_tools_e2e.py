"""Opt-in sandbox checks for the AD binaries used by the new tools.

Gated behind ``NEXUS_E2E=1``. No target is contacted: each binary is invoked
with its help flag only. The point is to prove the pipx-installed scripts
(which live outside the sandbox PATH) resolve to an absolute path and execute
inside the real sandbox allowlist.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from nexus_core.kernel.sandbox import LocalSandbox
from nexus_core.tools.handlers._ad import resolve_ad_binary
from nexus_core.tools.handlers._impacket_resolver import resolve_impacket_binary

pytestmark = pytest.mark.skipif(
    os.getenv("NEXUS_E2E") != "1", reason="requires NEXUS_E2E=1"
)


def _cases():
    return [
        ("netexec", "nxc", resolve_ad_binary("nxc", "netexec"), ["nxc", "smb", "--help"]),
        (
            "bloodhound",
            "bloodhound-python",
            resolve_ad_binary("bloodhound-python", "bloodhound.py"),
            ["bloodhound-python", "--help"],
        ),
        (
            "secretsdump",
            "secretsdump",
            resolve_impacket_binary("secretsdump"),
            ["secretsdump", "-h"],
        ),
        (
            "getuserspns",
            "GetUserSPNs",
            resolve_impacket_binary("GetUserSPNs"),
            ["GetUserSPNs", "-h"],
        ),
        ("psexec", "psexec", resolve_impacket_binary("psexec"), ["psexec", "-h"]),
    ]


@pytest.mark.parametrize("name,binary_key,resolved,argv", _cases())
def test_ad_binary_runs_help_in_sandbox(tmp_path, name, binary_key, resolved, argv):
    if not resolved:
        pytest.skip(f"{name} binary is not installed")
    # argv[0] must be the absolute pipx path so the restricted PATH cannot hide it.
    real_argv = [resolved, *argv[1:]]
    sandbox = LocalSandbox(tmp_path, allowed_programs=(resolved,))
    result = asyncio.run(sandbox.run(real_argv, timeout_seconds=30))
    output = (result.stdout + result.stderr).lower()
    assert result.exit_code == 0, f"{name} help failed: {result.stderr[:400]}"
    assert "usage" in output or "impacket" in output


def test_resolvers_find_pipx_scripts():
    for name, binary_key, resolved, _ in _cases():
        if resolved is not None:
            assert os.path.isabs(resolved)
            assert os.path.exists(resolved)
