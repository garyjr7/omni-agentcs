"""F1: the AD tools reach a tunnelled target *from inside the handler*.

Measured in DeadDrop (2026-10-23): ``netexec``/``impacket`` do not speak SOCKS,
so the model wrapped them in ``proxychains4`` and ran them through
``nexus.shell.exec``. The DC answered and the verifier recorded **nothing**
(``grounded: 0``), because ``shell.exec`` derives no AD fact. These tests pin the
two halves of the fix: the wrapper lives in the handler, and the handler's own
parsed output still becomes an assertion.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.kernel.fact_verification import (
    derive_assertions,
    netexec_admin_accounts,
)
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import _proxy, impacket_psexec, impacket_secretsdump, netexec
from nexus_core.tools.handlers._proxy import (
    ensure_proxy_in_scope,
    parse_proxy,
    proxychains_config,
)

pytestmark = pytest.mark.unit

TARGET = "10.0.0.5"
PROXY = "socks5://127.0.0.1:1080"
PASSWORD = "synthetic-password"

#: Two real NetExec rows: a fingerprint and the admin marker.
PWN3D_SAMPLE = (
    "SMB         10.0.0.5  445    DC01    [*] Windows Server 2019 Build 17763\n"
    f"SMB         10.0.0.5  445    DC01    [+] DEADDROP\\synthetic-user:{PASSWORD} (Pwn3d!)\n"
)

SAM = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
PSEXEC_OUT = "Microsoft Windows [Version 10.0.17763.1]\nNT AUTHORITY\\SYSTEM\nflag{fake_flag}\n"


class FakeSandbox:
    """Records argv and answers with a fixed capture (never spawns anything)."""

    def __init__(self, result: SandboxResult):
        self.result = result
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append(list(argv))
        return self.result


@contextlib.contextmanager
def _sandbox(module, result: SandboxResult):
    sandbox = FakeSandbox(result)
    allowlists: list[tuple[str, ...]] = []

    def factory(workspace_root, resolved=None, *extra):
        allowlists.append(tuple(item for item in (resolved, *extra) if item))
        return sandbox

    with mock.patch.object(module, "ad_sandbox", factory):
        yield sandbox, allowlists


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    """A workspace plus a fake ``proxychains4`` the operator could have installed."""
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    binary = tmp_path / "bin" / "proxychains4"
    binary.parent.mkdir()
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setenv("NEXUS_PROXYCHAINS_BINARY", str(binary))
    return root, binary.resolve()


def _context() -> RunContext:
    return RunContext("system", Identity("op", "system", roles=("operator",)), run_id="run-f1")


def _assertion_context() -> SimpleNamespace:
    return SimpleNamespace(invocation_id="inv-f1", run_id="run-f1", tenant_id="system")


# --------------------------------------------------------------- proxy parsing


def test_a_loopback_socks_url_is_the_tunnel_the_run_used():
    proxy = parse_proxy(PROXY)
    assert (proxy.scheme, proxy.host, proxy.port) == ("socks5", "127.0.0.1", 1080)
    assert proxy.chain_type == "socks5"
    # The generated config is what proxychains reads; no secret can be in it.
    config = proxychains_config(proxy)
    assert "strict_chain" in config and "proxy_dns" in config
    assert "socks5 127.0.0.1 1080" in config
    assert "proxy_dns" in config


def test_the_scheme_decides_the_default_port():
    assert parse_proxy("socks5://127.0.0.1").port == 1080
    assert parse_proxy("http://10.0.0.5").port == 8080
    assert parse_proxy("socks5h://[::1]:9050").host == "::1"


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1:1080",  # no scheme: proxychains would run direct
        "ftp://127.0.0.1:1080",  # a scheme proxychains does not speak
        "socks5://user:pass@127.0.0.1:1080",  # would write a secret to the workspace
        "socks5://127.0.0.1:0",
        "socks5://127.0.0.1:1080/socket",
        "socks5://127.0.0.1:1080 --evil",
        "",
    ],
)
def test_a_proxy_that_is_not_a_tunnel_is_refused(value):
    with pytest.raises(ValueError):
        parse_proxy(value)


def test_only_loopback_escapes_the_scope_check():
    assert ensure_proxy_in_scope(parse_proxy(PROXY), None) is None
    with pytest.raises(ValueError):
        # A remote SOCKS address is a second destination and needs a signed
        # scope to be validated against.
        ensure_proxy_in_scope(parse_proxy("socks5://10.0.0.9:1080"), None)


# ------------------------------------------------------------- netexec (accept)


def test_netexec_wraps_itself_in_proxychains_and_keeps_the_parser(workspace):
    """Acceptance F1: proxy=… → a proxychains4 command with the parsed answer."""
    root, binary = workspace
    with _sandbox(netexec, SandboxResult(0, PWN3D_SAMPLE, "")) as (sandbox, allowlists):
        with mock.patch.object(netexec, "resolve_ad_binary", return_value="/opt/nxc"):
            result = asyncio.run(
                netexec.netexec_handler(
                    {
                        "protocol": "smb",
                        "target": TARGET,
                        "domain": "DEADDROP",
                        "username": "synthetic-user",
                        "password": PASSWORD,
                        "proxy": PROXY,
                    },
                    _context(),
                )
            )

    argv = sandbox.calls[0]
    assert argv[0] == str(binary)
    assert argv[1] == "-q"
    assert argv[argv.index("-f") + 1].startswith(_proxy.PROXYCHAINS_CONFIG_DIRNAME)
    # The real tool runs behind the wrapper, so its output is still parsed.
    assert "/opt/nxc" in argv
    assert argv.index("/opt/nxc") > argv.index("-f")
    config = (root / argv[argv.index("-f") + 1]).read_text(encoding="utf-8")
    assert "socks5 127.0.0.1 1080" in config
    # Both binaries are allowlisted: the sandbox never starts a program it was
    # not told about, and proxychains is the one that starts nxc.
    assert "/opt/nxc" in allowlists[0] and str(binary) in allowlists[0]
    assert result.verified is True
    assert result.evidence["proxy"] == {
        "type": "socks5", "host": "127.0.0.1", "port": 1080, "via": "proxychains4",
    }


def test_a_pwn3d_row_asserts_access_and_privilege(workspace):
    with _sandbox(netexec, SandboxResult(0, PWN3D_SAMPLE, "")):
        with mock.patch.object(netexec, "resolve_ad_binary", return_value="/opt/nxc"):
            result = asyncio.run(
                netexec.netexec_handler(
                    {
                        "protocol": "smb", "target": TARGET, "domain": "DEADDROP",
                        "username": "synthetic-user", "password": PASSWORD, "proxy": PROXY,
                    },
                    _context(),
                )
            )

    facts = derive_assertions(
        "nexus.recon.netexec",
        {"username": "synthetic-user", "password": PASSWORD, "domain": "DEADDROP"},
        result,
        _assertion_context(),
    )
    by_type = {fact["fact_type"]: fact for fact in facts}
    assert by_type["access"]["value"]["username"] == "synthetic-user"
    assert by_type["access"]["value"]["transport"] == "smb"
    assert by_type["privilege"]["value"]["account"] == "synthetic-user"
    assert by_type["privilege"]["value"]["domain"] == "DEADDROP"
    assert by_type["privilege"]["value"]["source"] == "netexec:pwn3d"
    assert by_type["credential"]["value"]["secret_ref"].startswith("vault:")
    # The marker was read from NetExec's own line, never typed by the model.
    assert all(fact["asserted_by"] == "verifier" for fact in facts)
    assert all(fact["invocation_id"] == "inv-f1" for fact in facts)
    # The password NetExec echoes is never copied into a fact.
    assert PASSWORD not in json.dumps(facts)


def test_a_row_without_the_marker_asserts_nothing():
    assert netexec_admin_accounts(
        [{"text": "DEADDROP\\synthetic-user:synthetic-password"}]
    ) == ()


def test_the_account_parser_reads_the_name_and_drops_the_secret():
    assert netexec_admin_accounts(
        [{"text": f"DEADDROP\\synthetic-user:{PASSWORD} (Pwn3d!)"}]
    ) == (("DEADDROP", "synthetic-user"),)
    # Host-local accounts have no domain part.
    assert netexec_admin_accounts([{"text": "Administrator:x (Pwn3d!)"}]) == (
        ("", "Administrator"),
    )


# ---------------------------------------------------------- impacket (tunnel)


def test_secretsdump_runs_behind_the_tunnel_and_records_the_accounts(workspace):
    root, binary = workspace
    (root / "sd_run-f1.sam").write_text(SAM, encoding="utf-8")
    with _sandbox(impacket_secretsdump, SandboxResult(0, "", "")) as (sandbox, _):
        with mock.patch.object(
            impacket_secretsdump, "resolve_impacket_binary", return_value="/opt/secretsdump.py"
        ):
            result = asyncio.run(
                impacket_secretsdump.impacket_secretsdump_handler(
                    {
                        "target": TARGET, "domain": "DEADDROP", "username": "Administrator",
                        "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                        "proxy": PROXY,
                    },
                    _context(),
                )
            )

    argv = sandbox.calls[0]
    assert argv[0] == str(binary) and "-f" in argv
    assert "/opt/secretsdump.py" in argv
    assert result.verified is True

    facts = derive_assertions(
        "nexus.attack.impacket_secretsdump",
        {"username": "Administrator", "domain": "DEADDROP"},
        result,
        _assertion_context(),
    )
    by_type = {fact["fact_type"]: fact for fact in facts}
    assert by_type["access"]["value"]["via"] == "secretsdump"
    assert by_type["credential"]["value"]["username"] == "Administrator"
    assert by_type["credential"]["value"]["hash_type"] == "ntlm"
    assert by_type["credential"]["value"]["secret_ref"].startswith("vault:")
    # RID 500 is the built-in administrator of the database that was dumped.
    assert by_type["privilege"]["value"]["source"] == "secretsdump:rid500"
    # The hash lives in the vault, never in the fact (V1-29).
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in json.dumps(facts)


def test_psexec_runs_behind_the_tunnel_and_records_system(workspace):
    _root, binary = workspace
    with _sandbox(impacket_psexec, SandboxResult(0, PSEXEC_OUT, "")) as (sandbox, _):
        with mock.patch.object(
            impacket_psexec, "resolve_impacket_binary", return_value="/opt/psexec.py"
        ):
            result = asyncio.run(
                impacket_psexec.impacket_psexec_handler(
                    {
                        "target": TARGET, "domain": "DEADDROP", "username": "Administrator",
                        "password": PASSWORD,
                        "command": r"type C:\Users\Administrator\Desktop\flag.txt",
                        "proxy": PROXY,
                    },
                    _context(),
                )
            )

    argv = sandbox.calls[0]
    assert argv[0] == str(binary) and "-f" in argv
    assert "/opt/psexec.py" in argv

    facts = derive_assertions(
        "nexus.attack.impacket_psexec",
        {"username": "Administrator", "domain": "DEADDROP",
         "command": r"type C:\Users\Administrator\Desktop\flag.txt"},
        result,
        _assertion_context(),
    )
    by_type = {fact["fact_type"]: fact for fact in facts}
    assert by_type["access"]["value"]["transport"] == "smb-exec"
    assert by_type["privilege"]["value"]["account"] == "SYSTEM"
    assert by_type["loot"]["value"]["flag"] == "flag{fake_flag}"
    assert by_type["loot"]["value"]["path"].endswith("flag.txt")


def test_a_missing_proxychains_is_a_determinate_unavailable(workspace, monkeypatch):
    monkeypatch.delenv("NEXUS_PROXYCHAINS_BINARY", raising=False)
    monkeypatch.setattr(_proxy.shutil, "which", lambda *args, **kwargs: None)
    with _sandbox(netexec, SandboxResult(0, PWN3D_SAMPLE, "")) as (sandbox, _):
        with mock.patch.object(netexec, "resolve_ad_binary", return_value="/opt/nxc"):
            result = asyncio.run(
                netexec.netexec_handler(
                    {"protocol": "smb", "target": TARGET, "proxy": PROXY}, _context()
                )
            )
    assert sandbox.calls == []  # nothing ran: the tunnel is not installed
    assert result.success is False
    assert result.outcome == "unavailable"
    assert result.verification_method == "proxychains_unavailable"
    assert "instala proxychains4" in result.output["guidance"].lower()


def test_the_ad_tunnel_order_travels_with_the_netexec_tool():
    """A ``proxy`` argument the catalog cannot show is a fix the model never uses.

    ``CATALOG_MAX_ARGUMENTS`` is 5, and ``proxy`` sorts after the required and
    enum arguments of every AD tool, so the only channel that reaches the model
    on a compact turn is the order itself. It travels with ``netexec``, the tool
    it is about, so a recon profile that cannot call it never reads the line.
    """
    from nexus_core.agent.prompts import AD_TUNNEL_RULE_PROMPT, render_system_prompt
    from nexus_core.tools.registry import durable_tool_definitions

    catalog = durable_tool_definitions("system")
    prompt = render_system_prompt(
        catalog=catalog, objective="x", engagement_id="eng-1", scope_summary="s"
    )
    assert AD_TUNNEL_RULE_PROMPT in prompt
    assert 'proxy="socks5://127.0.0.1:1080"' in prompt
    gated = {k: v for k, v in catalog.items() if k != "nexus.recon.netexec"}
    without = render_system_prompt(
        catalog=gated, objective="x", engagement_id="eng-1", scope_summary="s"
    )
    assert "TÚNEL A AD" not in without


def test_no_proxy_keeps_the_command_unchanged(workspace):
    with _sandbox(netexec, SandboxResult(0, PWN3D_SAMPLE, "")) as (sandbox, _):
        with mock.patch.object(netexec, "resolve_ad_binary", return_value="/opt/nxc"):
            result = asyncio.run(
                netexec.netexec_handler(
                    {"protocol": "smb", "target": TARGET}, _context()
                )
            )
    assert sandbox.calls[0][0] == "/opt/nxc"
    assert "proxy" not in result.evidence
    assert not os.path.exists(os.path.join(os.environ["NEXUS_WORKSPACE_ROOT"], ".proxychains"))
