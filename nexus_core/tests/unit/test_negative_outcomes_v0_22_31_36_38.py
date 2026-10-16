"""V0-22 / V0-31 / V0-36 / V0-38: un negativo legítimo es un resultado, no una avería.

Una tool que corrió y contestó «aquí no hay nada» llegaba al operador como
``RuntimeError("tool post-condition was not verified")``, exactamente igual que
una tool que no pudo mirar. Evidencia medida: RUN_sala09 (13
``smb_listing_failed`` + 7 invocaciones de ``nexus.recon.netexec``), RUN_sala10
(2 ``smb_shares_empty``, ``ntlm_capture_no_connection``, ``bloodhound_no_output``)
y RUN_sala07 (``wp_bruteforce`` sin credencial).

El contrato que fijan estos tests es el ya commiteado para V0-22: ``verified``
sigue respondiendo «se observó la post-condición pedida», y una respuesta
determinada se declara por ``outcome`` (``negative``/``denied``/``unsupported``),
que **completa** la invocación, **no deriva ninguna aserción** y queda auditada
con su motivo. Lo que el handler no sabe clasificar sigue fallando cerrado.

Dos casos por handler: el positivo (verificado, con su método positivo) y el
negativo legítimo (completa, declara su outcome y conserva su evidencia).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from unittest import mock

import pytest

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.kernel.models import Identity, RunContext, ToolDefinition
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.tools.handlers import bloodhound as bloodhound_module
from nexus_core.tools.handlers import listener as listener_module
from nexus_core.tools.handlers import netexec as netexec_module
from nexus_core.tools.handlers import smb as smb_module
from nexus_core.tools.handlers import wp as wp_module
from nexus_core.tools.handlers.bloodhound import bloodhound_handler
from nexus_core.tools.handlers.listener import listener_handler
from nexus_core.tools.handlers.netexec import netexec_handler
from nexus_core.tools.handlers.smb import smb_handler
from nexus_core.tools.handlers.wp import wp_bruteforce_handler

pytestmark = pytest.mark.unit

TARGET = "10.0.0.5"
RUN_ID = "run-v0-negs"
#: The real tool ids, so ``derive_assertions`` sees the contract under test and
#: not an anonymous probe.
NXC_TOOL = "nexus.recon.netexec"
SMB_TOOL = "nexus.recon.smb"
LISTENER_TOOL = "nexus.post.listener"
BH_TOOL = "nexus.recon.bloodhound_python"
WP_TOOL = "nexus.web.wp_bruteforce"
SMB_BINARY = "/usr/bin/smbclient"
NXC_BINARY = "/home/u/.local/bin/nxc"
BH_BINARY = "/home/u/.local/bin/bloodhound-python"

#: ``\\*\n``: the UNC wildcard smbclient echoes back in an NT_STATUS line.
SMB_UNC_WILDCARD = "\\\\" + "*" + "\n"

SMB_SHARES_OUTPUT = "\n".join(
    [
        "\tSharename       Type      Comment",
        "\t---------       ----      -------",
        "\tADMIN$          Disk      Remote Admin",
        "\tnt4wrksv        Disk      ",
    ]
)

#: Measured in RUN_sala10: netexec answers with the target's decision and a
#: non-zero exit (``0xc0000022`` = STATUS_ACCESS_DENIED, ``operationsError``
#: = the LDAP operation needs a completed bind).
NXC_SAMPLE = (
    "SMB         10.0.0.5       445    DC01    [*] Windows Server 2019 Build 17763\n"
    "SMB         10.0.0.5       445    DC01    [+] CORP\\svc:Passw0rd (Pwn3d!)\n"
)
NXC_DENIED = (
    "SMB         10.0.0.5       445    DC01    [-] CORP\\svc: 0xc0000022 STATUS_ACCESS_DENIED\n"
)
NXC_LDAP_BIND_REQUIRED = (
    "LDAP        10.0.0.5       389    DC01    [-] operationsError: bind must be completed\n"
)
NXC_UNCLASSIFIED = (
    "SMB         10.0.0.5       445    DC01    [-] answer nobody taught the handler\n"
)

WP_HIT_PAYLOAD = {
    "ok": True,
    "transport": "xmlrpc",
    "username": "admin",
    "tested": 2,
    "total": 2,
    "password": "right",
    "verification": {"ok": True, "xmlrpc": True, "wp_login": True},
    "elapsed_seconds": 0.5,
    "rate_per_second": 4.0,
    "errors": [],
}
WP_MISS_PAYLOAD = {
    **WP_HIT_PAYLOAD,
    "password": None,
    "verification": {"ok": False, "xmlrpc": False, "wp_login": False},
}


class _FakeSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30) -> SandboxResult:
        self.calls.append(list(argv))
        return self.result


def _context(run_id: str = RUN_ID) -> RunContext:
    return RunContext(
        "system", Identity("operator", "system", roles=("operator",)), run_id=run_id
    )


# --------------------------------------------------------------------------- #
# Harness: the real handlers, then the real gateway over their result
# --------------------------------------------------------------------------- #


@contextlib.contextmanager
def _smb_stubbed(result: SandboxResult):
    sandbox = _FakeSandbox(result)
    with mock.patch.object(smb_module, "ad_sandbox", lambda *a, **k: sandbox), mock.patch.object(
        smb_module, "resolve_ad_binary", lambda *a, **k: SMB_BINARY
    ):
        yield sandbox


@contextlib.contextmanager
def _nxc_stubbed(result: SandboxResult):
    sandbox = _FakeSandbox(result)
    with mock.patch.object(netexec_module, "ad_sandbox", lambda *a, **k: sandbox), mock.patch.object(
        netexec_module, "resolve_ad_binary", lambda *a, **k: NXC_BINARY
    ):
        yield sandbox


@contextlib.contextmanager
def _bh_stubbed(result: SandboxResult):
    sandbox = _FakeSandbox(result)
    with mock.patch.object(bloodhound_module, "ad_sandbox", lambda *a, **k: sandbox), mock.patch.object(
        bloodhound_module, "resolve_ad_binary", lambda *a, **k: BH_BINARY
    ):
        yield sandbox


@contextlib.contextmanager
def _listener_stubbed(result: SandboxResult, *, peer_in_scope: bool = True):
    sandbox = _FakeSandbox(result)
    with mock.patch.object(
        listener_module, "sandbox_for_environment", lambda *a, **k: sandbox
    ), mock.patch.object(listener_module, "validate_session_scope", lambda ctx: None), mock.patch.object(
        listener_module, "_peer_in_scope", lambda ctx, peer: peer_in_scope
    ):
        yield sandbox


@contextlib.contextmanager
def _wp_stubbed(result: SandboxResult):
    sandbox = _FakeSandbox(result)
    with mock.patch.object(wp_module, "sandbox_for_environment", lambda *a, **k: sandbox):
        yield sandbox


def _smb_run(stdout: str, arguments: dict, *, exit_code: int = 0) -> object:
    with _smb_stubbed(SandboxResult(exit_code, stdout, "")):
        return asyncio.run(smb_handler(arguments, _context()))


def _nxc_run(stdout: str, arguments: dict, *, exit_code: int = 0) -> object:
    with _nxc_stubbed(SandboxResult(exit_code, stdout, "")):
        return asyncio.run(netexec_handler(arguments, _context()))


def _bh_run(arguments: dict) -> object:
    with _bh_stubbed(SandboxResult(0, "", "")):
        return asyncio.run(bloodhound_handler(arguments, _context()))


def _listener_run(payload: dict, *, peer_in_scope: bool = True) -> object:
    handler = getattr(listener_handler, "__wrapped__", listener_handler)
    with _listener_stubbed(
        SandboxResult(0, json.dumps(payload) + "\n", ""), peer_in_scope=peer_in_scope
    ):
        return asyncio.run(handler({"port": 9001}, _context()))


def _wp_run(arguments: dict, payload: dict) -> object:
    with _wp_stubbed(SandboxResult(0, json.dumps(payload), "")):
        return asyncio.run(wp_bruteforce_handler(arguments, _context()))


def _gateway(tmp_path, result, tool_id: str = "probe"):
    """Register *result* behind a governed tool and return ``(store, gateway)``."""
    store = ControlStore(tmp_path / "audit.db")
    store.initialize()
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store))
    gateway.register(
        ToolDefinition("probe", "system", {}, tool_id=tool_id, effect="read_only"),
        lambda arguments, context: result,
    )
    return store, gateway


def _run_through_gateway(tmp_path, result, tool_id: str = "probe"):
    """Push *result* through the real gateway; returns ``(store, returned)``."""
    store, gateway = _gateway(tmp_path, result, tool_id)
    returned = asyncio.run(gateway.invoke(tool_id, {}, _context()))
    return store, returned


def _assert_positive_completes(tmp_path, result, *, tool_id: str) -> dict:
    assert result.verified is True
    assert result.success is True
    _, returned = _run_through_gateway(tmp_path, result, tool_id)
    assert returned["success"] is True
    assert returned["outcome"] == "success"
    return returned


def _assert_negative_completes(
    tmp_path, result, expected_outcome: str, *, tool_id: str
) -> dict:
    assert result.verified is False
    assert result.outcome == expected_outcome
    store, returned = _run_through_gateway(tmp_path, result, tool_id)
    assert returned["success"] is False
    assert returned["outcome"] == expected_outcome
    # Completing must not invent a single positive fact.
    assert returned["assertions"] == []
    invocation = InvocationJournal(store).get(returned["invocation_id"], "system")
    assert invocation["state"] == "succeeded"
    trail = AuditWriter(store).export("system")
    completed = next(row for row in trail if row["action"] == "tool.complete")
    assert completed["payload"]["outcome"] == expected_outcome
    assert [row for row in trail if row["action"] == "tool.failed"] == []
    return returned


# --------------------------------------------------------------------------- #
# V0-31 · nexus.recon.netexec
# --------------------------------------------------------------------------- #


def test_netexec_positive_run_is_verified(tmp_path):
    result = _nxc_run(
        NXC_SAMPLE,
        {"protocol": "smb", "target": TARGET, "operation": "shares"},
        exit_code=0,
    )
    assert result.verification_method == "netexec_text_parsed"
    assert result.output["count"] == 2
    _assert_positive_completes(tmp_path, result, tool_id=NXC_TOOL)


def test_netexec_denied_answer_completes_as_denied(tmp_path):
    """``0xc0000022`` with a non-zero exit is the target's answer, not a crash."""
    result = _nxc_run(
        NXC_DENIED,
        {"protocol": "smb", "target": TARGET, "operation": "shares"},
        exit_code=2,
    )
    assert result.verification_method == "netexec_text_parsed"
    assert result.evidence["nt_status"] == "0xc0000022"
    assert "0xc0000022" in result.evidence["reason"]
    _assert_negative_completes(tmp_path, result, "denied", tool_id=NXC_TOOL)


def test_netexec_ldap_bind_required_completes_as_denied(tmp_path):
    result = _nxc_run(
        NXC_LDAP_BIND_REQUIRED,
        {"protocol": "ldap", "target": TARGET, "operation": "users"},
        exit_code=2,
    )
    assert result.evidence["nt_status"] == "operationsError"
    _assert_negative_completes(tmp_path, result, "denied", tool_id=NXC_TOOL)


def test_netexec_unclassified_answer_still_fails_closed(tmp_path):
    result = _nxc_run(NXC_UNCLASSIFIED, {"protocol": "smb", "target": TARGET}, exit_code=2)
    assert result.outcome == ""
    with pytest.raises(RuntimeError, match="post-condition"):
        _run_through_gateway(tmp_path, result, NXC_TOOL)


# --------------------------------------------------------------------------- #
# V0-31 / V0-36 · nexus.recon.smb
# --------------------------------------------------------------------------- #


def test_smb_share_listing_is_verified(tmp_path):
    result = _smb_run(SMB_SHARES_OUTPUT, {"target": TARGET, "action": "shares"})
    assert result.verification_method == "smb_shares_parsed"
    names = {share["name"] for share in result.output["shares"]}
    assert {"ADMIN$", "nt4wrksv"} <= names
    _assert_positive_completes(tmp_path, result, tool_id=SMB_TOOL)


def test_smb_path_that_does_not_exist_completes_as_unsupported(tmp_path):
    """V0-31 measured case: listing a missing path is an answer, not a fault."""
    result = _smb_run(
        "NT_STATUS_OBJECT_NAME_NOT_FOUND listing " + SMB_UNC_WILDCARD,
        {"target": TARGET, "share": "nt4wrksv", "action": "list"},
    )
    assert result.verification_method == "smb_listing_failed"
    assert result.evidence["nt_status"] == "NT_STATUS_OBJECT_NAME_NOT_FOUND"
    _assert_negative_completes(tmp_path, result, "unsupported", tool_id=SMB_TOOL)


def test_smb_empty_share_list_completes_as_negative(tmp_path):
    """V0-36 measured case: anonymous access lists nothing."""
    result = _smb_run("", {"target": TARGET, "action": "shares"})
    assert result.verification_method == "smb_shares_empty"
    assert result.evidence["count"] == 0
    _assert_negative_completes(tmp_path, result, "negative", tool_id=SMB_TOOL)


# --------------------------------------------------------------------------- #
# V0-36 · nexus.post.listener (el catcher, hermano de ntlm_capture)
# --------------------------------------------------------------------------- #


def _catch_payload(peer: str = "203.0.113.10") -> dict:
    return {
        "ok": True,
        "bound": True,
        "peer": peer,
        "port": 9001,
        "commands_sent": ["id"],
        "status": "closed",
        "bytes": 42,
        "sha256": "a" * 64,
        "transcript": "uid=33(www-data) gid=33(www-data)\n",
        "truncated": False,
        "elapsed_ms": 1200,
    }


def test_listener_catch_is_verified(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path / "ws"))
    (tmp_path / "ws").mkdir()
    result = _listener_run(_catch_payload())
    assert result.verification_method == "listener_session_captured"
    assert result.evidence["peer"] == "203.0.113.10"
    _assert_positive_completes(tmp_path, result, tool_id=LISTENER_TOOL)


def test_listener_without_connection_completes_as_negative(tmp_path):
    """A catch nobody took is a determinate answer about the target (V0-36)."""
    result = _listener_run(
        {
            "ok": False,
            "bound": True,
            "port": 9001,
            "listened_seconds": 5,
            "error": "no connection within timeout",
        }
    )
    assert result.verification_method == "listener_no_connection"
    assert result.evidence["bound"] is True
    assert result.evidence["listened_seconds"] == 5
    assert result.evidence["reason"] == "no connection within timeout"
    _assert_negative_completes(tmp_path, result, "negative", tool_id=LISTENER_TOOL)


def test_listener_bind_failure_still_fails_closed(tmp_path):
    """Could not offer the service at all: a failure of the body, not an answer."""
    result = _listener_run(
        {"ok": False, "bound": False, "port": 9001, "error": "OSError: address in use"}
    )
    assert result.verification_method == "listener_bind_failed"
    assert result.outcome == ""
    with pytest.raises(RuntimeError, match="post-condition"):
        _run_through_gateway(tmp_path, result, LISTENER_TOOL)


# --------------------------------------------------------------------------- #
# V0-38 · nexus.recon.bloodhound_python
# --------------------------------------------------------------------------- #


def test_bloodhound_collection_is_verified(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / f"bh_{RUN_ID}_users.json").write_text('[{"name": "a"}]', encoding="utf-8")
    result = _bh_run({"domain": "corp.local", "dc": "10.0.0.10"})
    assert result.verification_method == "bloodhound_json_parsed"
    assert result.output["file_count"] == 1
    _assert_positive_completes(tmp_path, result, tool_id=BH_TOOL)


def test_bloodhound_without_output_completes_with_collected_zero(tmp_path, monkeypatch):
    """V0-38: nothing to collect is a negative with ``collected=0``."""
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path / "ws"))
    (tmp_path / "ws").mkdir()
    result = _bh_run({"domain": "corp.local", "dc": "10.0.0.10"})
    assert result.verification_method == "bloodhound_no_output"
    assert result.evidence["collected"] == 0
    assert result.evidence["file_count"] == 0
    assert result.evidence["reason"]
    _assert_negative_completes(tmp_path, result, "negative", tool_id=BH_TOOL)


# --------------------------------------------------------------------------- #
# V0-22 · nexus.web.wp_bruteforce
# --------------------------------------------------------------------------- #


@pytest.fixture
def wordlist(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / "words.txt").write_text("wrong\nright\n", encoding="utf-8")
    return tmp_path


def test_wp_bruteforce_validated_credential_is_verified(wordlist):
    result = _wp_run(
        {
            "url": "http://internal.thm/blog",
            "username": "admin",
            "password_file": "words.txt",
        },
        WP_HIT_PAYLOAD,
    )
    assert result.verification_method == "wp_credential_validated"
    assert result.evidence["credentials_found"] == 1
    returned = _assert_positive_completes(wordlist, result, tool_id=WP_TOOL)
    # The positive path keeps promoting the credential it proved -and only the
    # credential: a validated wp-admin password is not a session (V1-31).
    kinds = {row["fact_type"] for row in returned["assertions"]}
    assert "credential" in kinds
    assert "access" not in kinds


def test_wp_bruteforce_exhausted_sweep_completes_as_negative(wordlist):
    """V0-22: tried every candidate and validated none is an answer, not a fault."""
    result = _wp_run(
        {
            "url": "http://internal.thm/blog",
            "username": "admin",
            "password_file": "words.txt",
        },
        WP_MISS_PAYLOAD,
    )
    assert result.verification_method == "wp_credential_validated"
    assert result.output["valid_credentials"] == []
    assert result.evidence["credentials_found"] == 0
    assert result.evidence["reason"]
    _assert_negative_completes(wordlist, result, "negative", tool_id=WP_TOOL)
