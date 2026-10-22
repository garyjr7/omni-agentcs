"""Tanda B, Fix 2: the engine resolves a board credential for the Windows channels.

Measured problem: ``nexus.post.ssh_exec`` completes its own transport from the
board (port and credential) and the two Windows channels did not. A run that had
already proved ``CORP\\svc`` on SMB had to retype the password for ``winrm_exec``
-every turn- or watch ``netexec`` run an anonymous fingerprint it had not asked
for. The engine now answers the same question with one module
(``kernel.credentials``), and the three cases are distinguished by *fact*:
exactly one handle resolves, zero and several refuse with the list in hand.
"""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.cli.engage import build_scope
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.credentials import (
    available_credentials,
    credential_entries,
    protocol_matches,
    resolve_credential_for,
)
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.kernel.secret_store import default_secret_store
from nexus_core.scope import EngagementStore
from nexus_core.tools.handlers import netexec as netexec_module
from nexus_core.tools.handlers import winrm as winrm_module
from nexus_core.tools.handlers.netexec import netexec_handler
from nexus_core.tools.handlers.winrm import winrm_exec_handler

pytestmark = pytest.mark.unit

SECRET = "test-signing-secret"
TARGET = "10.10.10.5"
TENANT = "system"
PASSWORD = "uzunLM+3131"

WINRM_SAMPLE = (
    "WINRM   10.10.10.5   5985   FIRE   [*] Windows Server 2019 Build 17763 (name:FIRE)\n"
    "WINRM   10.10.10.5   5985   FIRE   [+] CORP\\svc:uzunLM+3131 (Pwn3d!)\n"
    "WINRM   10.10.10.5   5985   FIRE   [+] Executed command (shell type: cmd)\n"
    "WINRM   10.10.10.5   5985   FIRE   corp\\svc\n"
)

NETEXEC_SAMPLE = (
    "SMB         10.10.10.5      445    DC01    [*] Windows Server 2019 Build 17763\n"
    "SMB         10.10.10.5      445    DC01    [+] CORP\\svc:uzunLM+3131 (Pwn3d!)\n"
    "SMB         10.10.10.5      445    DC01    Share           READ,WRITE      Desc\n"
)


class _FakeSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append(list(argv))
        return self.result


@contextlib.contextmanager
def _winrm_sandbox():
    sandbox = _FakeSandbox(SandboxResult(0, WINRM_SAMPLE, ""))
    with mock.patch.object(winrm_module, "ad_sandbox", lambda *a, **k: sandbox):
        with mock.patch.object(
            winrm_module, "resolve_ad_binary", return_value="/home/u/.local/bin/nxc"
        ):
            yield sandbox


@contextlib.contextmanager
def _netexec_sandbox():
    sandbox = _FakeSandbox(SandboxResult(0, NETEXEC_SAMPLE, ""))
    with mock.patch.object(netexec_module, "ad_sandbox", lambda *a, **k: sandbox):
        with mock.patch.object(
            netexec_module, "resolve_ad_binary", return_value="/home/u/.local/bin/nxc"
        ):
            yield sandbox


@pytest.fixture()
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_SCOPE_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    store = ControlStore(tmp_path / "board.db")
    store.initialize()
    scope = EngagementStore(store).create(build_scope("bench", f"{TARGET}/32", SECRET))
    return RunContext(
        TENANT,
        Identity("operator-1", TENANT, roles=("operator",)),
        store=store,
        scope=scope,
    )


def _handle(secret: str = PASSWORD, kind: str = "winrm") -> str:
    return default_secret_store().put(
        secret.encode("utf-8"), kind=kind, tenant_id=TENANT
    )


def _record(
    context: RunContext,
    key: str,
    *,
    username: str = "svc",
    service: str = "winrm",
    handle: str | None = None,
    host: str = TARGET,
) -> str:
    ref = handle or _handle()
    Blackboard(context.store).record(
        tenant_id=TENANT,
        engagement_id=context.engagement_id,
        fact_type="credential",
        key=key,
        value={"username": username, "secret_ref": ref, "service": service},
        source="nexus.cred.bruteforce",
        created_by="verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="cred_bruteforce_completed",
        invocation_id="inv-1",
    )
    assert host  # the host is carried by the key, as the producers write it
    return ref


# --------------------------------------------------------------- resolution API


def test_protocol_matching_keeps_ssh_and_windows_apart():
    # A password proved on SMB is the same AD account for WinRM/LDAP/RDP.
    assert protocol_matches("smb", "winrm")
    assert protocol_matches("winrm", "smb")
    # SSH is its own corpus; a web login is another one.
    assert not protocol_matches("ssh", "winrm")
    assert not protocol_matches("winrm", "ssh")
    assert not protocol_matches("http-post-form", "winrm")
    # An empty service is unknown provenance, not a mismatch: the board has
    # carried credentials without a service since before ``service`` existed.
    assert protocol_matches("", "winrm")
    assert protocol_matches("winrm", "")


def test_exactly_one_candidate_resolves(context):
    ref = _record(context, f"cred:winrm:svc@{TARGET}")
    resolved = resolve_credential_for(TARGET, "svc", "winrm", context=context)
    assert resolved is not None
    assert resolved.handle == ref
    assert resolved.password == PASSWORD
    assert resolved.source_fact_id == f"cred:winrm:svc@{TARGET}"
    assert resolved.evidence_note() == f"credential_ref resuelto por el motor: {ref}"


def test_two_candidates_are_an_ambiguity_not_a_guess(context):
    _record(context, f"cred:winrm:svc@{TARGET}", handle=_handle("first-secret"))
    _record(context, f"cred:smb:svc@{TARGET}", service="smb", handle=_handle("second-secret"))
    assert resolve_credential_for(TARGET, "svc", "winrm", context=context) is None


def test_a_credential_without_a_handle_is_never_injected(context):
    Blackboard(context.store).record(
        tenant_id=TENANT,
        engagement_id=context.engagement_id,
        fact_type="credential",
        key=f"cred:winrm:svc@{TARGET}",
        value={"username": "svc", "password": "plain-on-the-board"},
        source="nexus.knowledge.record_fact",
        created_by="agent",
    )
    assert resolve_credential_for(TARGET, "svc", "winrm", context=context) is None


# ------------------------------------------------------------------- winrm_exec


def test_winrm_resolves_the_single_board_credential(context):
    ref = _record(context, f"cred:winrm:svc@{TARGET}")
    with _winrm_sandbox() as sandbox:
        result = asyncio.run(
            winrm_exec_handler(
                {"target": TARGET, "username": "svc", "command": "whoami"}, context
            )
        )
    argv = sandbox.calls[0]
    # The plaintext never came from the model: the engine read it from the vault.
    assert argv[argv.index("-p") + 1] == PASSWORD
    assert result.verified is True
    note = f"credential_ref resuelto por el motor: {ref}"
    assert result.evidence["credential"] == note
    assert result.output["credential"] == note


def test_winrm_without_a_credential_lists_what_the_board_has(context):
    with pytest.raises(ValueError) as excinfo:
        asyncio.run(
            winrm_exec_handler(
                {"target": TARGET, "username": "svc", "command": "whoami"}, context
            )
        )
    message = str(excinfo.value)
    assert "no winrm credential for svc@10.10.10.5" in message
    assert "credential_ref" in message
    # The call never reached the sandbox: nothing ran.
    assert "no usable handle" in message


def test_winrm_with_two_credentials_asks_which_one(context):
    first = _record(context, f"cred:winrm:svc@{TARGET}", handle=_handle("first-secret"))
    second = _record(context, f"cred:smb:svc@{TARGET}", service="smb", handle=_handle("second-secret"))
    with _winrm_sandbox() as sandbox:
        with pytest.raises(ValueError) as excinfo:
            asyncio.run(
                winrm_exec_handler(
                    {"target": TARGET, "username": "svc", "command": "whoami"}, context
                )
            )
    message = str(excinfo.value)
    assert "2 credentials" in message
    assert first in message and second in message
    assert "credential_ref" in message
    assert sandbox.calls == []


def test_winrm_accepts_a_manual_password_without_reading_the_board(context):
    with _winrm_sandbox() as sandbox:
        result = asyncio.run(
            winrm_exec_handler(
                {
                    "target": TARGET,
                    "username": "svc",
                    "password": PASSWORD,
                    "command": "whoami",
                },
                context,
            )
        )
    assert "credential" not in result.evidence
    assert sandbox.calls[0][sandbox.calls[0].index("-p") + 1] == PASSWORD


# ---------------------------------------------------------------- nexus.recon.netexec


def test_netexec_resolves_the_single_board_credential(context):
    ref = _record(context, f"cred:smb:svc@{TARGET}", service="smb")
    with _netexec_sandbox() as sandbox:
        result = asyncio.run(
            netexec_handler(
                {"protocol": "smb", "target": TARGET, "username": "svc",
                 "operation": "shares"},
                context,
            )
        )
    argv = sandbox.calls[0]
    assert argv[argv.index("-p") + 1] == PASSWORD
    assert result.evidence["credential"] == f"credential_ref resuelto por el motor: {ref}"


def test_netexec_without_a_credential_lists_what_the_board_has(context):
    with pytest.raises(ValueError) as excinfo:
        asyncio.run(
            netexec_handler(
                {"protocol": "smb", "target": TARGET, "username": "svc"}, context
            )
        )
    assert "no smb credential for svc@10.10.10.5" in str(excinfo.value)


def test_netexec_with_two_credentials_asks_which_one(context):
    first = _record(context, f"cred:smb:svc@{TARGET}", service="smb",
                    handle=_handle("first-secret"))
    second = _record(context, f"cred:winrm:svc@{TARGET}", service="winrm",
                     handle=_handle("second-secret"))
    with pytest.raises(ValueError) as excinfo:
        asyncio.run(
            netexec_handler(
                {"protocol": "smb", "target": TARGET, "username": "svc"}, context
            )
        )
    message = str(excinfo.value)
    assert first in message and second in message


def test_netexec_without_a_username_stays_the_anonymous_probe(context):
    # No identity in the call: there is nothing to resolve, and injecting an
    # account would turn a fingerprint into a logged-in sweep.
    _record(context, f"cred:smb:svc@{TARGET}", service="smb")
    with _netexec_sandbox() as sandbox:
        result = asyncio.run(
            netexec_handler({"protocol": "smb", "target": TARGET}, context)
        )
    assert "-p" not in sandbox.calls[0]
    assert "credential" not in result.evidence


# ----------------------------------------------------------- prompt block (2.3)


def test_available_credentials_limits_to_three_per_host_and_counts_the_rest(context):
    for index in range(5):
        _record(
            context,
            f"cred:smb:user{index}@{TARGET}",
            username=f"user{index}",
            service="smb",
            handle=_handle(f"secret-{index}"),
        )
    entries = available_credentials(context)
    assert len(entries) == 3
    # Newest first, and the last line says how many are not shown.
    assert entries[-1]["extra"] == 2
    assert [entry["username"] for entry in entries][:3] == ["user4", "user3", "user2"]
    assert all(entry["host"] == TARGET for entry in entries)


def test_credential_entries_never_carry_the_plaintext(context):
    ref = _record(context, f"cred:winrm:svc@{TARGET}")
    for entry in credential_entries(context):
        assert entry["handle"] == ref
        assert PASSWORD not in str(entry)


def test_the_prompt_shows_one_credential_and_the_count_of_the_rest():
    from nexus_core.agent.prompts import (
        AVAILABLE_CREDENTIALS_HEADER,
        render_available_credentials,
    )

    one = render_available_credentials(
        [{"host": TARGET, "handle": "vault:" + "a" * 32,
          "username": "svc", "protocol": "smb"}]
    )
    assert AVAILABLE_CREDENTIALS_HEADER in one
    assert f"- `{TARGET}`: `vault:{'a' * 32}` (username=`svc`, protocol=`smb`)" in one

    five = render_available_credentials(
        [
            {"host": TARGET, "handle": "vault:" + str(index).rjust(32, "0"),
             "username": f"user{index}", "protocol": "smb",
             **({"extra": 2} if index == 2 else {})}
            for index in range(3)
        ]
    )
    assert five.count(f"- `{TARGET}`:") == 3
    assert "… y 2 más" in five
    assert render_available_credentials([]) == ""
