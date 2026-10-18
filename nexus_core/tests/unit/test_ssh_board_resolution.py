"""The SSH handlers complete their own transport from the engagement board.

Measured in the Simple CTF runs of 2026-10-17 (target ``10.64.128.102``, sshd on
2222): the engine had already proved the port (a verified ``service`` fact) and
the password (an authenticated session), yet the model had to retype both on
every turn. Its last three turns were a rejected call for omitting the
credential, a 20 s timeout against port 22 and a hand-typed ``sshpass`` line -
three consecutive failures that aborted the run with the flag one command away.

These tests pin what the engine now does by itself, and what it still refuses to
guess.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.scope import EngagementScope
from nexus_core.tools.handlers import ssh_post as module
from nexus_core.tools.handlers.ssh_post import (
    enum_system_handler,
    ssh_exec_definition,
    ssh_exec_handler,
)

pytestmark = [pytest.mark.unit]

TARGET = "10.64.128.102"
TENANT = "system"
ENGAGEMENT = "eng-1"
PASSWORD = "secret"


@pytest.fixture(autouse=True)
def _no_connect_cooldown(monkeypatch):
    monkeypatch.setattr(module, "SSH_CONNECT_COOLDOWN_SECONDS", 0.0)


@pytest.fixture(autouse=True)
def _private_vault(tmp_path, monkeypatch):
    """One vault per test: the resolved credential is written and read there."""
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))


class _FakeSandbox:
    """A paramiko payload with no socket behind it."""

    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append(list(argv))
        return SandboxResult(0, json.dumps(self.payload) + "\n", "")


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope() -> EngagementScope:
    return EngagementScope(
        engagement_id=ENGAGEMENT,
        tenant_id=TENANT,
        name="simple-ctf",
        client="acme",
        owner_id="owner-1",
        valid_from=_iso(-timedelta(days=1)),
        valid_until=_iso(timedelta(days=1)),
        cidrs=("10.64.0.0/16",),
        domains=(),
        urls=(),
        exclusions=(),
        created_at=_iso(timedelta(0)),
    )


def _store(tmp_path) -> ControlStore:
    store = ControlStore(tmp_path / "board.db")
    store.initialize()
    return store


def _record(store: ControlStore, fact_type: str, key: str, value: dict, **extra) -> None:
    Blackboard(store).record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type=fact_type,
        key=key,
        value=value,
        source=extra.pop("source", "nexus.post.ssh_exec"),
        created_by=extra.pop("created_by", "verifier"),
        verified=extra.pop("verified", True),
        asserted_by=extra.pop("asserted_by", "verifier"),
        verification_method=extra.pop("verification_method", "ssh_exec_completed"),
        invocation_id=extra.pop("invocation_id", "inv-1"),
        **extra,
    )


def _context(store: ControlStore) -> RunContext:
    return RunContext(
        TENANT,
        Identity("operator", TENANT, roles=("operator",)),
        store=store,
        scope=_scope(),
    )


_OK = {"ok": True, "connected": True, "mode": "exec", "exit_status": 0,
       "stdout": "uid=1001(mitch)\n", "stderr": ""}


def _invoke(handler, arguments: dict, store: ControlStore):
    sandbox = _FakeSandbox(_OK)
    with mock.patch.object(
        module, "sandbox_for_environment", lambda *a, **k: sandbox
    ):
        result = asyncio.run(handler(arguments, _context(store)))
    return result, sandbox


# ------------------------------------------------------------------- the schema
def test_the_handlers_no_longer_reject_a_call_for_omitting_the_credential():
    """The old ``anyOf`` killed the call before the handler could look it up.

    A rejected call still counted as a consecutive failure; three of them
    aborted the whole run (Simple CTF, 23:16 UTC, iteration 27).
    """
    schema = ssh_exec_definition().input_schema

    assert schema["required"] == ["target", "username", "command"]
    assert "anyOf" not in schema


# --------------------------------------------------------------------- the port
def test_the_port_the_engagement_proved_is_used_without_asking(tmp_path):
    """A verified ``service`` fact names the SSH port; the model never repeats it."""
    store = _store(tmp_path)
    _record(store, "service", f"{TARGET}:2222:tcp",
            {"port": "2222", "protocol": "tcp", "service": "ssh", "state": "open"})

    result, sandbox = _invoke(
        ssh_exec_handler,
        {"target": TARGET, "username": "mitch", "password": PASSWORD, "command": "id"},
        store,
    )

    # The client script takes the port as its 4th positional argument.
    assert sandbox.calls[0][5] == "2222"
    assert result.evidence["resolved_from_board"] == {"port": 2222}
    assert result.verified is True


def test_the_port_is_matched_on_the_host_that_carries_the_fact(tmp_path):
    """Another host's SSH service is not this host's port."""
    store = _store(tmp_path)
    _record(store, "service", "10.9.9.9:2222:tcp",
            {"port": "2222", "protocol": "tcp", "service": "ssh", "state": "open"})

    _, sandbox = _invoke(
        ssh_exec_handler,
        {"target": TARGET, "username": "mitch", "password": PASSWORD, "command": "id"},
        store,
    )

    assert sandbox.calls[0][5] == str(module.SSH_DEFAULT_PORT)


def test_the_port_of_the_proved_session_wins_over_a_scan_fact(tmp_path):
    """The port an authenticated session really used is the strongest evidence."""
    store = _store(tmp_path)
    _record(store, "service", f"{TARGET}:22:tcp",
            {"port": "22", "protocol": "tcp", "service": "ssh", "state": "open"})
    _record(store, "access", TARGET,
            {"transport": "ssh", "username": "mitch", "port": 2222})

    _, sandbox = _invoke(
        ssh_exec_handler,
        {"target": TARGET, "username": "mitch", "password": PASSWORD, "command": "id"},
        store,
    )

    assert sandbox.calls[0][5] == "2222"


def test_an_explicit_port_is_never_overridden(tmp_path):
    store = _store(tmp_path)
    _record(store, "access", TARGET,
            {"transport": "ssh", "username": "mitch", "port": 2222})

    _, sandbox = _invoke(
        ssh_exec_handler,
        {"target": TARGET, "username": "mitch", "password": PASSWORD,
         "command": "id", "port": 2022},
        store,
    )

    assert sandbox.calls[0][5] == "2022"


# --------------------------------------------------------------- the credential
def _proved_credential(store: ControlStore) -> str:
    from nexus_core.kernel.secret_store import default_secret_store

    ref = default_secret_store().put(PASSWORD.encode("utf-8"), kind="ssh", tenant_id=TENANT)
    _record(store, "credential", f"cred:ssh:mitch@{TARGET}",
            {"username": "mitch", "secret_ref": ref, "service": "ssh", "port": 2222})
    return ref


def test_a_credential_the_engagement_proved_is_reused_and_redacted(tmp_path):
    """The model omits the secret; the engine supplies the proved one (V1-29)."""
    store = _store(tmp_path)
    ref = _proved_credential(store)

    result, sandbox = _invoke(
        ssh_exec_handler,
        {"target": TARGET, "username": "mitch", "command": "id"},
        store,
    )

    assert sandbox.calls[0][7] == PASSWORD
    assert result.verified is True
    # The evidence names the real handle the engine resolved, not a synthesized
    # key that an operator cannot look up in the vault.
    assert result.evidence["resolved_from_board"] == {"credential": ref}
    # The boundary redactor still covers the secret the engine resolved itself.
    assert PASSWORD not in json.dumps(result.output)
    assert PASSWORD not in json.dumps(result.evidence)


def test_the_credential_is_reused_by_enum_system_too(tmp_path):
    store = _store(tmp_path)
    _proved_credential(store)
    enum_payload = {"ok": True, "connected": True, "mode": "enum",
                    "results": {"identity": {"stdout": "uid=1001(mitch)\n", "exit_status": 0}}}
    sandbox = _FakeSandbox(enum_payload)
    with mock.patch.object(module, "sandbox_for_environment", lambda *a, **k: sandbox):
        result = asyncio.run(enum_system_handler({"target": TARGET, "username": "mitch"},
                                                 _context(store)))

    assert sandbox.calls[0][7] == PASSWORD
    from nexus_core.kernel.secret_store import is_secret_ref

    assert is_secret_ref(result.evidence["resolved_from_board"]["credential"])
    assert result.verified is True


def test_a_call_without_any_proved_credential_says_how_to_get_one(tmp_path):
    """Fail closed, but name the three ways out instead of "password is required"."""
    store = _store(tmp_path)

    with pytest.raises(ValueError) as excinfo:
        _invoke(ssh_exec_handler, {"target": TARGET, "username": "mitch", "command": "id"},
                store)

    message = str(excinfo.value)
    assert "password" in message and "credential_ref" in message
    assert f"mitch@{TARGET}" in message


def _put_secret() -> str:
    from nexus_core.kernel.secret_store import default_secret_store

    return default_secret_store().put(PASSWORD.encode("utf-8"), kind="ssh", tenant_id=TENANT)


def test_the_credential_is_found_under_another_key_shape(tmp_path):
    """The lookup is structural: ``<user>@<host>`` is the same credential.

    Measured in Simple CTF (2026-10-18 02:35 UTC, iteration 29): the model called
    ``ssh_exec`` with only ``target`` and ``username``; the engine only accepted
    the literal ``cred:ssh:<user>@<host>`` key, so the board's credential was
    "missing" and the turn was lost.
    """
    store = _store(tmp_path)
    ref = _put_secret()
    _record(store, "credential", f"mitch@{TARGET}",
            {"username": "mitch", "secret_ref": ref, "service": "ssh"})

    result, sandbox = _invoke(
        ssh_exec_handler,
        {"target": TARGET, "username": "mitch", "command": "id"},
        store,
    )

    assert sandbox.calls[0][7] == PASSWORD
    assert result.evidence["resolved_from_board"] == {"credential": ref}


def test_an_access_fact_with_a_vault_handle_is_used_too(tmp_path):
    """The board's other credential shape (``access``) is consulted as well."""
    store = _store(tmp_path)
    ref = _put_secret()
    _record(store, "access", TARGET,
            {"transport": "ssh", "username": "mitch", "port": 2222,
             "secret_ref": ref})

    result, sandbox = _invoke(
        ssh_exec_handler,
        {"target": TARGET, "username": "mitch", "command": "id"},
        store,
    )

    assert sandbox.calls[0][7] == PASSWORD
    assert result.evidence["resolved_from_board"] == {"port": 2222, "credential": ref}
    # The port of the same fact is used as well.
    assert sandbox.calls[0][5] == "2222"


def test_an_unverified_credential_with_a_handle_is_reusable(tmp_path):
    """A vault handle is a stored secret, not a guess the model typed."""
    store = _store(tmp_path)
    ref = _put_secret()
    _record(store, "credential", f"mitch@{TARGET}",
            {"username": "mitch", "secret_ref": ref, "service": "ssh"},
            source="agent", created_by="agent", verified=False,
            asserted_by="agent", verification_method="", invocation_id="")

    result, sandbox = _invoke(
        ssh_exec_handler,
        {"target": TARGET, "username": "mitch", "command": "id"},
        store,
    )

    assert sandbox.calls[0][7] == PASSWORD
    assert result.evidence["resolved_from_board"] == {"credential": ref}


def test_a_hash_without_a_handle_is_not_used_and_the_error_says_why(tmp_path):
    """The measured iteration 29: a credential fact that is not a password."""
    store = _store(tmp_path)
    _record(store, "credential", "cmsms_mitch_hash",
            {"username": "mitch", "hash": "[REDACTED]", "salt": "1dac0d92",
             "source": "CVE-2019-9053 SQLi"},
            source="agent", created_by="agent", verified=False,
            asserted_by="agent", verification_method="", invocation_id="")

    with pytest.raises(ValueError) as excinfo:
        _invoke(ssh_exec_handler, {"target": TARGET, "username": "mitch", "command": "id"},
                store)

    message = str(excinfo.value)
    assert "sin un `secret_ref` utilizable" in message
    assert "hash" in message


def test_a_credential_for_another_user_is_never_reused(tmp_path):
    """The handle is bound to the user it was proved for."""
    store = _store(tmp_path)
    ref = _put_secret()
    _record(store, "credential", f"cred:ssh:lin@{TARGET}",
            {"username": "lin", "secret_ref": ref, "service": "ssh"})

    with pytest.raises(ValueError) as excinfo:
        _invoke(ssh_exec_handler, {"target": TARGET, "username": "mitch", "command": "id"},
                store)

    assert "no SSH credential for mitch@" in str(excinfo.value)
