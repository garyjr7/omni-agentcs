"""The identity chain closes: a name from a page becomes a confirmed account.

The oracle matters as much as the result. Kerberos user enumeration sends no
password, so it cannot lock an account -that is why it is allowed before any
spray. Its two implementations do not prove the same thing, and the tests pin
the difference: kerbrute decides absence, GetNPUsers does not, and the engine
never turns "not mentioned" into "does not exist".
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.kernel.fact_verification import derive_assertions
from nexus_core.kernel.models import Identity, RunContext, ToolResult
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import ad_user_enum as handler_module
from nexus_core.tools.handlers.ad_user_enum import ad_user_enum_handler, user_enum_definition
from nexus_core.tools.handlers.crack_hash import CRACK_FORMATS, detect_hash_type
from nexus_core.tools.parsers.impacket_asrep import (
    MODE_ASREP,
    MODE_KERBRUTE,
    parse_user_enum,
)

DC = "10.0.0.10"
DOMAIN = "services.local"
USERS = ["j.doe", "j.rock", "w.masters"]

KERBRUTE_OUTPUT = """kerbrute v1.0.3
2026/10/23 10:00:00 >  [+] VALID USERNAME:       j.doe@services.local
2026/10/23 10:00:00 >  [+] VALID USERNAME:       j.rock@services.local
2026/10/23 10:00:01 >  [x] Invalid username:      w.masters@services.local
"""

ASREP_OUTPUT = "$krb5asrep$23$j.doe@SERVICES.LOCAL:aabbccdd$eeff0011\n"
ASREP_ERRORS = "[-] User j.rock doesn't have UF_DONT_REQUIRE_PREAUTH set\n"


class _FakeSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30, **kwargs):
        self.calls.append(list(argv))
        return self.result


def _context(run_id: str = "run-1") -> RunContext:
    return RunContext("system", Identity("op", "system"), run_id=run_id)


def _run(payload: SandboxResult, arguments: dict, *, kerbrute: str | None, asrep: str | None):
    sandbox = _FakeSandbox(payload)
    with mock.patch.object(handler_module, "ad_sandbox", lambda *a, **k: sandbox), \
         mock.patch.object(handler_module, "resolve_ad_binary", lambda *a: kerbrute), \
         mock.patch.object(handler_module, "resolve_impacket_binary", lambda *a: asrep):
        result = asyncio.run(ad_user_enum_handler(arguments, _context()))
    return result, sandbox


# ------------------------------------------------------------------ parser
def test_kerbrute_decides_existence_and_absence():
    parsed = parse_user_enum(KERBRUTE_OUTPUT, USERS, mode=MODE_KERBRUTE, domain=DOMAIN)
    assert parsed.attribution == "full"
    assert parsed.existing == ("j.doe", "j.rock")
    assert parsed.missing == ("w.masters",)
    assert parsed.unknown == ()


def test_getnpusers_proves_the_accounts_it_names_and_nothing_else():
    parsed = parse_user_enum(ASREP_OUTPUT + ASREP_ERRORS, USERS, mode=MODE_ASREP, domain=DOMAIN)
    assert parsed.attribution == "partial"
    assert parsed.existing == ("j.doe", "j.rock")
    assert parsed.missing == ()
    # w.masters was never named: unknown, never "does not exist".
    assert parsed.unknown == ("w.masters",)
    assert parsed.roastable[0].username == "j.doe"
    assert parsed.roastable[0].hash.startswith("$krb5asrep$23$j.doe@")


def test_an_asrep_hash_is_kept_whole_for_john():
    parsed = parse_user_enum(ASREP_OUTPUT, ["j.doe"], mode=MODE_ASREP, domain=DOMAIN)
    assert parsed.roastable[0].hash == "$krb5asrep$23$j.doe@SERVICES.LOCAL:aabbccdd$eeff0011"


# ------------------------------------------------------------------ handler
def test_definition_requires_scope_on_the_dc_and_declares_recon():
    definition = user_enum_definition()
    assert definition.scope_target_field == "dc_ip"
    assert definition.scope_required is True
    assert definition.effect == "recon"
    assert definition.input_schema["required"] == ["dc_ip", "domain", "users"]


def test_kerbrute_is_preferred_and_no_password_is_ever_sent(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    result, sandbox = _run(
        SandboxResult(0, KERBRUTE_OUTPUT, ""),
        {"dc_ip": DC, "domain": DOMAIN, "users": USERS},
        kerbrute="/usr/bin/kerbrute",
        asrep="/usr/bin/impacket-GetNPUsers",
    )
    argv = sandbox.calls[0]
    assert argv[1] == "userenum" and "--dc" in argv and DOMAIN in argv
    assert not any(token in {"-p", "-no-pass", "--password"} for token in argv)
    assert result.verification_method == "userenum_kerbrute_parsed"
    assert result.verified is True
    assert result.output["existing"] == ["j.doe", "j.rock"]
    assert result.output["missing"] == ["w.masters"]
    assert result.evidence["lockout_risk"] == "none"
    # The list it staged is evidence, not a secret, and stays in the workspace.
    staged = list(tmp_path.glob("userenum_users_*.txt"))
    assert staged and staged[0].read_text().split() == USERS


def test_without_kerbrute_the_tool_falls_back_to_getnpusers(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    result, sandbox = _run(
        SandboxResult(0, ASREP_OUTPUT, ASREP_ERRORS),
        {"dc_ip": DC, "domain": DOMAIN, "users": USERS},
        kerbrute=None,
        asrep="/usr/bin/impacket-GetNPUsers",
    )
    argv = sandbox.calls[0]
    assert argv[1] == f"{DOMAIN}/"
    assert "-no-pass" in argv and "-usersfile" in argv
    assert result.output["attribution"] == "partial"
    assert result.output["unknown"] == ["w.masters"]
    assert result.output["roastable"][0]["username"] == "j.doe"
    assert "kerbrute" in " ".join(result.output["next_steps"])


def test_no_binary_is_unavailable_and_never_crashes(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    result, sandbox = _run(
        SandboxResult(0, "", ""),
        {"dc_ip": DC, "domain": DOMAIN, "users": USERS},
        kerbrute=None,
        asrep=None,
    )
    assert sandbox.calls == []
    assert result.verified is False
    assert result.outcome == "unavailable"
    assert result.verification_method == "userenum_unavailable"


def test_a_silent_run_is_a_negative_not_a_list_of_nonexistent_users(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    result, _ = _run(
        SandboxResult(0, "kerbrute v1.0.3\n", ""),
        {"dc_ip": DC, "domain": DOMAIN, "users": USERS},
        kerbrute="/usr/bin/kerbrute",
        asrep=None,
    )
    assert result.verified is False
    assert result.outcome == "negative"
    assert result.verification_method == "userenum_no_answer"
    assert result.output["missing"] == []


def test_users_are_deduplicated_and_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    result, sandbox = _run(
        SandboxResult(0, KERBRUTE_OUTPUT, ""),
        {"dc_ip": DC, "domain": DOMAIN, "users": ["j.doe", "J.Doe", "j.rock"]},
        kerbrute="/usr/bin/kerbrute",
        asrep=None,
    )
    assert result.output["users_requested"] == 2
    assert sandbox.calls


def test_a_bad_username_is_rejected_before_the_sandbox(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(ValueError):
        asyncio.run(
            ad_user_enum_handler(
                {"dc_ip": DC, "domain": DOMAIN, "users": ["j.doe;rm -rf /"]},
                _context(),
            )
        )


# ------------------------------------------------------------------ facts
def test_the_verifier_confirms_accounts_and_vaults_the_asrep_hash(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    context = SimpleNamespace(invocation_id="i", run_id="r", tenant_id="system")
    result = ToolResult(
        output={
            "domain": DOMAIN,
            "existing": ["j.doe", "j.rock"],
            "roastable": [{
                "username": "j.doe",
                "domain": "SERVICES.LOCAL",
                "hash": "$krb5asrep$23$j.doe@SERVICES.LOCAL:aabb$ccdd",
            }],
        },
        verified=True,
        verification_method="userenum_asrep_parsed",
    )
    facts = derive_assertions("nexus.attack.ad_user_enum", {"domain": DOMAIN}, result, context)
    users = {fact["key"] for fact in facts if fact["fact_type"] == "user"}
    assert users == {"j.doe", "j.rock"}
    credential = next(fact for fact in facts if fact["fact_type"] == "credential")
    assert credential["key"] == "krb5asrep:j.doe"
    assert credential["value"]["hash_type"] == "krb5asrep"
    assert credential["value"]["secret_ref"].startswith("vault:")
    assert "hash" not in credential["value"]

    from nexus_core.kernel.secret_store import default_secret_store

    assert default_secret_store().get(credential["value"]["secret_ref"]).startswith(b"$krb5asrep$")


def test_an_asrep_hash_is_a_known_crack_format():
    line = "$krb5asrep$23$j.doe@SERVICES.LOCAL:aabb$ccdd"
    assert detect_hash_type(line) == "krb5asrep"
    assert CRACK_FORMATS["krb5asrep"] == "krb5asrep"
    assert "krb5tgs" in CRACK_FORMATS
