"""Unit tests for the durable AD password change/reset handler (sandbox mocked).

The post-condition is the interesting part: the handler must not trust
Impacket's own banner, so the tests pin that a reset is only reported verified
when the *new* credential independently authenticates, and that a refused reset
stays a declared negative with its output attached.
"""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import impacket_changepasswd as module
from nexus_core.tools.handlers.impacket_changepasswd import (
    impacket_changepasswd_definition,
    impacket_changepasswd_handler,
    validate_new_password,
)

CHANGE_OK = (
    "Impacket v0.14.0.dev0 - Copyright Fortra, LLC\n\n"
    "[*] Setting the password of windcorp.thm\\brittanycr as windcorp.thm\\edwardle\n"
    "[*] Password was changed successfully.\n"
)
LOGIN_OK = "SMB                      10.0.0.5   445    FIRE             [+] windcorp.thm\\brittanycr:OmniReset#2026!\n"
LOGIN_FAIL = "SMB                      10.0.0.5   445    FIRE             [-] windcorp.thm\\brittanycr:OmniReset#2026! STATUS_LOGON_FAILURE\n"


class QueueSandbox:
    """Return one queued result per ``run`` call and record the argv."""

    def __init__(self, *results: SandboxResult):
        self.results = list(results)
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append(list(argv))
        if len(self.results) > 1:
            return self.results.pop(0)
        return self.results[0]


@contextlib.contextmanager
def _fake_sandbox(*results: SandboxResult):
    sandbox = QueueSandbox(*results)

    def factory(workspace_root, resolved=None, *extra):
        return sandbox

    with mock.patch.object(module, "ad_sandbox", factory), mock.patch.object(
        module, "resolve_impacket_binary", return_value="/usr/bin/impacket-changepasswd"
    ), mock.patch.object(
        module, "resolve_ad_binary", return_value="/usr/bin/nxc"
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("op", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(impacket_changepasswd_handler(arguments, _context()))


def _reset_args(**overrides) -> dict:
    arguments = {
        "target": "10.0.0.5",
        "account": "brittanycr",
        "domain": "windcorp.thm",
        "new_password": "OmniReset#2026!",
        "alt_username": "edwardle",
        "alt_password": "!Angelus25!",
    }
    arguments.update(overrides)
    return arguments


# ------------------------------------------------------------------ definition
def test_definition_is_high_risk_scoped_and_verified_by_login():
    definition = impacket_changepasswd_definition()
    assert definition.tool_id == "nexus.attack.impacket_changepasswd"
    assert definition.risk is RiskLevel.HIGH
    assert definition.scope_required is True
    assert definition.scope_target_field == "target"
    assert definition.effect == "exploit"
    assert "Account Operator" in definition.description


# ----------------------------------------------------------------- reset mode
def test_reset_mode_uses_alt_credentials_and_needs_no_old_password():
    with _fake_sandbox(SandboxResult(0, CHANGE_OK, ""), SandboxResult(0, LOGIN_OK, "")) as sandbox:
        result = _run(_reset_args())
    argv = sandbox.calls[0]
    assert argv[0].endswith("impacket-changepasswd")
    assert argv[argv.index("-protocol") + 1] == "smb-samr"
    assert "-reset" in argv
    assert argv[argv.index("-altuser") + 1] == "windcorp.thm/edwardle"
    assert argv[argv.index("-altpass") + 1] == "!Angelus25!"
    # The positional only names the target account: no old password is required.
    assert argv[-1] == "windcorp.thm/brittanycr@10.0.0.5"
    assert result.verified is True
    assert result.verification_method == "changepasswd_verified"
    assert result.evidence["mode"] == "reset"
    assert result.evidence["verified_by_login"] is True


def test_reset_is_verified_by_an_independent_login_not_by_the_banner():
    with _fake_sandbox(SandboxResult(0, CHANGE_OK, ""), SandboxResult(0, LOGIN_FAIL, "")) as sandbox:
        result = _run(_reset_args())
    assert sandbox.calls[1][1] == "smb"  # the second call really is the login check
    assert result.verified is False
    assert result.verification_method == "changepasswd_unverified"
    assert result.evidence["change_accepted"] is True
    assert result.evidence["verified_by_login"] is False


def test_refused_reset_is_a_declared_negative_with_the_server_answer():
    denied = "[!] Could not reset password: rpc_s_access_denied\n"
    with _fake_sandbox(SandboxResult(1, denied, "")) as sandbox:
        result = _run(_reset_args())
    assert len(sandbox.calls) == 1  # no pointless login attempt after a refusal
    assert result.verified is False
    assert result.verification_method == "changepasswd_denied"
    assert "access_denied" in result.evidence["error"]


# ---------------------------------------------------------------- change mode
def test_change_mode_puts_the_current_password_in_the_positional():
    with _fake_sandbox(SandboxResult(0, CHANGE_OK, ""), SandboxResult(0, LOGIN_OK, "")) as sandbox:
        result = _run(
            _reset_args(alt_username=None, alt_password=None, old_password="Old#Pass1")
        )
    argv = sandbox.calls[0]
    assert "-reset" not in argv
    assert "-altuser" not in argv
    assert argv[-1] == "windcorp.thm/brittanycr:Old#Pass1@10.0.0.5"
    assert result.evidence["mode"] == "change"


# ----------------------------------------------------------------- validation
def test_alt_username_requires_a_secret():
    with (
        _fake_sandbox(SandboxResult(0, CHANGE_OK, "")),
        pytest.raises(ValueError, match="alt_username requires"),
    ):
        _run(_reset_args(alt_password=None))


def test_unsupported_protocol_is_refused():
    with (
        _fake_sandbox(SandboxResult(0, CHANGE_OK, "")),
        pytest.raises(ValueError, match="unsupported protocol"),
    ):
        _run(_reset_args(protocol="smb"))


def test_short_or_control_characters_in_the_new_password_are_refused():
    with pytest.raises(ValueError):
        validate_new_password("short")
    with pytest.raises(ValueError):
        validate_new_password("long\x00enough")
    assert validate_new_password("OmniReset#2026!") == "OmniReset#2026!"


def test_handler_never_spawns_a_subprocess():
    with (
        _fake_sandbox(SandboxResult(0, CHANGE_OK, ""), SandboxResult(0, LOGIN_OK, "")),
        mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses"),
        ),
    ):
        _run(_reset_args())


def test_unavailable_binary_is_reported_without_touching_the_target():
    with mock.patch.object(module, "resolve_impacket_binary", return_value=None):
        result = _run(_reset_args())
    assert result.verified is False
    assert result.verification_method == "changepasswd_unavailable"
