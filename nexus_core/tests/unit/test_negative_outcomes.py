"""V0-22: "execution completed" and "something was found" are two questions.

Measured evidence: 89 ``smb_listing_failed``, one ``bloodhound_no_output``, one
``ntlm_capture_no_connection`` and one ``ntlm_capture_no_hash`` reached the
operator as a ``RuntimeError``, so a run that *looked and found nothing* was
recorded exactly like a run that *could not look*. These tests drive the real
handlers, push their result through the gateway, and require the negative to
complete: audited with its outcome, journaled as succeeded, deriving no
assertion. A result the handler did not classify keeps failing closed.
"""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.errors import ProviderFailure
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.kernel.models import Identity, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.tools.handlers import bloodhound as bloodhound_module
from nexus_core.tools.handlers import smb as smb_module
from nexus_core.tools.handlers.bloodhound import bloodhound_handler
from nexus_core.tools.handlers.smb import smb_handler

TARGET = "203.0.113.10"
SMB_BINARY = "/usr/bin/smbclient"
BH_BINARY = "/home/u/.local/bin/bloodhound-python"


class _FakeSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30) -> SandboxResult:
        self.calls.append(list(argv))
        return self.result


@contextlib.contextmanager
def _stubbed(module, binary: str, result: SandboxResult):
    sandbox = _FakeSandbox(result)
    with mock.patch.object(module, "ad_sandbox", lambda *args, **kwargs: sandbox):
        with mock.patch.object(module, "resolve_ad_binary", lambda *args, **kwargs: binary):
            yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator", "system", roles=("operator",)), run_id="run-v0-22")


def _smb(stdout: str, arguments: dict, *, exit_code: int = 0) -> ToolResult:
    with _stubbed(smb_module, SMB_BINARY, SandboxResult(exit_code, stdout, "")):
        return asyncio.run(smb_handler(arguments, _context()))


def _bloodhound(tmp_path, monkeypatch) -> ToolResult:
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _stubbed(bloodhound_module, BH_BINARY, SandboxResult(0, "", "")):
        return asyncio.run(
            bloodhound_handler({"domain": "corp.local", "dc": "10.0.0.10"}, _context())
        )


def _real_negatives(tmp_path, monkeypatch) -> dict[str, tuple[ToolResult, str]]:
    """The measured negatives, produced by the real handlers (sandbox mocked)."""
    return {
        "smb_shares_empty": (_smb("", {"target": TARGET, "action": "shares"}), "negative"),
        "smb_listing_failed": (
            _smb(
                "NT_STATUS_ACCESS_DENIED listing \\\\*\n",
                {"target": TARGET, "share": "nt4wrksv", "action": "list"},
            ),
            "denied",
        ),
        "bloodhound_no_output": (_bloodhound(tmp_path, monkeypatch), "negative"),
    }


def _gateway(tmp_path, result: ToolResult):
    store = ControlStore(tmp_path / "audit.db")
    store.initialize()
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store))
    gateway.register(
        ToolDefinition("probe", "system", {}, tool_id="probe", effect="read_only"),
        lambda arguments, context: result,
    )
    return store, gateway


@pytest.mark.parametrize("method", ["smb_shares_empty", "smb_listing_failed", "bloodhound_no_output"])
def test_legitimate_empty_results_complete_without_assertions(tmp_path, monkeypatch, method):
    result, expected = _real_negatives(tmp_path, monkeypatch)[method]
    assert result.success is False
    assert result.verification_method == method
    assert result.outcome == expected

    store, gateway = _gateway(tmp_path, result)
    returned = asyncio.run(gateway.invoke("probe", {}, _context()))

    # The call completed and says what happened...
    assert returned["success"] is False
    assert returned["outcome"] == expected
    # ...without inventing a single positive fact.
    assert returned["assertions"] == []
    invocation = InvocationJournal(store).get(returned["invocation_id"], "system")
    assert invocation["state"] == "succeeded"
    trail = AuditWriter(store).export("system")
    completed = next(row for row in trail if row["action"] == "tool.complete")
    assert completed["payload"]["outcome"] == expected
    assert [row for row in trail if row["action"] == "tool.failed"] == []


def test_denied_and_unsupported_are_not_flattened_into_one_negative(tmp_path):
    """A refusal must stay readable as a refusal."""
    denied = _smb(
        "NT_STATUS_ACCESS_DENIED listing \\\\*\n",
        {"target": TARGET, "share": "nt4wrksv", "action": "list"},
    )
    unsupported = _smb(
        "NT_STATUS_BAD_NETWORK_NAME opening \\\\*\\SYSVOL\n",
        {"target": TARGET, "share": "SYSVOL", "action": "list"},
    )
    assert (denied.outcome, denied.verification_method) == ("denied", "smb_listing_failed")
    assert (unsupported.outcome, unsupported.verification_method) == (
        "unsupported",
        "smb_listing_failed",
    )


def test_unknown_nt_status_still_fails_closed(tmp_path):
    """An answer the handler cannot classify is not reported as an observation."""
    result = _smb(
        "NT_STATUS_SOMETHING_UNHEARD_OF listing \\\\*\n",
        {"target": TARGET, "share": "nt4wrksv", "action": "list"},
    )
    assert result.success is False
    assert result.outcome == ""
    _, gateway = _gateway(tmp_path, result)
    with pytest.raises(RuntimeError, match="post-condition"):
        asyncio.run(gateway.invoke("probe", {}, _context()))


def test_timeout_and_missing_infrastructure_keep_their_own_error(tmp_path):
    timed_out = ToolResult({}, False, "smb_timeout", {}, timed_out=True)
    unavailable = ToolResult({}, False, "_".join(["smbclient", "unavailable"]))
    # Distinct arguments so the two calls do not share a durable step key.
    for result, method in ((timed_out, "smb_timeout"), (unavailable, "smbclient_unavailable")):
        _, gateway = _gateway(tmp_path, result)
        with pytest.raises(ProviderFailure):
            asyncio.run(gateway.invoke("probe", {"probe_case": method}, _context()))
        assert result.outcome_class != "negative"


def test_an_unparsed_answer_is_still_a_failure(tmp_path):
    """No parseable output means the body did not observe anything."""
    result = ToolResult({"error": "wp_enum produced no result"}, False, "wp_enum_no_output")
    assert result.completed is False
    _, gateway = _gateway(tmp_path, result)
    with pytest.raises(RuntimeError, match="post-condition"):
        asyncio.run(gateway.invoke("probe", {}, _context()))


def test_an_invented_outcome_is_rejected():
    with pytest.raises(ValueError, match="unknown tool outcome"):
        ToolResult({}, False, "probe", {}, outcome="fine_and_dandy")
