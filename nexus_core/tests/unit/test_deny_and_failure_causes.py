"""Tanda B, Fix 3a/3b: one deny list with two scopes, and failures that say why.

3a is a coherence fix, not a new capability. The same lexical list used to mean
two different things depending on which tool the model picked: ``sudo`` was
refused in ``nexus.shell.exec`` and in ``nexus.session.pty`` (both run on the
operator's machine, so that is right) and also in
``nexus.post.shell_exec``/``nexus.post.ssh_exec`` (both run on the target, where
``sudo -l`` is the enumeration step). Meanwhile ``shutdown`` and
``find / -delete`` were refused locally for no reason at all -the sandbox is
ephemeral and a targeted delete is not a wipe.

3b is the other half of the same complaint: a failure that says "the tool failed"
costs a turn, because the model can neither fix the call nor retire the route.
The cause now travels with the result: the budget that expired, the program the
sandbox refused, the exit status and the redacted tail of stderr.
"""

from __future__ import annotations

import asyncio
import json
from unittest import mock

import pytest

from nexus_core.cli.engage import build_scope
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.scope import EngagementStore
from nexus_core.tools.handlers import ssh_post as ssh_module
from nexus_core.tools.handlers.shell_exec import shell_exec_definition as post_shell_definition
from nexus_core.tools.handlers.shell_exec_local import (
    DESTRUCTIVE_REASON,
    LOCAL_PRIVILEGE_REASON,
    denied_command,
    shell_exec_handler,
)
from nexus_core.tools.handlers.session_pty import command_denial

pytestmark = pytest.mark.unit

SECRET = "test-signing-secret"
TARGET = "10.10.10.5"


@pytest.fixture()
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_SCOPE_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(workspace))
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    scope = EngagementStore(store).create(build_scope("bench", f"{TARGET}/32", SECRET))
    return RunContext(
        "system",
        Identity("operator-1", "system", roles=("operator",)),
        store=store,
        scope=scope,
        project_root=str(workspace),
        run_id="run-tanda-b",
    )


class _FakeSandbox:
    def __init__(self, result=None, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[list[str]] = []

    async def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if self.error is not None:
            raise self.error
        return self.result


def _with_shell_sandbox(sandbox: _FakeSandbox):
    import nexus_core.tools.handlers.shell_exec_local as module

    return mock.patch.object(module, "sandbox_for_environment", lambda *a, **k: sandbox)


def _run(arguments: dict, context: RunContext):
    return asyncio.run(shell_exec_handler(arguments, context))


# ------------------------------------------------------- 3a: which rule, where


@pytest.mark.parametrize(
    "command,local_kind,allowed_remotely",
    [
        ("sudo id", "local_privilege", True),
        ("doas id", "local_privilege", True),
        ("su - root", "local_privilege", True),
        ("rm -rf /", "destructive", False),
        ("rm -rf $HOME", "destructive", False),
        ("dd if=/dev/zero of=/dev/sda", "destructive", False),
        ("chmod -R 777 /", "destructive", False),
        # Dropped from the local list on purpose (3a.1): a targeted delete and
        # host power management are policy, not self-destruction.
        ("find / -name x -delete", None, True),
        ("shutdown -h now", None, True),
        ("reboot", None, True),
    ],
)
def test_one_list_two_scopes(command, local_kind, allowed_remotely):
    local = denied_command(command)
    remote = denied_command(command, local_privileges=False)
    assert (local.kind if local else None) == local_kind
    # The destructive half is identical on both sides of the link; only the
    # local-privilege half is scope-dependent.
    assert (remote is None) is allowed_remotely


def test_the_two_refusals_carry_their_own_reason():
    assert denied_command("sudo id").reason == LOCAL_PRIVILEGE_REASON
    assert denied_command("rm -rf /").reason == DESTRUCTIVE_REASON


def test_local_shell_refuses_sudo_with_the_honest_reason(context):
    result = _run({"command": "sudo id"}, context)
    assert result.verified is False
    assert result.outcome == "denied"
    assert result.verification_method == "shell_command_denied"
    assert result.output["reason"] == LOCAL_PRIVILEGE_REASON
    assert result.output["kind"] == "local_privilege"
    assert "nexus.post.ssh_exec" in result.output["guidance"]
    # Nothing ran: the refusal is lexical and happens before the sandbox.
    assert result.exit_code is None


def test_local_pty_refuses_sudo(context):
    denial = command_denial(context, "sudo -l")
    assert denial["outcome"] == "denied"
    assert denial["reason"] == LOCAL_PRIVILEGE_REASON
    assert denial["denial_kind"] == "local_privilege"


def test_a_remote_channel_allows_sudo_but_keeps_the_destructive_list(context):
    """``local_scope=False`` is the whole remote policy: sudo yes, wipe no.

    That is where ``sudo -l`` is the enumeration step, not a threat. The call is
    HIGH risk, so the approval gate asks the human; the handler does not decide
    policy with a regex.
    """
    assert command_denial(context, "sudo -l", local_scope=False) is None
    assert command_denial(context, "su - root", local_scope=False) is None
    # The destructive list still applies there -the link does not change what
    # ``rm -rf /`` does.
    assert command_denial(context, "rm -rf /", local_scope=False)["reason"] == DESTRUCTIVE_REASON
    assert post_shell_definition().risk is RiskLevel.HIGH


def test_a_listener_pane_stays_fail_closed(context):
    """``raw``/``pty`` are tmux panes on the operator's machine.

    The listener starts them locally and a reverse shell connects *into* the
    pane, so the handler cannot prove a remote prompt is in the foreground when
    it types. Denying there is the conservative half of the asymmetry, and the
    target's ``sudo`` has three unambiguous remote channels
    (``nexus.post.ssh_exec``, ``msf_session_interact``, ``sliver_exec``).
    """
    assert command_denial(context, "sudo -l")["reason"] == LOCAL_PRIVILEGE_REASON


_OK_PAYLOAD = {
    "ok": True,
    "connected": True,
    "mode": "exec",
    "exit_status": 0,
    "stdout": "User svc may run the following commands:\n",
    "stderr": "",
}


def _ssh_sandbox(payload: dict):
    sandbox = _FakeSandbox(SandboxResult(0, json.dumps(payload) + "\n", ""))

    class _Runner(_FakeSandbox):
        pass

    return sandbox


def _run_ssh(arguments: dict, context: RunContext, payload: dict | None = None):
    sandbox = _FakeSandbox(SandboxResult(0, json.dumps(payload or _OK_PAYLOAD) + "\n", ""))
    with mock.patch.object(ssh_module, "sandbox_for_environment", lambda *a, **k: sandbox):
        with mock.patch.object(ssh_module, "SSH_CONNECT_COOLDOWN_SECONDS", 0.0):
            result = asyncio.run(ssh_module.ssh_exec_handler(arguments, context))
    return result, sandbox


def test_ssh_exec_lets_sudo_through_to_the_approval_gate(context):
    result, sandbox = _run_ssh(
        {"target": TARGET, "username": "svc", "password": "pw", "command": "sudo -l"},
        context,
    )
    argv = sandbox.calls[0]
    assert result.verified is True
    assert result.outcome == ""
    # ``sudo -S`` with the credential on stdin: the model did not have to spell
    # the escalation around the tool.
    assert json.loads(argv[-1])["command"].startswith("sudo -S ")


def test_ssh_exec_refuses_a_self_destructive_command_with_the_shared_list(context):
    result, sandbox = _run_ssh(
        {"target": TARGET, "username": "svc", "password": "pw",
         "command": "rm -rf $HOME"},
        context,
    )
    assert result.outcome == "denied"
    assert result.verification_method == "ssh_command_denied"
    assert result.output["reason"] == DESTRUCTIVE_REASON
    assert sandbox.calls == []


def test_the_prompt_states_both_scopes_and_never_denies_ssh(context):
    from nexus_core.agent.prompts import render_denied_patterns
    from nexus_core.tools.registry import durable_tool_definitions

    block = render_denied_patterns(durable_tool_definitions("system"))
    lines = block.splitlines()
    destructive, local, remote = lines[0], lines[1], lines[2]
    # Every channel refuses the destructive list.
    assert "rm -rf /" in destructive and "mkfs" in destructive
    # sudo is refused only where the command runs on the operator's machine...
    assert "nexus.shell.exec" in local and "nexus.session.pty" in local
    assert "sudo" in local and "nexus.post.ssh_exec" not in local
    # ...and on the target it is an approved step, never a denied pattern.
    assert "nexus.post.ssh_exec" in remote
    assert "aprobación HIGH" in remote and "sudo" in remote
    # ``ssh`` is not on any deny list: the word only appears as a channel.
    assert "ssh" not in block.replace("nexus.post.ssh_exec", "").lower()


def test_the_deny_block_omits_channels_the_catalog_does_not_offer():
    from nexus_core.agent.prompts import render_denied_patterns

    block = render_denied_patterns({"nexus.recon.nmap": object()})
    assert "nexus.post.ssh_exec" not in block
    assert "nexus.shell.exec" not in block
    # The rule that applies everywhere is still stated.
    assert "rm -rf /" in block


# ------------------------------------------------------------ 3b: the real cause


def test_a_shell_timeout_names_the_budget_that_expired(context):
    sandbox = _FakeSandbox(SandboxResult(-1, "antes\n", "", timed_out=True))
    with _with_shell_sandbox(sandbox):
        result = _run({"command": "tail -f /dev/null", "timeout_seconds": 7}, context)

    assert result.outcome == "timeout"
    assert result.output["timeout_seconds"] == 7
    assert result.evidence["timeout_seconds"] == 7
    assert result.output["reason"] == "command timed out"
    assert result.timed_out is True


def test_a_sandbox_refusal_is_a_denial_that_names_the_program(context):
    sandbox = _FakeSandbox(error=PermissionError("program is not allowed in this sandbox"))
    with _with_shell_sandbox(sandbox):
        result = _run({"command": "echo hola"}, context)

    assert result.outcome == "denied"
    assert result.verification_method == "shell_program_denied"
    assert result.output["reason"] == "program not allowed in sandbox: bash"
    assert result.evidence["program"] == "bash"


def test_a_missing_binary_is_unavailable_not_denied(context):
    sandbox = _FakeSandbox(error=FileNotFoundError("no such file: bash"))
    with _with_shell_sandbox(sandbox):
        result = _run({"command": "echo hola"}, context)

    assert result.outcome == "unavailable"
    assert result.verification_method == "shell_unavailable"
    assert "not available" in result.output["reason"]


def test_a_nonzero_exit_carries_the_status_and_the_stderr_tail(context):
    sandbox = _FakeSandbox(SandboxResult(2, "out\n", "one\ntwo\nthree\nfour\n"))
    with _with_shell_sandbox(sandbox):
        result = _run({"command": "grep -q x f"}, context)

    assert result.outcome == "command_failed"
    assert result.output["exit_code"] == 2
    # Three lines: the tail, not the whole stream (the artifact has it all).
    assert result.output["stderr_tail"] == "two\nthree\nfour"
    assert result.evidence["stderr_tail"] == "two\nthree\nfour"


@pytest.mark.parametrize(
    "stderr",
    [
        "mysql: access denied\nline2\npassword=Hunter2Super\n",
        'login failed: no user\nline2\npassword="Hunter2Super"\n',
        "sudo: 1 incorrect password attempt\npassword: Hunter2Super\n",
    ],
)
def test_the_stderr_tail_is_redacted_before_it_is_persisted(context, stderr):
    sandbox = _FakeSandbox(SandboxResult(1, "", stderr))
    with _with_shell_sandbox(sandbox):
        result = _run({"command": "mysql -u svc -p 'x'"}, context)

    tail = result.output["stderr_tail"]
    assert "[REDACTED]" in tail
    assert "Hunter2Super" not in tail
    assert "Hunter2Super" not in json.dumps(result.to_dict())


def test_the_artifact_keeps_the_full_stream_but_the_observation_is_redacted(context):
    """Only the bounded copy is redacted here; the artifact is the raw capture.

    The three-line tail is what the *model* reads, so that is the boundary this
    fix redacts. The full stream already goes through the artifact store's own
    sanitisation and never reaches the prompt.
    """
    sandbox = _FakeSandbox(SandboxResult(1, "", "ok\nok\npassword=Hunter2Super\n"))
    with _with_shell_sandbox(sandbox):
        result = _run({"command": "mysql -u svc"}, context)
    assert result.output["stderr_tail"].count("[REDACTED]") == 1
    # The summary embeds stderr: it is the text the model reads, so it is
    # redacted too (the artifact keeps the raw capture).
    assert "Hunter2Super" not in result.output["summary"]
    assert "[REDACTED]" in result.output["summary"]


def test_an_ssh_timeout_names_its_budget(context):
    sandbox = _FakeSandbox(SandboxResult(-1, "", "", timed_out=True))
    with mock.patch.object(ssh_module, "sandbox_for_environment", lambda *a, **k: sandbox):
        with mock.patch.object(ssh_module, "SSH_CONNECT_COOLDOWN_SECONDS", 0.0):
            result = asyncio.run(
                ssh_module.ssh_exec_handler(
                    {"target": TARGET, "username": "svc", "password": "pw",
                     "command": "id", "timeout_seconds": 30},
                    context,
                )
            )
    assert result.outcome == "timeout"
    assert result.output["timeout_seconds"] == 30
    assert result.verification_method == "ssh_exec_timeout"


def test_a_failed_ssh_command_carries_the_redacted_tail(context):
    payload = {
        "ok": False,
        "connected": True,
        "mode": "exec",
        "exit_status": 1,
        "stdout": "",
        "stderr": "[sudo] password for svc: pwHunter2\nsudo: 1 incorrect password attempt\n",
        "error": "CommandFailed: sudo",
    }
    result, _ = _run_ssh(
        {"target": TARGET, "username": "svc", "password": "pwHunter2", "command": "sudo id"},
        context,
        payload=payload,
    )
    assert result.outcome == "command_failed"
    # The SSH handler's field is ``exit_status`` (the remote command's status,
    # which the verifier reads); ``ToolResult.exit_code`` mirrors it.
    assert result.output["exit_status"] == 1
    assert result.exit_code == 1
    assert "pwHunter2" not in result.output["stderr_tail"]
    assert "1 incorrect password attempt" in result.output["stderr_tail"]
