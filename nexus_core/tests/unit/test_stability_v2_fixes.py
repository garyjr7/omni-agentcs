"""Regressions of the four stability fixes (Hijack V1, 2026-10-29).

Each test pins one measured failure of that run:

* **trust mode** registered the install approval for
  ``execute:tool:nexus.system.install_tool`` while the gateway consumes
  ``execute:tool:…:<sha256 of the plan>``, so the *first* install was rejected as
  "approval is invalid or already used" (iteration 38);
* that denial closed the run (``Transition.STOP``) with 82 iterations and 1 M
  tokens of budget unused;
* ``nexus.web.request`` reported a 3 843-byte ``login.php`` as a successful
  navigation, so the agent believed it was inside the panel for 17 turns;
* ``mount -t nfs`` printed "failed to apply fstab options", was returned as a
  normal success (the command ended in ``; ls``) and the model retried it four
  times before asking to install ``nfs-common``.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.agent.prompts import render_system_prompt
from nexus_core.agent.react import run_react_loop
from nexus_core.cli.approval import make_approval_callback
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.models import PolicyDecision
from nexus_core.provisioner.installer import approval_action, plan_install
from nexus_core.tests.msf_support import context as msf_context
from nexus_core.tests.msf_support import gateway as msf_gateway
from nexus_core.tests.unit.test_http_request_handler import (
    _fake_sandbox,
    _ok_payload,
    _sandbox_for,
)
from nexus_core.tests.unit.test_phase3b_fixes import ScriptedLLM, ToolSpy, _config

# The fixtures are imported for their side effect: pytest registers an imported
# fixture under its own name, and the tests request it by name through
# ``usefixtures`` (a same-named parameter would be a redefinition, F811).
from nexus_core.tests.unit.test_phase3b_fixes import harness as _react_harness  # noqa: F401
from nexus_core.tests.unit.test_shell_exec_local import _with_sandbox
from nexus_core.tests.unit.test_shell_exec_local import context as _shell_context  # noqa: F401
from nexus_core.tools.handlers import http_request as http_module
from nexus_core.tools.handlers.shell_exec_local import mount_requires_root
from nexus_core.tools.registry import durable_tool_definitions

TENANT = "system"


# ---------------------------------------------------------------- 1 · trust mode
def _install_gateway(tmp_path, onboarding_env):
    """Gateway whose package manager is mocked (no host installs)."""
    onboarding_env.which.side_effect = lambda name: (
        "/usr/bin/" + name if name in {"apt", "go", "sudo", "env"} else None
    )
    gw, audit = msf_gateway(tmp_path)
    from nexus_core.kernel.approvals import ApprovalService

    gw.approvals = ApprovalService(audit.store)
    return gw, msf_context()


def test_trust_mode_registers_the_exact_install_plan(tmp_path, onboarding_env):
    """The durable row must match the action the gateway consumes.

    Before the fix the trust branch returned before rewriting the action, so the
    row said ``execute:tool:nexus.system.install_tool`` and ``consume`` refused
    it on the first call: the approval existed, was fresh, and was still
    rejected.
    """
    gw, ctx = _install_gateway(tmp_path, onboarding_env)
    session = SimpleNamespace(
        input_reader=lambda prompt: "y",
        operator_id="operator-1",
        store=gw.audit.store,
        build_run_context=lambda run_id: ctx,
    )
    callback = make_approval_callback(
        session, gw.audit.store, ctx.tenant_id, ctx.run_id, trust_mode=True
    )
    decision = callback(
        "nexus.system.install_tool",
        {"tool_name": "nmap"},
        PolicyDecision(True, "test", "test", requires_approval=True),
    )

    assert decision.approved is True
    assert decision.reason == "trust_mode"
    assert gw.approvals.verify(
        decision.approval_id, ctx, approval_action(plan_install("nmap"))
    )
    # And the call it authorized really goes through.
    result = asyncio.run(
        gw.invoke(
            "nexus.system.install_tool",
            {"tool_name": "nmap"},
            ctx,
            approval_id=decision.approval_id,
        )
    )
    assert result["verified"] is True


def test_trust_mode_does_not_weaken_the_single_use_rule(tmp_path, onboarding_env):
    """The fix is the action string, not a reusable approval."""
    gw, ctx = _install_gateway(tmp_path, onboarding_env)
    session = SimpleNamespace(
        input_reader=lambda prompt: "y",
        operator_id="operator-1",
        store=gw.audit.store,
        build_run_context=lambda run_id: ctx,
    )
    callback = make_approval_callback(
        session, gw.audit.store, ctx.tenant_id, ctx.run_id, trust_mode=True
    )
    decision = callback(
        "nexus.system.install_tool",
        {"tool_name": "nmap"},
        PolicyDecision(True, "test", "test", requires_approval=True),
    )
    action = approval_action(plan_install("nmap"))
    assert gw.approvals.consume(decision.approval_id, ctx, action) is True
    assert gw.approvals.consume(decision.approval_id, ctx, action) is False


# --------------------------------------------------------- 2 · governance denial
def _tool_call(target: str = "10.0.0.5") -> str:
    return (
        '{"thought": "escaneo", "action": "tool_call", "'
        'tool_id": "nexus.recon.nmap", "arguments": {"target": "%s", '
        '"flags": ["-Pn"]}, "expected_outcome": "puertos"}' % target
    )


def _task_complete() -> str:
    return '{"thought": "listo", "action": "task_complete", "summary": "ok", "findings": []}'


@pytest.mark.usefixtures("_react_harness", "lab_scope")
async def test_a_governance_denial_is_an_observation_not_the_end(request):
    """One denied call must not close an engagement with budget left."""
    store, context_ = request.getfixturevalue("_react_harness")
    spy = ToolSpy(error=PermissionError("approval is invalid or already used"))

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context_,
            objective="compromete el host",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([_tool_call(), _task_complete()]),
            config=_config(max_iterations=4),
        )

    assert result.status != "governance_denial"
    # The loop reached the model's next action instead of stopping on the denial.
    assert result.iterations >= 2
    observations = [
        message["content"]
        for message in store.list_messages(TENANT, result.conversation_id)
        if message["metadata"].get("kind") == "react.observation"
    ]
    assert any("gateway denegó esta invocación" in text for text in observations)


@pytest.mark.usefixtures("_react_harness", "lab_scope")
async def test_the_run_still_ends_when_the_model_insists(request):
    """Three different denied calls in a row keep the fail-closed exit."""
    _, context_ = request.getfixturevalue("_react_harness")
    spy = ToolSpy(error=PermissionError("denied by policy"))

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context_,
            objective="compromete el host",
            engagement_id="eng-1",
            llm_client=ScriptedLLM(
                [_tool_call("10.0.0.5"), _tool_call("10.0.0.6"), _tool_call("10.0.0.7")]
            ),
            config=_config(max_iterations=8),
        )

    assert result.status == "governance_denial"
    assert result.iterations == 3


# ------------------------------------------- 3 · session that does not authenticate
def _run_http(arguments: dict):
    return asyncio.run(http_module.http_request_handler(arguments, _http_context()))


def _http_context():
    from nexus_core.kernel.models import Identity, RunContext

    return RunContext(TENANT, Identity("operator-1", TENANT, roles=("operator",)))


LOGIN_FORM = (
    '<html><body><form method="post" action="/login.php">'
    '<input name="username"><input type="password" name="password">'
    "</form></body></html>"
)


def test_a_session_that_lands_on_the_login_form_is_not_authenticated(tmp_path, monkeypatch):
    from nexus_core.kernel.secret_store import default_secret_store

    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    ref = default_secret_store().put("PHPSESSID=abc", kind="session")
    with _fake_sandbox(_sandbox_for(_ok_payload(body_preview=LOGIN_FORM))):
        result = _run_http(
            {"url": "http://203.0.113.10/administration.php", "session_ref": ref}
        )

    assert result.outcome == "partial"
    assert result.verified is False
    assert result.verification_method == "http_session_not_authenticated"
    assert result.evidence["session_state"] == "not_authenticated"
    assert result.output["session_state"] == "not_authenticated"
    assert "NO autentica" in result.output["guidance"]
    # A cookie handed out by a rejected login must not become a vault handle.
    assert "session_ref" not in result.output


def test_a_rejected_session_does_not_poison_the_vault(tmp_path, monkeypatch):
    from nexus_core.kernel.secret_store import default_secret_store

    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    ref = default_secret_store().put("PHPSESSID=abc", kind="session")
    payload = _ok_payload(
        body_preview=LOGIN_FORM, set_cookie=["PHPSESSID=second; Path=/"]
    )
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run_http({"url": "http://203.0.113.10/panel", "session_ref": ref})

    assert result.evidence["session_ref_issued"] is None
    assert result.output["session_state"] == "not_authenticated"


def test_a_login_page_without_a_session_stays_a_normal_response():
    """The check is about *our* handle, never about \"the page has a form\"."""
    with _fake_sandbox(_sandbox_for(_ok_payload(body_preview=LOGIN_FORM))):
        result = _run_http({"url": "http://203.0.113.10/login.php"})

    assert result.verified is True
    assert result.verification_method == "http_response_received"
    assert "session_state" not in result.output


# ------------------------------------------------------------ 4 · mount without root
@pytest.mark.usefixtures("_shell_context")
def test_an_nfs_mount_without_root_is_unavailable(request):
    """The measured command: mount NFS, print the refusal, end in ``; ls``."""
    from nexus_core.kernel.sandbox import SandboxResult

    shell_context = request.getfixturevalue("_shell_context")

    command = (
        "mkdir -p /tmp/nfsmnt && (mount -t nfs -o vers=3,nolock "
        "10.10.10.5:/mnt/share /tmp/nfsmnt 2>&1 || mount -t nfs "
        "10.10.10.5:/mnt/share /tmp/nfsmnt 2>&1); ls -laR /tmp/nfsmnt 2>&1 | head"
    )
    with _with_sandbox(
        SandboxResult(0, "/tmp/nfsmnt\n---\n", "mount: /tmp/nfsmnt: failed to apply fstab options\n")
    ):
        from nexus_core.tools.handlers.shell_exec_local import shell_exec_handler

        result = asyncio.run(shell_exec_handler({"command": command}, shell_context))

    assert result.outcome == "unavailable"
    assert result.verified is False
    assert result.verification_method == "mount_requires_root"
    assert "nexus.recon.nfs" in result.output["guidance"]
    assert "nfs-common" in result.output["guidance"]


def test_a_non_nfs_mount_failure_keeps_its_own_outcome():
    """The classifier is keyed to the command, not to the phrase."""
    assert mount_requires_root(
        "mount -t ext4 /dev/sdb /mnt", "", "mount: permission denied"
    ) is False
    assert mount_requires_root(
        "ssh host 'mount -t nfs 10.0.0.5:/srv /mnt'",
        "",
        "mount.nfs: permission denied",
    ) is False
    assert mount_requires_root(
        "mount -t nfs 10.0.0.5:/srv /mnt", "", "failed to apply fstab options"
    ) is True


# ------------------------------------------------------------------- 4 · prompt sync
def _prompt(**kwargs) -> str:
    catalog = durable_tool_definitions(TENANT)
    arguments = {
        "catalog": catalog,
        "objective": "compromete el host",
        "engagement_id": "eng-1",
        "scope_summary": "10.0.0.0/24",
    }
    arguments.update(kwargs)
    return render_system_prompt(**arguments)


def test_the_unrestricted_profile_does_not_claim_a_subset():
    unrestricted = _prompt(subagent_unrestricted=True)
    assert "PERFIL ACTIVO SIN SUBCONJUNTO" in unrestricted
    assert "Solo puedes invocar tools de ESE subconjunto" not in unrestricted
    # The restricted wording is what a legacy profile still gets.
    restricted = _prompt()
    assert "Solo puedes invocar tools de ESE subconjunto" in restricted
    assert "PERFIL ACTIVO SIN SUBCONJUNTO" not in restricted


def test_installing_is_the_last_resort_not_the_first_answer():
    prompt = _prompt()
    assert "INSTALACIÓN = ÚLTIMO RECURSO" in prompt
    assert "alternativa pasiva" in prompt
    assert "no da privilegios" not in prompt  # that sentence lives in the tool hint


def test_the_install_rule_is_not_named_without_the_tool():
    """A catalog without ``install_tool`` must not mention it."""
    catalog = {"nexus.recon.nmap": durable_tool_definitions(TENANT)["nexus.recon.nmap"]}
    prompt = render_system_prompt(
        catalog=catalog,
        objective="x",
        engagement_id=None,
        scope_summary="10.0.0.0/24",
    )
    assert "nexus.system.install_tool" not in prompt
    assert "INSTALACIÓN = ÚLTIMO RECURSO" not in prompt


def test_restricted_profile_still_sees_its_own_scope_rule():
    """The old contract is untouched for the legacy profiles (WP2)."""
    restricted = _prompt(subagent_unrestricted=False)
    assert "Solo puedes invocar tools de ESE subconjunto" in restricted
    assert "Solo puedes invocar tools de ESE subconjunto" not in _prompt(
        subagent_unrestricted=True
    )
