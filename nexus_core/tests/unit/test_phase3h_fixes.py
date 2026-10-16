"""Phase 3h fixes: secret handles, banner hygiene and access derivation.

Measured in rerun 8 (``run_9b6103075b9e4347ac298cba3bd21081``, commit ``0bbe80e``):
``hydra`` validated ``lin``'s SSH password and the agent could not use it, because
the blackboard redacted the value it had just verified and the only copy that
survived was a literal ``[REDACTED]`` in the model's own history. The same run
also leaked the argument in clear through the trust-mode banner (21 non-JSON
lines in the NDJSON stream), closed ``exploitation`` on a credential that never
opened a shell, and answered two SSH failures with ``exit_status: null``.

Each test below fails on the pre-fix engine:

* V1-29 - ``nexus_core/kernel/secret_store.py`` + ``secret_ref`` in the facts.
* V1-30 - the banner redacts its arguments and stdout stays NDJSON.
* V1-31 - ``access`` needs a proven channel, not a validated password.
* V1-32 - ``ssh_exec`` surfaces the backend diagnostic.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.agent.planner import active_phase, build_plan
from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.fact_verification import derive_assertions
from nexus_core.kernel.models import Identity, RunContext, ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.kernel.secret_store import (
    SecretStore,
    default_secret_store,
    is_secret_ref,
    resolve_secret_reference,
)
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.scope import EngagementScope, EngagementStore
from nexus_core.tools.handlers import cred_bruteforce as cred_module
from nexus_core.tools.handlers import ssh_post as ssh_module
from nexus_core.tools.handlers.cred_bruteforce import cred_bruteforce_handler
from nexus_core.tools.handlers.ssh_post import ssh_exec_definition, ssh_exec_handler

pytestmark = pytest.mark.unit

TENANT = "system"
TARGET = "10.0.0.1"
PASSWORD = "synthetic-password"


# --------------------------------------------------------------------- helpers
class FakeSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append((list(argv), timeout_seconds))
        return self.result


@contextlib.contextmanager
def _fake_sandbox(module, result: SandboxResult):
    sandbox = FakeSandbox(result)
    with mock.patch.object(module, "sandbox_for_environment", lambda *a, **k: sandbox):
        yield sandbox


def _context() -> RunContext:
    return RunContext(TENANT, Identity("operator-1", TENANT, roles=("operator",)))


def _hydra_workspace(tmp_path: Path) -> None:
    (tmp_path / "locks.txt").write_text("\n".join(f"pw{i}" for i in range(5)) + "\n",
                                        encoding="utf-8")


def _run_bruteforce(tmp_path: Path, stdout: str) -> ToolResult:
    with _fake_sandbox(cred_module, SandboxResult(0, stdout, "")):
        return asyncio.run(
            cred_bruteforce_handler(
                {
                    "target": TARGET,
                    "service": "ssh",
                    "username": "lin",
                    "password_file": "locks.txt",
                },
                _context(),
            )
        )


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _create_scope(store: ControlStore) -> None:
    EngagementStore(store).create(
        EngagementScope(
            engagement_id="eng-vault",
            tenant_id=TENANT,
            name="engagement-eng-vault",
            client="acme",
            owner_id="owner-1",
            valid_from=_iso(-timedelta(days=1)),
            valid_until=_iso(timedelta(days=1)),
            cidrs=(f"{TARGET}/32",),
            domains=(),
            urls=(),
            exclusions=(),
            created_at=_iso(timedelta(0)),
        )
    )


def _run_context(store: ControlStore) -> RunContext:
    """Governed RunContext of one invocation: identity + signed-scope + store."""
    from nexus_core.kernel.scope_loader import load_engagement_scope

    run = store.create_run(TENANT, {})
    return RunContext(
        TENANT,
        Identity("operator-1", TENANT, kind="agent", roles=("operator",)),
        run_id=run["id"],
        trace_id=run["id"],
        scope=load_engagement_scope(store, TENANT, "eng-vault"),
        store=store,
    )


def _approved(store: ControlStore, context, action: str) -> str:
    """Register and decide an approval for the run behind ``context``.

    ``ApprovalService.request`` needs an identity, which an
    :class:`ExecutionContext` does not carry; the run id is what binds the row to
    the invocation the gateway later consumes it for.
    """
    service = ApprovalService(store)
    requester = RunContext(
        TENANT, Identity("operator-1", TENANT, roles=("operator",)), run_id=context.run_id
    )
    approval = service.request(requester, action)
    service.decide(approval["id"], TENANT, "admin-2", True, "ok")
    return approval["id"]


# ===================================================== V1-29: secret handles
def test_secret_store_put_get_roundtrip(tmp_path):
    """A stored secret is addressed by an opaque, private, 0600 file."""
    store = SecretStore(tmp_path / "vault")
    ref = store.put(PASSWORD, kind="credential", tenant_id=TENANT)

    assert is_secret_ref(ref) and ref.startswith("vault:")
    assert store.get(ref) == PASSWORD.encode()
    assert store.metadata(ref)["kind"] == "credential"
    assert store.metadata(ref)["tenant_id"] == TENANT
    # The reference is not the secret, and the metadata never holds it.
    assert PASSWORD not in ref
    assert PASSWORD not in json.dumps(store.metadata(ref))
    token = ref.split(":", 1)[1]
    assert (tmp_path / "vault" / f"{token}.secret").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "vault").stat().st_mode & 0o777 == 0o700

    with pytest.raises(KeyError):
        store.get("vault:" + "0" * 32)
    with pytest.raises(ValueError):
        store.get("not-a-reference")
    with pytest.raises(ValueError):
        store.put("", kind="credential")


def test_secret_store_refuses_another_tenant(tmp_path):
    store = SecretStore(tmp_path / "vault")
    ref = store.put(PASSWORD, tenant_id="acme")
    assert store.get(ref, tenant_id="acme") == PASSWORD.encode()
    with pytest.raises(KeyError):
        store.get(ref, tenant_id="other")


def test_resolve_secret_reference_keeps_manual_password(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    vault = default_secret_store()
    ref = vault.put(PASSWORD)
    resolved = resolve_secret_reference({"credential_ref": ref, "target": TARGET})
    assert resolved["password"] == PASSWORD
    assert resolved["credential_ref"] == ref
    # A manual call keeps its plaintext, untouched.
    manual = {"target": TARGET, "password": "manual"}
    assert resolve_secret_reference(manual) is manual
    with pytest.raises(ValueError):
        resolve_secret_reference({"credential_ref": "vault:" + "0" * 32})


def test_cred_bruteforce_stores_secret_and_returns_ref(tmp_path, monkeypatch):
    """hydra's hit becomes a handle; the result carries no plaintext."""
    _hydra_workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))

    result = _run_bruteforce(
        tmp_path, f"[22][ssh] host: {TARGET}   login: lin   password: {PASSWORD}\n"
    )

    assert result.verified is True and result.evidence["found_count"] == 1
    entry = result.output["valid_credentials"][0]
    assert "password" not in entry
    assert entry["username"] == "lin"
    assert entry["secret_ref"] == result.evidence["secret_refs"][0]
    assert default_secret_store().get(entry["secret_ref"]) == PASSWORD.encode()


def test_tool_result_of_hydra_has_no_plaintext_in_preview(tmp_path, monkeypatch):
    """No field of the ToolResult -not even the raw capture- holds the secret."""
    _hydra_workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))

    result = _run_bruteforce(
        tmp_path, f"[22][ssh] host: {TARGET}   login: lin   password: {PASSWORD}\n"
    )

    assert PASSWORD not in json.dumps(result.output, ensure_ascii=False)
    assert PASSWORD not in json.dumps(result.evidence, ensure_ascii=False)
    assert PASSWORD not in (result.stdout or "")
    assert PASSWORD not in json.dumps(result.to_dto(), default=str)
    assert "[REDACTED]" in (result.stdout or "")


def test_ssh_exec_resolves_credential_ref_without_leaking_plaintext(tmp_path, monkeypatch,
                                                                   lab_scope):
    """The gateway resolves the handle in-process; no durable record sees it."""
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    store = ControlStore(tmp_path / "gateway.db")
    store.initialize()
    _create_scope(store)
    context = _run_context(store)
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store), ApprovalService(store))
    seen: dict = {}

    async def handler(arguments, run_context):
        seen.update(arguments)
        return ToolResult(
            output={"target": arguments["target"], "command": arguments["command"],
                    "stdout": "uid=0(root)\n", "stderr": "", "exit_status": 0},
            verified=True,
            verification_method="ssh_exec_completed",
        )

    gateway.register(ssh_exec_definition(), handler)
    handle = default_secret_store().put(PASSWORD)
    approval_id = _approved(store, context, "execute:tool:nexus.post.ssh_exec")

    result = asyncio.run(
        gateway.invoke(
            "nexus.post.ssh_exec",
            {"target": TARGET, "username": "lin", "credential_ref": handle, "command": "id"},
            context,
            permissions=("execute:tool:nexus.post.ssh_exec",),
            approval_id=approval_id,
        )
    )

    # The handler received the plaintext...
    assert seen["password"] == PASSWORD
    assert seen["credential_ref"] == handle
    # ...and the result carries the evidence, never the secret.
    assert result["verified"] is True and result["output"]["stdout"] == "uid=0(root)\n"
    assert PASSWORD not in json.dumps(result, default=str)
    # The audit trail keeps the reference, not the value.
    audit = json.dumps(AuditWriter(store).export(TENANT), default=str)
    assert PASSWORD not in audit
    assert handle in audit


def test_gateway_refuses_an_unknown_credential_ref(tmp_path, monkeypatch, lab_scope):
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    store = ControlStore(tmp_path / "gateway.db")
    store.initialize()
    _create_scope(store)
    context = _run_context(store)
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store), ApprovalService(store))
    gateway.register(
        ssh_exec_definition(),
        lambda arguments, run_context: ToolResult(
            output={}, verified=True, verification_method="ssh_exec_completed"
        ),
    )
    approval_id = _approved(store, context, "execute:tool:nexus.post.ssh_exec")
    with pytest.raises(ValueError, match="unknown credential_ref"):
        asyncio.run(
            gateway.invoke(
                "nexus.post.ssh_exec",
                {"target": TARGET, "username": "lin", "credential_ref": "vault:" + "0" * 32,
                 "command": "id"},
                context,
                permissions=("execute:tool:nexus.post.ssh_exec",),
                approval_id=approval_id,
            )
        )


def test_blackboard_never_contains_password_plaintext(tmp_path, monkeypatch):
    """The fact the agent reads back holds the handle, never the secret."""
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    store = ControlStore(tmp_path / "facts.db")
    store.initialize()
    handle = default_secret_store().put(PASSWORD)
    board = Blackboard(store)
    board.record(
        tenant_id=TENANT,
        engagement_id="eng-vault",
        fact_type="credential",
        key=f"cred:ssh:lin@{TARGET}",
        value={"username": "lin", "service": "ssh", "secret_ref": handle},
        source="nexus.cred.bruteforce",
        created_by="deterministic-verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="cred_bruteforce_completed",
        invocation_id="invocation-1",
    )

    facts = board.list_facts(TENANT, "eng-vault")
    stored = json.dumps(facts, ensure_ascii=False)
    assert PASSWORD not in stored
    assert facts[0]["value"]["secret_ref"] == handle
    assert "password" not in facts[0]["value"]
    assert handle in board.render(TENANT, "eng-vault")
    # And the redactor still refuses a legacy plaintext (it was not relaxed).
    from nexus_core.kernel.redaction import sanitize

    assert sanitize({"password": PASSWORD})["password"] == "[REDACTED]"


def test_agent_never_receives_literal_redacted_marker(tmp_path, monkeypatch):
    """The credential the model reads is a handle, not a ``[REDACTED]`` marker."""
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    store = ControlStore(tmp_path / "facts.db")
    store.initialize()
    handle = default_secret_store().put(PASSWORD)
    board = Blackboard(store)
    board.record(
        tenant_id=TENANT,
        engagement_id="eng-vault",
        fact_type="credential",
        key=f"cred:ssh:lin@{TARGET}",
        value={"username": "lin", "service": "ssh", "secret_ref": handle},
        source="nexus.cred.bruteforce",
        created_by="deterministic-verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="cred_bruteforce_completed",
        invocation_id="invocation-1",
    )
    rendered = board.render(TENANT, "eng-vault")
    assert "[REDACTED]" not in rendered
    assert handle in rendered
    # The clue the model actually needs to make the next call reachable.
    assert "secret_ref" in rendered


# =============================================== V1-31: access needs a session
@pytest.mark.parametrize(
    "tool_id, verification_method, output",
    [
        ("nexus.cred.bruteforce", "cred_bruteforce_completed",
         {"target": TARGET, "service": "ssh", "username": "lin",
          "valid_credentials": [{"host": TARGET, "username": "lin", "password": PASSWORD}]}),
        ("nexus.post.pivot_bruteforce", "pivot_credential_validated",
         {"target": TARGET, "form_url": "http://x/j_security_check",
          "valid_credentials": [{"username": "admin", "password": PASSWORD}]}),
        ("nexus.web.wp_bruteforce", "wp_credential_validated",
         {"url": "http://x/blog", "username": "admin",
          "valid_credentials": [{"username": "admin", "password": PASSWORD}]}),
    ],
)
def test_cred_bruteforce_does_not_derive_access(tmp_path, monkeypatch, tool_id,
                                               verification_method, output):
    """Validating a password proves the password: never a session."""
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    result = ToolResult(output=output, verified=True, verification_method=verification_method)
    context = mock.Mock(invocation_id="invocation-1", run_id="run-1", tenant_id=TENANT)
    rows = derive_assertions(tool_id, {}, result, context)

    assert {row["fact_type"] for row in rows} == {"credential"}
    assert all("password" not in row["value"] for row in rows)


@pytest.mark.parametrize(
    "tool_id, verification_method, output",
    [
        ("nexus.post.ssh_exec", "ssh_exec_completed",
         {"target": TARGET, "command": "id", "stdout": "uid=0(root)", "exit_status": 0}),
        ("nexus.win.winrm_exec", "winrm_command_executed",
         {"target": TARGET, "command": "whoami", "stdout": "nt authority\\system"}),
        ("nexus.web.wp_exec", "wp_command_executed",
         {"url": "http://x", "outputs": [{"command": "id", "stdout": "uid=0(root)"}]}),
    ],
)
def test_access_fact_requires_real_session(tool_id, verification_method, output):
    """A command that really ran on the host is what proves access."""
    result = ToolResult(output=output, verified=True, verification_method=verification_method)
    context = mock.Mock(invocation_id="invocation-1", run_id="run-1", tenant_id=TENANT)
    rows = derive_assertions(tool_id, {}, result, context)

    assert "access" in {row["fact_type"] for row in rows}


def test_plan_does_not_close_exploitation_without_session():
    """A credential closes enumeration; only a session closes exploitation."""
    credential_only = {"host": 1, "service": 1, "credential": 1}
    plan = build_plan(counts=credential_only)
    assert active_phase(credential_only) == "exploitation"
    assert {phase.id: phase.status for phase in plan.phases}["exploitation"] == "current"

    with_session = {**credential_only, "access": 1}
    assert active_phase(with_session) == "privilege_escalation"
    assert {phase.id: phase.status for phase in build_plan(counts=with_session).phases}[
        "exploitation"
    ] == "done"


# ============================================ V1-32: the backend error survives
def test_ssh_exec_surfaces_backend_error(tmp_path):
    """A failed channel answers with *why*, not ``exit_status: null``."""
    payload = {"ok": False, "connected": False,
               "error": "AuthenticationException: Authentication failed."}
    with _fake_sandbox(ssh_module, SandboxResult(0, json.dumps(payload) + "\n", "")):
        result = asyncio.run(
            ssh_exec_handler(
                {"target": TARGET, "username": "lin", "password": "wrong", "command": "id"},
                _context(),
            )
        )

    assert result.verified is False
    assert result.output["error"] == "AuthenticationException: Authentication failed."
    assert result.evidence["error_detail"] == "AuthenticationException: Authentication failed."
    assert result.output["exit_status"] is None


def test_tool_result_includes_error_detail_when_backend_fails(tmp_path):
    """The diagnostic is bounded and absent on a healthy call."""
    detail = "SSHException: " + "x" * 1000
    payload = {"ok": False, "connected": False, "error": detail}
    with _fake_sandbox(ssh_module, SandboxResult(0, json.dumps(payload) + "\n", "")):
        failed = asyncio.run(
            ssh_exec_handler(
                {"target": TARGET, "username": "lin", "password": "wrong", "command": "id"},
                _context(),
            )
        )
    assert len(failed.evidence["error_detail"]) == ssh_module.SSH_ERROR_DETAIL_MAX
    assert len(failed.output["error"]) == ssh_module.SSH_ERROR_DETAIL_MAX

    healthy = {"ok": True, "connected": True, "stdout": "uid=0(root)\n", "stderr": "",
               "exit_status": 0}
    with _fake_sandbox(ssh_module, SandboxResult(0, json.dumps(healthy) + "\n", "")):
        ok = asyncio.run(
            ssh_exec_handler(
                {"target": TARGET, "username": "lin", "password": PASSWORD, "command": "id"},
                _context(),
            )
        )
    assert ok.verified is True
    assert "error" not in ok.output and "error_detail" not in ok.evidence


# =================================== V1-30: banner and NDJSON stream hygiene
def test_banner_never_prints_secret_plaintext():
    """The trust-mode banner announces the call, never the credential."""
    from nexus_core.cli import render

    buffer = StringIO()
    render.set_color_enabled(False)
    try:
        with contextlib.redirect_stdout(buffer):
            render.render_trust_mode(
                "nexus.post.ssh_exec",
                {"target": TARGET, "username": "lin", "password": PASSWORD, "command": "id",
                 "options": {"PASSWORD": PASSWORD}},
                "operator:kali",
            )
    finally:
        render.set_color_enabled(True)

    printed = buffer.getvalue()
    assert PASSWORD not in printed
    assert "[REDACTED]" in printed
    assert TARGET in printed and "nexus.post.ssh_exec" in printed


def test_banner_shows_the_handle_instead_of_the_secret():
    """A ``credential_ref`` is shown by its own key: it is a pointer, not a secret."""
    from nexus_core.cli import render

    buffer = StringIO()
    render.set_color_enabled(False)
    handle = "vault:" + "a" * 32
    try:
        with contextlib.redirect_stdout(buffer):
            render.render_trust_mode(
                "nexus.post.ssh_exec",
                {"target": TARGET, "username": "lin", "credential_ref": handle, "command": "id"},
                "operator:kali",
            )
    finally:
        render.set_color_enabled(True)

    printed = buffer.getvalue()
    assert handle in printed
    assert PASSWORD not in printed


class _FakeStream:
    """Minimal session stub: enough for ``run_headless`` to write its record."""

    def __init__(self, store: ControlStore) -> None:
        self.store = store
        self.tenant_id = TENANT
        self.engagement_id = None
        self.run_id = None
        self.conversation_id = None
        self.max_iterations = 1
        self.worker_id = "worker-test"
        self.agent_id = "agent-test"
        self.permissions = ()
        self.active_skills = []
        self.trust_mode = False
        self.subagent_override = None
        self.llm_client = None
        self.agent_identity_payload = {"subject_id": "operator-1", "roles": ["operator"]}

    def _ensure_work_session(self) -> str:
        return "conversation-test"


def test_cli_stream_json_keeps_stdout_machine_readable(onboarding_env, monkeypatch, capsys):
    """The real ``omni run --stream-json``: banner and record never share stdout.

    This is the interface the rerun 8 consumer used (``grep -cv '^{'`` over
    stdout). It also pins the pre-run path: a message printed before the run
    starts must land on stderr too, and the record must not end up on the stream
    the guard installed.
    """
    import omni

    from nexus_core.cli import headless, render

    monkeypatch.setenv("LLM_PROVIDER", "fake")
    monkeypatch.setenv("NEXUS_LLM_DEFAULT_PROVIDER", "fake")

    class CompletedRun:
        status = "completed"
        completion_verified = True
        iterations = 1
        findings: list = []
        plan = None
        subagent_id = None
        final_summary = "ok"

    async def fake_loop(**kwargs):
        # The banner is exactly what used to land in the NDJSON stream.
        render.render_trust_mode("nexus.post.ssh_exec", {"target": TARGET, "password": PASSWORD},
                                 "operator:kali")
        return CompletedRun()

    monkeypatch.setattr(headless, "run_react_loop", fake_loop)

    code = omni.main(["run", "enumerate services", "--stream-json", "--no-wizard"])
    captured = capsys.readouterr()

    lines = [line for line in captured.out.splitlines() if line.strip()]
    assert lines, "the CLI must write its record to stdout"
    parsed = [json.loads(line) for line in lines]  # a banner line breaks this
    assert parsed[-1]["type"] == "run.complete"
    assert "\x1b[" not in captured.out
    assert PASSWORD not in captured.out
    # The banner went to stderr, redacted, and so did the pre-run notice.
    assert "TRUST MODE" in captured.err and "[REDACTED]" in captured.err
    assert PASSWORD not in captured.err
    assert code == 0


def test_stream_json_stdout_is_pure_ndjson(tmp_path, monkeypatch):
    """Under ``--stream-json`` stdout is NDJSON only; humans read stderr."""
    from nexus_core.cli import headless, render

    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    store = ControlStore(tmp_path / "stream.db")
    store.initialize()

    async def fake_loop(**kwargs):
        # The banner is exactly what used to land in the NDJSON stream.
        render.render_trust_mode("nexus.post.ssh_exec", {"target": TARGET, "password": PASSWORD},
                                 "operator:kali")
        headless.write_line(sys_stdout_holder["stream"], {"type": "react.action", "payload": {}})
        return SimpleResult()

    class SimpleResult:
        status = "completed"
        completion_verified = True
        iterations = 1
        findings = []
        plan = None
        subagent_id = None
        final_summary = "ok"

    stdout = StringIO()
    stderr = StringIO()
    sys_stdout_holder = {"stream": stdout}
    # No explicit ``stream=``: this is how ``omni run --stream-json`` calls it, so
    # the run record must land on the stdout that existed *before* the guard
    # re-routed human output -not on the stderr the guard installed.
    with mock.patch.object(headless, "run_react_loop", side_effect=fake_loop), \
            contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
        code = headless.run_headless(_FakeStream(store), "objetivo", mode="stream",
                                     max_iterations=1, preflight=None)

    lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
    assert lines, "the run must emit at least one NDJSON line"
    parsed_lines = [json.loads(line) for line in lines]  # a non-JSON line breaks this
    assert all(isinstance(parsed, dict) for parsed in parsed_lines)
    # The record itself is on stdout, not on the stream the banner was moved to.
    assert parsed_lines[-1]["type"] == "run.complete"
    assert PASSWORD not in stdout.getvalue()
    assert "\x1b[" not in stdout.getvalue()
    server_side = stderr.getvalue()
    assert "TRUST MODE" in server_side
    assert "[REDACTED]" in server_side
    assert PASSWORD not in server_side
    assert code == 0
