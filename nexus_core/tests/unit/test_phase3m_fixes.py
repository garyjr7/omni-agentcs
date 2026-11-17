"""Phase 3m fix: the vault secret can no longer be echoed into an observation.

Measured in rerun 13 (``run_c1b80861abcd408fb5fdd956b1271c8a``, see
``docs/missions/diag/diag_rerun13_2026-10-16.md`` §11.4): iteration 8 ran a
command that **starts with ``sudo``** and carries ``-n``::

    sudo -n -l 2>&1; echo '---SUID---'; find / -perm -4000 -type f …

``ssh_exec_handler`` (``ssh_post.py``) saw the ``sudo `` prefix, rewrote it to
``sudo -S -n -l …`` and wrote the credential to stdin; the paramiko client opened
the channel with ``get_pty=True`` because there was stdin. ``sudo -n`` means "do
not ask", so sudo never read that stdin — the pty's terminal echo printed the
password as a bare line of the tool's ``stdout``, which became an observation the
model read and that ``kernel_messages`` persisted. The value was exactly an entry
of ``locks.txt`` (index 9) and it appeared **0 times** in the NDJSON: the model had
sent ``credential_ref``, so it did not come from the argv.

That contradicts the invariant ``kernel/secret_store.py`` declares for the vault:
the plaintext must never enter *a result, an observation or the model's context*.

Two independent halves, both pinned here:

* **the cause** — no password is injected when ``sudo`` is told not to ask
  (``-n``/``--non-interactive``), and no pty is ever allocated on a channel that
  carries the secret (a pipe is enough for ``sudo -S``); and
* **the net** — the resolved credential is redacted from the observation, the
  evidence and the raw client capture of the three SSH handlers, by value rather
  than by field name, so a target that echoes it for any other reason cannot get
  it into the model's context either.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.agent.evidence import annotate_findings, fabricated_evidence
from nexus_core.agent.planner import (
    OBJECTIVE_COMPLETE_SUBAGENTS,
    PHASES,
    build_plan,
    objective_completion,
)
from nexus_core.agent.react_coordinator import ReActCoordinator
from nexus_core.agent.react_services import ContextBuilder
from nexus_core.agent.react_support import (
    _completion_objections,
    _premature_completion_message,
)
from nexus_core.agent.react_types import (
    BUDGET_EXEMPT_EVENT_TYPE,
    OBJECTIVE_COMPLETE_EVENT_TYPE,
    STATUS_SUBAGENT_BUDGET,
    ReActConfig,
)
from nexus_core.agent.subagents import select_for_plan
from nexus_core.agent.turn_telemetry import TurnTelemetryRecorder
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.redaction import redact_secret_values
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import ssh_post as module
from nexus_core.tools.handlers.ssh_post import (
    SSH_CLIENT_SCRIPT,
    enum_system_handler,
    ssh_exec_handler,
    sudo_needs_no_password,
)

pytestmark = pytest.mark.unit

TARGET = "10.0.0.1"
#: A same-shape stand-in for the credential of the run (17 characters, i.e. above
#: ``MIN_INLINE_SECRET_LENGTH``, so both the line-exact and the inline path are
#: exercised). The real value stays out of the repository.
SECRET = "P4ssw0rdSynd1cat3"

#: The command of iteration 8 of the rerun 13, verbatim.
RERUN13_COMMAND = (
    "sudo -n -l 2>&1; echo '---SUID---'; find / -perm -4000 -type f 2>/dev/null; "
    "echo '---CAPS---'; getcap -r / 2>/dev/null; echo '---USERFLAG---'; "
    "find / -name user.txt 2>/dev/null; find / -name root.txt 2>/dev/null"
)

#: Its stdout, verbatim except for the credential (see ``SECRET``).
RERUN13_STDOUT = (
    "sudo: a password is required\r\n"
    "---SUID---\r\n"
    f"{SECRET}\r\n"
    "/snap/core18/2934/bin/mount\r\n"
    "/snap/core18/2934/bin/ping\r\n"
    "/usr/bin/pkexec\r\n"
    "---CAPS---\r\n"
    "/bin/ping = cap_net_raw+ep\r\n"
)


class FakeSandbox:
    def __init__(self, result: SandboxResult):
        self.result = result
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append((list(argv), timeout_seconds))
        return self.result


@contextlib.contextmanager
def _fake_sandbox(result: SandboxResult):
    sandbox = FakeSandbox(result)
    with mock.patch.object(
        module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(handler, arguments: dict) -> object:
    return asyncio.run(handler(arguments, _context()))


def _sandbox_for(payload: dict, exit_code: int = 0) -> SandboxResult:
    return SandboxResult(exit_code, json.dumps(payload) + "\n", "")


def _exec(command: str, payload: dict) -> tuple[dict, object, FakeSandbox]:
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run(
            ssh_exec_handler,
            {"target": TARGET, "username": "lin", "password": SECRET, "command": command},
        )
    remote = json.loads(sandbox.calls[0][0][-1])
    return remote, result, sandbox


# --------------------------------------------------- the cause: no contradictory stdin


@pytest.mark.parametrize(
    "command",
    [
        "sudo -n -l",
        "sudo --non-interactive -l",
        "sudo -nl -l",
        # Conservative: the flag belongs to the wrapped program, and the injection
        # is still skipped. Failing closed costs one call; leaking costs a secret.
        "sudo /bin/tar cf /dev/null /dev/null -n",
    ],
)
def test_sudo_with_n_flag_does_not_inject_password_to_stdin(command):
    """``-n`` means "do not ask for a password": injecting one contradicts it.

    Rerun 13 measured the consequence: sudo did not read stdin, the pty echoed the
    password and the model read it.
    """
    assert sudo_needs_no_password(command) is True

    remote, result, _ = _exec(
        command,
        {"ok": True, "connected": True, "stdout": "sudo: a password is required\n",
         "stderr": "", "exit_status": 1},
    )
    # The command reaches the target exactly as the model wrote it: no ``-S`` is
    # added and nothing is written to stdin.
    assert remote["command"] == command
    assert remote["stdin"] is None
    assert result.evidence["sudo_stdin"] is False
    assert result.evidence["sudo_stdin_skipped"] == "non_interactive_flag"


def test_sudo_with_S_reads_password_from_stdin_without_pty_echo():
    """Without ``-n`` the credential is fed on stdin, and no pty echoes it back."""
    assert sudo_needs_no_password("sudo /bin/tar cf /dev/null /dev/null") is False

    remote, result, _ = _exec(
        "sudo /bin/tar cf /dev/null /dev/null",
        {"ok": True, "connected": True, "stdout": "uid=0(root)\n", "stderr": "",
         "exit_status": 0},
    )
    assert remote["command"].startswith("sudo -S ")
    assert remote["stdin"] == SECRET + "\n"
    assert result.evidence["sudo_stdin"] is True
    assert "sudo_stdin_skipped" not in result.evidence

    # The pty is what echoed the secret: a channel that carries it must be a pipe.
    assert "get_pty=True" not in SSH_CLIENT_SCRIPT
    assert "get_pty=False" in SSH_CLIENT_SCRIPT


# ------------------------------------------------------ the net: redaction by value


def test_output_redacted_when_it_matches_the_vault_secret():
    """A known value is removed from text, whether it is a line of its own or not."""
    redacted = redact_secret_values(RERUN13_STDOUT, (SECRET,))
    assert SECRET not in redacted
    assert "[REDACTED]" in redacted
    # Only the secret changes: the rest of the evidence survives byte for byte.
    assert "sudo: a password is required" in redacted
    assert "/snap/core18/2934/bin/mount" in redacted
    assert "/bin/ping = cap_net_raw+ep" in redacted

    # Indented, inline and CRLF shapes.
    assert redact_secret_values(f"\t{SECRET}\r\n", (SECRET,)) == "\t[REDACTED]\r\n"
    assert redact_secret_values(
        f"[sudo] password for lin: {SECRET}\n", (SECRET,)
    ) == "[sudo] password for lin: [REDACTED]\n"

    # A short value is only redacted as a whole line: replacing it inside a line
    # would corrupt output that has nothing to do with the credential.
    assert redact_secret_values("pw is not the word\n", ("pw",)) == "pw is not the word\n"
    assert redact_secret_values("pw\n", ("pw",)) == "[REDACTED]\n"
    # Nothing to redact and no values are both no-ops.
    assert redact_secret_values("", (SECRET,)) == ""
    assert redact_secret_values("text\n", ()) == "text\n"


def test_no_secret_leak_in_observation_after_sudo_S():
    """Even if the target echoes the secret, it never reaches the model."""
    payload = {
        "ok": True,
        "connected": True,
        "stdout": f"[sudo] password for lin: {SECRET}\r\nuid=0(root) gid=0(root)\r\n",
        "stderr": f"{SECRET}\r\n",
        "exit_status": 0,
    }
    _, result, _ = _exec("sudo /bin/tar cf /dev/null /dev/null", payload)

    blob = json.dumps(
        {
            "output": result.output,
            "evidence": result.evidence,
            "stdout": result.stdout,
            "stderr": result.stderr,
        },
        ensure_ascii=False,
    )
    assert SECRET not in blob
    assert "[REDACTED]" in blob

    # The proof the escalation produced is untouched, and the raw client capture
    # is still valid JSON after the substitution.
    assert "uid=0(root)" in result.output["stdout"]
    assert json.loads(result.stdout)["stdout"].count("[REDACTED]") == 1


def test_regression_rerun13_leak_scenario():
    """The exact shape of the rerun 13: cause and net, on the same fixture.

    Iteration 8 of ``run_c1b80861abcd408fb5fdd956b1271c8a``: a ``sudo -n`` command
    whose tool output carried the vault password on its own line (stdout line 3),
    with the model's ``credential_ref`` in the arguments and 0 occurrences of the
    value in the NDJSON.
    """
    remote, result, _ = _exec(
        RERUN13_COMMAND,
        {"ok": True, "connected": True, "stdout": RERUN13_STDOUT, "stderr": "",
         "exit_status": 1},
    )

    # 1. The cause is gone: no ``-S`` rewrite, no stdin, audited as skipped.
    assert remote["command"] == RERUN13_COMMAND
    assert remote["stdin"] is None
    assert result.evidence["sudo_stdin_skipped"] == "non_interactive_flag"

    # 2. And if the target echoed it anyway, the observation cannot carry it.
    observation = json.dumps(
        {"output": result.output, "stdout": result.stdout, "stderr": result.stderr},
        ensure_ascii=False,
    )
    assert SECRET not in observation
    # The enumeration result the run needed is still there, line by line.
    assert "sudo: a password is required" in result.output["stdout"]
    assert result.output["stdout"].splitlines()[2].strip() == "[REDACTED]"
    assert "/usr/bin/pkexec" in result.output["stdout"]


def test_enum_system_result_is_redacted_too():
    """The same net covers the other handler that carries a credential."""
    payload = {
        "ok": True,
        "connected": True,
        "results": {
            "__SUDO__": {
                "command": "sudo -n -l",
                "stdout": f"[sudo] password for lin: {SECRET}\r\nUser lin may run …",
                "stderr": "",
                "exit_status": 0,
            }
        },
    }
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run(
            enum_system_handler,
            {"target": TARGET, "username": "lin", "password": SECRET},
        )
    blob = json.dumps(result.output, ensure_ascii=False)
    assert SECRET not in blob
    assert "[REDACTED]" in blob


# ══════════════════════════════════════════════════════════════════════════
# Fix 1 · V1-46 — ``post_exploitation`` gana su turno antes de cerrar
# ══════════════════════════════════════════════════════════════════════════

#: Run 13 of the series; also the run the phase-3m leak fix above was measured in.
RUN13 = "run_c1b80861abcd408fb5fdd956b1271c8a"
TENANT = "system"
ENGAGEMENT = "eng-3m"
TARGET = "10.0.0.1"
#: The user flag iteration 9 promoted as a verified ``loot`` fact.
FLAG = "flag{fake_flag}"

#: The board of the rerun 13 once the escalation landed (iteration 12): the
#: ``loot`` is from iteration 9, so it was already there when ``privilege``
#: arrived -which is exactly why the phase closed without a turn.
RERUN13_COUNTS = {
    "host": 1,
    "service": 3,
    "credential": 1,
    "access": 1,
    "loot": 1,
    "privilege": 1,
}

POST_EXPLOITATION = next(phase for phase in PHASES if phase.id == "post_exploitation")
PRIVILEGE_ESCALATION = next(phase for phase in PHASES if phase.id == "privilege_escalation")


def _loop_state() -> ReActCoordinator:
    """The coordinator's turn bookkeeping, without the rest of the loop.

    Only the two attributes ``_note_completed_turn`` reads are set, so the test
    drives the *real* counter instead of re-implementing it.
    """
    coordinator = ReActCoordinator.__new__(ReActCoordinator)
    # An empty plan, never read: each test replaces it through ``_turn`` before
    # the counter runs. It is a real plan so the stub keeps the loop's invariant.
    coordinator.plan = build_plan(counts={})
    coordinator.phase_turns = {}
    return coordinator


def _turn(coordinator: ReActCoordinator, counts: dict) -> object:
    """One iteration: the plan is built with the history, then the turn is spent."""
    plan = build_plan(counts=counts, phase_turns=coordinator.phase_turns)
    coordinator.plan = plan
    coordinator._note_completed_turn()
    return plan


def test_post_exploitation_cannot_close_in_same_turn_it_opened():
    """``min_turns=1``: the phase that consumes the privilege gets a turn first."""
    assert POST_EXPLOITATION.min_turns == 1

    # The state iteration 12 left behind in the rerun 13: the escalation closed
    # *during the run* (its own turn is already recorded) while the `loot` was
    # already on the board from iteration 9.
    plan = build_plan(counts=RERUN13_COUNTS, phase_turns={"privilege_escalation": 1})
    statuses = {item.id: item.status for item in plan.phases}

    assert statuses["privilege_escalation"] == "done"
    assert statuses["post_exploitation"] == "current"
    assert plan.progress == (4, 6)
    # And the profile that owns it is the one that can read root.txt as root.
    assert select_for_plan(plan).id == "postexploit"

    # The hold is about a phase that opened *during the run*: a board that arrives
    # already complete (a resumed run, a second objective of the same session) is
    # not held, because the turn it would demand is not one this run owes.
    assert build_plan(counts=RERUN13_COUNTS, phase_turns={}).current == "reporting"


def test_post_exploitation_closes_after_one_turn():
    """One full turn is enough: the hold releases on the next plan."""
    opened = build_plan(counts=RERUN13_COUNTS, phase_turns={"privilege_escalation": 1})
    assert opened.current == "post_exploitation"

    released = build_plan(counts=RERUN13_COUNTS, phase_turns={"privilege_escalation": 1,
                                                              "post_exploitation": 1})
    assert released.current == "reporting"
    assert released.progress == (5, 6)

    # It counts *this* phase's turns, not the run's, and it does not accumulate:
    # more turns than demanded release it just the same.
    assert build_plan(
        counts=RERUN13_COUNTS, phase_turns={"privilege_escalation": 9}
    ).current == "post_exploitation"
    assert build_plan(
        counts=RERUN13_COUNTS, phase_turns={"privilege_escalation": 1, "post_exploitation": 5}
    ).current == "reporting"


def test_rerun13_scenario_postexploit_gets_a_turn():
    """The measured sequence, turn by turn (iterations 9 onward).

    Before the fix, iteration 12 closed ``privilege_escalation`` **and**
    ``post_exploitation`` in the same turn (the ``loot`` of iteration 9 already
    satisfied the second), the plan jumped to ``reporting``, the selected profile
    became ``reporter`` and iteration 13 was denied the ``ssh_exec`` it needed,
    because that profile is ``read_only``.
    """
    coordinator = _loop_state()
    without_privilege = dict(RERUN13_COUNTS)
    without_privilege.pop("privilege")

    # Iterations 9-11: the user flag is captured, root is not.
    plan = _turn(coordinator, without_privilege)
    assert plan.current == "privilege_escalation"
    assert select_for_plan(plan).id == "privesc"

    # Iteration 12: `sudo /bin/tar` proves uid=0 in the same turn the escalation
    # closes; the phase that consumes it cannot be closed by that evidence.
    plan = _turn(coordinator, RERUN13_COUNTS)
    assert plan.current == "post_exploitation"
    assert select_for_plan(plan).id == "postexploit"
    assert coordinator.phase_turns == {
        "privilege_escalation": 1,
        "post_exploitation": 1,
    }

    # Iteration 14: post-exploitation has had its turn; the plan may close.
    plan = _turn(coordinator, RERUN13_COUNTS)
    assert plan.current == "reporting"
    assert select_for_plan(plan).id == "reporter"


def test_phase_without_min_turns_closes_immediately_as_today():
    """Regression: nothing changed for phases that declare no ``min_turns``."""
    assert PRIVILEGE_ESCALATION.min_turns == 0
    assert [phase.id for phase in PHASES if phase.min_turns] == ["post_exploitation"]

    # `privilege` closes the escalation on the very turn it lands, as always.
    landed = build_plan(
        counts={"host": 1, "service": 3, "loot": 1, "privilege": 1}, phase_turns={}
    )
    assert {item.id: item.status for item in landed.phases}["privilege_escalation"] == "done"

    # Without a turn history at all (CLI, report, any other caller) the statuses
    # are the ones the evidence alone produces - exactly the behaviour before.
    assert build_plan(counts=RERUN13_COUNTS).current == "reporting"
    assert build_plan(counts=RERUN13_COUNTS).progress == (5, 6)


# ══════════════════════════════════════════════════════════════════════════
# Fix 2 · V1-47 — el perfil que cierra el run ve el objetivo cumplido
# ══════════════════════════════════════════════════════════════════════════


def _privilege_fact(*, verified: bool = True) -> dict:
    return {
        "fact_type": "privilege",
        "key": TARGET,
        "value": {"uid": 0, "user": "root"},
        "source": "nexus.post.ssh_exec",
        "verified": verified,
        "asserted_by": "verifier" if verified else "agent",
        "verification_method": "ssh_exec_completed" if verified else "",
        "invocation_id": "inv-rerun13-priv" if verified else "",
    }


def _loot_fact(*, verified: bool = True) -> dict:
    return {
        "fact_type": "loot",
        "key": FLAG,
        "value": {"flag": FLAG, "command": "cat /home/lin/user.txt", "service": "ssh"},
        "source": "nexus.post.ssh_exec",
        "verified": verified,
        "asserted_by": "verifier" if verified else "agent",
        "verification_method": "ssh_exec_completed" if verified else "",
        "invocation_id": "inv-rerun13-loot" if verified else "",
    }


def test_objective_complete_with_reporter_profile():
    """The verdict reads the board, not the profile that happens to hold the turn."""
    assert "reporter" in OBJECTIVE_COMPLETE_SUBAGENTS
    facts = [_privilege_fact(), _loot_fact()]

    complete = objective_completion(facts, subagent_id="reporter")
    assert complete.complete is True
    assert complete.privilege_ref and complete.loot_refs

    # The material condition is unchanged, and it is still a gate: a profile that
    # does not own the tail of the chain sees nothing, and neither does `reporter`
    # without root + loot verified on the board.
    assert objective_completion(facts, subagent_id="recon").complete is False
    assert objective_completion([_privilege_fact()], subagent_id="reporter").complete is False
    assert objective_completion([_loot_fact()], subagent_id="reporter").complete is False
    assert objective_completion(
        [_privilege_fact(verified=False), _loot_fact(verified=False)],
        subagent_id="reporter",
    ).complete is False


def _board(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    return Blackboard(store), store


def _verified(board, *, fact_type: str, key: str, value: dict, invocation_id: str = "inv-rerun13-1"):
    return board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type=fact_type,
        key=key,
        value=value,
        source="nexus.post.ssh_exec",
        created_by="deterministic-verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="ssh_exec_completed",
        invocation_id=invocation_id,
    )


def _events(store, run_id: str, event_type: str) -> list[dict]:
    return [
        event
        for event in store.list_run_events(TENANT, run_id)
        if event.get("event_type") == event_type
    ]


def _bare_coordinator(store, *, run_id: str, plan, subagent_id: str = "reporter"):
    """The coordinator stripped to the state the closure rules read."""
    coordinator = ReActCoordinator.__new__(ReActCoordinator)
    coordinator.tenant_id = TENANT
    coordinator.engagement_id = ENGAGEMENT
    coordinator.store = store
    coordinator.run_id = run_id
    coordinator.iteration = 14
    coordinator.plan = plan
    coordinator.plan_reason = None
    coordinator.status = ""
    coordinator.final_summary = ""
    coordinator.last_phase = plan.current
    coordinator.last_subagent_id = subagent_id
    coordinator.subagent_override = None
    coordinator.subagent_iterations = 1
    coordinator.previous_profile = None
    coordinator.objective_complete = False
    coordinator.objective_complete_emitted = False
    coordinator.budget_exempt = False
    coordinator.telemetry = TurnTelemetryRecorder(
        store=store, tenant_id=TENANT, run_id=run_id
    )
    return coordinator


def test_budget_exempt_applies_when_reporter_has_objective_complete(tmp_path):
    """V1-38's waiver now reaches the profile that closes the run.

    The verdict is computed by the *rule* (the half this fix changes), not set by
    the test: only the wiring between the rule and the ceiling is under test.
    """
    board, store = _board(tmp_path)
    run = store.create_run(TENANT, {"engagement_id": ENGAGEMENT})
    _verified(board, fact_type="privilege", key=TARGET, value={"uid": 0, "user": "root"})
    _verified(board, fact_type="loot", key=FLAG, value={"flag": FLAG, "service": "ssh"})

    plan = build_plan(counts=RERUN13_COUNTS, phase_turns={"post_exploitation": 1})
    assert plan.current == "reporting"
    coordinator = _bare_coordinator(store, run_id=run["id"], plan=plan)
    coordinator.objective_complete = objective_completion(
        coordinator._blackboard_facts(), subagent_id="reporter"
    ).complete
    assert coordinator.objective_complete is True
    # `reporter` is already over its own ceiling when the turn opens (its budget is
    # 30 000; the rerun 13 measured 31 669).
    store.record_usage(TENANT, run["id"], "model_route", "react:reporter", "tokens", 31_669)

    transition = asyncio.run(coordinator._select_profile())

    assert transition.name == "READY"
    assert coordinator.budget_exempt is True
    assert coordinator.status != STATUS_SUBAGENT_BUDGET
    payload = _events(store, run["id"], BUDGET_EXEMPT_EVENT_TYPE)[0]["payload"]
    assert payload["subagent_id"] == "reporter"
    assert payload["spent"] == 31_669
    assert payload["budget_exempt_if_objective_complete"] is True


def test_rerun13_scenario_reporter_exempt_from_token_budget(tmp_path):
    """Iterations 13-14 of the rerun 13, over the run's own board.

    Measured in the run: ``reporter`` was selected at iteration 13 (the plan had
    jumped straight to ``reporting``), spent 31 669 of its 30 000 tokens, the
    verdict came back ``false`` because ``reporter`` was not an accepted profile,
    ``react.budget_exempt`` fired **0** times and the run died without
    ``task_complete``. After V1-46 the phase gets its turn first; after V1-47 the
    reporter -which is now the one holding it- is exempt and can close.
    """
    board, store = _board(tmp_path)
    run = store.create_run(TENANT, {"engagement_id": ENGAGEMENT})
    for fact_type, key, value in (
        ("host", TARGET, {"ip": TARGET}),
        ("service", f"{TARGET}:22", {"port": 22}),
        ("credential", "cred:ssh:lin@10.0.0.1", {"username": "lin"}),
        ("access", f"{TARGET}:lin", {"user": "lin"}),
        ("loot", FLAG, {"flag": FLAG, "service": "ssh"}),
        ("privilege", TARGET, {"uid": 0, "user": "root"}),
    ):
        _verified(board, fact_type=fact_type, key=key, value=value)

    # Iteration 13: the turn the escalation closed in is already recorded (this run
    # has been running since iteration 1), so the phase that consumes the privilege
    # is the current one -and the profile that owns it is the one with ssh_exec.
    snapshot = asyncio.run(_gather(store, run["id"], phase_turns={"privilege_escalation": 1}))
    assert snapshot.plan.current == "post_exploitation"
    assert select_for_plan(snapshot.plan).id == "postexploit"

    # Iteration 14: it has had its turn, the plan closes and the reporter takes it.
    snapshot = asyncio.run(
        _gather(store, run["id"], phase_turns={"privilege_escalation": 1, "post_exploitation": 1})
    )
    assert snapshot.plan.current == "reporting"
    assert select_for_plan(snapshot.plan).id == "reporter"

    coordinator = _bare_coordinator(store, run_id=run["id"], plan=snapshot.plan)
    store.record_usage(TENANT, run["id"], "model_route", "react:reporter", "tokens", 31_669)

    # The verdict the run never had, audited once with its refs.
    coordinator._refresh_objective_complete()
    assert coordinator.objective_complete is True
    emitted = _events(store, run["id"], OBJECTIVE_COMPLETE_EVENT_TYPE)
    assert len(emitted) == 1
    assert emitted[0]["payload"]["subagent_id"] == "reporter"
    assert emitted[0]["payload"]["privilege_ref"] == TARGET
    assert FLAG in emitted[0]["payload"]["loot_refs"]

    # And the turn that closes the run is not the turn the ceiling kills.
    assert asyncio.run(coordinator._select_profile()).name == "READY"
    assert coordinator.budget_exempt is True
    assert len(_events(store, run["id"], BUDGET_EXEMPT_EVENT_TYPE)) == 1


def test_rerun13_postexploit_profile_can_read_root_txt():
    """Regression: the turn the phase gained is held by a profile that can use it.

    Iteration 13 of the run tried ``ssh_exec`` to read ``root.txt`` and the gateway
    denied it (``subagent_tool_denied``): the selected profile was ``reporter`` -
    ``read_only``, no ``nexus.post.ssh_exec``- because the plan had skipped
    post-exploitation entirely. With the phase held open, the profile that owns it
    is the one that can spend the privilege.
    """
    from nexus_core.agent.subagents import SUBAGENTS_BY_ID

    plan = build_plan(counts=RERUN13_COUNTS, phase_turns={"privilege_escalation": 1})
    selected = select_for_plan(plan)

    assert selected.id == "postexploit"
    assert selected.read_only is False
    assert "nexus.post.ssh_exec" in selected.tools

    # The counterfactual the fix removes: the closing profile cannot do it.
    reporter = SUBAGENTS_BY_ID["reporter"]
    assert reporter.read_only is True
    assert "nexus.post.ssh_exec" not in reporter.tools


def _gather(store, run_id: str, *, phase_turns=None):
    """The plan one iteration would see, through the loop's own context path."""
    return ContextBuilder().gather(
        store=store,
        tenant_id=TENANT,
        run_id=run_id,
        conversation_id=f"conv-{run_id}",
        llm_client=None,
        config=ReActConfig(enable_summarization=False),
        hooks=SimpleNamespace(emit=lambda *args, **kwargs: None),
        engagement_id=ENGAGEMENT,
        phase_turns=phase_turns,
    )


# ══════════════════════════════════════════════════════════════════════════
# Fix 3 · V1-48 — el rechazo dice *qué* cita está mal
# ══════════════════════════════════════════════════════════════════════════


def _observation(invocation_id: str, fact_type: str, target: str, *, value=None) -> dict:
    return {
        "verified": True,
        "verification_method": "ssh_exec_completed",
        "run_id": RUN13,
        "invocation_id": invocation_id,
        "fact_type": fact_type,
        "target": target,
        "value": value if value is not None else {"port": 22},
    }


def test_premature_completion_exposes_per_finding_detail():
    """The payload carries, per rejected finding, what it cited and why (V1-48)."""
    observations = [
        _observation("inv-loot", "loot", TARGET),
        _observation("inv-priv", "privilege", TARGET),
    ]
    findings = [
        {"title": "Root por sudo tar", "invocation_id": "inv-inventado",
         "fact_type": "privilege", "target": TARGET},
        # A real invocation, cited as the wrong type. The title claims root, so
        # the citation is refused by the guard that still applies (V1-50): no
        # verified ``privilege`` assertion of that invocation.
        {"title": "Escalada a root por sudo tar", "invocation_id": "inv-loot",
         "fact_type": "privilege", "target": TARGET},
    ]

    _, stats = annotate_findings(findings, observations=observations, run_id=RUN13)

    # The counters the run 13 already had are untouched, and so is the gate.
    assert stats["findings_total"] == 2 and stats["stale"] == 2 and stats["grounded"] == 0
    assert fabricated_evidence(stats) is True

    detail = stats["rejected_findings"]
    assert [item["finding_ref"] for item in detail] == [
        "Root por sudo tar",
        "Escalada a root por sudo tar",
    ]
    first, second = detail
    assert first["reason"] == "stale_evidence"
    assert first["cited"] == {
        "invocation_id": "inv-inventado",
        "fact_type": "privilege",
        "target": TARGET,
    }
    # The invocation was invented, so nothing of it is in the corpus -and the
    # suggestion is the observation that shares type *and* target.
    assert first["found_in_corpus"] is False
    assert first["closest_match"]["invocation_id"] == "inv-priv"
    # The second one cites a real invocation of this run, but as the wrong type.
    assert second["found_in_corpus"] is True
    assert second["objection"] == "root_claim_needs_privilege_fact"
    assert second["closest_match"]["invocation_id"] == "inv-loot"
    assert second["closest_match"]["fact_type"] == "loot"

    # A lead with no citation at all is detailed too, and gets no suggestion.
    _, bare = annotate_findings([{"title": "Algo sin cita"}], observations=observations, run_id=RUN13)
    assert bare["rejected_findings"][0]["closest_match"] is None
    assert bare["rejected_findings"][0]["cited"]["invocation_id"] == ""


def test_premature_completion_suggests_correct_citation():
    """The correction the model reads names the finding and how to check it."""
    observations = [_observation("inv-priv", "privilege", TARGET, value={"uid": 0})]
    findings = [{"title": "Root por sudo tar", "invocation_id": "inv-otro",
                 "fact_type": "privilege", "target": TARGET}]
    _, stats = annotate_findings(findings, observations=observations, run_id=RUN13)
    # The plan of the turn after iteration 12: the phase is held, so the refusal
    # mixes the phase objection with the citation detail.
    plan = build_plan(counts=RERUN13_COUNTS, phase_turns={"privilege_escalation": 1})

    objections = _completion_objections(
        plan,
        enforce_completion_gates=True,
        evidence_stats=stats,
        engagement_id=ENGAGEMENT,
    )
    message = _premature_completion_message(objections, plan)

    assert "Root por sudo tar" in message
    assert "invocation_id=inv-otro" in message
    assert "query_facts" in message
    assert "no aparece en ninguna observación de este run" in message
    # The way out: the observation that would ground the claim.
    assert "inv-priv" in message
    assert "La observación más cercana del corpus" in message


def test_a_finding_with_its_own_value_still_grounds():
    """The model's summary in ``value`` is not a contradiction (measured bug).

    Simple CTF, 2026-10-18 (``run_fc39e6369d1c440e92a4d2e4e2db5250``): both flags
    captured, four ``task_complete`` attempts, and every finding refused as
    ``stale_evidence`` with a citation identical to the observation it named -
    because the finding carried its own ``value`` dict.
    """
    observations = [
        _observation("inv-loot", "loot", TARGET,
                     value={"flag": "W3ll d0n3. You made it!", "path": "/root/root.txt"}),
    ]
    findings = [{
        "title": "Flag capturada en root.txt",
        "invocation_id": "inv-loot", "fact_type": "loot", "target": TARGET,
        "value": {"flag": "W3ll d0n3. You made it!", "obtained_via": "sudo vim"},
    }]

    annotated, stats = annotate_findings(findings, observations=observations, run_id=RUN13)

    assert stats["grounded"] == 1 and stats["rejected_findings"] == []
    # The observation's value wins: the model's prose never becomes evidence.
    assert annotated[0]["value"] == observations[0]["value"]
    assert annotated[0]["evidence_source"] == "current_run"


def test_a_root_claim_still_needs_a_privilege_fact():
    """The narrowing keeps the guard: claiming root on a loot fact is refused."""
    observations = [_observation("inv-loot", "loot", TARGET, value={"flag": "x"})]
    findings = [{
        "title": "Escalada a root vía sudo vim",
        "invocation_id": "inv-loot", "fact_type": "loot", "target": TARGET,
    }]

    _, stats = annotate_findings(findings, observations=observations, run_id=RUN13)

    assert stats["grounded"] == 0 and stats["stale"] == 1
    assert stats["rejected_findings"][0]["objection"] == "root_claim_needs_privilege_fact"


def test_a_summarized_value_is_accepted_and_the_observation_wins():
    """A different value on one key no longer refuses a real citation (V1-50).

    The model habitually restates the observation in its own words (``port``
    22 while the assertion carries 2222, a ``user`` key the fact does not
    have). That is a summary, not a fabrication: grounding rewrites the finding
    with the *observation's* value, so the report can never carry the model's
    version as evidence.
    """
    observations = [_observation("inv-svc", "service", TARGET, value={"port": 2222})]
    findings = [{
        "title": "Servicio ssh",
        "invocation_id": "inv-svc", "fact_type": "service", "target": TARGET,
        "value": {"port": 22},
    }]

    annotated, stats = annotate_findings(findings, observations=observations, run_id=RUN13)

    assert stats["grounded"] == 1 and stats["stale"] == 0
    assert annotated[0]["value"] == {"port": 2222}
    # The model's claim is preserved only as a hypothesis, never as evidence.
    assert annotated[0]["declared_finding"]["value"] == {"port": 22}
    assert annotated[0]["declared_finding"]["verification_status"] == "hypothesis"


def test_a_citation_with_the_wrong_fact_type_still_grounds():
    """The invocation is the identity; the type only ranks the candidates.

    Measured in Simple CTF (2026-10-18, ``run_fc39e6369d1c440e92a4d2e4e2db5250``):
    the same ``ssh_exec`` invocation asserted ``access``, ``credential`` and
    ``privilege``, and findings that cited ``access`` where the model meant the
    host -or ``hint`` where it meant ``host``- were refused for three
    ``task_complete`` attempts with both flags already captured.
    """
    observations = [
        _observation("inv-ssh", "access", TARGET, value={"username": "mitch"}),
        _observation("inv-ssh", "privilege", TARGET, value={"uid": 0, "user": "root"}),
    ]
    findings = [{
        # Cites ``host`` (an assertion this invocation did not make) and writes
        # the target with the ssh port attached.
        "title": "Acceso SSH como mitch",
        "invocation_id": "inv-ssh", "fact_type": "host", "target": f"{TARGET}:22",
        "value": {"username": "mitch", "port": 22},
    }]

    annotated, stats = annotate_findings(findings, observations=observations, run_id=RUN13)

    assert stats["grounded"] == 1 and stats["stale"] == 0
    # The typed fact that grounds it is the observation's, not the model's.
    assert annotated[0]["fact_type"] == "access"
    assert annotated[0]["target"] == TARGET
    assert annotated[0]["value"] == {"username": "mitch"}


def test_a_changed_flag_is_refused_and_named():
    """A flag is the one value that cannot differ from the observation."""
    observations = [_observation(
        "inv-loot", "loot", TARGET,
        value={"flag": "flag{fake_flag_observed}", "path": "/root/root.txt"},
    )]
    findings = [{
        "title": "Flag capturada en root.txt",
        "invocation_id": "inv-loot", "fact_type": "loot", "target": TARGET,
        "value": {"flag": "flag{fake_flag_changed}"},
    }]

    _, stats = annotate_findings(findings, observations=observations, run_id=RUN13)

    assert stats["stale"] == 1 and stats["grounded"] == 0
    rejected = stats["rejected_findings"][0]
    assert rejected["reason"] == "stale_evidence"
    assert rejected["objection"] == "flag_conflict:flag{fake_flag_changed}"
    assert rejected["found_in_corpus"] is True


def test_grounded_finding_still_passes():
    """Regression: a correctly cited finding grounds, and grounds nothing else."""
    observations = [
        _observation("inv-priv", "privilege", TARGET, value={"uid": 0, "user": "root"})
    ]
    findings = [{"invocation_id": "inv-priv", "fact_type": "privilege", "target": TARGET}]

    annotated, stats = annotate_findings(findings, observations=observations, run_id=RUN13)

    assert stats["grounded"] == 1 and stats["stale"] == 0 and stats["unsupported"] == 0
    assert stats["rejected_findings"] == []
    assert fabricated_evidence(stats) is False
    assert annotated[0]["verification_status"] == "confirmed_finding"
    assert annotated[0]["evidence_source"] == "current_run"

    # With the plan on its final phase, a completion built on it is not refused.
    plan = build_plan(counts=RERUN13_COUNTS, phase_turns={"post_exploitation": 1})
    assert plan.current == "reporting"
    assert _completion_objections(
        plan,
        enforce_completion_gates=True,
        evidence_stats=stats,
        engagement_id=ENGAGEMENT,
    ) == []


@pytest.fixture(autouse=True)
def _legacy_phase_loop(monkeypatch):
    """WP2: these tests pin the phase-gated loop, now behind the legacy flag."""
    monkeypatch.setenv("NEXUS_LEGACY_PROFILES", "1")
