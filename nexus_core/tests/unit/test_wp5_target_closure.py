"""WP5 · Cierre limpio cuando el objetivo ya está cumplido.

Measured in the RootMe run (``run_3b7cc43f…``): the agent captured
``flag{fake_flag_user}`` and ``flag{fake_flag_root}`` and then kept firing
curls until the 250k budget killed the run with ``status=budget_exceeded`` and
exit 1 -the work was done and the process said it failed. The three mechanics
pinned here are:

* FIX 1 - the flags the objective asked for are detected deterministically from
  the board (verified ``loot`` facts) or from the successful output of this run
  (a webshell command prints them with no verifier assertion at all).
* FIX 2 - the next prompt carries an imperative closure warning.
* FIX 3 - after three tool calls that ignore it, the loop intercepts the next
  one and closes with a synthesized ``task_complete``; the run ends
  ``completed`` / ``completion_verified=true`` / ``exit_code=0``.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent.planner import (
    expected_flag_count,
    flag_tokens,
    target_reached,
)
from nexus_core.agent.react import (
    STATUS_BUDGET_EXCEEDED,
    STATUS_COMPLETED,
    ReActConfig,
    run_react_loop,
)
from nexus_core.agent.react_types import (
    TARGET_REACHED_EVENT_TYPE,
    TARGET_REACHED_FORCED_EVENT_TYPE,
    TARGET_REACHED_GRACE_TURNS,
    TARGET_REACHED_PROMPT,
)
from nexus_core.cli.headless import result_payload
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("lab_scope")]

TENANT = "system"
ENGAGEMENT = "eng-wp5"
TARGET = "10.0.0.1"
USER_FLAG = "flag{fake_flag_user}"
ROOT_FLAG = "flag{fake_flag_root}"
INVOCATION = "wp5-invocation"
OBJECTIVE = (
    "Resuelve la sala RootMe en 10.0.0.1. Consigue una shell, escala "
    "privilegios y captura user.txt y root.txt."
)

SHELL_OK = {
    "tool_id": "nexus.shell.exec",
    "output": {
        "success": True,
        "verified": True,
        "verification_method": "shell_exit_code",
        "evidence": {"exit_code": 0, "stdout_lines": 1},
        "output": {"command": "cat /root/root.txt", "stdout": f"{ROOT_FLAG}\n", "exit_code": 0},
    },
}

#: The RootMe shape: one webshell command printed both flags, no assertion at all.
SHELL_TWO_FLAGS = {
    "tool_id": "nexus.shell.exec",
    "output": {
        "success": True,
        "verified": True,
        "verification_method": "shell_exit_code",
        "evidence": {"exit_code": 0, "stdout_lines": 2},
        "output": {
            "command": "cat user.txt root.txt",
            "stdout": f"{USER_FLAG}\n{ROOT_FLAG}\n",
            "exit_code": 0,
        },
    },
}


# ------------------------------------------------------------------- primitives
def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _loot_fact(flag: str, *, verified: bool = True, key: str | None = None) -> dict:
    return {
        "fact_type": "loot",
        "key": key or flag,
        "value": {"flag": flag, "command": "cat user.txt", "service": "webshell"},
        "source": "nexus.post.ssh_exec",
        "verified": verified,
        "asserted_by": "verifier" if verified else "agent",
        "verification_method": "ssh_exec_completed" if verified else "",
        "invocation_id": INVOCATION if verified else "",
    }


def _engagement(tmp_path, name: str, flags: tuple[str, ...] = (USER_FLAG, ROOT_FLAG)):
    """An engagement whose board already carries the captured flags."""
    store = ControlStore(tmp_path / name)
    store.initialize()
    EngagementStore(store).create(
        EngagementScope(
            engagement_id=ENGAGEMENT,
            tenant_id=TENANT,
            name="wp5",
            client="acme",
            owner_id="owner-1",
            valid_from=_iso(-timedelta(days=1)),
            valid_until=_iso(timedelta(days=1)),
            cidrs=("10.0.0.0/24",),
            domains=(),
            urls=(),
            exclusions=(),
            created_at=_iso(timedelta(0)),
        )
    )
    board = Blackboard(store)
    board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="host",
        key=TARGET,
        value={"ip": TARGET},
        source="nexus.recon.nmap",
        created_by="deterministic-verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="nmap_xml_parsed",
        invocation_id=INVOCATION,
    )
    for flag in flags:
        board.record(
            tenant_id=TENANT,
            engagement_id=ENGAGEMENT,
            fact_type="loot",
            key=flag,
            value={"flag": flag, "command": "cat user.txt", "service": "webshell"},
            source="nexus.post.ssh_exec",
            created_by="deterministic-verifier",
            verified=True,
            asserted_by="verifier",
            verification_method="ssh_exec_completed",
            invocation_id=INVOCATION,
        )
    return store


def _context(store) -> ExecutionContext:
    run = store.create_run(TENANT, {})
    task = {
        "id": f"task-{run['id']}",
        "tenant_id": TENANT,
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": OBJECTIVE,
            "engagement_id": ENGAGEMENT,
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": [],
        },
    }
    return ExecutionContext(store, task, "worker-test")


def _events(store, run_id, event_type):
    return [
        event
        for event in store.list_run_events(TENANT, run_id)
        if event.get("event_type") == event_type
    ]


class ScriptedLLM:
    """Replays scripted answers, repeating the last one when exhausted."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0
        self.prompts: list[str] = []

    async def complete(self, messages, **kwargs):
        self.calls += 1
        index = min(self.calls - 1, max(0, len(self.responses) - 1))
        self.prompts.append("\n".join(str(m.content) for m in messages))
        return LLMResponse(
            content=self.responses[index] if self.responses else "",
            model="scripted-test",
            provider=LLMProvider.FAKE,
        )


class ToolSpy:
    """Stands in for ``execute_tool``: records the payload and returns *response*."""

    def __init__(self, response: dict | None = None):
        self.payloads: list[dict] = []
        self.response = response or SHELL_OK

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        result = copy.deepcopy(self.response)
        result["tool_id"] = payload["tool_id"]
        result["output"]["assertions"] = [
            {
                "invocation_id": INVOCATION,
                "run_id": context.run_id,
                "target": TARGET,
                "fact_type": "loot",
                "verified": True,
                "verification_method": "shell_exit_code",
            }
        ]
        return result


def _tool_call(command: str = "cat /root/root.txt") -> str:
    return json.dumps(
        {
            "thought": "Sigo buscando vectores.",
            "action": "tool_call",
            "tool_id": "nexus.shell.exec",
            "arguments": {"command": command},
            "expected_outcome": "más datos",
        }
    )


def _complete() -> str:
    return json.dumps(
        {
            "thought": "Objetivo cumplido.",
            "action": "task_complete",
            "summary": "flags capturadas",
            "findings": [],
        }
    )


# ------------------------------------------------------- FIX 1 · the rule itself
def test_only_verified_flag_loot_reaches_the_target():
    objective = "Captura las flags de la sala"
    assert target_reached([_loot_fact(USER_FLAG)], objective=objective).reached is True
    # A lead is a hypothesis: an agent-recorded flag is not evidence.
    assert target_reached([_loot_fact(USER_FLAG, verified=False)], objective=objective).reached is False
    # Loot that is not flag-shaped is not a capture.
    assert target_reached(
        [{"fact_type": "loot", "key": "notes", "value": {"note": "nada"},
          "verified": True, "asserted_by": "verifier",
          "verification_method": "m", "invocation_id": "i"}],
        objective=objective,
    ).reached is False
    # An objective that never asked for flags is not a flag hunt.
    assert target_reached([_loot_fact(USER_FLAG)], objective="Enumera el servidor web").reached is False


def test_a_second_named_flag_file_must_also_be_captured():
    assert expected_flag_count(OBJECTIVE) == 2
    assert expected_flag_count("Captura la flag") == 1
    assert target_reached([_loot_fact(USER_FLAG)], objective=OBJECTIVE).reached is False
    both = target_reached([_loot_fact(USER_FLAG), _loot_fact(ROOT_FLAG)], objective=OBJECTIVE)
    assert both.reached is True
    assert both.flags == (USER_FLAG, ROOT_FLAG)
    assert both.verified is True


#: Vulnversity: ``user.txt`` is an MD5, ``root.txt`` another hash. Neither has a
#: ``flag{fake_flag}`` shape, so only the key (the file the verifier proved it read) can
#: say the objective was met.
MD5_USER = "8bd7992fbe8a6ad22a63361004cfcedb"
MD5_ROOT = "a9c5f1d2e3b4c5d6e7f8091a2b3c4d5e"


def _flag_file_loot(key: str, content: str, *, verified: bool = True) -> dict:
    return {
        "fact_type": "loot",
        "key": key,
        "value": {"content": content, "flag": content, "path": key.split("@")[0]},
        "verified": verified,
        "asserted_by": "verifier" if verified else "agent",
        "verification_method": "ssh_exec_completed" if verified else "",
        "invocation_id": INVOCATION if verified else "",
    }


def test_a_hash_capture_counts_when_the_key_names_the_flag_file():
    verdict = target_reached(
        [_flag_file_loot("ssh:file:user.txt", MD5_USER)],
        objective="captura user.txt y root.txt",
    )
    # One of the two named files is in hand, so the objective is not yet met.
    assert verdict.reached is False
    assert verdict.flags == (MD5_USER,)

    both = target_reached(
        [_flag_file_loot("ssh:file:user.txt", MD5_USER),
         _flag_file_loot("root.txt@10.0.0.1", MD5_ROOT)],
        objective="captura user.txt y root.txt",
    )
    assert both.reached is True
    assert set(both.flags) == {MD5_USER, MD5_ROOT}
    assert all(source["verified"] for source in both.sources)


def test_an_agent_declared_hash_is_not_a_capture():
    fact = _flag_file_loot("ssh:file:user.txt", MD5_USER, verified=False)
    assert target_reached([fact], objective="captura user.txt").reached is False


def test_a_flag_file_capture_is_loot_even_without_a_prefix():
    from nexus_core.agent.planner import loot_is_evidence

    assert loot_is_evidence({"content": MD5_USER, "flag": MD5_USER}) is True
    assert loot_is_evidence(
        {"content": "W3ll d0n3. You made it!", "flag": "W3ll d0n3. You made it!"}
    ) is True
    assert loot_is_evidence({"note": "nada que ver"}) is False


def test_a_flag_nested_under_its_own_key_is_still_a_capture():
    """The RootMe fact used ``user_txt``/``root_txt``, not ``flag``."""
    assert flag_tokens({"user_txt": USER_FLAG}) == (USER_FLAG,)
    fact = _loot_fact(ROOT_FLAG)
    fact["value"] = {"user_txt": USER_FLAG, "root_txt": ROOT_FLAG}
    verdict = target_reached([fact], objective="captura user.txt y root.txt")
    assert verdict.reached is True
    assert set(verdict.flags) == {USER_FLAG, ROOT_FLAG}


# ------------------------------------- FIX 2 · the prompt of the following turn
async def test_the_prompt_orders_the_closure_once_the_flags_are_in_hand(tmp_path):
    store = _engagement(tmp_path, "wp5-prompt.db")
    context = _context(store)
    llm = ScriptedLLM([_complete()])

    result = await run_react_loop(
        context=context,
        objective=OBJECTIVE,
        engagement_id=ENGAGEMENT,
        llm_client=llm,
        config=ReActConfig(max_iterations=4, enforce_completion_gates=True),
    )

    assert result.status == STATUS_COMPLETED
    assert TARGET_REACHED_PROMPT in llm.prompts[0]
    assert "OBJETIVO CUMPLIDO" in llm.prompts[0]
    event = _events(store, context.run_id, TARGET_REACHED_EVENT_TYPE)
    assert len(event) == 1
    assert set(event[0]["payload"]["flags"]) == {USER_FLAG, ROOT_FLAG}


# ------------------------------------- FIX 3 · the margin and the forced closure
async def test_three_tool_calls_after_the_warning_are_intercepted(tmp_path):
    store = _engagement(tmp_path, "wp5-force.db")
    context = _context(store)
    llm = ScriptedLLM([_tool_call()])
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective=OBJECTIVE,
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=ReActConfig(max_iterations=10, enforce_completion_gates=True),
        )

    # Two calls ran; the third was intercepted before reaching the gateway.
    assert len(spy.payloads) == TARGET_REACHED_GRACE_TURNS - 1
    assert result.status == STATUS_COMPLETED
    assert result.status != STATUS_BUDGET_EXCEEDED
    forced = [entry for entry in result.actions if entry.get("forced")]
    assert len(forced) == 1
    assert forced[0]["action"] == "task_complete"
    assert set(forced[0]["flags"]) == {USER_FLAG, ROOT_FLAG}
    assert {finding["value"]["flag"] for finding in result.findings} == {
        USER_FLAG,
        ROOT_FLAG,
    }
    assert _events(store, context.run_id, TARGET_REACHED_FORCED_EVENT_TYPE)
    # Every turn after the detection carried the imperative warning.
    assert TARGET_REACHED_PROMPT in llm.prompts[1]
    assert TARGET_REACHED_PROMPT in llm.prompts[2]


async def test_the_forced_closure_produces_a_clean_run_complete(tmp_path):
    store = _engagement(tmp_path, "wp5-complete.db")
    context = _context(store)
    llm = ScriptedLLM([_tool_call()])

    with mock.patch.object(runtime_module, "execute_tool", ToolSpy()):
        result = await run_react_loop(
            context=context,
            objective=OBJECTIVE,
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=ReActConfig(max_iterations=10, enforce_completion_gates=True),
        )

    payload = result_payload(result, context.run_id)
    assert payload["type"] == "run.complete"
    assert payload["status"] == "completed"
    assert payload["termination_reason"] == "completed"
    assert payload["completion_verified"] is True
    assert payload["exit_code"] == 0
    # The technical objective and the deliverable are two different claims: this
    # forced closure never produced a report, and the summary has to say so
    # instead of implying an engagement that was engaged *and* reported
    # (Bounty Hacker v2, 2026-10-31).
    assert "objetivo técnico cumplido" in payload["summary"]
    assert "informe PENDIENTE" in payload["summary"]


# ------------------------------- the measured RootMe shape: no verifier assertion
async def test_a_flag_printed_by_a_successful_tool_output_closes_the_run(tmp_path):
    """The board has no loot fact: the flag lives in the command output."""
    store = _engagement(tmp_path, "wp5-observed.db", flags=())
    context = _context(store)
    llm = ScriptedLLM([_tool_call("cat user.txt root.txt")])
    spy = ToolSpy(SHELL_TWO_FLAGS)

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective=OBJECTIVE,
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=ReActConfig(max_iterations=10, enforce_completion_gates=True),
        )

    event = _events(store, context.run_id, TARGET_REACHED_EVENT_TYPE)
    assert event and event[0]["payload"]["sources"][0]["source"] == "observation"
    assert result.status == STATUS_COMPLETED
    assert result_payload(result, context.run_id)["exit_code"] == 0
