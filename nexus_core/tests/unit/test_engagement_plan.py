"""PLAN MODE: the engagement's TODO contract, before and during the ACT loop.

The measured defect (run v8, ``run_a00cddfa69da488d8946188daddee3e3``): the run
captured one flag and closed, because the only thing holding it was the
deterministic kill chain -and a single ``loot`` satisfies ``post_exploitation``.
What was missing is not another heuristic: it is the contract the engagement
promised (*"compromete, escala a root y captura las flags"*) written down, shared
and enforced.

These tests pin the whole path: the Markdown file, the tools that write it, the
planning turn, the PLAN-FIRST gate (no attack without a plan), the closure gate
(no closure with TODOs open) and the panel that shows it to the human.
"""

from __future__ import annotations

import copy
import json
import os
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent.engagement_plan import (
    PLAN_RELATIVE_PATH,
    TODO_DONE,
    TODO_FAILED,
    Todo,
    is_bounded_order,
    is_engagement_objective,
    load_plan,
    new_plan,
    parse_markdown,
    plan_path,
    prompt_block,
    reconcile,
    render_markdown,
    save_plan,
    seed_todos,
    status_payload,
    todo_from_mapping,
)
from nexus_core.agent.planning import draft_engagement_plan, todos_from_payload
from nexus_core.agent.react import (
    STATUS_COMPLETED,
    STATUS_MAX_ITERATIONS,
    STATUS_PREMATURE_COMPLETION,
    ReActConfig,
    run_react_loop,
)
from nexus_core.agent.react_types import MAX_PREMATURE_COMPLETIONS
from nexus_core.cli.tui.panels import panel_lines
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore
from nexus_core.tools.handlers.plan_engagement import (
    CREATE_PLAN_TOOL,
    create_plan_handler,
    get_plan_status_handler,
    update_plan_handler,
)

#: The loop fixtures are unsigned on purpose (``lab`` scope mode), exactly like
#: the other loop suites of this repo.
pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("lab_scope")]

TENANT = "system"
ENGAGEMENT = "eng-plan"
OBJECTIVE = (
    "Realiza una prueba de penetración. Compromete el sistema, escala a root y "
    "captura las flags como prueba del compromiso. Documenta la cadena de ataque."
)


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _todo(raw: dict) -> Todo:
    return todo_from_mapping(raw)


def _fact(fact_type: str, key: str, **value) -> dict:
    return {
        "fact_type": fact_type,
        "key": key,
        "value": value,
        "verified": True,
        "asserted_by": "verifier",
        "verification_method": "test",
        "invocation_id": "inv-1",
    }


# ------------------------------------------------------------- objective shape
def test_a_question_never_gets_a_plan():
    """The operator's rule: a question is answered by reasoning, not by a plan."""
    for question in (
        "¿Qué es un pivot en un pentest?",
        "Explica la diferencia entre SUID y capabilities",
        "resume lo que hicimos en la sala anterior",
    ):
        assert is_engagement_objective(question) is False, question


def test_an_engagement_instruction_gets_a_plan():
    assert is_engagement_objective(OBJECTIVE) is True
    assert is_engagement_objective("Escanea 10.10.10.5 y enumera los servicios") is True
    assert is_engagement_objective("audita https://lab.local/") is True


def test_a_bounded_scan_order_is_not_an_engagement():
    # Measured failure (2026-11-10): this objective was planned with 5 TODOs
    # and could not close because `report-results` stayed pending.
    objective = "Escanea los puertos 80 y 443 de scanme.nmap.org usando nmap."
    assert is_engagement_objective(objective) is False
    assert is_bounded_order(objective) is True


# --------------------------------------------------------------- the Markdown
def test_the_plan_is_a_real_markdown_checklist_at_loot(tmp_path):
    plan = new_plan(
        OBJECTIVE,
        ENGAGEMENT,
        [
            _todo({"id": "recon", "description": "Descubrir puertos",
                   "evidence": "nmap full_tcp", "fact_types": ["host", "service"]}),
            _todo({"id": "flag_root", "description": "Capturar root.txt",
                   "fact_types": ["flag"]}),
        ],
    )
    path = save_plan(plan, str(tmp_path))

    assert path == str(tmp_path / "loot" / "ENGAGEMENT_PLAN.md")
    text = (tmp_path / "loot" / "ENGAGEMENT_PLAN.md").read_text(encoding="utf-8")
    # The exact 9-item shape the operator asked for: human-readable checkboxes.
    assert "- [ ] `recon` — Descubrir puertos" in text
    assert "## TODOs" in text
    assert load_plan(str(tmp_path)) == plan


def test_the_file_round_trips_through_the_parser(tmp_path):
    plan = new_plan(
        OBJECTIVE,
        ENGAGEMENT,
        [_todo({"id": "a", "description": "Paso (con paréntesis) y — guiones",
                "fact_types": ["privilege"], "evidence": "uid=0"})],
    )
    parsed = parse_markdown(render_markdown(plan))
    assert parsed == plan
    assert parsed.todos[0].description == "Paso (con paréntesis) y — guiones"


def test_an_empty_or_unrelated_file_is_no_plan(tmp_path):
    (tmp_path / "loot").mkdir()
    (tmp_path / "loot" / "ENGAGEMENT_PLAN.md").write_text("# notas\n", encoding="utf-8")
    assert load_plan(str(tmp_path)) is None


def test_a_todo_id_or_fact_type_is_validated():
    with pytest.raises(ValueError, match="invalid todo id"):
        _todo({"id": "con espacios", "description": "x"})
    with pytest.raises(ValueError, match="unknown fact type"):
        _todo({"id": "x", "description": "x", "fact_types": ["invented"]})
    with pytest.raises(ValueError, match="needs a description"):
        _todo({"id": "x", "description": "  "})


# ------------------------------------------------------- evidence reconciliation
def test_a_verified_fact_ticks_the_todo_that_declared_it():
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "access", "description": "Acceso", "fact_types": ["credential"]}),
        _todo({"id": "flag_root", "description": "root", "fact_types": ["flag"]}),
        _todo({"id": "report", "description": "informe"}),
    ])
    updated, ticks = reconcile(plan, [
        _fact("credential", "john", user="john"),
        _fact("loot", "/root/root.txt", flag="flag{fake_flag}"),
    ])

    assert ticks == ["access", "flag_root"]
    statuses = {todo.id: todo.status for todo in updated.todos}
    assert statuses == {"access": TODO_DONE, "flag_root": TODO_DONE, "report": "pending"}
    assert updated.todos[1].verified_by.startswith("loot:")
    # The report declares no fact type: only the model closes it.
    assert updated.todos[2].status == "pending"


def test_a_lead_never_ticks_a_todo():
    """``verified`` must be true: the agent's own claim is not evidence."""
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "access", "description": "Acceso", "fact_types": ["credential"]}),
    ])
    lead = _fact("credential", "john")
    lead["verified"] = False
    _, ticks = reconcile(plan, [lead])
    assert ticks == []


def test_a_fact_from_another_engagement_does_not_tick_anything():
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "access", "description": "Acceso", "fact_types": ["credential"]}),
    ])
    _, ticks = reconcile(plan, [_fact("credential", "john")], engagement_id="eng-other")
    assert ticks == []


def test_the_first_flag_does_not_tick_the_root_todo():
    """A TODO that names its file only accepts that file (the v8 confusion)."""
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "flag_root", "description": "Capturar /root/root.txt",
               "fact_types": ["flag"]}),
    ])
    _, ticks = reconcile(plan, [
        _fact("loot", "/home/lin/user.txt", flag="flag{fake_flag}"),
    ])
    assert ticks == []

    _, ticks = reconcile(plan, [
        _fact("loot", "/root/root.txt", flag="flag{fake_flag}"),
    ])
    assert ticks == ["flag_root"]


def test_a_todo_that_names_hosts_waits_for_a_fact_on_that_host():
    """DeadDrop (2026-10-22): el barrido de la DMZ cerró el TODO del pivote.

    El plan tenía ``pivot`` (nombrando 192.168.11.51 y 192.168.11.100) y
    ``enum-lan``; los hechos ``service`` de 192.168.11.200:22/80 los dieron por
    hechos, así que el agente podía creer la LAN enumerada sin haberla tocado.
    """
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "pivot", "description": "Pivote a 192.168.11.51 y 192.168.11.100",
               "fact_types": ["host", "service"]}),
    ])
    dmz = _fact("service", "192.168.11.200:80:tcp", port="80")
    dmz["target"] = "192.168.11.200"
    _, ticks = reconcile(plan, [dmz])
    assert ticks == []

    internal = _fact("host", "192.168.11.100", state="up")
    internal["target"] = "192.168.11.100"
    _, ticks = reconcile(plan, [internal])
    assert ticks == ["pivot"]


def test_a_step_from_a_proved_host_to_a_new_one_is_not_proved_by_the_source():
    """DeadDrop P2 (2026-10-22): «pivote desde .200 hacia .51/.100».

    El TODO nombra el host de origen y los de destino; el barrido del origen ya
    lo había probado, así que sin esta regla el hecho ``host:.200`` cerraba el
    pivote y el plan mentía por segunda vez.
    """
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "recon", "description": "Barrido de 192.168.11.200",
               "fact_types": ["host"]}),
        _todo({"id": "pivot",
               "description": "Pivote desde 192.168.11.200 hacia 192.168.11.51 "
                              "y 192.168.11.100",
               "fact_types": ["access", "host"]}),
    ])
    dmz = _fact("host", "192.168.11.200", state="up")
    dmz["target"] = "192.168.11.200"
    updated, ticks = reconcile(plan, [dmz])
    assert ticks == ["recon"]

    internal = _fact("host", "192.168.11.51", state="up")
    internal["target"] = "192.168.11.51"
    _, ticks = reconcile(updated, [dmz, internal])
    assert ticks == ["pivot"]


def test_a_todo_that_only_names_a_proved_host_keeps_the_old_rule():
    """Reverificar el mismo host (foothold → privesc) no se bloquea."""
    plan = new_plan("o", ENGAGEMENT, [
        Todo("recon", "Barrido de 192.168.11.200", fact_types=("host",),
             status=TODO_DONE, verified_by="host:192.168.11.200"),
        _todo({"id": "privesc", "description": "Escalar en 192.168.11.200",
               "fact_types": ["access"]}),
    ])
    got_root = _fact("access", "192.168.11.200:root")
    got_root["target"] = "192.168.11.200"
    _, ticks = reconcile(plan, [got_root])
    assert ticks == ["privesc"]


def test_a_todo_that_names_hosts_still_accepts_a_fact_with_no_address():
    """Un hecho sin IP propia no se puede atribuir: se conserva el comportamiento."""
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "creds", "description": "Credenciales hacia 192.168.11.100",
               "fact_types": ["credential"]}),
    ])
    updated, ticks = reconcile(plan, [_fact("credential", "john", user="john")])
    assert ticks == ["creds"]
    assert updated.todos[0].verified_by.startswith("credential:")


def test_a_loot_without_a_flag_is_not_a_flag():
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "flag_root", "description": "root", "fact_types": ["flag"]}),
    ])
    _, ticks = reconcile(plan, [_fact("loot", "/etc/passwd", command="cat")])
    assert ticks == []


def test_prompt_block_marks_the_next_todo_and_the_closure():
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "recon", "description": "Puertos", "fact_types": ["service"]}),
        _todo({"id": "report", "description": "Informe"}),
    ])
    block = prompt_block(plan)
    assert "[ ] recon" in block
    assert "SIGUIENTE TODO: recon" in block

    done = new_plan("o", ENGAGEMENT, [Todo("report", "Informe", status=TODO_DONE)])
    assert "TODOS COMPLETADOS" in prompt_block(done)


def test_status_payload_names_what_is_pending():
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "recon", "description": "Puertos", "fact_types": ["service"]}),
        _todo({"id": "flag_root", "description": "root", "fact_types": ["flag"]}),
    ])
    payload = status_payload(plan)
    assert payload["exists"] is True
    assert payload["pending"] == ["recon", "flag_root"]
    assert payload["flags_pending"] == ["flag_root"]
    assert payload["complete"] is False
    assert payload["path"] == PLAN_RELATIVE_PATH


# ------------------------------------------------------------------- the tools
@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    return tmp_path


def _context(*, engagement_id: str = "", store=None) -> RunContext:
    scope = None
    if engagement_id:
        scope = EngagementScope(
            engagement_id=engagement_id,
            tenant_id=TENANT,
            name="plan",
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
    return RunContext(
        tenant_id=TENANT,
        identity=Identity("operator-1", TENANT),
        scope=scope,
        store=store,
        objective=OBJECTIVE,
    )


async def test_create_plan_writes_the_contract_and_refuses_to_erase_progress(workspace):
    first = await create_plan_handler(
        {
            "todos": [
                {"id": "recon", "description": "Puertos", "fact_types": ["service"]},
                {"id": "report", "description": "Informe"},
            ]
        },
        _context(),
    )
    assert first.verified is True
    assert (workspace / "loot" / "ENGAGEMENT_PLAN.md").is_file()

    await update_plan_handler({"status": [{"id": "report", "status": "done"}]}, _context())
    with pytest.raises(ValueError, match="already has progress"):
        await create_plan_handler(
            {"todos": [{"id": "recon", "description": "Otra vez"}]}, _context()
        )


async def test_update_plan_cannot_declare_done_what_evidence_must_prove(workspace):
    await create_plan_handler(
        {"todos": [{"id": "flag_root", "description": "root", "fact_types": ["flag"]}]},
        _context(),
    )
    with pytest.raises(ValueError, match="closes with evidence"):
        await update_plan_handler(
            {"status": [{"id": "flag_root", "status": "done"}]}, _context()
        )
    # ... but it can justify it as failed, and that unblocks the closure.
    result = await update_plan_handler(
        {"status": [{"id": "flag_root", "status": "failed", "reason": "host sin root"}]},
        _context(),
    )
    assert result.output["counts"]["failed"] == 1
    assert result.output["counts"]["pending"] == 0


async def test_update_plan_requires_a_reason_to_fail(workspace):
    await create_plan_handler(
        {"todos": [{"id": "recon", "description": "Puertos"}]}, _context()
    )
    with pytest.raises(ValueError, match="without a reason"):
        await update_plan_handler(
            {"status": [{"id": "recon", "status": "failed"}]}, _context()
        )


async def test_update_plan_adds_a_newly_discovered_vector(workspace):
    await create_plan_handler(
        {"todos": [{"id": "recon", "description": "Puertos"}]}, _context()
    )
    result = await update_plan_handler(
        {"add": [{"id": "wp_admin", "description": "WordPress en /wp-admin",
                  "fact_types": ["credential"]}]},
        _context(),
    )
    ids = [todo["id"] for todo in result.output["todos"]]
    assert ids == ["recon", "wp_admin"]
    assert load_plan(str(workspace)).by_id("wp_admin") is not None


async def test_an_update_without_an_plan_says_what_to_call(workspace):
    with pytest.raises(ValueError, match=CREATE_PLAN_TOOL):
        await update_plan_handler({"add": [{"id": "x", "description": "y"}]}, _context())


async def test_get_plan_status_reconciles_with_the_board(workspace):
    store = ControlStore(workspace / "plan.db")
    store.initialize()
    EngagementStore(store).create(_context(engagement_id=ENGAGEMENT).scope)
    from nexus_core.kernel.blackboard import Blackboard

    Blackboard(store).record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="loot",
        key="/root/root.txt",
        value={"flag": "flag{fake_flag}"},
        source="nexus.shell.exec",
        created_by="verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="shell_exit_code",
        invocation_id="inv-1",
    )
    await create_plan_handler(
        {"todos": [
            {"id": "recon", "description": "Puertos", "fact_types": ["service"]},
            {"id": "flag_root", "description": "root", "fact_types": ["flag"]},
        ]},
        _context(engagement_id=ENGAGEMENT),
    )
    context = _context(engagement_id=ENGAGEMENT, store=store)

    result = await get_plan_status_handler({}, context)

    assert result.verified is True
    assert result.output["pending"] == ["recon"]
    assert result.output["counts"]["done"] == 1
    assert result.output["todos"][1]["verified_by"].startswith("loot:")
    # The tick is persisted, not just reported.
    assert load_plan(str(workspace)).by_id("flag_root").status == TODO_DONE


# ------------------------------------------------------------- planning (turn 0)
class ScriptedLLM:
    def __init__(self, content: str = "") -> None:
        self.content = content
        self.calls = 0
        self.messages: list[list[dict[str, str]]] = []

    async def complete(self, messages, **kwargs):
        self.calls += 1
        self.messages.append([{"role": m.role, "content": m.content} for m in messages])
        return LLMResponse(content=self.content, model="scripted", provider=LLMProvider.FAKE)


async def test_the_planning_turn_writes_the_model_plan(workspace):
    answer = json.dumps(
        {
            "todos": [
                {"id": "recon", "description": "Puertos", "fact_types": ["host", "service"]},
                {"id": "privesc", "description": "root", "fact_types": ["privilege"]},
                {"id": "flag_root", "description": "root.txt", "fact_types": ["flag"]},
                {"id": "report", "description": "Informe"},
            ]
        }
    )
    llm = ScriptedLLM(answer)

    plan = await draft_engagement_plan(
        llm_client=llm, objective=OBJECTIVE, engagement_id=ENGAGEMENT,
        workspace=str(workspace),
    )

    assert plan is not None and plan.source == "model"
    assert [todo.id for todo in plan.todos] == ["recon", "privesc", "flag_root", "report"]
    assert load_plan(str(workspace)) == plan
    # It is one call, before the loop: the plan is not negotiated turn by turn.
    assert llm.calls == 1
    assert OBJECTIVE in llm.messages[0][1]["content"]


async def test_a_broken_planning_answer_falls_back_to_the_seed(workspace):
    for answer in ("", "no soy JSON", '{"todos": []}', '{"todos": [{"id": "con espacio"}]}'):
        plan = await draft_engagement_plan(
            llm_client=ScriptedLLM(answer), objective=OBJECTIVE,
            engagement_id=ENGAGEMENT, workspace=str(workspace),
        )
        assert plan is not None and plan.source == "seed"
        assert plan.todos and plan.flags_pending
        (workspace / "loot" / "ENGAGEMENT_PLAN.md").unlink()


async def test_a_question_is_not_planned(workspace):
    llm = ScriptedLLM("{}")
    plan = await draft_engagement_plan(
        llm_client=llm, objective="¿Qué es un pivot?", engagement_id=ENGAGEMENT,
        workspace=str(workspace),
    )
    assert plan is None
    assert llm.calls == 0
    assert not (workspace / "loot" / "ENGAGEMENT_PLAN.md").exists()


async def test_a_bounded_scan_order_is_not_planned(workspace):
    objective = "Escanea los puertos 80 y 443 de scanme.nmap.org usando nmap."
    llm = ScriptedLLM("{}")
    plan = await draft_engagement_plan(
        llm_client=llm, objective=objective, engagement_id=ENGAGEMENT,
        workspace=str(workspace),
    )
    assert plan is None
    assert llm.calls == 0, "a bounded order must not pay for a planner call"
    assert not (workspace / "loot" / "ENGAGEMENT_PLAN.md").exists()


async def test_a_resumed_engagement_keeps_its_plan(workspace):
    existing = new_plan(OBJECTIVE, ENGAGEMENT, [
        Todo("recon", "Puertos", fact_types=("service",), status=TODO_DONE,
             verified_by="service:10.0.0.5:22/ssh"),
        Todo("flag_root", "root", fact_types=("flag",)),
    ])
    save_plan(existing, str(workspace))
    llm = ScriptedLLM('{"todos": [{"id": "otro", "description": "otro"}]}')

    plan = await draft_engagement_plan(
        llm_client=llm, objective=OBJECTIVE, engagement_id=ENGAGEMENT,
        workspace=str(workspace),
    )

    assert plan == existing
    assert llm.calls == 0, "a resume must not erase the ticks the evidence earned"


def test_planning_rejects_duplicate_ids_and_too_many_todos():
    with pytest.raises(ValueError, match="duplicate todo ids"):
        todos_from_payload({"todos": [
            {"id": "a", "description": "x"}, {"id": "a", "description": "y"}]})
    with pytest.raises(ValueError, match="too many todos"):
        todos_from_payload({"todos": [
            {"id": f"t{index}", "description": "x"} for index in range(30)]})


# ------------------------------------------------- the real CLI entry point
def test_the_cli_plans_before_it_acts_and_refuses_to_close(tmp_path):
    """The whole promise, through ``run_objective`` (the path an operator uses).

    PLAN MODE is one model call *before* the loop; the ACT loop then reads the
    contract from the prompt and cannot close while a TODO is open. This is the
    v8 failure reproduced with a scripted model: the plan exists first, and one
    ``task_complete`` is not enough.
    """
    from nexus_core.cli.session import OmniSession

    store = ControlStore(tmp_path / "cli.db")
    store.initialize()
    scope = EngagementStore(store).create(_context(engagement_id=ENGAGEMENT).scope)
    plan_answer = json.dumps(
        {
            "todos": [
                {"id": "recon", "description": "Puertos", "fact_types": ["host", "service"]},
                {"id": "flag_root", "description": "root.txt", "fact_types": ["flag"]},
                {"id": "report", "description": "Informe"},
            ]
        }
    )
    llm = ScriptedLLM_loop([plan_answer, _complete()])
    session = OmniSession(
        store=store,
        tenant_id=TENANT,
        engagement=scope,
        llm_client=llm,
        operator_id="operator:tester",
        use_tui=False,
    )
    session.workspace_root = tmp_path

    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        result = session.run_objective(OBJECTIVE)

    plan_file = tmp_path / "loot" / "ENGAGEMENT_PLAN.md"
    assert plan_file.is_file(), "the planning turn must write the contract first"
    stored = load_plan(str(tmp_path))
    assert [todo.id for todo in stored.todos] == ["recon", "flag_root", "report"]
    assert stored.source == "model"
    # The first model call is the plan, and it carries the engagement objective.
    assert "PLAN" in llm.messages[0][0]["content"]
    assert OBJECTIVE in llm.messages[0][1]["content"]
    # The ACT turn reads the contract back from the prompt.
    assert "PLAN DEL ENGAGEMENT" in llm.messages[1][0]["content"]
    assert "SIGUIENTE TODO: recon" in llm.messages[1][0]["content"]
    # ... and the run cannot close with the TODOs open.
    assert result.status == STATUS_PREMATURE_COMPLETION
    assert any("TODO" in objection for objection in result.completion_objections)


# ------------------------------------------------------------- the loop gates
TOOL_SUCCESS = {
    "tool_id": "nexus.recon.nmap",
    "output": {"success": True, "verified": True, "verification_method": "nmap_xml_parsed"},
}


class ToolSpy:
    def __init__(self) -> None:
        self.payloads: list[dict] = []

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        result = copy.deepcopy(TOOL_SUCCESS)
        result["tool_id"] = payload["tool_id"]
        return result


def _tool_call(tool_id: str, **arguments) -> str:
    return json.dumps(
        {
            "thought": "Sigo el plan.",
            "action": "tool_call",
            "tool_id": tool_id,
            "arguments": arguments or {"target": "10.0.0.5"},
            "expected_outcome": "evidencia",
        }
    )


def _complete() -> str:
    return json.dumps(
        {"thought": "He terminado.", "action": "task_complete", "summary": "hecho",
         "findings": []}
    )


@pytest.fixture()
def harness(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    store = ControlStore(tmp_path / "loop.db")
    store.initialize()
    EngagementStore(store).create(_context(engagement_id=ENGAGEMENT).scope)
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
    return store, ExecutionContext(store, task, "worker-test"), tmp_path


def _config(*, require_plan_first: bool = True, max_iterations: int = 6) -> ReActConfig:
    return ReActConfig(
        max_iterations=max_iterations,
        enforce_completion_gates=True,
        require_plan_first=require_plan_first,
    )


async def test_a_bounded_scan_order_runs_without_a_plan(harness):
    _, context, _ = harness
    objective = "Escanea los puertos 80 y 443 de 10.0.0.5 usando nmap."
    llm = ScriptedLLM_loop(
        [
            _tool_call(
                "nexus.recon.nmap", target="10.0.0.5", flags=["-p", "80,443"]
            ),
            _complete(),
        ]
    )
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context, objective=objective, engagement_id=ENGAGEMENT,
            llm_client=llm, config=_config(max_iterations=2),
        )

    assert [payload["tool_id"] for payload in spy.payloads] == ["nexus.recon.nmap"]
    assert result.status == STATUS_COMPLETED, "the scan itself closes the order"


async def test_no_attack_runs_before_the_plan_exists(harness):
    store, context, workspace = harness
    llm = ScriptedLLM_loop([_tool_call("nexus.recon.nmap"), _complete()])
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context, objective=OBJECTIVE, engagement_id=ENGAGEMENT,
            llm_client=llm, config=_config(max_iterations=3),
        )

    assert spy.payloads == [], "the nmap call must never reach the executor"
    denied = result.actions[0]["tool_result"]
    assert denied["status"] == "denied_no_plan"
    assert CREATE_PLAN_TOOL in denied["error"]
    events = [
        event for event in store.list_run_events(TENANT, context.run_id)
        if event["event_type"] == "orchestrator.plan_required"
    ]
    assert len(events) == 1


async def test_the_plan_tools_are_allowed_before_the_plan(harness):
    _, context, _ = harness
    llm = ScriptedLLM_loop([_tool_call(CREATE_PLAN_TOOL, todos=[
        {"id": "recon", "description": "Puertos", "fact_types": ["service"]}])])
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        await run_react_loop(
            context=context, objective=OBJECTIVE, engagement_id=ENGAGEMENT,
            llm_client=llm, config=_config(max_iterations=1),
        )

    assert [payload["tool_id"] for payload in spy.payloads] == [CREATE_PLAN_TOOL]


async def test_a_plan_with_open_todos_refuses_the_closure(harness):
    _, context, workspace = harness
    save_plan(
        new_plan(OBJECTIVE, ENGAGEMENT, [
            Todo("recon", "Puertos", fact_types=("service",)),
            Todo("flag_root", "root", fact_types=("flag",)),
        ]),
        str(workspace),
    )
    llm = ScriptedLLM_loop([_complete()])

    with mock.patch.object(runtime_module, "execute_tool", ToolSpy()):
        result = await run_react_loop(
            context=context, objective=OBJECTIVE, engagement_id=ENGAGEMENT,
            llm_client=llm, config=_config(max_iterations=MAX_PREMATURE_COMPLETIONS + 1),
        )

    assert result.status == STATUS_PREMATURE_COMPLETION
    assert any("TODO" in objection for objection in result.completion_objections)
    assert any("flag_root" in objection for objection in result.completion_objections)


async def test_a_plan_fully_closed_or_justified_lets_the_run_close(harness):
    _, context, workspace = harness
    save_plan(
        new_plan(OBJECTIVE, ENGAGEMENT, [
            Todo("recon", "Puertos", fact_types=("service",), status=TODO_DONE,
                 verified_by="service:22/ssh"),
            Todo("flag_root", "root", fact_types=("flag",), status=TODO_FAILED,
                 reason="host sin root tras 3 intentos"),
            Todo("report", "Informe", status=TODO_DONE),
        ]),
        str(workspace),
    )
    llm = ScriptedLLM_loop([_complete()])

    with mock.patch.object(runtime_module, "execute_tool", ToolSpy()):
        result = await run_react_loop(
            context=context, objective=OBJECTIVE, engagement_id=ENGAGEMENT,
            llm_client=llm, config=_config(),
        )

    assert result.status == STATUS_COMPLETED
    assert result.completion_objections == []
    assert result.engagement_plan["complete"] is True


def _capture_the_flag(store) -> None:
    """A verified flag on the board: the objective's first flag is in hand."""
    from nexus_core.kernel.blackboard import Blackboard

    Blackboard(store).record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="loot",
        key="/home/lin/user.txt",
        value={"flag": "flag{fake_flag}"},
        source="nexus.shell.exec",
        created_by="deterministic-verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="shell_exit_code",
        invocation_id="inv-flag",
    )


async def test_the_forced_closure_waits_for_the_flag_the_plan_promises(harness):
    """FIX 3: ``target_reached_forced`` only fires when the flag TODOs are done.

    The v8 shape: the first flag is in hand and the model keeps calling tools.
    WP5 would close the run at the margin; the plan says ``flag_root`` is still
    owed, so the margin is reset and the run keeps working instead.
    """
    store, context, workspace = harness
    _capture_the_flag(store)
    save_plan(
        new_plan(OBJECTIVE, ENGAGEMENT, [
            Todo("flag_user", "Primera flag", fact_types=("loot",), status=TODO_DONE,
                 verified_by="loot:/home/lin/user.txt"),
            Todo("flag_root", "root.txt", fact_types=("flag",)),
        ]),
        str(workspace),
    )
    llm = ScriptedLLM_loop([_tool_call("nexus.shell.exec", command="cat root.txt")])
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context, objective=OBJECTIVE, engagement_id=ENGAGEMENT,
            llm_client=llm, config=_config(max_iterations=4),
        )

    assert result.status != STATUS_COMPLETED, "the root flag is still owed"
    assert result.status == STATUS_MAX_ITERATIONS
    events = [
        event["event_type"] for event in store.list_run_events(TENANT, context.run_id)
    ]
    assert "orchestrator.plan_open_at_target" in events
    assert "react.target_reached_forced" not in events
    # The turns were spent executing the calls, not being intercepted.
    assert len(spy.payloads) >= 3


async def test_the_forced_closure_still_fires_when_the_plan_is_satisfied(harness):
    """The other side of FIX 3: a satisfied plan must not block the WP5 closure."""
    store, context, workspace = harness
    _capture_the_flag(store)
    save_plan(
        new_plan(OBJECTIVE, ENGAGEMENT, [
            Todo("flag_user", "Primera flag", fact_types=("loot",), status=TODO_DONE,
                 verified_by="loot:/home/lin/user.txt"),
            Todo("report", "Informe", status=TODO_DONE),
        ]),
        str(workspace),
    )
    llm = ScriptedLLM_loop([_tool_call("nexus.shell.exec", command="id")])
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context, objective=OBJECTIVE, engagement_id=ENGAGEMENT,
            llm_client=llm, config=_config(max_iterations=6),
        )

    assert result.status == STATUS_COMPLETED
    events = [
        event["event_type"] for event in store.list_run_events(TENANT, context.run_id)
    ]
    assert "react.target_reached_forced" in events


async def test_the_prompt_carries_the_plan_and_its_next_todo(harness):
    _, context, workspace = harness
    save_plan(
        new_plan(OBJECTIVE, ENGAGEMENT, [
            Todo("recon", "Descubrir puertos", fact_types=("service",)),
            Todo("flag_root", "Capturar root.txt", fact_types=("flag",)),
        ]),
        str(workspace),
    )
    llm = ScriptedLLM_loop([_complete()])

    with mock.patch.object(runtime_module, "execute_tool", ToolSpy()):
        await run_react_loop(
            context=context, objective=OBJECTIVE, engagement_id=ENGAGEMENT,
            llm_client=llm, config=_config(max_iterations=1),
        )

    system_prompt = llm.messages[0][0]["content"]
    assert "PLAN DEL ENGAGEMENT" in system_prompt
    assert "SIGUIENTE TODO: recon" in system_prompt
    assert "PLAN-FIRST" in system_prompt


class ScriptedLLM_loop:
    """Replays scripted answers, repeating the last one when exhausted."""

    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.calls = 0
        self.messages: list[list[dict[str, str]]] = []

    async def complete(self, messages, **kwargs):
        self.calls += 1
        self.messages.append([{"role": m.role, "content": m.content} for m in messages])
        index = min(self.calls - 1, max(0, len(self.responses) - 1))
        return LLMResponse(
            content=self.responses[index] if self.responses else "",
            model="scripted-test",
            provider=LLMProvider.FAKE,
        )


# ------------------------------------------------------------------ the panel
def test_the_panel_shows_the_plan_checkboxes():
    plan = new_plan(OBJECTIVE, ENGAGEMENT, [
        Todo("recon", "Descubrir puertos", status=TODO_DONE, verified_by="service:22"),
        Todo("ssh_foothold", "Acceso SSH", status="in_progress"),
        Todo("flag_root", "Capturar root.txt", status=TODO_FAILED, reason="sin root"),
    ])
    payload = plan.to_dict()
    payload["todos_done"] = 1
    payload["todos_total"] = 3

    rendered = "\n".join(text for _style, text in panel_lines(payload))

    assert "PLAN DEL ENGAGEMENT (1/3)" in rendered
    assert "✓ recon" in rendered
    assert "⏳ ssh_foothold" in rendered
    assert "✗ flag_root" in rendered


# ------------------------------------------------------- profile integration
def test_every_profile_can_read_and_write_the_plan():
    """No profile may be unable to fix the contract it is held to."""
    from nexus_core.agent.subagents import (
        ORCHESTRATOR_PLAN_TOOLS,
        SUBAGENTS,
        validate_registry,
    )
    from nexus_core.tools.registry import durable_tool_definitions

    catalog = durable_tool_definitions(TENANT)
    for tool_id in ORCHESTRATOR_PLAN_TOOLS:
        assert tool_id in catalog
    for profile in SUBAGENTS:
        assert ORCHESTRATOR_PLAN_TOOLS <= profile.tools, profile.id
    assert validate_registry(catalog) == []


# ------------------------------------------------------------------- seed plan
def test_the_seed_plan_covers_the_engagement_promise():
    todos = seed_todos(OBJECTIVE)
    ids = [todo.id for todo in todos]
    assert ids[:3] == ["recon", "enumeration", "access"]
    assert "privesc" in ids
    assert [todo.id for todo in todos if "flag" in todo.fact_types] == ["flag_root"]
    assert all(todo.fact_types or todo.id == "report" for todo in todos)


def test_the_plan_file_is_the_one_the_loop_reads(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    assert plan_path() == str(tmp_path / "loot" / "ENGAGEMENT_PLAN.md")
    assert os.path.basename(PLAN_RELATIVE_PATH) == "ENGAGEMENT_PLAN.md"


# ------------------------------------------- condition: identity of the fact
# DeadDrop (2026-10-22) closed `apk-creds` with the shadow hash: both TODOs
# declared `credential`, so the first credential to land ticked both and the
# plan claimed 7/12 with 6/12 of work. A TODO can now say which fact closes it.


def _apk_condition() -> dict:
    return {
        "credential": {"source": "apk_decompile", "key_matches": "synthetic-user*"},
    }


def test_a_conditioned_todo_ignores_a_fact_of_the_same_type_from_elsewhere():
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "crack-shadow", "description": "Crackear /etc/shadow",
               "fact_types": ["credential", "user"]}),
        _todo({"id": "apk-creds", "description": "Credenciales del APK",
               "fact_types": ["credential", "artifact", "access"],
               "condition": _apk_condition()}),
    ])
    shadow = _fact("credential", "hash:$6$f1331af2", user="svc-drop")
    shadow["source"] = "nexus.post.crack_hash"

    updated, ticks = reconcile(plan, [shadow])

    assert ticks == ["crack-shadow"]
    assert updated.todos[1].open
    assert updated.counts()[TODO_DONE] == 1


def test_a_conditioned_todo_closes_with_the_fact_it_names():
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "apk-creds", "description": "Credenciales del APK",
               "fact_types": ["credential", "artifact"],
               "condition": _apk_condition()}),
    ])
    # ``source`` is whatever the plan named: the operator points it at the tool
    # that extracts the APK, not at the one that cracked the shadow.
    from_apk = _fact("credential", "synthetic-user", secret_ref="vault:1")
    from_apk["source"] = "apk_decompile"

    updated, ticks = reconcile(plan, [from_apk])

    assert ticks == ["apk-creds"]
    assert updated.todos[0].verified_by == "credential:synthetic-user"


def test_a_condition_matches_exactly_unless_it_carries_a_wildcard():
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "apk-creds", "description": "APK",
               "fact_types": ["credential"],
               "condition": {"credential": {"source": "apk_decompile"}}}),
    ])
    close_enough = _fact("credential", "synthetic-user")
    close_enough["source"] = "apk_decompile_easter_egg"

    assert reconcile(plan, [close_enough])[1] == []


def test_a_condition_on_the_value_reads_that_field():
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "route", "description": "Llegar al DC",
               "fact_types": ["route"],
               "condition": {"route": {"value.to_host": "192.168.11.100"}}}),
    ])
    elsewhere = _fact("route", "a", from_host="192.168.11.200",
                      to_host="192.168.11.51", to_port=None, method="socks",
                      forwarder_ref=None, verified_by="inv-1")
    assert reconcile(plan, [elsewhere])[1] == []

    right = _fact("route", "b", from_host="192.168.11.200",
                  to_host="192.168.11.100", to_port=None, method="socks",
                  forwarder_ref=None, verified_by="inv-2")
    assert reconcile(plan, [right])[1] == ["route"]


def test_a_todo_without_a_condition_closes_exactly_as_before():
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "creds", "description": "Credenciales",
               "fact_types": ["credential"]}),
    ])
    assert reconcile(plan, [_fact("credential", "anyone")])[1] == ["creds"]


def test_the_condition_is_validated_against_the_declared_types():
    with pytest.raises(ValueError):
        _todo({"id": "x", "description": "d", "fact_types": ["credential"],
               "condition": {"access": {"source": "ssh"}}})
    with pytest.raises(ValueError):
        _todo({"id": "x", "description": "d", "fact_types": ["credential"],
               "condition": {"credential": {"colour": "red"}}})
    with pytest.raises(ValueError):
        _todo({"id": "x", "description": "d", "fact_types": ["credential"],
               "condition": {"credential": {"source": ""}}})


def test_the_condition_survives_the_markdown_round_trip(tmp_path):
    plan = new_plan(OBJECTIVE, ENGAGEMENT, [
        _todo({"id": "apk-creds", "description": "Credenciales del APK",
               "fact_types": ["credential", "artifact"],
               "evidence": "unzip + jadx", "condition": _apk_condition()}),
    ])
    assert "condición: credential.source=apk_decompile" in render_markdown(plan)

    save_plan(plan, str(tmp_path))
    back = load_plan(str(tmp_path))

    assert back is not None
    assert back.todos[0].condition == _apk_condition()
    assert back.todos[0].fact_types == ("credential", "artifact")
    assert back.todos[0].evidence == "unzip + jadx"


def test_the_prompt_names_what_closes_the_next_todo():
    plan = new_plan("o", ENGAGEMENT, [
        _todo({"id": "apk-creds", "description": "Credenciales del APK",
               "fact_types": ["credential"], "condition": _apk_condition()}),
    ])
    block = prompt_block(plan)

    assert "SIGUIENTE TODO: apk-creds" in block
    assert "credential.source=apk_decompile" in block
