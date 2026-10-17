"""WP4: the agent can find, load and follow a curated recipe.

The measured failure: the RootMe run spent 21 calls between ``shell.exec`` and
``web.upload`` against ``/panel/``, never uploaded the webshell -the form needs
``submit=Upload`` and an extension the filter accepts- and died at
``stuck_detected``. Skills existed, but only the operator could name one, so the
recipe could not reach the model. These tests pin the three halves of the fix:

* ``nexus.skill.list`` / ``nexus.skill.load`` are real read-only catalog tools
  that every capability profile can call;
* ``.agents/skills/web-upload-webshell/SKILL.md`` ships the recipe that unblocks
  the room, and the prompt carries a one-line index of it;
* three turns of the same tool with ``blackboard_delta = 0`` make the next prompt
  offer the catalogue, and a new fact resets that streak.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from nexus_core.agent.planner import build_plan
from nexus_core.agent.react import ReActConfig, run_react_loop
from nexus_core.agent.react_services import ContextBuilder, ContextSnapshot
from nexus_core.agent.react_types import (
    SKILL_NUDGE_EVENT_TYPE,
    SKILL_NUDGE_PROMPT,
    SKILL_NUDGE_TURNS,
)
from nexus_core.agent.skills import (
    discover_skills,
    load_skill,
    render_skill_index,
    sign_skill,
    skill_description,
)
from nexus_core.agent.subagents import OMNI_PROFILE, SUBAGENTS
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMMessage, LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore
from nexus_core.tools.handlers.skill import (
    LIST_TOOL_ID,
    LOAD_TOOL_ID,
    skill_list_handler,
    skill_load_handler,
)
from nexus_core.tools.registry import durable_tool_definitions

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("lab_scope")]

TENANT = "system"
ENGAGEMENT = "eng-1"
TARGET = "10.65.175.32"
REPO_ROOT = Path(__file__).resolve().parents[3]
SKILL_DIR = REPO_ROOT / ".agents" / "skills" / "web-upload-webshell"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _write_skill(root: Path, name: str, body: str) -> Path:
    directory = root / ".agents" / "skills" / name
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "SKILL.md"
    path.write_text(body, encoding="utf-8")
    return path


def _run_context() -> RunContext:
    return RunContext(
        TENANT,
        Identity("operator-1", TENANT, roles=("operator",)),
        run_id="run-wp4",
    )


# --------------------------------------------------------------------------- #
# FIX 1 - the tools exist, are read-only, and no profile can lose them
# --------------------------------------------------------------------------- #


def test_skill_tools_are_read_only_and_scope_free() -> None:
    catalog = durable_tool_definitions(TENANT)
    for tool_id in (LIST_TOOL_ID, LOAD_TOOL_ID):
        definition = catalog[tool_id][0]
        assert definition.risk is RiskLevel.READ_ONLY
        assert definition.effect == "read_only"
        assert definition.scope_required is False
        assert definition.sandbox_required is False


def test_every_profile_can_list_and_load_a_skill() -> None:
    """A recipe the model cannot load is a recipe that does not exist."""
    for profile in SUBAGENTS:
        assert {LIST_TOOL_ID, LOAD_TOOL_ID} <= profile.tools, profile.id
    # ``omni`` is the unrestricted default profile: its empty subset means the
    # whole catalog, so the assertion belongs on ``allows`` for both.
    for profile in (*SUBAGENTS, OMNI_PROFILE):
        assert profile.allows(LIST_TOOL_ID) and profile.allows(LOAD_TOOL_ID), profile.id


async def test_skill_list_reports_the_catalogue_with_one_sentence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_skill(
        tmp_path,
        "alpha",
        "---\nname: alpha\ndescription: Primera receta del catálogo.\n---\n\n# Alpha\ncuerpo\n",
    )
    _write_skill(tmp_path, "beta", "# Beta\n\nSegunda receta sin frontmatter.\n")
    monkeypatch.chdir(tmp_path)

    result = await skill_list_handler({}, _run_context())

    assert result.output["count"] == 2
    assert result.output["load_with"] == LOAD_TOOL_ID
    entries = {entry["name"]: entry for entry in result.output["skills"]}
    assert entries["alpha"]["description"] == "Primera receta del catálogo."
    assert entries["beta"]["description"] == "Segunda receta sin frontmatter."
    assert entries["alpha"]["trust"] == "unsigned"
    assert entries["alpha"]["usable"] is True
    # The index is the same text the system prompt carries.
    assert "- alpha: Primera receta del catálogo." in result.output["index"]


async def test_skill_load_returns_the_body_and_its_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_skill(
        tmp_path, "alpha", "---\ndescription: d\n---\n\nPASO 1: haz `id`.\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NEXUS_SCOPE_SIGNING_SECRET", raising=False)

    result = await skill_load_handler({"name": "alpha"}, _run_context())

    assert "PASO 1: haz `id`." in result.output["content"]
    assert result.output["trust"] == "unsigned"
    assert result.output["signed"] is False
    assert result.output["truncated"] is False
    # Provenance travels with the body: the model (and the audit) can tell which
    # file it followed and whether it was signed.
    assert result.output["path"] == str(path)
    assert len(result.output["sha256"]) == 64
    # The post-condition is local (the bytes that produced the hash), so the
    # gateway accepts the call; it asserts nothing about the target.
    assert result.verified is True


async def test_the_gateway_lets_the_loop_invoke_both_skill_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end through policy and audit -the path the loop really takes."""
    from nexus_core.kernel.audit import AuditWriter
    from nexus_core.kernel.policy import PolicyEngine
    from nexus_core.kernel.tool_gateway import ToolGateway

    _write_skill(tmp_path, "alpha", "# Alpha\n\nreceta\n")
    monkeypatch.chdir(tmp_path)
    store = ControlStore(tmp_path / "gateway.db")
    store.initialize()
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store))
    catalog = durable_tool_definitions(TENANT)
    for tool_id in (LIST_TOOL_ID, LOAD_TOOL_ID):
        gateway.register(*catalog[tool_id])
    context = RunContext(
        TENANT,
        Identity("operator-1", TENANT, roles=("operator",)),
        run_id="run-wp4-gateway",
        store=store,
        authorized_permissions=(f"execute:tool:{LIST_TOOL_ID}", f"execute:tool:{LOAD_TOOL_ID}"),
    )

    listed = await gateway.invoke(LIST_TOOL_ID, {}, context)
    assert listed["success"] is True
    assert [item["name"] for item in listed["output"]["skills"]] == ["alpha"]
    loaded = await gateway.invoke(LOAD_TOOL_ID, {"name": "alpha"}, context)
    assert loaded["success"] is True
    assert "receta" in loaded["output"]["content"]


async def test_skill_load_refuses_unknown_names_and_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_skill(tmp_path, "alpha", "# Alpha\n")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError) as unknown:
        await skill_load_handler({"name": "nope"}, _run_context())
    assert "available: alpha" in str(unknown.value)
    for name in ("../etc", "a/b", ".."):
        with pytest.raises(ValueError):
            await skill_load_handler({"name": name}, _run_context())


async def test_skill_load_verifies_the_signature_before_rendering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_skill(tmp_path, "alpha", "# Alpha\nreceta firmada\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NEXUS_SCOPE_SIGNING_SECRET", "wp4-secret")
    signature = path.with_name("SKILL.md.sig")

    signature.write_text("0" * 64, encoding="utf-8")
    with pytest.raises(PermissionError):
        await skill_load_handler({"name": "alpha"}, _run_context())

    signature.write_text(sign_skill(path.read_bytes(), "wp4-secret"), encoding="utf-8")
    result = await skill_load_handler({"name": "alpha"}, _run_context())
    assert result.output["trust"] == "signed"
    assert result.output["signed"] is True


# --------------------------------------------------------------------------- #
# FIX 2 - the recipe that unblocks RootMe travels with the repository
# --------------------------------------------------------------------------- #


def test_the_webshell_skill_is_shipped_unsigned() -> None:
    body = SKILL_DIR / "SKILL.md"
    assert body.is_file()
    # No HMAC: a signature that everybody can verify is a signature everybody can
    # forge, and the repository cannot ship the operator's secret. Unsigned means
    # "untrusted data with a warning", which is exactly the safe mode.
    assert not body.with_name("SKILL.md.sig").exists()
    skill = load_skill("web-upload-webshell", REPO_ROOT)
    assert skill is not None
    assert skill.trust == "unsigned"
    assert skill.usable is True


async def test_the_webshell_skill_carries_the_steps_the_run_missed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(REPO_ROOT)
    monkeypatch.delenv("NEXUS_SCOPE_SIGNING_SECRET", raising=False)

    content = (await skill_load_handler({"name": "web-upload-webshell"}, _run_context())).output[
        "content"
    ].lower()

    # Identify the form / upload with curl / evade the filter.
    assert '<input type="file"' in content
    assert "curl" in content and "nexus.shell.exec" in content
    assert "-f \"fileupload=@shell.phtml\"" in content
    assert "submit=upload" in content
    for extension in (".phtml", ".php5", ".php3", ".php"):
        assert extension in content
    # Check the upload and trigger the shell.
    assert "/uploads/" in content
    assert "?c=id" in content
    # The two mistakes that cost the measured run its turns.
    assert "no olvidar" in content or "falta `submit=upload`" in content
    assert "workspace" in content


def test_the_prompt_index_names_the_skills_and_their_sentence() -> None:
    index = render_skill_index(discover_skills(REPO_ROOT))
    assert "- web-upload-webshell:" in index
    assert "webshell" in index.lower()
    # File-derived text is delivered as data, never as instructions.
    assert index.startswith("<<UNTRUSTED_TOOL_OUTPUT>>")


def test_skill_description_prefers_the_frontmatter() -> None:
    assert (
        skill_description("---\nname: x\ndescription: 'Una frase.'\n---\n\n# T\n")
        == "Una frase."
    )
    assert skill_description("# T\n\nPrimera línea.\n") == "Primera línea."
    assert skill_description("") == "(sin descripción)"


# --------------------------------------------------------------------------- #
# FIX 3 - three identical barren turns offer the catalogue
# --------------------------------------------------------------------------- #


def _render(same_tool_no_progress: int) -> str:
    builder = ContextBuilder()
    messages = builder.render(
        ContextSnapshot(
            run_history=[],
            history_summary="",
            plan=build_plan(objective="rootme", engagement_id=ENGAGEMENT),
            facts_text="",
            run_id="run-wp4",
        ),
        allowed_catalog={},
        objective="rootme",
        engagement_id=ENGAGEMENT,
        scope=None,
        subagent=OMNI_PROFILE,
        project_instruction=None,
        active_skills=[],
        store=None,
        tenant_id=TENANT,
        same_tool_no_progress=same_tool_no_progress,
    )
    return "\n".join(str(message.content) for message in messages if message.role == "system")


def test_the_nudge_appears_only_from_the_third_repeated_turn() -> None:
    assert SKILL_NUDGE_TURNS == 3
    assert SKILL_NUDGE_PROMPT not in _render(2)
    assert SKILL_NUDGE_PROMPT in _render(3)
    assert "nexus.skill.list" in SKILL_NUDGE_PROMPT
    assert "web-upload-webshell" in SKILL_NUDGE_PROMPT


def test_the_prompt_carries_the_skill_index_on_every_turn() -> None:
    prompt = _render(0)
    assert "SKILLS DISPONIBLES" in prompt
    assert "- web-upload-webshell:" in prompt


# ------------------------------- loop harness ------------------------------- #


class ScriptedLLM:
    """Replays the scripted replies (the last one forever), keeping each prompt."""

    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.calls = 0
        self.system_prompts: list[str] = []

    async def complete(self, messages: list[LLMMessage], **kwargs: Any) -> LLMResponse:
        self.calls += 1
        self.system_prompts.append(
            "\n".join(
                str(getattr(message, "content", ""))
                for message in messages
                if getattr(message, "role", "") == "system"
            )
        )
        index = min(self.calls - 1, max(0, len(self.responses) - 1))
        return LLMResponse(
            content=self.responses[index] if self.responses else "",
            model="scripted-test",
            provider=LLMProvider.FAKE,
            tokens_input=100,
            tokens_output=25,
        )


def _tool_call(tool_id: str = "nexus.recon.nmap", **arguments: Any) -> str:
    return json.dumps(
        {
            "thought": "Intento el mismo formulario otra vez.",
            "action": "tool_call",
            "tool_id": tool_id,
            "arguments": arguments or {"target": TARGET},
            "expected_outcome": "algo",
        }
    )


def _harness(tmp_path: Path) -> tuple[ControlStore, ExecutionContext]:
    store = ControlStore(tmp_path / "wp4.db")
    store.initialize()
    EngagementStore(store).create(
        EngagementScope(
            engagement_id=ENGAGEMENT,
            tenant_id=TENANT,
            name="wp4",
            client="acme",
            owner_id="owner-1",
            valid_from=_iso(-timedelta(days=1)),
            valid_until=_iso(timedelta(days=1)),
            cidrs=("10.65.175.0/24",),
            domains=(),
            urls=(),
            exclusions=(),
            created_at=_iso(timedelta(0)),
        )
    )
    run = store.create_run(TENANT, {})
    task = {
        "id": "task-1",
        "tenant_id": TENANT,
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "RootMe",
            "engagement_id": ENGAGEMENT,
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": [
                "execute:tool:nexus.recon.nmap",
                "execute:tool:nexus.skill.list",
            ],
        },
    }
    return store, ExecutionContext(store, task, "worker-test")


def _events(store: ControlStore, context: ExecutionContext, event_type: str) -> list[dict]:
    return [
        event
        for event in store.list_run_events(context.tenant_id, context.run_id)
        if event["event_type"] == event_type
    ]


async def test_the_loop_offers_the_catalogue_after_three_identical_turns(
    tmp_path: Path,
) -> None:
    store, context = _harness(tmp_path)
    llm = ScriptedLLM([_tool_call()])

    async def fake_tool(payload: dict[str, Any], run_context: ExecutionContext) -> dict[str, Any]:
        return {"tool_id": payload["tool_id"], "output": {"success": True}}

    with mock.patch.object(runtime_module, "execute_tool", fake_tool):
        result = await run_react_loop(
            context=context,
            objective="RootMe",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=ReActConfig(max_iterations=4, enforce_completion_gates=False),
        )

    assert [turn["blackboard_delta"] for turn in result.turns] == [0, 0, 0, 0]
    # The prompt already sent on turn 3 cannot warn; the next one does, and it
    # arrives with the way out instead of only the diagnosis.
    assert SKILL_NUDGE_PROMPT not in llm.system_prompts[2]
    assert SKILL_NUDGE_PROMPT in llm.system_prompts[3]
    signals = _events(store, context, SKILL_NUDGE_EVENT_TYPE)
    assert len(signals) == 1
    assert signals[0]["payload"] == {
        "iterations_stuck": 3,
        "tool_id": "nexus.recon.nmap",
        "phase": "recon",
        "subagent_id": "omni",
    }


async def test_a_new_fact_resets_the_repeated_tool_streak(tmp_path: Path) -> None:
    store, context = _harness(tmp_path)
    llm = ScriptedLLM([_tool_call()])
    board = Blackboard(store)
    calls = {"count": 0}

    async def fake_tool(payload: dict[str, Any], run_context: ExecutionContext) -> dict[str, Any]:
        calls["count"] += 1
        if calls["count"] == 3:
            board.record(
                tenant_id=TENANT,
                engagement_id=ENGAGEMENT,
                fact_type="host",
                key=TARGET,
                value={"state": "up"},
                source="nexus.recon.nmap",
                created_by="deterministic-verifier",
                verified=True,
                asserted_by="verifier",
                verification_method="nmap_xml_parsed",
                invocation_id="inv-host",
            )
        return {"tool_id": payload["tool_id"], "output": {"success": True}}

    with mock.patch.object(runtime_module, "execute_tool", fake_tool):
        await run_react_loop(
            context=context,
            objective="RootMe",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=ReActConfig(max_iterations=5, enforce_completion_gates=False),
        )

    # Turn 3 produced a fact, so the streak restarts and never reaches three.
    assert all(SKILL_NUDGE_PROMPT not in prompt for prompt in llm.system_prompts)
    assert _events(store, context, SKILL_NUDGE_EVENT_TYPE) == []
