"""Fase 3d fixes: the operator's callback published, the exploit budget widened.

Measured in the rerun 4 of the same room (``run_44b43bad8c5e4a998cf06b513c3eba60``,
``10.65.175.32``, ``MSF_LHOST`` configured and the doctor green):

* iteration 11: the model proposed ``nexus.exploit.msf_exploit`` with an invented
  ``lhost=10.65.175.1``. The handler refused it ("``lhost is fixed by MSF_LHOST``")
  but the catalog kept publishing ``lhost:string`` as an ordinary argument, so the
  rejection was **unavoidable** with the information the model had (V1-20).
* iteration 12: MS17-010 ran with the correct callback for 47 s and failed in the
  SMB stage (``RubySMB::Error::CommunicationError Read timeout``) -a legitimate
  failure of the exploit against that target, not a defect of ours. The ``exploit``
  profile then died at ``subagent_budget_exceeded`` with 8 iterations spent on 3
  bookkeeping turns and 2 avoidable rejections, never trying an alternative
  (V1-21).
* the ``react.stuck_detected`` events of iterations 5 and 10 were emitted, but the
  question left open was whether they reach the *prompt* of the next turn, or stay
  as an audit-only signal (V1-22).

Three items, one commit:

1. ``ToolDefinition.fixed_by_env`` publishes the arguments whose value belongs to
   the operator's environment, and the catalog shows them as ``lhost:env(MSF_LHOST)``
   plus one "no ajustables" line that survives ``CATALOG_MAX_ARGUMENTS``.
2. The ``exploit`` profile's iteration budget goes 8 -> **15** as a *measurable
   experiment* for rerun 5: if the agent still does not pivot, the cause is the
   prompt/planner and not the budget (V1-21). No other profile is touched.
3. The stuck signal already reached the next prompt (Fase 3 fixes); this file
   re-verifies that link on the rerun 4 evidence instead of assuming it (V1-22).
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest import mock

import pytest

from nexus_core.agent.prompts import render_tool_catalog
from nexus_core.agent.react import run_react_loop
from nexus_core.agent.react_types import STUCK_EVENT_TYPE, STUCK_PROMPT_LINE
from nexus_core.agent.subagents import SUBAGENTS_BY_ID
from nexus_core.kernel import runtime as runtime_module
from nexus_core.tests.msf_support import context, scope
from nexus_core.tests.unit.test_phase3_fixes import (
    ENGAGEMENT,
    ScriptedLLM,
    TOOL_SUCCESS,
    TARGET,
    _events,
    _harness,
    _loop_config,
    tool_call,
)
from nexus_core.tools.handlers import msf_auxiliary as msf_auxiliary_module
from nexus_core.tools.handlers import msf_exploit as msf_exploit_module
from nexus_core.tools.registry import durable_tool_definitions

pytestmark = [
    pytest.mark.unit,
    # The unsigned fixtures of the scope/session behavior; governed stays the
    # default everywhere else (same convention as the Phase 3/3b/3c suites).
    pytest.mark.usefixtures("lab_scope"),
]

EXPLOIT_ARGS = {
    "module": "exploit/windows/smb/ms17_010_eternalblue",
    "target": TARGET,
}

#: The two tools that own a callback, with the declaration each one publishes and
#: the exact line the catalog must carry for it. ``msf_exploit`` takes
#: ``lhost``/``lport`` as top-level arguments; ``msf_auxiliary`` only exposes
#: ``options``, so its callback keys are declared as their argument path.
CALLBACK_TOOLS = (
    (
        "nexus.exploit.msf_exploit",
        msf_exploit_module,
        {"lhost": "MSF_LHOST", "lport": "MSF_LPORT"},
        "lhost/lport fijos por env MSF_LHOST/MSF_LPORT (no ajustables)",
    ),
    (
        "nexus.exploit.msf_auxiliary",
        msf_auxiliary_module,
        {"options.LHOST": "MSF_LHOST", "options.LPORT": "MSF_LPORT"},
        "LHOST/LPORT fijos por env MSF_LHOST/MSF_LPORT (no ajustables)",
    ),
)

#: The iteration budget of every *other* profile, as measured before the rerun 5
#: experiment. A deliberate change to one of these needs its own measurement and
#: must update this table; the point of the test is that the experiment moved one
#: budget and nothing else.
OTHER_BUDGETS = {
    "recon": 8,
    "web": 10,
    "services": 10,
    "cred": 6,
    "postexploit": 8,
    "privesc": 10,
    "lateral": 8,
    "reporter": 4,
}


def _line(catalog: dict[str, Any], tool_id: str) -> str:
    text = render_tool_catalog(catalog)
    return next(line for line in text.splitlines() if line.startswith(f"- {tool_id}:"))


def _definition(catalog: dict[str, Any], tool_id: str) -> Any:
    entry = catalog[tool_id]
    return entry[0] if isinstance(entry, tuple) else entry


# ------------------------------------------------------------------ 1 · V1-20


@pytest.mark.parametrize(
    "tool_id,module,declared,note",
    CALLBACK_TOOLS,
    ids=["msf_exploit", "msf_auxiliary"],
)
def test_catalog_marks_lhost_lport_fixed_by_env(tool_id, module, declared, note):
    """The catalog says the callback is the operator's, before the model tries.

    Rerun 4 lost iteration 11 to ``lhost is fixed by MSF_LHOST and cannot be set by
    the model`` while the same catalog line advertised ``lhost:string``: the model
    could not know. The declaration travels into the render as a per-tool line
    *outside* the ``args[…]`` list, because ``CATALOG_MAX_ARGUMENTS`` truncates
    that list and a hidden constraint is the error the model repeats.
    """
    catalog = durable_tool_definitions("system")
    definition = _definition(catalog, tool_id)
    line = _line(catalog, tool_id)

    assert definition.fixed_by_env == declared, f"{tool_id} declares no env-fixed callback"
    assert note in line
    # The note is not part of the (truncatable) argument list.
    assert "no ajustables]" not in line

    # Publishing is information, never authorization: the handler keeps refusing
    # a model-supplied callback.
    if module is msf_exploit_module:
        with mock.patch.dict("os.environ", {"MSF_LHOST": "203.0.113.9"}):
            with pytest.raises(ValueError) as refusal:
                asyncio.run(
                    module.msf_exploit_handler(
                        {**EXPLOIT_ARGS, "lhost": "10.65.175.1"}, context(scope())
                    )
                )
        assert "MSF_LHOST" in str(refusal.value)
    else:
        with pytest.raises(ValueError) as refusal:
            module.validated_options({"LHOST": "10.65.175.1"})
        assert "'LHOST'" in str(refusal.value)


# ------------------------------------------------------------------ 2 · V1-21


def test_exploit_subagent_budget_is_15():
    """The ``exploit`` profile gets 15 iterations for the rerun 5 experiment.

    8 were not enough *to try an alternative*: rerun 4 spent them on 3 bookkeeping
    turns (two of them the very same ``netexec`` call) and 2 avoidable rejections
    before the MS17-010 failure, and then reported ``subagent_budget_exceeded``
    with 27 global iterations still unused.
    """
    assert SUBAGENTS_BY_ID["exploit"].max_iterations == 15


def test_other_subagent_budgets_unchanged():
    """Only ``exploit`` moved: the experiment isolates one variable."""
    budgets = {profile.id: profile.max_iterations for profile in SUBAGENTS_BY_ID.values()}
    assert budgets == {"exploit": 15, **OTHER_BUDGETS}
    # The token budget of the profile was not part of the experiment either.
    assert SUBAGENTS_BY_ID["exploit"].token_budget == 60_000


# ------------------------------------------------------------------ 3 · V1-22


async def test_stuck_signal_reaches_next_prompt(tmp_path):
    """The stuck signal is not audit-only: the next prompt asks for a pivot.

    Rerun 4 emitted ``react.stuck_detected`` twice (iterations 5 and 10) and the
    agent kept re-issuing the same call, so this re-verifies the link between the
    event and the prompt that follows it. The turn in which the threshold is
    crossed cannot be warned -its prompt was already sent-; the next one carries
    the line. The threshold itself stays at 5: the experiment never touched it.
    """
    store, run_context = _harness(tmp_path)
    llm = ScriptedLLM([tool_call()])

    async def fake_tool(payload: dict[str, Any], execution: Any) -> dict[str, Any]:
        return dict(TOOL_SUCCESS)

    with mock.patch.object(runtime_module, "execute_tool", fake_tool):
        result = await run_react_loop(
            context=run_context,
            objective=f"Enumera {TARGET}",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(max_iterations=6),
        )

    signals = _events(store, run_context, STUCK_EVENT_TYPE)
    assert len(signals) == 1
    assert signals[0]["payload"]["iterations_stuck"] == 5

    line = STUCK_PROMPT_LINE.format(iterations=5)
    assert line not in llm.system_prompts[4], "turn 5 is already being answered"
    assert line in llm.system_prompts[5], "the signal has to reach the next prompt"
    assert result.iterations == 6
