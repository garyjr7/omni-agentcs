"""Fase 3.8: the loop always sends a ``user`` turn.

Some chat templates (Qwen) reject a conversation with no user message. The first
ReAct iteration used to build ``[system]`` only, which made
``qwen/qwen3.8-27b`` fail with HTTP 400. ``with_kickoff_user_turn`` fixes that
without changing the input of a model that already accepted the old shape.
"""

from __future__ import annotations

from nexus_core.agent.react import KICKOFF_USER_PROMPT, with_kickoff_user_turn
from nexus_core.llm.abstraction import LLMMessage


def test_adds_a_user_turn_when_context_has_none():
    messages = [LLMMessage(role="system", content="eres OmniAgent")]

    result = with_kickoff_user_turn(messages, "compromete bounty hacker")

    assert [m.role for m in result] == ["system", "user"]
    assert result[-1].content == KICKOFF_USER_PROMPT.format(
        objective="compromete bounty hacker"
    )


def test_is_idempotent_when_a_user_turn_already_exists():
    messages = [
        LLMMessage(role="system", content="sys"),
        LLMMessage(role="user", content="observacion previa"),
        LLMMessage(role="assistant", content="{}"),
    ]

    result = with_kickoff_user_turn(messages, "objetivo")

    # Returned unchanged (same object) so nothing is duplicated per iteration.
    assert result is messages
