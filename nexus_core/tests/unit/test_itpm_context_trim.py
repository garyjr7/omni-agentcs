"""Fase 4.0: an input-budget 413 trims the conversation.

``qwen/qwen3.8-27b`` (free tier) enforces an input budget (ITPM 7000); the ReAct
context reached 7136 and every retry failed because shrinking ``max_tokens``
cannot shrink the prompt. The client now trims the oldest turns instead.
"""

from __future__ import annotations

from nexus_core.llm.abstraction import trim_oldest_messages
from nexus_core.llm.limits import mentions_input_token_limit


def _msg(role: str, content: str) -> dict:
    return {"role": role, "content": content}


def test_helper_detects_itpm_messages():
    assert mentions_input_token_limit(
        Exception("... on input tokens per minute (ITPM): Limit 7000, Requested 7136")
    )
    assert not mentions_input_token_limit(Exception("output tokens per minute (OTPM)"))


def test_trim_keeps_the_system_prompt_and_newest_turns():
    messages = [_msg("system", "sys")] + [_msg("user", str(i)) for i in range(10)]

    trimmed = trim_oldest_messages(messages, keep=3)

    assert trimmed[0]["role"] == "system"
    assert [m["content"] for m in trimmed[1:]] == ["7", "8", "9"]


def test_trim_is_a_noop_when_short_enough():
    messages = [_msg("system", "sys"), _msg("user", "a")]

    assert trim_oldest_messages(messages, keep=6) is messages
