"""Provider-native reasoning: read, capped and never part of the prompt."""

from nexus_core.llm.abstraction import (
    LLMResponse,
    LLMProvider,
    _reasoning_effort_option,
    _reasoning_from_raw,
)


def test_anthropic_thinking_blocks_are_concatenated():
    raw = {"content": [
        {"type": "text", "text": "respuesta"},
        {"type": "thinking", "thinking": "paso uno"},
        {"type": "thinking", "thinking": "paso dos"},
    ]}
    assert _reasoning_from_raw(raw) == "paso uno\n\npaso dos"


def test_openai_compatible_reasoning_content_is_read():
    raw = {"choices": [{"message": {"content": "{}", "reasoning_content": "analizo"}}]}
    assert _reasoning_from_raw(raw) == "analizo"
    raw = {"choices": [{"message": {"content": "{}", "reasoning": "analizo"}}]}
    assert _reasoning_from_raw(raw) == "analizo"


def test_reasoning_is_capped_at_two_thousand_characters():
    raw = {"choices": [{"message": {"reasoning_content": "x" * 5000}}]}
    assert len(_reasoning_from_raw(raw) or "") == 2000


def test_no_reasoning_returns_none():
    assert _reasoning_from_raw({}) is None
    assert _reasoning_from_raw({"content": []}) is None


def test_response_carries_reasoning_without_touching_content():
    response = LLMResponse(content="{}", model="m", provider=LLMProvider.OPENAI,
                           reasoning="razonamiento")
    assert response.reasoning == "razonamiento" and response.content == "{}"


def test_reasoning_effort_is_opt_in_and_validated(monkeypatch):
    monkeypatch.delenv("NEXUS_REASONING_EFFORT", raising=False)
    assert _reasoning_effort_option("gpt-5") is None
    monkeypatch.setenv("NEXUS_REASONING_EFFORT", "high")
    assert _reasoning_effort_option("gpt-5") == "high"
    assert _reasoning_effort_option("gpt-4o") is None
    monkeypatch.setenv("NEXUS_REASONING_EFFORT", "extremo")
    assert _reasoning_effort_option("gpt-5") is None
