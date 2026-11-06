"""Unit tests for the tolerant ReAct response parser."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_core.agent.parser import ReActParseError, parse_react_response

FIXTURES = Path(__file__).parents[1] / "fixtures" / "react"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_parse_valid_tool_call():
    action = parse_react_response(_fixture("llm_response_tool_call.json"))

    assert action.action == "tool_call"
    assert action.tool_id == "nexus.recon.nmap"
    assert action.arguments == {"target": "10.0.0.5", "flags": ["-Pn", "-p", "22,80"]}
    assert action.expected_outcome
    assert action.thought
    assert action.warnings == ()


def test_parse_valid_task_complete():
    action = parse_react_response(_fixture("llm_response_task_complete.json"))

    assert action.action == "task_complete"
    assert "10.0.0.5" in action.summary
    assert len(action.findings) == 2
    assert action.findings[0]["severity"] == "high"
    assert action.tool_id is None


def test_parse_valid_clarification():
    action = parse_react_response(_fixture("llm_response_clarification.json"))

    assert action.action == "request_clarification"
    assert action.question.startswith("¿Puedo")


def test_parse_extracts_json_from_markdown_fence():
    text = "Aquí está mi decisión:\n```json\n" + _fixture("llm_response_tool_call.json") + "\n```\n"

    action = parse_react_response(text)

    assert action.action == "tool_call"
    assert action.tool_id == "nexus.recon.nmap"
    assert any("markdown fence" in warning for warning in action.warnings)


def test_parse_handles_json_with_nested_braces():
    text = (
        '{"thought": "anida {llaves} en el texto", "action": "tool_call", '
        '"tool_id": "nexus.recon.nmap", '
        '"arguments": {"target": "10.0.0.5", "flags": ["-Pn", "-p", "22,80"]}}'
    )

    action = parse_react_response(text)

    assert action.arguments["flags"] == ["-Pn", "-p", "22,80"]
    assert "{llaves}" in action.thought


def test_parse_rejects_missing_tool_id():
    text = json.dumps({"thought": "x", "action": "tool_call", "arguments": {}})

    with pytest.raises(ReActParseError) as error:
        parse_react_response(text)

    assert "tool_id" in str(error.value)


def test_parse_rejects_missing_arguments():
    text = json.dumps({"thought": "x", "action": "tool_call", "tool_id": "nexus.recon.nmap"})

    with pytest.raises(ReActParseError) as error:
        parse_react_response(text)

    assert "arguments" in str(error.value)


def test_parse_rejects_missing_summary():
    text = json.dumps({"thought": "x", "action": "task_complete", "findings": []})

    with pytest.raises(ReActParseError) as error:
        parse_react_response(text)

    assert "summary" in str(error.value)


def test_parse_rejects_invalid_action():
    text = json.dumps({"thought": "x", "action": "delete_everything"})

    with pytest.raises(ReActParseError) as error:
        parse_react_response(text)

    assert "unknown or missing action" in str(error.value)


def test_parse_rejects_the_invented_wait_action_with_the_fix():
    """A measured run answered ``{"action": "wait", "task_id": "bg-1"}``.

    The loop yields to the background job by itself, so ``wait`` is not (and will
    not become) an action. The refusal must teach that, otherwise the generic
    "unknown action" correction leads the model to ask the human instead.
    """
    text = json.dumps({"thought": "espero el escaneo", "action": "wait", "task_id": "bg-1"})

    with pytest.raises(ReActParseError) as error:
        parse_react_response(text)

    message = str(error.value)
    assert "no existe la acción 'wait'" in message
    assert "background: true" in message and "task_complete" in message


def test_parse_rejects_completely_invalid_text():
    with pytest.raises(ReActParseError) as error:
        parse_react_response(_fixture("llm_response_invalid_json.txt"))

    assert "parsable JSON object" in str(error.value)


def test_parse_takes_first_action_on_multi_action():
    action = parse_react_response(_fixture("llm_response_multi_action.json"))

    assert action.action == "tool_call"
    assert action.tool_id == "nexus.recon.nmap"
    assert any("multiple actions" in warning for warning in action.warnings)


def test_parse_preserves_raw_response_for_audit():
    text = _fixture("llm_response_tool_call.json")

    action = parse_react_response(text)

    assert action.raw_response == text


def test_parse_error_preserves_raw_response_for_audit():
    broken = "definitivamente no es json"

    with pytest.raises(ReActParseError) as error:
        parse_react_response(broken)

    assert error.value.raw_response == broken


def test_parse_rejects_empty_response():
    with pytest.raises(ReActParseError):
        parse_react_response("   ")


def test_parse_accepts_json_array_and_keeps_first():
    text = json.dumps([{"thought": "x", "action": "tool_call", "tool_id": "a.b", "arguments": {}}])

    action = parse_react_response(text)

    assert action.tool_id == "a.b"


def test_an_oversized_batch_is_truncated_instead_of_rejected():
    """hijack_v7 iter 2: nine record_fact calls became nine wasted turns.

    The model batched one call per service; the DTO caps the batch at four, and
    the old parser failed the whole turn (``invalid action fields:
    tool_calls.calls``). The first four must run and the answer must say so.
    """
    calls = [
        {
            "tool_id": "nexus.knowledge.record_fact",
            "arguments": {"fact_type": "service", "key": f"10.0.0.5:{port}:tcp"},
        }
        for port in range(21, 30)
    ]
    action = parse_react_response(
        json.dumps({"thought": "registro los servicios", "action": "tool_calls", "calls": calls})
    )
    assert action.action == "tool_calls"
    assert len(action.calls) == 4
    assert action.calls[0].arguments["key"] == "10.0.0.5:21:tcp"
    assert any("only the first 4" in warning for warning in action.warnings)


def test_parse_rejects_non_object_arguments():
    text = json.dumps(
        {"thought": "x", "action": "tool_call", "tool_id": "a.b", "arguments": ["--bad"]}
    )

    with pytest.raises(ReActParseError) as error:
        parse_react_response(text)

    assert "arguments must be a JSON object" in str(error.value)


def test_parse_extracts_json_embedded_in_prose():
    text = (
        "Voy a responder así: "
        '{"thought": "x", "action": "tool_call", "tool_id": "a.b", "arguments": {"n": 1}} '
        "y espero el resultado."
    )

    action = parse_react_response(text)

    assert action.tool_id == "a.b"
    assert any("unparsable text" in warning for warning in action.warnings)
