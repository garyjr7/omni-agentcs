"""Deterministic parser for the outcome of one command sent to a session."""

from __future__ import annotations

import pytest

from nexus_core.tools.parsers.metasploit import (
    MetasploitSessionInteraction,
    parse_msf_interaction,
)

UUID = "sess-1"
COMMAND = "id"


def raw(status: str = "ok", output: str = "uid=0(root)\n", duration: float = 1.25) -> dict:
    return {"status": status, "output": output, "duration_seconds": duration}


def test_parse_msf_interaction_ok():
    parsed = parse_msf_interaction(raw(), UUID, COMMAND)
    assert isinstance(parsed, MetasploitSessionInteraction)
    assert parsed.status == "ok"
    assert parsed.session_uuid == UUID and parsed.command == COMMAND
    assert parsed.output == "uid=0(root)\n"
    assert parsed.output_bytes == len("uid=0(root)\n".encode())
    assert parsed.duration_seconds == 1.25


def test_parse_msf_interaction_timeout_keeps_partial_output():
    parsed = parse_msf_interaction(raw("timeout", "partial", 60.0), UUID, COMMAND)
    assert parsed.status == "timeout"
    assert parsed.output == "partial"
    assert parsed.output_bytes == 7


def test_parse_msf_interaction_session_dead():
    parsed = parse_msf_interaction(raw("session_dead", ""), UUID, COMMAND)
    assert parsed.status == "session_dead"
    assert parsed.output == "" and parsed.output_bytes == 0
    assert parsed.to_dict()["status"] == "session_dead"


def test_parse_msf_interaction_preserves_sha256():
    first = parse_msf_interaction(raw(), UUID, COMMAND)
    second = parse_msf_interaction(raw(), UUID, COMMAND)
    changed = parse_msf_interaction(raw(output="another\n"), UUID, COMMAND)
    assert first.raw_sha256 == second.raw_sha256
    assert first.raw_sha256 != changed.raw_sha256
    assert first.raw_sha256


@pytest.mark.parametrize(
    "payload",
    [
        ["not", "a", "dict"],
        "not-a-dict",
        {"status": "exploded"},
        {},
        {"status": "ok", "output": 123},
        {"status": "ok", "duration_seconds": "soon"},
    ],
)
def test_parse_msf_interaction_rejects_malformed(payload):
    with pytest.raises(ValueError):
        parse_msf_interaction(payload, UUID, COMMAND)


def test_parse_msf_interaction_null_output_becomes_empty():
    parsed = parse_msf_interaction({"status": "ok", "output": None}, UUID, COMMAND)
    assert parsed.output == "" and parsed.output_bytes == 0
    assert parsed.duration_seconds == 0.0
