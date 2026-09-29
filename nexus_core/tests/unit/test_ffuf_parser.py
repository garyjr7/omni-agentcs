"""Unit tests for nexus_core.tools.parsers.ffuf (no network, no ffuf binary)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from nexus_core.tools.parsers.ffuf import parse_ffuf_output

FIXTURES = Path(__file__).parents[1] / "fixtures" / "ffuf"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_parse_ndjson_matches():
    result = parse_ffuf_output(_read("ndjson.jsonl"))
    assert len(result.matches) == 2
    first = result.matches[0]
    assert first.url == "https://scanme.example/admin"
    assert first.status == 200
    assert first.length == 1234
    assert first.content_type == "text/html"
    assert first.input == {"FUZZ": "admin"}


def test_parse_envelope_matches():
    result = parse_ffuf_output(_read("envelope.json"))
    assert len(result.matches) == 1
    assert result.matches[0].url == "https://scanme.example/admin"
    assert result.matches[0].status == 200


def test_parse_empty_output_returns_empty_result():
    result = parse_ffuf_output("")
    assert result.matches == ()
    assert result.to_dict()["count"] == 0


def test_parse_malformed_json_raises_value_error():
    with pytest.raises(ValueError):
        parse_ffuf_output('{"broken json": ')


def test_parse_missing_optional_fields():
    result = parse_ffuf_output('{"url":"https://scanme.example/x","status":200}\n')
    match = result.matches[0]
    assert match.length == 0
    assert match.words == 0
    assert match.lines == 0
    assert match.content_type == ""
    assert match.redirect_location == ""
    assert match.duration_ms == 0
    assert match.input == {}


def test_parse_counts_status_codes():
    result = parse_ffuf_output(_read("ndjson.jsonl"))
    assert result.status_counts == {"200": 1, "302": 1}


def test_parse_tolerates_junk_lines_around_valid_records():
    text = '{"url":"https://scanme.example/x","status":200}\nnot json\n'
    result = parse_ffuf_output(text)
    assert len(result.matches) == 1
    assert result.malformed_lines == 1


def test_parse_preserves_raw_sha256_of_the_payload():
    text = _read("ndjson.jsonl")
    result = parse_ffuf_output(text)
    assert result.raw_sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_parse_redirect_location_and_duration():
    result = parse_ffuf_output(_read("ndjson.jsonl"))
    redirect = result.matches[1]
    assert redirect.status == 302
    assert redirect.redirect_location == "https://scanme.example/login/"
    assert redirect.duration_ms == 9
