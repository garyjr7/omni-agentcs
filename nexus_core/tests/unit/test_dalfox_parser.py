"""Unit tests for nexus_core.tools.parsers.dalfox (no network, no binary)."""

from __future__ import annotations

import hashlib

import pytest

from nexus_core.tools.parsers.dalfox import parse_dalfox_json

#: Real shape captured from dalfox v2.13 (``type`` is "V", plus a {} filler).
SAMPLE = (
    "[\n"
    '{"type":"V","inject_type":"inHTML-URL","poc_type":"plain","method":"GET",'
    '"data":"http://127.0.0.1:8765/?q=test",'
    '"param":"q","payload":"<script>alert(1)</script>","evidence":"1 line",'
    '"cwe":"CWE-79","severity":"High","message_id":670,'
    '"message_str":"Triggered XSS Payload"},\n'
    "{}\n"
    "]"
)


def test_parse_real_finding():
    result = parse_dalfox_json(SAMPLE, target="http://127.0.0.1:8765/")
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.method == "GET"
    assert finding.param == "q"
    assert finding.payload == "<script>alert(1)</script>"
    assert finding.inject_type == "inHTML-URL"
    assert finding.cwe == "CWE-79"
    assert finding.severity == "High"
    assert finding.message == "Triggered XSS Payload"


def test_parse_empty_placeholder_is_zero_findings():
    result = parse_dalfox_json("[\n{}]")
    assert result.findings == ()
    assert result.to_dict()["count"] == 0


def test_parse_empty_output_returns_empty_result():
    result = parse_dalfox_json("")
    assert result.findings == ()
    assert result.target == ""


def test_parse_ndjson_is_accepted():
    text = (
        '{"type":"V","method":"GET","param":"a","payload":"x"}\n'
        '{"type":"V","method":"GET","param":"b","payload":"y"}\n'
    )
    result = parse_dalfox_json(text, target="http://x/")
    assert len(result.findings) == 2


def test_parse_malformed_json_raises_value_error():
    with pytest.raises(ValueError):
        parse_dalfox_json("{not json at all")


def test_parse_multiple_findings_in_array():
    text = (
        '[{"type":"V","param":"a","payload":"p1"},'
        '{"type":"V","param":"b","payload":"p2"},{}]'
    )
    result = parse_dalfox_json(text)
    assert [f.param for f in result.findings] == ["a", "b"]


def test_parse_missing_optional_fields():
    result = parse_dalfox_json('[{"type":"V","param":"q","payload":"p"}]')
    finding = result.findings[0]
    assert finding.cwe == ""
    assert finding.severity == ""
    assert finding.evidence == ""
    assert finding.method == "GET"


def test_parse_preserves_raw_json_sha256():
    result = parse_dalfox_json(SAMPLE)
    assert result.raw_json_sha256 == hashlib.sha256(SAMPLE.encode("utf-8")).hexdigest()


def test_parse_record_without_evidence_is_not_a_finding():
    result = parse_dalfox_json('[{"type":"info","message_str":"scan started"}]')
    assert result.findings == ()
