"""Unit tests for nexus_core.tools.parsers.nuclei (no network, no nuclei binary)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from nexus_core.tools.parsers.nuclei import parse_nuclei_jsonl

FIXTURES = Path(__file__).parents[1] / "fixtures" / "nuclei"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_parse_typical_jsonl_returns_findings():
    result = parse_nuclei_jsonl(_read("findings.jsonl"))
    assert len(result.findings) == 3
    high = result.findings[2]
    assert high.template_id == "CVE-2021-41773"
    assert high.name == "Apache Path Traversal"
    assert high.severity == "high"
    assert high.host == "scanme.example"
    assert high.matched_at.endswith("/cgi-bin/.%2e/")
    assert high.finding_type == "http"


def test_parse_empty_output_is_a_valid_no_findings_result():
    result = parse_nuclei_jsonl("")
    assert result.findings == ()
    assert result.to_dict()["count"] == 0


def test_parse_malformed_json_raises_value_error():
    with pytest.raises(ValueError):
        parse_nuclei_jsonl("nuclei: templates could not be loaded")


def test_parse_minimal_finding_with_optional_fields_absent():
    result = parse_nuclei_jsonl(_read("minimal.jsonl"))
    finding = result.findings[0]
    assert finding.template_id == "ssl-dns-names"
    assert finding.severity == "info"
    assert finding.matcher_name == ""
    assert finding.extracted == ()
    assert finding.tags == ()


def test_parse_counts_severities_in_order():
    result = parse_nuclei_jsonl(_read("findings.jsonl"))
    assert result.severity_counts == {"high": 1, "info": 2}


def test_parse_extracts_tags_and_matcher_name():
    result = parse_nuclei_jsonl(_read("findings.jsonl"))
    headers = result.findings[0]
    assert "misconfig" in headers.tags
    assert headers.matcher_name == "x-frame-options"
    assert headers.extracted == ("X-Frame-Options",)


def test_parse_tolerates_noise_lines_around_valid_records():
    text = _read("minimal.jsonl") + "\n[INF] scan completed\n"
    result = parse_nuclei_jsonl(text)
    assert len(result.findings) == 1
    assert result.malformed_lines == 1


def test_parse_preserves_raw_sha256_of_the_payload():
    text = _read("findings.jsonl")
    result = parse_nuclei_jsonl(text)
    assert result.raw_sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_parse_unknown_severity_missing_defaults_to_unknown():
    result = parse_nuclei_jsonl('{"template-id":"x","info":{"name":"No Severity"}}\n')
    assert result.findings[0].severity == "unknown"
    assert result.severity_counts == {"unknown": 1}
