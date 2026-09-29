"""Unit tests for nexus_core.tools.parsers.subfinder (no network, no subfinder)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from nexus_core.tools.parsers.subfinder import parse_subfinder_jsonl

FIXTURES = Path(__file__).parents[1] / "fixtures" / "subfinder"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_parse_typical_jsonl_returns_subdomains():
    result = parse_subfinder_jsonl(_read("enumeration.jsonl"), "scanme.example")
    assert result.domain == "scanme.example"
    assert result.subdomains == (
        "www.scanme.example",
        "api.scanme.example",
        "mail.scanme.example",
    )
    assert result.to_dict()["count"] == 3


def test_parse_deduplicates_repeated_hosts():
    result = parse_subfinder_jsonl(_read("enumeration.jsonl"))
    assert len(result.subdomains) == len(set(result.subdomains))


def test_parse_empty_output_returns_empty_result():
    result = parse_subfinder_jsonl("", "scanme.example")
    assert result.subdomains == ()
    assert result.to_dict()["count"] == 0


def test_parse_malformed_json_raises_value_error():
    with pytest.raises(ValueError):
        parse_subfinder_jsonl("<<html>gateway error</html>>")


def test_parse_line_with_missing_optional_fields():
    result = parse_subfinder_jsonl('{"host":"only.scanme.example"}\n')
    assert result.subdomains == ("only.scanme.example",)
    assert result.sources == ()


def test_parse_counts_malformed_lines_when_some_are_valid():
    text = '{"host":"good.scanme.example"}\nnot json at all\n'
    result = parse_subfinder_jsonl(text)
    assert result.subdomains == ("good.scanme.example",)
    assert result.malformed_lines == 1


def test_parse_falls_back_to_plain_silent_lines():
    result = parse_subfinder_jsonl(_read("plain_lines.txt"), "scanme.example")
    assert result.subdomains == (
        "www.scanme.example",
        "api.scanme.example",
        "mail.scanme.example",
    )


def test_parse_preserves_raw_sha256_of_the_payload():
    text = _read("enumeration.jsonl")
    result = parse_subfinder_jsonl(text)
    assert result.raw_sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_parse_extracts_sources():
    result = parse_subfinder_jsonl(_read("enumeration.jsonl"))
    assert set(result.sources) == {"crtsh", "github", "dnsdumpster"}
