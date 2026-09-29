"""Unit tests for nexus_core.tools.parsers.httpx (no network, no httpx binary)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from nexus_core.tools.parsers.httpx import parse_httpx_jsonl

FIXTURES = Path(__file__).parents[1] / "fixtures" / "httpx"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_parse_typical_jsonl_returns_probes():
    result = parse_httpx_jsonl(_read("probes.jsonl"))
    assert len(result.probes) == 3
    assert result.hosts_alive == 3
    first = result.probes[0]
    assert first.url == "https://scanme.example"
    assert first.status_code == 200
    assert first.title == "Scanme"
    assert first.tech == ("Nginx", "PHP")
    assert first.webserver == "nginx"


def test_parse_empty_output_returns_empty_result():
    result = parse_httpx_jsonl("")
    assert result.probes == ()
    assert result.to_dict()["count"] == 0


def test_parse_malformed_json_raises_value_error():
    with pytest.raises(ValueError):
        parse_httpx_jsonl("connection refused by proxy")


def test_parse_minimal_record_with_optional_fields_absent():
    result = parse_httpx_jsonl(_read("minimal.jsonl"))
    probe = result.probes[0]
    assert probe.url == "https://scanme.example"
    assert probe.status_code == 200
    assert probe.title == ""
    assert probe.tech == ()
    assert probe.webserver == ""
    assert probe.cname == ()


def test_parse_counts_status_codes():
    result = parse_httpx_jsonl(_read("probes.jsonl"))
    assert result.status_counts == {"200": 1, "301": 1, "403": 1}


def test_parse_aggregates_technologies_without_duplicates():
    result = parse_httpx_jsonl(_read("probes.jsonl"))
    assert result.tech == ("Nginx", "PHP", "Cloudflare")


def test_parse_tolerates_noise_lines_around_valid_records():
    text = _read("minimal.jsonl") + "\n[warn] unexpected banner\n"
    result = parse_httpx_jsonl(text)
    assert len(result.probes) == 1
    assert result.malformed_lines == 1


def test_parse_preserves_raw_sha256_of_the_payload():
    text = _read("probes.jsonl")
    result = parse_httpx_jsonl(text)
    assert result.raw_sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()
