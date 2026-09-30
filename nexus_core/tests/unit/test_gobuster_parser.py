"""Unit tests for nexus_core.tools.parsers.gobuster (no network, no binary)."""

from __future__ import annotations

import hashlib

import pytest

from nexus_core.tools.parsers.gobuster import parse_gobuster_output

HITS = (
    "index.html           (Status: 200) [Size: 6974]\n"
    "images               (Status: 301) [Size: 318] [--> http://scanme.nmap.org/images/]\n"
)


def test_parse_status_and_size():
    result = parse_gobuster_output(HITS, mode="dir", target="http://scanme.nmap.org/")
    assert len(result.hits) == 2
    first = result.hits[0]
    assert first.path == "index.html"
    assert first.status == 200
    assert first.size == 6974
    assert first.redirect is None


def test_parse_redirect():
    result = parse_gobuster_output(HITS)
    redirect = result.hits[1]
    assert redirect.status == 301
    assert redirect.redirect == "http://scanme.nmap.org/images/"


def test_parse_accepts_leading_slash():
    result = parse_gobuster_output("/admin  (Status: 403) [Size: 0]\n")
    assert result.hits[0].path == "/admin"


def test_parse_size_missing_is_none():
    result = parse_gobuster_output("admin  (Status: 403)\n")
    assert result.hits[0].size is None


def test_parse_empty_output_returns_empty_result():
    result = parse_gobuster_output("")
    assert result.hits == ()
    assert result.to_dict()["count"] == 0


def test_parse_banner_only_output_is_empty():
    banner = (
        "===============================================================\n"
        "Gobuster v3.8.2\n"
        "by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)\n"
        "===============================================================\n"
        "Starting gobuster in directory enumeration mode\n"
    )
    result = parse_gobuster_output(banner)
    assert result.hits == ()


def test_parse_malformed_hit_line_raises_value_error():
    with pytest.raises(ValueError):
        parse_gobuster_output("admin (Status: abc) [Size: nope]\n")


def test_parse_preserves_metadata_and_hash():
    result = parse_gobuster_output(HITS, mode="vhost", target="host", duration_seconds=1.5)
    assert result.mode == "vhost"
    assert result.target == "host"
    assert result.duration_seconds == 1.5
    assert result.raw_output_sha256 == hashlib.sha256(HITS.encode("utf-8")).hexdigest()


def test_parse_tolerates_junk_lines_around_hits():
    text = "Starting gobuster\n" + HITS + "Finished\n"
    result = parse_gobuster_output(text)
    assert len(result.hits) == 2


def test_parse_to_dict_shape():
    payload = parse_gobuster_output(HITS).to_dict()
    assert payload["count"] == 2
    assert payload["hits"][0]["path"] == "index.html"
