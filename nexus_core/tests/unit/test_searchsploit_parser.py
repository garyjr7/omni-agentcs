"""Unit tests for nexus_core.tools.parsers.searchsploit (no network, no binary)."""

from __future__ import annotations

import hashlib

import pytest

from nexus_core.tools.parsers.searchsploit import parse_searchsploit_json

SAMPLE = (
    '{"SEARCH":"apache","DB_PATH_EXPLOIT":"/opt/exploitdb",'
    '"RESULTS_EXPLOIT":['
    '{"Title":"Apache Log4j 2 - RCE","EDB-ID":"50592","Date_Published":"2021-12-14",'
    '"Author":"kozmer","Type":"remote","Platform":"java",'
    '"Path":"/opt/exploitdb/exploits/java/remote/50592.py"}],'
    '"RESULTS_SHELLCODE":[]}'
)


def test_parse_exploit_entry_fields():
    result = parse_searchsploit_json(SAMPLE, "apache")
    assert result.total == 1
    entry = result.exploits[0]
    assert entry.title == "Apache Log4j 2 - RCE"
    assert entry.edb_id == "50592"
    assert entry.date == "2021-12-14"
    assert entry.author == "kozmer"
    assert entry.type == "remote"
    assert entry.platform == "java"
    assert entry.path.endswith("50592.py")


def test_parse_query_is_preserved():
    result = parse_searchsploit_json(SAMPLE, "apache")
    assert result.query == "apache"


def test_parse_query_falls_back_to_search_field():
    result = parse_searchsploit_json(SAMPLE)
    assert result.query == "apache"


def test_parse_empty_results_are_not_an_error():
    result = parse_searchsploit_json(
        '{"SEARCH":"apache","RESULTS_EXPLOIT":[],"RESULTS_SHELLCODE":[]}', "apache"
    )
    assert result.total == 0
    assert result.exploits == ()
    assert result.shellcodes == ()


def test_parse_empty_text_returns_empty_result():
    result = parse_searchsploit_json("", "apache")
    assert result.total == 0
    assert result.query == "apache"


def test_parse_invalid_json_raises_value_error():
    with pytest.raises(ValueError):
        parse_searchsploit_json("{broken", "apache")


def test_parse_non_object_root_raises_value_error():
    with pytest.raises(ValueError):
        parse_searchsploit_json("[]", "apache")


def test_parse_shellcodes_are_separated():
    text = (
        '{"SEARCH":"x","RESULTS_EXPLOIT":[{"Title":"e","EDB-ID":"1"}],'
        '"RESULTS_SHELLCODE":[{"Title":"s","EDB-ID":"2"}]}'
    )
    result = parse_searchsploit_json(text, "x")
    assert result.total == 2
    assert len(result.exploits) == 1
    assert len(result.shellcodes) == 1


def test_parse_missing_optional_fields():
    text = '{"SEARCH":"x","RESULTS_EXPLOIT":[{"Title":"e","EDB-ID":"7"}],"RESULTS_SHELLCODE":[]}'
    entry = parse_searchsploit_json(text, "x").exploits[0]
    assert entry.date is None
    assert entry.author is None
    assert entry.type is None
    assert entry.platform is None


def test_parse_preserves_raw_json_sha256():
    result = parse_searchsploit_json(SAMPLE, "apache")
    assert result.raw_json_sha256 == hashlib.sha256(SAMPLE.encode("utf-8")).hexdigest()
