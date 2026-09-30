"""Unit tests for nexus_core.tools.parsers.whatweb (no network, no binary)."""

from __future__ import annotations

import hashlib

import pytest

from nexus_core.tools.parsers.whatweb import parse_whatweb_json

SAMPLE = (
    '[{"target":"http://scanme.nmap.org/","http_status":200,'
    '"request_config":{"headers":{"User-Agent":"WhatWeb/0.5.5"}},'
    '"plugins":{'
    '"Apache":{"version":["2.4.7"]},'
    '"Country":{"string":["RESERVED"],"module":["ZZ"]},'
    '"HTTPServer":{"os":["Ubuntu Linux"],"string":["Apache/2.4.7 (Ubuntu)"]},'
    '"HTML5":{}}}]'
)


def test_parse_target_and_status():
    result = parse_whatweb_json(SAMPLE)
    assert len(result.targets) == 1
    target = result.targets[0]
    assert target.url == "http://scanme.nmap.org/"
    assert target.http_status == 200


def test_parse_fingerprints_count_and_names():
    result = parse_whatweb_json(SAMPLE)
    names = {fp.name for fp in result.targets[0].fingerprints}
    assert names == {"Apache", "Country", "HTTPServer", "HTML5"}


def test_parse_version_and_details():
    result = parse_whatweb_json(SAMPLE)
    by_name = {fp.name: fp for fp in result.targets[0].fingerprints}
    assert by_name["Apache"].version == "2.4.7"
    assert by_name["HTTPServer"].details == "Apache/2.4.7 (Ubuntu)"


def test_parse_plugin_without_evidence():
    result = parse_whatweb_json(SAMPLE)
    by_name = {fp.name: fp for fp in result.targets[0].fingerprints}
    assert by_name["HTML5"].version is None
    assert by_name["HTML5"].details == ""
    assert by_name["HTML5"].confidence == 1.0


def test_parse_multiple_targets():
    text = (
        '[{"target":"http://a/","http_status":200,"plugins":{}},'
        '{"target":"http://b/","http_status":404,"plugins":{}}]'
    )
    result = parse_whatweb_json(text)
    assert [target.http_status for target in result.targets] == [200, 404]


def test_parse_empty_output_returns_empty_result():
    result = parse_whatweb_json("")
    assert result.targets == ()
    assert result.to_dict()["count"] == 0


def test_parse_invalid_json_raises_value_error():
    with pytest.raises(ValueError):
        parse_whatweb_json("{not json")


def test_parse_non_list_root_raises_value_error():
    with pytest.raises(ValueError):
        parse_whatweb_json('"a string"')


def test_parse_single_object_root_is_accepted():
    result = parse_whatweb_json('{"target":"http://a/","http_status":200,"plugins":{}}')
    assert len(result.targets) == 1


def test_parse_preserves_raw_json_sha256():
    result = parse_whatweb_json(SAMPLE)
    assert result.raw_json_sha256 == hashlib.sha256(SAMPLE.encode("utf-8")).hexdigest()
