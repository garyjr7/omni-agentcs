from dataclasses import FrozenInstanceError
import hashlib
import json

import pytest

from nexus_core.tools.parsers.metasploit import parse_msf_auxiliary, parse_msf_search


def test_empty_search():
    assert parse_msf_search([], "q").to_dict()["count"] == 0


def test_one_search():
    result = parse_msf_search(
        [{"fullname": "auxiliary/scanner/smb/smb_version", "name": "SMB"}], "smb"
    )
    assert result.modules[0].module_type == "auxiliary"
    assert result.query == "smb"


def test_multiple_search():
    assert (
        len(parse_msf_search([{"fullname": "auxiliary/a"}, {"fullname": "exploit/b"}], "").modules)
        == 2
    )


def test_optional_fields():
    assert parse_msf_search([{"fullname": "auxiliary/a", "name": None}], "").modules[0].name == ""


def test_invalid_search():
    for raw in ({}, [None], [{}]):
        with pytest.raises(ValueError):
            parse_msf_search(raw, "")


def test_hash_and_frozen():
    raw = [{"fullname": "auxiliary/a"}]
    parsed = parse_msf_search(raw, "")
    assert (
        parsed.raw_sha256
        == hashlib.sha256(
            json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
        ).hexdigest()
    )
    with pytest.raises(FrozenInstanceError):
        parsed.query = "other"


def test_auxiliary_completed_null_result():
    result = parse_msf_auxiliary(
        {"status": "completed", "uuid": "u", "result": None}, "auxiliary/a", "host"
    )
    assert result.status == "completed" and result.output is None and result.uuid == "u"


def test_auxiliary_error_and_output():
    assert (
        parse_msf_auxiliary({"status": "errored", "error": "failed"}, "m", "t").output == "failed"
    )
    assert parse_msf_auxiliary({"status": "completed", "output": "text"}, "m", "t").output == "text"


def test_auxiliary_empty_and_invalid():
    assert parse_msf_auxiliary({}, "m", "t").status == "unknown"
    for raw in ([], {"status": "invented"}):
        with pytest.raises(ValueError):
            parse_msf_auxiliary(raw, "m", "t")
