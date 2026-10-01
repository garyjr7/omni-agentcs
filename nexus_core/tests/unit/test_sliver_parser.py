"""Deterministic Sliver parsers: versions, sessions/beacons, exec and pivots."""

from __future__ import annotations

import pytest

from nexus_core.tests.sliver_support import session_record
from nexus_core.tools.parsers.sliver import (
    parse_sliver_exec,
    parse_sliver_pivots,
    parse_sliver_session,
    parse_sliver_sessions,
    parse_sliver_version,
)


def test_parse_version():
    info = parse_sliver_version(
        {
            "version": {"Major": 1, "Minor": 6, "Patch": 2, "Commit": "abc"},
            "operators": [
                {"Name": "nexus", "Online": True},
                {"Name": "other", "Online": False},
            ],
            "jobs": [{"ID": 1}, {"ID": 2}],
        }
    )
    assert info.version == "1.6.2-abc"
    assert info.jobs_count == 2
    assert info.operators[0] == {"name": "nexus", "online": True}
    assert info.to_dict()["operators_count"] == 2
    assert info.raw_sha256


def test_parse_version_without_commit():
    info = parse_sliver_version({"version": {"Major": 1, "Minor": 5, "Patch": 0}})
    assert info.version == "1.5.0"
    assert info.jobs_count == 0


def test_parse_version_rejects_bad_payload():
    with pytest.raises(ValueError):
        parse_sliver_version({"version": "not-an-object"})


def test_parse_sessions_empty():
    assert parse_sliver_sessions([], []) == ()
    assert parse_sliver_sessions({"sessions": [], "beacons": []}) == ()


def test_parse_sessions_multiple():
    parsed = parse_sliver_sessions([session_record("s2"), session_record("s1")])
    assert [item.session_id for item in parsed] == ["s1", "s2"]
    first = parsed[0]
    assert first.kind == "session"
    assert first.hostname == "victim"
    assert first.os == "linux"
    assert first.arch == "amd64"
    assert first.remote_address == "203.0.113.10:4444"
    assert first.transport == "mtls"
    assert first.process_id == 4001
    assert first.last_checkin == "1700000000"


def test_parse_sessions_mixed_kinds():
    parsed = parse_sliver_sessions(
        {"sessions": [session_record("sess-1")], "beacons": [session_record("beac-1")]}
    )
    kinds = {item.session_id: item.kind for item in parsed}
    assert kinds == {"sess-1": "session", "beac-1": "beacon"}


def test_parse_sessions_explicit_kind_wins():
    parsed = parse_sliver_sessions([{**session_record("b1"), "Kind": "beacon"}])
    assert parsed[0].kind == "beacon"


def test_parse_session_rejects_record_without_id():
    with pytest.raises(ValueError):
        parse_sliver_session({"Hostname": "victim"})


def test_parse_exec_ok():
    result = parse_sliver_exec(
        {"status_code": 0, "stdout": "uid=0\n", "stderr": "", "duration_seconds": 0.5},
        "sess-1",
        "id",
    )
    assert result.status == "ok"
    assert result.stdout == "uid=0\n"
    assert result.duration_seconds == 0.5
    assert result.to_dict()["session_id"] == "sess-1"


def test_parse_exec_error():
    failed = parse_sliver_exec(
        {"status_code": 1, "stdout": "", "stderr": "boom", "duration_seconds": 0.1},
        "sess-1",
        "false",
    )
    assert failed.status == "error"
    assert failed.stderr == "boom"
    timed_out = parse_sliver_exec(
        {"status": "timeout", "status_code": 0, "stdout": "", "stderr": ""},
        "sess-1",
        "sleep 100",
    )
    assert timed_out.status == "timeout"


def test_parse_pivots():
    pivots = parse_sliver_pivots(
        [
            {"ID": 1, "Type": "TCP", "BindAddress": "0.0.0.0:1080"},
            {"TunnelID": 7, "SessionID": "sess-1"},
            {"Port": 9000, "Host": "10.0.0.5:8080", "kind": "portfwd"},
        ]
    )
    by_kind = {pivot.kind: pivot for pivot in pivots}
    assert by_kind["socks5"].forward_id == 7
    assert by_kind["portfwd"].bind_port == 1080
    forward = next(pivot for pivot in pivots if pivot.remote_host == "10.0.0.5")
    assert forward.remote_port == 8080
    assert forward.bind_port == 9000


def test_parse_pivots_empty():
    assert parse_sliver_pivots([]) == ()
    assert parse_sliver_pivots({"listeners": []}) == ()


def test_parser_preserves_sha256():
    payload = {"version": {"Major": 1, "Minor": 0, "Patch": 0}, "operators": []}
    first = parse_sliver_version(payload)
    second = parse_sliver_version(payload)
    assert first.raw_sha256 == second.raw_sha256
    changed = parse_sliver_version({**payload, "operators": [{"Name": "x", "Online": True}]})
    assert changed.raw_sha256 != first.raw_sha256
