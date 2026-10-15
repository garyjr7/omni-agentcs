"""Fase 3e fixes: a real session is accepted, and the evidence says why.

Measured in rerun 5 (``run_cf7e95bdab064ddea36b44255ee86e6c``, ``10.65.175.32``,
2026-10-15), iteration 12: ``nexus.exploit.msf_exploit`` ran
``exploit/windows/smb/ms17_010_psexec``, MS17-010 succeeded in 9,9 s and
``msfrpcd`` held a Meterpreter session as ``NT AUTHORITY\\SYSTEM @
WIN-JO6REVNMMMP``. The handler answered ``session_provenance_unverified`` and the
run closed with ``findings: 0`` and the session unregistered -**the room was
owned and the report said nothing**.

The cause was a comparison between two identifiers of a different nature: the
handler required ``session["exploit_uuid"]`` to equal ``parsed.job_uuid``, i.e. an
8-character *module* uuid (``w87amfh3``, the module that opened the session)
against the 24-character *RPC job* uuid (``E7pL2s8DZTFpZF7DoYiVUMwC``, the
execution in ``msfrpcd``). They can never be equal, so the check could not be
satisfied by any real session. The test that covered it forced the equality in its
own fixture (``"exploit_uuid": "job-uuid"``), so it could only pass while the bug
was in place.

One fix, one commit:

* ``MetasploitClient.execute_exploit`` reports every session observed in the **job
  window** (``new_sessions``: ``session.list`` sampled immediately before
  ``module.execute`` and polled until one appears).
* ``msf_exploit`` correlates by *window* (exactly one new session) and *target*
  (the session must report the pinned target), never by identifier equality. A
  clean correlation registers the session and returns ``session_established``;
  0 or more than one new session is ``session_provenance_ambiguous`` with
  ``outcome="unavailable"`` (there *is* a session, we just cannot say which job
  opened it).
* Every result carries both identifiers -``job_uuid`` and ``exploit_uuid``- in
  its evidence, including the refusals that used to expose neither.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.sessions import SessionRegistry
from nexus_core.tests.msf_support import context, fake_client, scope
from nexus_core.tools.handlers import msf_exploit as module

pytestmark = [
    pytest.mark.unit,
    # The unsigned fixtures of the scope/session behavior; governed stays the
    # default everywhere else (same convention as the Phase 3/3b/3c/3d suites).
    pytest.mark.usefixtures("lab_scope"),
]

FIXTURES = Path(__file__).parents[1] / "fixtures" / "metasploit"
#: The verbatim pair of the run that measured the bug: 24-character RPC job uuid
#: against the 8-character module uuid of the session it opened.
RERUN5 = FIXTURES / "rerun5_session_provenance.json"

TARGET = "10.65.175.32"
MODULE = "exploit/windows/smb/ms17_010_psexec"
ARGS = {"module": MODULE, "target": TARGET}

#: The six fields the evidence of an established session must carry (V1-23).
REQUIRED_EVIDENCE = ("session_uuid", "tunnel_peer", "exploit_uuid", "job_uuid", "module", "target")


def _rerun5() -> dict[str, Any]:
    return json.loads(RERUN5.read_text(encoding="utf-8"))


def _session_record(**overrides: Any) -> dict[str, Any]:
    """A session on the run's target, shaped like the fixture's."""
    record = {
        "type": "meterpreter",
        "tunnel_local": "192.168.144.132:4444",
        "tunnel_peer": f"{TARGET}:50197",
        "via_exploit": MODULE,
        "via_payload": "payload/windows/x64/meterpreter/reverse_tcp",
        "info": "NT AUTHORITY\\SYSTEM @ WIN-ROOM",
        "session_host": TARGET,
        "session_port": 445,
        "target_host": TARGET,
        "uuid": "sess-1",
        "exploit_uuid": "w87amfh3",
    }
    record.update(overrides)
    return record


def _raw(session: dict[str, Any] | None, **overrides: Any) -> dict[str, Any]:
    """The dict ``execute_exploit`` returns for an exploit that opened a session."""
    payload: dict[str, Any] = {
        "status": "session_opened",
        "module": MODULE,
        "job_id": 7,
        "job_uuid": "E7pL2s8DZTFpZF7DoYiVUMwC",
        "session_uuid": None,
        "duration_seconds": 3.5,
    }
    if session is not None:
        payload["session"] = session
        payload["session_uuid"] = str(session.get("uuid") or "sess-1")
        payload["new_sessions"] = [{"uuid": payload["session_uuid"], "record": session}]
    payload.update(overrides)
    return payload


def _run(tmp_path: Path, raw: dict[str, Any], monkeypatch) -> tuple[Any, Any]:
    """Invoke the handler against the fixture raw response; return (result, store)."""
    client = fake_client(monkeypatch, module)
    client.execute_exploit.return_value = raw
    store = ControlStore(tmp_path / "phase3e.db")
    store.initialize()
    run_context = replace(context(scope(cidrs=("10.65.175.0/24",))), store=store)
    result = asyncio.run(module.msf_exploit_handler(ARGS, run_context))
    return result, store


# --------------------------------------------------------------- 1 · clean window


def test_msf_exploit_registers_session_when_correlation_is_clean(tmp_path, monkeypatch):
    """Exactly one new session in the window, on the job's target: it is ours.

    The two identifiers are different by construction here, so passing means the
    decision did not depend on comparing them.
    """
    result, store = _run(tmp_path, _raw(_session_record()), monkeypatch)

    assert result.success and result.verified
    assert result.verification_method == "session_established"
    assert result.completed is True
    record = SessionRegistry(store).get("system", "sess-1")
    assert record is not None and record["target_host"] == TARGET
    assert record["opened_by_tool"] == "nexus.exploit.msf_exploit"
    assert result.output["status"] == "session_opened"
    for field in REQUIRED_EVIDENCE:
        assert result.evidence.get(field), f"evidence is missing {field}"
    assert result.evidence["window_sessions"] == 1
    assert result.evidence["session_hosts"] == [TARGET]


# ----------------------------------------------------------- 2 · ambiguous window


def test_msf_exploit_returns_ambiguous_when_two_sessions_in_window(tmp_path, monkeypatch):
    """Two sessions in the job window: there is one, we cannot tell which is ours.

    ``unavailable`` (never a silent rejection, never ``negative``): nothing was
    proven about *our* target, the session is not registered, and the loop is free
    to pivot. The evidence keeps both identifiers plus the count.
    """
    other = _session_record(uuid="sess-2")
    raw = _raw(
        _session_record(),
        new_sessions=[
            {"uuid": "sess-1", "record": _session_record()},
            {"uuid": "sess-2", "record": other},
        ],
    )
    result, store = _run(tmp_path, raw, monkeypatch)

    assert not result.verified
    assert result.verification_method == "session_provenance_ambiguous"
    assert result.outcome == "unavailable"
    assert result.completed is True  # determinate: the loop counts it and pivots
    assert result.evidence["window_sessions"] == 2
    assert result.evidence["job_uuid"] and result.evidence["exploit_uuid"]
    assert SessionRegistry(store).get("system", "sess-1") is None
    assert SessionRegistry(store).get("system", "sess-2") is None


def test_msf_exploit_returns_ambiguous_when_zero_sessions_in_window(tmp_path, monkeypatch):
    """The module reports a session and the window shows none (it died first).

    Same contract as the other ambiguous case: the session is unknown, so it is
    ``unavailable`` -not ``negative`` (nothing was observed about our target) and
    not a contract failure.
    """
    result, store = _run(
        tmp_path, _raw(_session_record(), new_sessions=[]), monkeypatch
    )

    assert not result.verified
    assert result.verification_method == "session_provenance_ambiguous"
    assert result.outcome == "unavailable"
    assert result.completed is True
    assert result.evidence["window_sessions"] == 0
    assert result.evidence["job_uuid"] and result.evidence["exploit_uuid"]
    assert SessionRegistry(store).get("system", "sess-1") is None


# ------------------------------------------------------------------ 3 · evidence


def test_msf_exploit_evidence_includes_both_uuids_even_on_failure(tmp_path, monkeypatch):
    """A refused session still reports *what was seen*, both identifiers included.

    In rerun 5 the refusal carried neither uuid, so the operator could not even
    tell which module had opened the session that was thrown away.
    """
    # One new session that reports another host: not our session, refused.
    foreign = _session_record(
        uuid="sess-2",
        session_host="198.51.100.1",
        target_host="198.51.100.1",
        tunnel_peer="198.51.100.1:50197",
    )
    raw = _raw(foreign, session_uuid="sess-2")
    raw["new_sessions"] = [{"uuid": "sess-2", "record": foreign}]
    result, store = _run(tmp_path, raw, monkeypatch)

    assert not result.verified
    assert result.verification_method == "session_provenance_unverified"
    assert result.evidence["job_uuid"] == "E7pL2s8DZTFpZF7DoYiVUMwC"
    assert result.evidence["exploit_uuid"] == "w87amfh3"
    assert result.evidence["job_uuid"] != result.evidence["exploit_uuid"]
    assert result.evidence["session_hosts"] == ["198.51.100.1"]
    assert SessionRegistry(store).get("system", "sess-2") is None

    # The paths where no session exists keep the keys too (``None``/empty), so a
    # consumer never has to guess whether they were dropped.
    timeout = _raw(None, status="timeout")
    result, _ = _run(tmp_path, timeout, monkeypatch)
    assert result.verification_method == "msf_exploit_timeout"
    assert result.evidence["job_uuid"] == "E7pL2s8DZTFpZF7DoYiVUMwC"
    assert result.evidence["exploit_uuid"] is None


# ------------------------------------------------- 4 · the bug does not come back


def test_no_rejection_by_uuid_equality(tmp_path, monkeypatch):
    """The verbatim rerun 5 pair must be **accepted**, and equality is irrelevant.

    The fixture keeps the real values: ``job_uuid`` of 24 characters and the
    session's ``exploit_uuid`` of 8 -the pair the old check compared and could
    never satisfy (it rejected the SYSTEM Meterpreter this fixture describes).
    The second half pins the other direction: forcing the identifiers to be equal
    does not change the decision either, because the decision never reads them.
    """
    fixture = _rerun5()
    job_uuid, session = fixture["job_uuid"], fixture["session"]
    assert len(job_uuid) == 24 and len(session["exploit_uuid"]) == 8
    assert job_uuid != session["exploit_uuid"]

    raw = {
        "status": "session_opened",
        "module": fixture["_source"]["module"],
        "job_id": 12,
        "job_uuid": job_uuid,
        "session_uuid": fixture["session_uuid"],
        "session": session,
        "new_sessions": [{"uuid": fixture["session_uuid"], "record": session}],
        "duration_seconds": fixture["_source"]["observed_result"]["duration_seconds"],
    }
    client = fake_client(monkeypatch, module)
    client.execute_exploit.return_value = raw
    store = ControlStore(tmp_path / "phase3e-rerun5.db")
    store.initialize()
    run_context = replace(context(scope(cidrs=("10.65.175.0/24",))), store=store)
    args = {"module": fixture["_source"]["module"], "target": fixture["_source"]["target"]}
    result = asyncio.run(module.msf_exploit_handler(args, run_context))

    assert result.success and result.verified
    assert result.verification_method == "session_established"
    assert result.evidence["job_uuid"] == job_uuid
    assert result.evidence["exploit_uuid"] == session["exploit_uuid"]
    assert result.evidence["tunnel_peer"] == session["tunnel_peer"]
    record = SessionRegistry(store).get("system", fixture["session_uuid"])
    assert record is not None and record["target_host"] == TARGET

    # Same window and target, identifiers forced equal: still accepted.
    same = {**session, "exploit_uuid": job_uuid}
    equal_raw = {**raw, "session": same, "new_sessions": [{"uuid": same["uuid"], "record": same}]}
    result, _ = _run(tmp_path, equal_raw, monkeypatch)
    assert result.verified and result.verification_method == "session_established"
