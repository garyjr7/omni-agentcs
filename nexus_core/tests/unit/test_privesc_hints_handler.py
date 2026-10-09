"""Unit tests for the privilege-escalation hint handler (no network)."""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.tools.handlers.privesc_hints import (
    analyze_privilege_escalation,
    privesc_hints_definition,
    privesc_hints_handler,
)


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(privesc_hints_handler(arguments, _context()))


def test_definition_is_read_only_and_needs_no_scope():
    definition = privesc_hints_definition()
    assert definition.risk.value == "read_only"
    assert definition.scope_required is False


def test_sudo_tar_yields_gtfobins_command():
    candidates = analyze_privilege_escalation(sudo_rules=["/bin/tar"], suid=[], capabilities=[])
    assert candidates and candidates[0]["binary"] == "tar"
    assert candidates[0]["vector"] == "sudo"
    assert candidates[0]["command"].startswith("sudo /bin/tar")
    assert candidates[0]["proof_expected"] == "uid=0(root)"


def test_suid_find_yields_candidate():
    candidates = analyze_privilege_escalation(
        sudo_rules=[], suid=["/usr/bin/find"], capabilities=[]
    )
    assert candidates[0]["vector"] == "suid"
    assert candidates[0]["binary"] == "find"


def test_suid_python2_7_yields_candidate():
    candidates = analyze_privilege_escalation(
        sudo_rules=[], suid=["/usr/bin/python2.7"], capabilities=[]
    )
    assert candidates and candidates[0]["vector"] == "suid"
    assert candidates[0]["binary"] == "python2.7"
    assert "os.setuid(0)" in candidates[0]["command"]


def test_capability_setuid_yields_candidate():
    candidates = analyze_privilege_escalation(
        sudo_rules=[], suid=[], capabilities=["/usr/bin/python3.8 cap_setuid+ep"]
    )
    assert candidates[0]["vector"] == "capabilities"
    assert candidates[0]["binary"] == "python3.8"


def test_sudo_ranked_before_suid():
    candidates = analyze_privilege_escalation(
        sudo_rules=["/bin/tar"], suid=["/usr/bin/find"], capabilities=[]
    )
    assert [item["vector"] for item in candidates] == ["sudo", "suid"]


def test_unmatched_binary_is_ignored():
    candidates = analyze_privilege_escalation(sudo_rules=["/bin/ls"], suid=[], capabilities=[])
    assert candidates == []


def test_handler_returns_verified_candidates():
    result = _run({"sudo_rules": ["/bin/tar"]})
    assert result.verified is True
    assert result.verification_method == "privesc_hints_computed"
    assert result.output["count"] == 1
    assert result.evidence["candidate_vectors"] == ["sudo"]


def test_handler_requires_at_least_one_input():
    with pytest.raises(ValueError):
        _run({})
