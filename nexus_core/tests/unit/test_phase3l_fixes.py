"""Phase 3l fixes: the escalation tools name the vector that actually elevates.

Measured in rerun 12 (``run_6ad15e0ffff1414f884c4b9b7e06691f`` against Bounty
Hacker, commit ``c467b0f``, report
``docs/missions/diag/diag_rerun12_2026-10-16.md``): the planner fix held -the plan
stayed on ``privilege_escalation`` with the ``privesc`` profile for 8 iterations and
never closed the phase by position- and the run still failed, in the *tool* layer:

* iteration 9 read ``/home/lin/Desktop/user.txt`` and ran ``sudo -n -l``, which
  answered ``sudo: a password is required``. The model read that as "sudo is
  unusable" and never called ``nexus.post.enum_system``, the one tool in its own
  subset that resolves ``sudo -l`` by feeding the vault credential to ``sudo -S``
  (``ssh_post.py``). The rerun 10 had done exactly that call and reached
  ``uid=0(root)`` on the same box;
* it did call ``privesc_hints`` -with ``sudo_rules: []``- and received a single
  candidate: the **SUID** template of ``/bin/tar``. It ran that vector verbatim
  (iterations 11 and 13) and measured ``uid=1001(lin)``: ``/bin/tar`` carries the
  SUID bit and does not elevate. The handler already had the ``sudo`` template of
  the same binary -the one that elevates- but the hint said nothing about which
  vector it was offering;
*  the remaining budget went into a hand-built PwnKit, and the run died at
  ``63465/60000`` tokens without root, ``findings: 0`` and no ``task_complete``.

Two fixes, each pinned below: V1-44 (``enum_system``'s description says it resolves
``sudo -l`` with the vault credential and the ``privesc`` profile hint names it
right after the failure symptom) and V1-45 (every ``privesc_hints`` candidate
declares its ``vector_kind`` and its ``preconditions``, and the description says
SUID and sudo are different vectors over the same binary).

The first fix only counts if the model *reads* it: ``render_tool_catalog`` shows
one line per tool and cuts every description at ``CATALOG_DESCRIPTION_CHARS`` (64),
so the tests below assert on the rendered, truncated line -the text that reaches
the prompt- instead of on the full attribute.
"""

from __future__ import annotations

import pytest

from nexus_core.agent.prompts import render_tool_catalog
from nexus_core.agent.subagents import SUBAGENTS_BY_ID
from nexus_core.tools.handlers.privesc_hints import (
    VECTOR_KINDS,
    analyze_privilege_escalation,
    privesc_hints_definition,
)
from nexus_core.tools.handlers.ssh_post import enum_system_definition
from nexus_core.tools.registry import durable_tool_definitions

pytestmark = pytest.mark.unit


def _visible_description(tool_id: str) -> str:
    """The description **as the model reads it** in the system prompt.

    ``render_tool_catalog`` truncates every catalog line to
    ``CATALOG_DESCRIPTION_CHARS`` (64), so a sentence written past that cut is a
    sentence the model never sees: asserting on ``definition.description`` alone
    would pass while the fix did nothing. These tests check the visible prefix.
    """
    line = next(
        line
        for line in render_tool_catalog(durable_tool_definitions("system")).splitlines()
        if line.startswith(f"- {tool_id}:")
    )
    visible = line[len(f"- {tool_id}: ") :].split(" | args[")[0]
    assert visible, tool_id
    return visible.lower()


# ------------------------------------------------ V1-44: the tool says what it solves


def test_enum_system_description_mentions_sudo_resolution():
    """The symptom is the trigger and this tool is the answer to it.

    Rerun 12: ``sudo: a password is required`` from ``ssh_exec`` sent the model
    down the SUID path instead of to the tool that resolves it.
    """
    visible = _visible_description("nexus.post.enum_system")
    assert "sudo -l" in visible
    assert "sudo: a password is required" in visible
    assert "resuelve" in visible
    # The text the model reads is the tool's own description, not a paraphrase
    # that could drift from it.
    assert visible.rstrip("…").strip() in enum_system_definition().description.lower()


def test_enum_system_description_mentions_vault_credential():
    """It works because the engine feeds the stored secret to ``sudo -S``."""
    visible = _visible_description("nexus.post.enum_system")
    assert "vault" in visible
    description = enum_system_definition().description.lower()
    assert "sudo -s" in description
    assert "contraseña guardada" in description
    assert "una llamada" in description
    assert "no invoques sudo -l por" in description


# ------------------------------------------- V1-45: one vector per hint, with conditions


def test_privesc_hints_have_vector_kind():
    """No candidate mixes vectors: each declares exactly one, from the vocabulary."""
    candidates = analyze_privilege_escalation(
        sudo_rules=["/bin/tar"],
        suid=["/usr/bin/find"],
        capabilities=["/usr/bin/python3.8 cap_setuid+ep"],
    )
    # ``sudo`` first: it is the vector that elevates without a second condition.
    assert [item["vector_kind"] for item in candidates] == ["sudo", "capabilities", "suid"]
    for item in candidates:
        assert item["vector_kind"] == item["vector"]
        assert item["vector_kind"] in VECTOR_KINDS


def test_privesc_hints_have_preconditions():
    """The agent has to check observable conditions before running the command."""
    sudo_candidate = analyze_privilege_escalation(
        sudo_rules=["/bin/tar"], suid=[], capabilities=[]
    )[0]
    suid_candidate = analyze_privilege_escalation(
        sudo_rules=[], suid=["/bin/tar"], capabilities=[]
    )[0]

    assert "user in sudoers" in sudo_candidate["preconditions"]
    assert any("vault" in text for text in sudo_candidate["preconditions"])
    assert "file has SUID bit" in suid_candidate["preconditions"]
    assert "running as the SUID owner" in suid_candidate["preconditions"]

    # Every hint carries the list, as strings, and no two hints share one object
    # (a caller that mutated it would rewrite its neighbours).
    for item in (sudo_candidate, suid_candidate):
        assert item["preconditions"]
        assert all(isinstance(text, str) and text for text in item["preconditions"])
    assert sudo_candidate["preconditions"] is not suid_candidate["preconditions"]


def test_privesc_hints_distinguishes_suid_and_sudo_for_tar():
    """Same binary, two vectors: SUID measured ``uid=1001``, sudo reached root.

    The board of the rerun 12 held both surfaces (the SUID bit on ``/bin/tar``
    *and* the sudo rule the run never enumerated), so the two hints must not be
    interchangeable.
    """
    candidates = analyze_privilege_escalation(
        sudo_rules=["/bin/tar"], suid=["/bin/tar"], capabilities=[]
    )
    by_kind = {item["vector_kind"]: item for item in candidates}
    assert set(by_kind) == {"sudo", "suid"}

    sudo, suid = by_kind["sudo"], by_kind["suid"]
    assert sudo["binary"] == suid["binary"] == "tar"
    assert sudo["command"].startswith("sudo /bin/tar")
    assert suid["command"].startswith("/bin/tar")
    assert not suid["command"].startswith("sudo ")
    assert sudo["preconditions"] != suid["preconditions"]
    # The vector that needs the sudo rule is read first.
    assert candidates[0]["vector_kind"] == "sudo"


def test_privesc_hints_description_explains_vector_difference():
    """The description states the distinction where the model reads it.

    Rerun 12 offered SUID and sudo for the same binary and the model took the
    first one it saw; a distinction explained past the 64-character cut would not
    have helped.
    """
    visible = _visible_description("nexus.post.privesc_hints")
    assert "vector_kind" in visible
    assert "preconditions" in visible
    assert "suid" in visible and "sudo" in visible

    description = privesc_hints_definition().description.lower()
    assert "distintos" in description
    assert "sudoers" in description


# ------------------------------------------------ V1-44: the profile hint reaches the prompt


def test_privesc_subagent_hint_mentions_enum_system():
    """The correction lives where the model reads the active profile."""
    profile = SUBAGENTS_BY_ID["privesc"]
    assert profile.hint
    assert "nexus.post.enum_system" in profile.hint
    assert "sudo: a password is required" in profile.hint
    # The hint is in the prompt frame, and the tool it points at is in this very
    # subset (a hint must never name a tool the gateway would deny).
    frame = profile.describe()
    assert f"pista: {profile.hint}" in frame
    assert "nexus.post.enum_system" in profile.tools
    assert profile.to_dict()["hint"] == profile.hint
    # The default profile stays without a hint: this one is a measured correction.
    assert SUBAGENTS_BY_ID["recon"].hint is None
