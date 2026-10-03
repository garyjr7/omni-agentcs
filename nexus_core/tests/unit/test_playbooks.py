"""V4.5 deterministic playbooks: applicability, completion and the tool."""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.agent.playbooks import (
    LATERAL_MOVEMENT,
    PLAYBOOKS,
    match_playbook,
    select_playbooks,
)
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.tests.sliver_support import owned_context
from nexus_core.tools.handlers import playbook as playbook_handler_module

TOOL_ID = "nexus.orchestrator.playbook"


def facts(*items):
    return [
        {"fact_type": fact_type, "key": key, "value": value, "verified": True}
        for fact_type, key, value in items
    ]


def test_three_playbooks_are_registered():
    assert {item.playbook_id for item in PLAYBOOKS} == {
        "ftp_anon_to_cred",
        "linux_privesc",
        "lateral_movement",
    }


def test_ftp_playbook_applies_to_ftp_service():
    board = facts(("service", "10.0.0.5:21/tcp", {"port": 21, "product": "vsftpd"}))
    (match,) = select_playbooks(board)
    assert match.playbook.playbook_id == "ftp_anon_to_cred"
    assert match.next_step.step_id == "ftp_list"
    assert match.next_step.tool_id == "nexus.recon.ftp"


def test_ftp_playbook_completes_after_credential():
    board = facts(
        ("service", "s", {"port": 21}),
        ("endpoint", "e", {}),
        ("artifact", "a", {}),
        ("credential", "c", {}),
    )
    (match,) = select_playbooks(board)
    assert match.completed == ("ftp_list", "ftp_download", "bruteforce")
    assert match.next_step is None


def test_privesc_playbook_requires_access():
    assert select_playbooks(facts(("service", "s", {"port": 22}))) == ()
    board = facts(("access", "host", {"kind": "ssh"}))
    (match,) = select_playbooks(board)
    assert match.playbook.playbook_id == "linux_privesc"
    assert match.next_step.tool_id == "nexus.post.enum_system"


def test_privesc_completes_when_privilege_recorded():
    board = facts(
        ("access", "host", {}),
        ("privilege", "root", {"vector": "sudo tar"}),
    )
    match = match_playbook(LATERAL_MOVEMENT, board)  # smoke: unrelated playbook
    assert match.playbook.playbook_id == "lateral_movement"
    (privesc,) = [
        item for item in select_playbooks(board) if item.playbook.playbook_id == "linux_privesc"
    ]
    assert privesc.next_step is None
    assert "escalate" in privesc.completed


def lateral_matches(board):
    return [
        item for item in select_playbooks(board)
        if item.playbook.playbook_id == "lateral_movement"
    ]


def test_lateral_requires_access_and_service():
    assert lateral_matches(facts(("access", "h", {}))) == []
    board = facts(("access", "h", {}), ("service", "s", {"port": 22}))
    (match,) = lateral_matches(board)
    assert match.next_step.tool_id == "nexus.c2.sliver_generate"


def test_lateral_completes_once_session_exists():
    board = facts(
        ("access", "h", {}),
        ("service", "s", {"port": 22}),
        ("session", "new", {}),
    )
    (match,) = lateral_matches(board)
    assert match.next_step is None
    assert match.completed == ("generate", "deploy", "register")


def test_list_includes_not_ready_playbooks():
    matches = select_playbooks(facts(), only_ready=False)
    assert len(matches) == 3
    assert all(match.next_step is None for match in matches)


def _record(board, run_context, fact_type, key, value):
    board.record(
        tenant_id="system",
        engagement_id=run_context.scope.engagement_id,
        fact_type=fact_type,
        key=key,
        value=value,
        source="test",
        created_by="tester",
    )


def test_handler_next_lists_applicable_playbooks(tmp_path):
    run_context, store = owned_context(tmp_path)
    _record(Blackboard(store), run_context, "service", "10.0.0.5:21", {"port": 21})
    result = asyncio.run(
        playbook_handler_module.playbook_handler({"action": "next"}, run_context)
    )
    assert result.success
    assert result.verification_method == "playbook_next"
    assert result.output["playbooks"][0]["playbook_id"] == "ftp_anon_to_cred"
    assert result.output["playbooks"][0]["next_step"]["tool_id"] == "nexus.recon.ftp"


def test_handler_show_returns_full_steps(tmp_path):
    run_context, store = owned_context(tmp_path)
    _record(Blackboard(store), run_context, "access", "h", {})
    result = asyncio.run(
        playbook_handler_module.playbook_handler(
            {"action": "show", "playbook_id": "linux_privesc"}, run_context
        )
    )
    assert result.output["applicable"] is True
    step_ids = [step["step_id"] for step in result.output["playbook"]["steps"]]
    assert step_ids == ["enum_system", "privesc_hints", "escalate"]


def test_handler_show_rejects_unknown(tmp_path):
    run_context, _ = owned_context(tmp_path)
    with pytest.raises(ValueError):
        asyncio.run(
            playbook_handler_module.playbook_handler(
                {"action": "show", "playbook_id": "nope"}, run_context
            )
        )


def test_playbook_tool_registered_and_read_only():
    from nexus_core.tools.registry import durable_tool_definitions

    definition, _handler = durable_tool_definitions()[TOOL_ID]
    assert definition.risk.value == "read_only"
    assert definition.scope_required is False
