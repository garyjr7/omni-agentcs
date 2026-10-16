"""V4.5 deterministic playbooks: applicability, completion and the tool."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from nexus_core.agent.playbooks import PlaybookMatch
from nexus_core.kernel.models import RunContext


import asyncio

import pytest

from nexus_core.agent.playbooks import (
    LATERAL_MOVEMENT,
    PLAYBOOKS,
    match_playbook,
    registered_playbooks,
    select_playbooks,
)
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.tests.sliver_support import owned_context
from nexus_core.tools.handlers import playbook as playbook_handler_module

TOOL_ID = "nexus.orchestrator.playbook"


def facts(*items: tuple[str, str, dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"fact_type": fact_type, "key": key, "value": value, "verified": True,
         "asserted_by": "verifier", "verification_method": "fixture", "invocation_id": "fixture"}
        for fact_type, key, value in items
    ]


def test_three_playbooks_are_registered() -> None:
    assert {item.playbook_id for item in PLAYBOOKS} == {
        "ftp_anon_to_cred",
        "linux_privesc",
        "lateral_movement",
    }


def matches_for(board: list[dict[str, Any]], playbook_id: str) -> list[PlaybookMatch]:
    """The matches of one playbook (the registry also carries the packaged chain,
    so a hand-written playbook is asserted by id instead of by position)."""
    return [
        match
        for match in select_playbooks(board)
        if match.playbook.playbook_id == playbook_id
    ]


def test_ftp_playbook_applies_to_ftp_service() -> None:
    board = facts(("service", "10.0.0.5:21/tcp", {"port": 21, "product": "vsftpd"}))
    (match,) = matches_for(board, "ftp_anon_to_cred")
    assert match.next_step is not None
    assert match.next_step.step_id == "ftp_list"
    assert match.next_step.tool_id == "nexus.recon.ftp"


def test_ftp_global_credential_does_not_complete_unexecuted_steps() -> None:
    board = facts(
        ("service", "s", {"port": 21}),
        ("endpoint", "e", {}),
        ("artifact", "a", {}),
        ("credential", "c", {}),
    )
    (match,) = matches_for(board, "ftp_anon_to_cred")
    assert match.completed == ()
    assert match.next_step is not None and match.next_step.step_id == "ftp_list"


def test_privesc_playbook_requires_access() -> None:
    assert matches_for(facts(("service", "s", {"port": 22})), "linux_privesc") == []
    board = facts(("access", "host", {"kind": "ssh"}))
    (match,) = matches_for(board, "linux_privesc")
    assert match.next_step is not None
    assert match.next_step.tool_id == "nexus.post.enum_system"


def test_global_privilege_does_not_complete_unexecuted_steps() -> None:
    board = facts(
        ("access", "host", {}),
        ("privilege", "root", {"vector": "sudo tar"}),
    )
    match = match_playbook(LATERAL_MOVEMENT, board)  # smoke: unrelated playbook
    assert match.playbook.playbook_id == "lateral_movement"
    (privesc,) = [
        item for item in select_playbooks(board) if item.playbook.playbook_id == "linux_privesc"
    ]
    assert privesc.next_step is not None
    assert privesc.completed == ()


def lateral_matches(board: list[dict[str, Any]]) -> list[PlaybookMatch]:
    return matches_for(board, "lateral_movement")


def test_lateral_requires_access_and_service() -> None:
    assert lateral_matches(facts(("access", "h", {}))) == []
    board = facts(("access", "h", {}), ("service", "s", {"port": 22}))
    (match,) = lateral_matches(board)
    assert match.next_step is not None
    assert match.next_step.tool_id == "nexus.c2.sliver_generate"


def test_global_session_does_not_complete_unexecuted_steps() -> None:
    board = facts(
        ("access", "h", {}),
        ("service", "s", {"port": 22}),
        ("session", "new", {}),
    )
    (match,) = lateral_matches(board)
    assert match.next_step is not None
    assert match.completed == ()


def test_list_includes_not_ready_playbooks() -> None:
    matches = select_playbooks(facts(), only_ready=False)
    registered = registered_playbooks()
    # Every registered playbook is listed (the packaged red_team_base chain
    # included); only the ones whose gate already holds have a next step.
    assert {match.playbook.playbook_id for match in matches} == {
        playbook.playbook_id for playbook in registered
    }
    assert any(match.next_step is None for match in matches)
    ready = {match.playbook.playbook_id for match in matches if match.next_step is not None}
    assert ready == {"red_team_base.stealth_recon"}


def _record(board: Blackboard, run_context: RunContext, fact_type: str, key: str, value: dict[str, Any]) -> None:
    assert run_context.scope is not None
    board.record(
        tenant_id="system",
        engagement_id=run_context.scope.engagement_id,
        fact_type=fact_type,
        key=key,
        value=value,
        source="test",
        created_by="tester", verified=True, asserted_by="verifier",
        verification_method="fixture", invocation_id="fixture",
    )


def test_handler_next_lists_applicable_playbooks(tmp_path: Path) -> None:
    run_context, store = owned_context(tmp_path)
    _record(Blackboard(store), run_context, "service", "10.0.0.5:21", {"port": 21})
    result = asyncio.run(
        playbook_handler_module.playbook_handler({"action": "next"}, run_context)
    )
    assert result.success
    assert result.verification_method == "playbook_next"
    assert result.output["playbooks"][0]["playbook_id"] == "ftp_anon_to_cred"
    assert result.output["playbooks"][0]["next_step"]["tool_id"] == "nexus.recon.ftp"


def test_handler_show_returns_full_steps(tmp_path: Path) -> None:
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


def test_handler_show_rejects_unknown(tmp_path: Path) -> None:
    run_context, _ = owned_context(tmp_path)
    with pytest.raises(ValueError):
        asyncio.run(
            playbook_handler_module.playbook_handler(
                {"action": "show", "playbook_id": "nope"}, run_context
            )
        )


def test_playbook_tool_registered_and_read_only() -> None:
    from nexus_core.tools.registry import durable_tool_definitions

    definition, _handler = durable_tool_definitions()[TOOL_ID]
    assert definition.risk.value == "read_only"
    assert definition.scope_required is False
