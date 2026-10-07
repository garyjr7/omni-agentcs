"""Fase 4.0: the applicable playbook is injected into the system prompt.

The deterministic chains already existed, but the model only saw them if it
chose to call ``nexus.orchestrator.playbook``. The E2E #5 walked into HTTP
instead of FTP with the FTP chain sitting unused. These tests lock the guidance
into the prompt so that cannot happen silently.
"""

from __future__ import annotations

from nexus_core.agent.playbooks import (
    render_playbook_matches,
    select_playbooks,
)
from nexus_core.agent.prompts import render_system_prompt


def _ftp_facts() -> list[dict]:
    return [
        {
            "fact_type": "service",
            "key": "ftp_21",
            "value": {"port": 21, "protocol": "tcp", "service": "ftp"},
        }
    ]


def test_ftp_service_selects_the_ftp_playbook_with_the_right_next_step():
    matches = select_playbooks(_ftp_facts())

    assert [m.playbook.playbook_id for m in matches] == ["ftp_anon_to_cred"]
    assert matches[0].next_step is not None
    assert matches[0].next_step.tool_id == "nexus.recon.ftp"


def test_render_is_empty_state_when_nothing_applies():
    assert render_playbook_matches(()) == "(ningún playbook aplica todavía)"


def test_render_names_the_next_tool_so_the_model_can_prioritise():
    rendered = render_playbook_matches(select_playbooks(_ftp_facts()))

    assert "nexus.recon.ftp" in rendered
    assert "FTP" in rendered


def test_system_prompt_carries_the_playbook_guidance():
    rendered = render_playbook_matches(select_playbooks(_ftp_facts()))

    prompt = render_system_prompt(
        catalog={},
        objective="compromete bounty hacker",
        engagement_id="eng-1",
        scope_summary="scope",
        playbook_summary=rendered,
    )

    assert "PLAYBOOKS APLICABLES" in prompt
    assert "nexus.recon.ftp" in prompt


def test_system_prompt_defaults_the_playbook_block_when_omitted():
    prompt = render_system_prompt(
        catalog={},
        objective="o",
        engagement_id="e",
        scope_summary="s",
    )

    assert "(ningún playbook aplica todavía)" in prompt
