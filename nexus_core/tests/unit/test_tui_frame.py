"""The prompt frame: header timer, work pulse, completion line and permissions.

These tests pin the visual contract of the mock, not a terminal: every piece is
a string or a row height, so they run without a pty.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from prompt_toolkit.formatted_text import fragment_list_to_text

from nexus_core.cli.tui import frame

pytestmark = pytest.mark.unit


def test_header_names_brand_and_engagement_and_shows_the_timer_only_while_working() -> None:
    assert frame.header_text("scanme-lab") == "BW • OMNI [ scanme-lab ]"
    assert frame.header_text("scanme-lab", elapsed_seconds=3014) == (
        "BW • OMNI [ scanme-lab ]   50m 14s"
    )
    # No engagement yet: the frame still has a fixed, meaningful header.
    assert frame.header_text("") == "BW • OMNI [ workspace ]"
    assert frame.header_text(None) == "BW • OMNI [ workspace ]"


def test_format_elapsed_matches_the_mock_units() -> None:
    assert frame.format_elapsed(0) == "0s"
    assert frame.format_elapsed(59) == "59s"
    assert frame.format_elapsed(3014) == "50m 14s"
    assert frame.format_elapsed(3900) == "1h 05m"


def test_the_pulse_is_seven_cells_that_sweep_without_changing_their_text() -> None:
    rows = [
        frame.busy_cells(index * frame.PULSE_STEP_SECONDS)
        for index in range(frame.PULSE_CELLS)
    ]
    assert all("".join(cell for _, cell in row) == "[+][+][+][+][+][+][+]" for row in rows)
    assert all(sum(style == frame.PULSE_BRIGHT for style, _ in row) == 1 for row in rows)
    assert len({tuple(row) for row in rows}) == frame.PULSE_CELLS
    assert frame.busy_text() == "[+][+][+][+][+][+][+] · esc interrupt"


def test_completion_names_the_duration_and_the_hour() -> None:
    stamp = datetime(2026, 10, 31, 16, 35)
    assert frame.completion_text(192, now=stamp) == "Worked for 3m 12s • 04:35 PM"


def test_the_permission_question_names_the_exact_command() -> None:
    payload = {"tool_id": "nexus.c2.sliver_exec", "arguments": {"command": "id"}}
    assert frame.approval_command(payload) == "id"
    assert frame.approval_question("id") == "[+] ¿Puedo ejecutar id?"
    # A tool with no command is named by its target, never by an invented argv.
    assert frame.approval_command(
        {"tool_id": "nexus.recon.nmap", "arguments": {"target": "203.0.113.9"}}
    ) == "nexus.recon.nmap target=203.0.113.9"


def test_enter_authorizes_once_not_for_the_whole_engagement() -> None:
    assert [token for _, token in frame.APPROVAL_OPTIONS] == ["a", "y", "n"]
    assert frame.APPROVAL_TOKENS[frame.APPROVAL_DEFAULT] == "y"


def test_the_header_row_carries_the_live_timer_and_drops_it_when_idle(tui_factory) -> None:
    session = tui_factory().session
    session.set_status(engagement="scanme-lab")
    assert fragment_list_to_text(session._header_badge()) == "BW • OMNI [ scanme-lab ]"
    session.set_busy("Ejecutando nmap")
    session._status.busy_started_at -= 3014
    assert fragment_list_to_text(session._header_badge()) == (
        "BW • OMNI [ scanme-lab ]   50m 14s"
    )
    # Fixed during a run, even before the startup masthead scrolls away.
    assert session._show_engagement_badge()
    session.clear_busy()
    assert "50m 14s" not in fragment_list_to_text(session._header_badge())


def test_the_completion_line_replaces_the_same_row_as_the_pulse(tui_factory) -> None:
    session = tui_factory().session
    session.set_busy()
    # Fixed row: the chat cannot scroll the pulse away, and it never became a
    # log line in the first place.
    assert session._busy_window.height() == 1
    assert session._completion_window.height() == 0
    assert "[+][+][+][+][+][+][+]" not in session.transcript
    session._status.busy_started_at -= 3
    session.clear_busy()
    assert session._busy_window.height() == 0
    assert session._completion_window.height() == 1
    assert fragment_list_to_text(session._completion_formatted()).startswith(
        "Worked for 3s •"
    )
    assert "Worked for" not in session.transcript
    rows = session._rows
    assert rows.index(session._busy_window) == rows.index(session._completion_window) - 1
    assert rows.index(session._completion_window) == rows.index(session._input_window) - 2


def test_the_permission_menu_grows_out_of_the_input_panel(tui_factory) -> None:
    session = tui_factory().session
    rows = session._rows
    assert rows.index(session._approval_panel) == rows.index(session._input_window) - 1
    assert session._approval_panel.height() == 0
    session.set_approval(
        {
            "tool_id": "nexus.c2.sliver_exec",
            "risk": "high",
            "arguments": {"command": "id"},
        }
    )
    assert session._approval_panel.height() >= 4
    text = "\n".join(line for _, line in session._approval_formatted())
    assert "[+] ¿Puedo ejecutar id?" in text
    assert "Sí, siempre en este engagement" in text
    assert "Sí, solo esta vez" in text
    assert "No" in text
    session.clear_approval()
    assert session._approval_panel.height() == 0


def test_the_selected_permission_option_is_a_solid_red_row() -> None:
    from nexus_core.cli.tui.panels import approval_lines, approval_style

    lines = approval_lines({"tool_id": "t", "arguments": {"command": "id"}}, selected=0)
    selected = [text for style, text in lines if style == "class:approval-selected"]
    assert len(selected) == 1
    assert "Sí, siempre en este engagement" in selected[0]
    assert "bg:#ff0055" in approval_style()["approval-selected"]
    # Only the chosen row is filled; the other options stay on the panel.
    assert not any(
        "approval-selected" == style
        for style, text in lines
        if "Sí, solo esta vez" in text or text.strip() == "No"
    )
