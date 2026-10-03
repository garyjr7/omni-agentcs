import json
from pathlib import Path
from unittest.mock import patch

from nexus_core.cli.tui.stream import format_tool_invocation, render_tool_result, render_message


def test_tool_invocation_shown_as_single_line():
    text = format_tool_invocation("nexus.recon.nmap", {"target": "lab", "flags": ["-sV", "-p", "80"]})
    assert "[Recon-NMAP] nmap -sV -p 80 -oX - lab" in text
    assert "\n" not in text and len(text) <= 100


def test_tool_complete_shows_three_lines_max():
    text = render_tool_result({"success": True, "stdout": "a\nb\nc\nd\ne"})
    assert len([line for line in text.splitlines() if "->" in line]) == 3


def test_tool_complete_shows_ellipsis_when_truncated():
    assert render_tool_result({"stdout": "a\nb\nc\nd"}).count("...") == 1


def test_tool_complete_summary_line():
    text = render_tool_result({"success": True, "evidence": {"ports_open_total": 4, "noise_level": "low", "elapsed_seconds": 4.2}})
    assert "✓ 4 puertos abiertos · noise: low · 4.2s" in text


def test_tool_failed_shows_error():
    text = render_tool_result({"success": False, "output": {"error": "timeout 120s"}, "verification_method": "nmap_timeout"})
    assert "✗ timeout 120s · verification_method=nmap_timeout" in text


def test_collapsed_card_reports_hidden_lines():
    text = render_tool_result({"success": True, "stdout": "\n".join(f"l{n}" for n in range(10))})
    assert "línea(s) oculta(s)" in text
    assert "F3" in text


def test_expanded_card_shows_every_line():
    text = render_tool_result(
        {"success": True, "stdout": "\n".join(f"l{n}" for n in range(10))}, expanded=True
    )
    assert text.count("->") == 10
    assert "oculta" not in text


def test_expanded_card_has_no_ellipsis_marker():
    text = render_tool_result({"success": True, "stdout": "a\nb\nc\nd"}, expanded=True)
    assert "..." not in text
    assert "✓" in text


def test_no_run_in_terminal_calls():
    cli = Path(__file__).parents[2] / "cli"
    assert not [p for p in cli.rglob("*.py") if "run_in_terminal" in p.read_text()]


def test_scrollback_autoscrolls(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    ui.session.append_scrollback("line\n" * 100)
    ui.session.flush()
    assert ui.session._scrollback.cursor_position == len(ui.session._scrollback.text)


def test_scrollback_not_invalidated_per_write(tui_factory):
    ui = tui_factory()
    with patch.object(ui.session, "invalidate") as redraw:
        for _ in range(20):
            ui.session.append_scrollback("event\n")
    redraw.assert_not_called()


def test_durable_observation_uses_real_body():
    message = {"metadata": {"kind": "react.observation", "tool_result": {"success": True}},
               "content": json.dumps({"output": "real output", "evidence": {"ports_open_total": 2}})}
    assert "real output" in render_message(message)
    assert "2 puertos abiertos" in render_message(message)


def test_daemon_uses_compact_messages_in_tui(tui_factory):
    from types import SimpleNamespace
    from nexus_core.cli.session import OmniSession, _drain_stream
    from nexus_core.cli.tui.output import TuiOutput
    ui = tui_factory()
    session = OmniSession(store=None, use_tui=False)
    session._tui, session._output = ui.session, TuiOutput(ui.session)
    session.run_id, session.conversation_id = "r", "c"
    messages = [{"metadata": {"kind": "react.action", "action": "tool_call", "tool_id": "nexus.recon.nmap", "arguments": {"target": "lab"}}}]
    session.store = SimpleNamespace(list_run_events=lambda *a, **k: [], list_messages=lambda *a, **k: messages)
    state = {"run_id": "r", "sequence": 0, "messages": 0}
    _drain_stream(session, state)
    _drain_stream(session, state)
    assert ui.session.transcript.count("[Recon-NMAP]") == 1
