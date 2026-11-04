"""The visual transcript is bounded; the durable conversation is not."""

from nexus_core.cli.tui import session as session_module


def test_old_blocks_are_dropped_from_the_visual_transcript(tui_factory, monkeypatch):
    monkeypatch.setattr(session_module, "TRANSCRIPT_MAX_SEGMENTS", 3)
    ui = tui_factory()
    for index in range(6):
        ui.session.append_scrollback(f"msg {index}\n")

    transcript = ui.session.transcript
    assert "msg 0" not in transcript and "msg 2" not in transcript
    assert "msg 3" in transcript and "msg 5" in transcript
    assert len(ui.session._segments) == 3


def test_the_line_cap_drops_the_oldest_block(tui_factory, monkeypatch):
    monkeypatch.setattr(session_module, "TRANSCRIPT_MAX_LINES", 4)
    ui = tui_factory()
    ui.session.append_scrollback("a\nb\nc\nd\ne\n")
    ui.session.append_scrollback("f\n")

    transcript = ui.session.transcript
    assert "a" not in transcript
    assert "f" in transcript
    assert len(ui.session._segments) == 1


def test_scroll_cannot_point_past_a_trimmed_transcript(tui_factory, monkeypatch):
    monkeypatch.setattr(session_module, "TRANSCRIPT_MAX_SEGMENTS", 3)
    monkeypatch.setenv("NEXUS_TUI_TYPEWRITER", "0")
    monkeypatch.setattr(session_module, "TRANSCRIPT_MAX_LINES", 1000)
    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    ui.session.append_scrollback("a\nb\nc\nd\ne\nf\ng\nh\n")
    ui.session.flush()
    ui.session.scroll_transcript(-100)
    assert ui.session._auto_scroll is False

    for index in range(8):
        ui.session.append_scrollback(f"new {index}\n")
    ui.session.flush()

    assert ui.session._scrollback_window.vertical_scroll >= 0
    assert ui.session._scrollback_window.vertical_scroll < max(
        1, len(ui.session._styled_lines)
    )
