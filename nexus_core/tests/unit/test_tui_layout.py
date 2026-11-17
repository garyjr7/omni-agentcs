from types import SimpleNamespace

from prompt_toolkit.formatted_text import fragment_list_to_text

from nexus_core.cli.tui.strings import PLACEHOLDER_TEXT

PLACEHOLDER = PLACEHOLDER_TEXT


def _first_row(ui):
    """The empty editor row as the processor sees it (only ``fragments`` is read)."""
    del ui
    return SimpleNamespace(fragments=[])


def _hint_fragments(ui):
    transformed = ui._placeholder.apply_transformation(_first_row(ui))
    return [fragment for fragment in transformed.fragments if fragment[1] == PLACEHOLDER]


def test_placeholder_shows_only_in_an_empty_focused_editor(tui_factory):
    # No completion: typing here runs without a live app loop (no async task).
    ui = tui_factory(enable_completion=False).session
    assert ui._placeholder.visible() is True
    assert _hint_fragments(ui) == [("class:placeholder", PLACEHOLDER)]
    # It is drawn inside the existing editor row: no extra row, same dock.
    assert ui._input_height() == 5
    ui._input.insert_text("nmap")
    assert ui._placeholder.visible() is False
    assert _hint_fragments(ui) == []


def test_placeholder_hides_for_secret_and_permission_prompts(tui_factory):
    ui = tui_factory().session
    ui._secret_mode = True
    try:
        assert ui._placeholder.visible() is False
    finally:
        ui._secret_mode = False
    assert ui.set_approval({"tool_id": "nexus.recon.nmap"}) is True
    assert ui._placeholder.visible() is False
    ui.clear_approval()
    assert ui._placeholder.visible() is True


def test_placeholder_never_reaches_the_submission_or_the_history(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("enumera el puerto 80\r")
    assert ui.session.prompt() == "enumera el puerto 80"
    history = ui.session._input.history.get_strings()
    assert "enumera el puerto 80" in history
    assert all(PLACEHOLDER not in entry for entry in history)
    assert PLACEHOLDER not in ui.session.transcript


def test_a_long_paste_still_becomes_a_chip_and_hides_the_placeholder(tui_factory):
    ui = tui_factory().session
    ui.paste_text("A" * 600)
    # The chip is a reference in the document, not literal text (paste path
    # untouched), so the hint disappears with it.
    assert ui.input_document.refs
    assert ui._placeholder.visible() is False


def test_layout_locks_bottom_to_editor_and_helper_hints(tui_factory):
    ui = tui_factory()
    children = ui.session._app.layout.container.content.children
    # All status/output renderables stay out of the fixed prompt dock.
    assert children == ui.session._rows
    assert children == [
        ui.session._badge_window,
        ui.session._scrollback_window,
        ui.session._chips_window,
        ui.session._thought_row,
        ui.session._busy_window,
        ui.session._completion_window,
        ui.session._approval_panel,
        ui.session._input_window,
        ui.session._hints_top_margin,
        ui.session._hints_window,
        ui.session._hints_bottom_margin,
    ]
    assert ui.session._regions == [ui.session._scrollback_window, ui.session._input_window]
    assert ui.session._busy_window in children
    assert ui.session._status_window not in children
    assert ui.session._hints_window not in ui.session._regions


def test_engagement_badge_appears_only_after_startup_banner_scrolls_off(tui_factory):
    ui = tui_factory().session
    assert not ui._show_engagement_badge()
    ui.append_scrollback("banner\\n" * 8)
    ui.mark_startup_banner()
    assert not ui._show_engagement_badge()
    ui._scrollback_window.vertical_scroll = ui._banner_end_line + 1
    assert ui._show_engagement_badge()


def test_completion_summary_replaces_the_pulse_above_the_input(tui_factory):
    ui = tui_factory().session
    ui.set_busy()
    ui.clear_busy()
    # It is the run's status line, not a log entry: it sits right above the
    # input panel where the working pulse was.
    assert "completado en " in fragment_list_to_text(ui._completion_formatted())
    assert "completado en " not in ui.transcript
    assert ui._completion_window in ui._rows


def test_full_screen_true_by_default(tui_factory):
    # A clean dedicated screen (alt-screen) is the default, like the top CLIs.
    assert tui_factory().session._app.full_screen is True


def test_full_screen_inline_opt_in(tui_factory):
    assert tui_factory(full_screen=False).session._app.full_screen is False


def test_alt_screen_disabled_by_env(tui_factory, monkeypatch):
    monkeypatch.setenv("NEXUS_NO_ALT_SCREEN", "1")
    assert tui_factory().session._app.full_screen is False


def test_full_screen_layout_renders(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("hi\r")
    assert ui.session.prompt() == "hi"
    ui.session.set_status(engagement="lab", scope_targets=2)
    ui.session.print("out")
    ui.session.flush()
    assert "out" in ui.session._scrollback.text
    assert ui.session._app.full_screen is True


def test_inline_layout_renders(tui_factory):
    ui = tui_factory(full_screen=False)
    ui.pipe.send_text("hi\r")
    assert ui.session.prompt() == "hi"
    ui.session.print("out")
    ui.session.flush()
    assert "out" in ui.session._scrollback.text
    assert ui.session._app.full_screen is False


def test_expand_cards_toggles(tui_factory):
    ui = tui_factory()
    assert ui.session.expand_cards is False
    assert ui.session.set_expand(True) is True
    assert ui.session.expand_cards is True
    assert ui.session.set_expand(False) is False


def test_status_bar_is_not_a_fixed_output_region(tui_factory):
    ui = tui_factory()
    assert ui.session._status_window not in ui.session._rows


def test_input_is_the_only_fixed_content_region(tui_factory):
    ui = tui_factory()
    assert ui.session._regions == [ui.session._scrollback_window, ui.session._input_window]


def test_scrollback_grows_independently(tui_factory):
    ui = tui_factory()
    ui.session.append_scrollback("line\n" * 2200)
    assert ui.session._scrollback.text.count("line") == 2200
    assert ui.session._input.text == ""


def test_layout_renders_all_regions(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("begin\r")
    ui.session.prompt()
    ui.session.set_status(engagement="lab", scope_targets=2)
    ui.session.set_busy()
    ui.session.print("output")
    ui.session.flush()
    assert "output" in ui.session._scrollback.text
    assert "esc para interrumpir" in fragment_list_to_text(ui.session._render_busy())
    assert "Alcance: 2 objetivos" in fragment_list_to_text(ui.session._toolbar())
    assert ui.session._app.layout.current_buffer is ui.session._input


def test_scroll_transcript_moves_the_view_without_lag(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    ui.session.append_scrollback("\n".join(f"line {n:03d}" for n in range(200)))
    ui.session.flush()
    import time
    time.sleep(0.3)
    before = ui.session._scrollback_window.vertical_scroll
    ui.pipe.send_bytes(b"\x1b[5~")  # PageUp
    time.sleep(0.3)
    after = ui.session._scrollback_window.vertical_scroll
    # The first PageUp already scrolls the view (the old handler lagged a page).
    assert after < before
    assert ui.session._auto_scroll is False


def test_wheel_scrolls_three_lines(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    ui.session.append_scrollback("\n".join(f"line {n:03d}" for n in range(200)))
    ui.session.flush()
    import time
    time.sleep(0.3)
    before = ui.session._scrollback_window.vertical_scroll
    # A real SGR wheel event, not the keyboard approximation: it must reach the
    # scrollback control and update the follow state, not only Window's offset.
    ui.pipe.send_bytes(b"\x1b[<64;10;10M")
    time.sleep(0.3)
    assert ui.session._scrollback_window.vertical_scroll == before - 3
    assert ui.session._auto_scroll is False


def test_ctrl_u_scrolls_up_and_ctrl_d_returns_to_the_tail(tui_factory):
    """The emacs keys move the viewport when the editor is empty."""
    import threading
    import time

    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    ui.session.print("\n".join(f"line {n}" for n in range(100)))
    ui.session.flush()
    time.sleep(0.3)

    moved = threading.Event()
    ui.session._scrollback.on_cursor_position_changed += lambda _: moved.set()
    ui.pipe.send_bytes(b"\x15")  # Ctrl+U
    assert moved.wait(2)
    assert ui.session._auto_scroll is False
    assert ui.session.is_scrolling is True
    assert ui.session._is_scrolling is True

    returned = threading.Event()
    ui.session._scrollback.on_cursor_position_changed += lambda _: returned.set()
    ui.pipe.send_bytes(b"\x04")  # Ctrl+D
    assert returned.wait(2)
    assert ui.session._auto_scroll is True
    assert ui.session.is_scrolling is False
    assert ui.session._scrollback.cursor_position == len(ui.session._scrollback.text)


def test_ctrl_u_keeps_line_discard_while_the_editor_has_text(tui_factory):
    import time

    ui = tui_factory(enable_completion=False)
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    ui.session._input.insert_text("una tarea")
    ui.pipe.send_bytes(b"\x15")  # Ctrl+U
    time.sleep(0.2)
    assert ui.session._input.text == ""
    assert ui.session.is_scrolling is False


def test_scrollback_and_inset_paint_a_solid_background(tui_factory):
    from nexus_core.cli.theme import THEME

    ui = tui_factory()
    assert ui.session._scrollback_window.style == THEME.app_background_style
    margin = ui.session._scrollback_window.left_margins[0]
    fragments = margin.create_margin(None, 2, 3)
    assert fragments and all(style == THEME.app_background_style for style, _ in fragments)


def test_screen_is_cleared_once_before_the_first_frame(tui_factory):
    from unittest.mock import patch

    ui = tui_factory()
    with patch.object(ui.output, "erase_screen") as erase:
        ui.session._clear_screen_once()
        ui.session._clear_screen_once()
    erase.assert_called_once()


def test_answer_buffer_has_no_agent_label_and_commits(tui_factory):
    ui = tui_factory()
    ui.session.begin_answer()
    assert ui.session.answer_active is True
    ui.session.append_answer("# Hola\n")
    ui.session.append_answer("una **prueba**")
    assert ui.session.answer_height() >= 2
    assert "OmniAgent" not in "".join(part[1] for part in ui.session._answer_formatted())
    assert ui.session._answer_float not in ui.session._app.layout.container.floats
    text = ui.session.end_answer()
    assert text == "# Hola\nuna **prueba**"
    assert ui.session.answer_active is False
    assert ui.session.answer_height() == 0


def test_set_answer_replaces_a_cumulative_snapshot(tui_factory):
    ui = tui_factory()
    ui.session.set_answer("El servicio")
    ui.session.set_answer("El servicio 80 responde")
    assert ui.session.answer_active is True
    assert ui.session.end_answer() == "El servicio 80 responde"


def test_pageup_preserves_history_and_pauses_follow(tui_factory):
    import threading
    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    ui.session.print("\n".join(f"line {n}" for n in range(100)))
    ui.session.flush()
    moved = threading.Event()
    ui.session._scrollback.on_cursor_position_changed += lambda _: moved.set()
    ui.pipe.send_bytes(b"\x1b[5~")
    assert moved.wait(2)
    position = ui.session._scrollback.cursor_position
    ui.session.print("new event")
    ui.session.flush()
    assert not ui.session._auto_scroll
    assert ui.session._scrollback.cursor_position == position
    assert "line 0\n" in ui.session._scrollback.text


def test_pagedown_returns_to_the_live_tail_after_a_pageup(tui_factory):
    import threading

    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    ui.session.print("\n".join(f"line {n}" for n in range(100)))
    ui.session.flush()
    ui.session._follow_tail()  # the live tail, where the new work is written

    moved = threading.Event()
    ui.session._scrollback.on_cursor_position_changed += lambda _: moved.set()
    ui.pipe.send_bytes(b"\x1b[5~")  # PageUp
    assert moved.wait(2)
    assert ui.session._auto_scroll is False

    returned = threading.Event()
    ui.session._scrollback.on_cursor_position_changed += lambda _: returned.set()
    ui.pipe.send_bytes(b"\x1b[6~")  # PageDown, back to where the work is written
    assert returned.wait(2)
    assert ui.session._auto_scroll is True
    assert ui.session._scrollback.cursor_position == len(ui.session._scrollback.text)


def test_idle_typeahead_between_prompts_is_not_discarded(tui_factory):
    import threading
    ui = tui_factory()
    ui.pipe.send_text("first\r")
    assert ui.session.prompt() == "first"
    typed = threading.Event()
    ui.session._input.on_text_changed += lambda _: typed.set() if ui.session._input.text == "second" else None
    ui.pipe.send_text("second\r")
    assert typed.wait(2)
    assert ui.session.prompt() == "second"


def test_a_second_question_keeps_the_previous_cards_and_resumes_follow(tui_factory):
    import threading

    ui = tui_factory()
    session = ui.session
    ui.pipe.send_text("primera pregunta\r")
    assert session.prompt() == "primera pregunta"
    session.begin_tool("nexus.recon.nmap", {"target": "10.0.0.5", "flags": ["-sV"]})
    session.complete_tool({
        "success": True, "tool_id": "nexus.recon.nmap",
        "output": {"scan": {
            "hosts": [{"state": "up", "ip": "10.0.0.5", "ports": [
                {"port": 80, "protocol": "tcp", "state": "open",
                 "service": "http", "product": "nginx", "version": "1.24.0"},
            ]}],
            "hosts_up": 1, "elapsed_seconds": 2.1,
        }},
    })
    session.append_answer_block("## Servicio\nnginx en 80/tcp.")
    session.flush()

    moved = threading.Event()
    session._scrollback.on_cursor_position_changed += lambda _: moved.set()
    ui.pipe.send_bytes(b"\x1b[5~")  # PageUp over the previous work
    assert moved.wait(2)
    assert session._auto_scroll is False

    ui.pipe.send_text("segunda pregunta\r")
    assert session.prompt() == "segunda pregunta"
    session.begin_tool("nexus.recon.nmap", {"target": "10.0.0.5", "flags": ["-p", "443"]})
    session.complete_tool({"success": True, "tool_id": "nexus.recon.nmap",
                           "stdout": "443/tcp open https"})
    # A second call of the same subagent in this turn opens its own box.
    session.begin_tool("nexus.recon.nmap", {"target": "10.0.0.5", "flags": ["-p", "8443"]})
    session.complete_tool({"success": True, "tool_id": "nexus.recon.nmap",
                           "stdout": "8443/tcp closed"})
    session.flush()

    text = session._scrollback.text
    # Asking again never discards the work above: both turns and every call
    # stay in the transcript.
    assert "primera pregunta" in text and "segunda pregunta" in text
    assert "nginx" in text and "443/tcp open https" in text
    assert "8443/tcp closed" in text
    # Numbering is per subagent and per turn: the second call is ``(2)``.
    assert "╭─ OMNI · Recon (2) ─" in text
    assert text.count("╭─ OMNI · Recon ─") == 2
    # The new question returns to the live tail, where the answer is coming.
    assert session._auto_scroll is True
    assert session.is_scrolling is False
    assert session._scrollback.cursor_position == len(text)


def test_a_reveal_does_not_pull_a_scrolled_reader_back_to_the_tail(tui_factory):
    ui = tui_factory(no_color=True)
    session = ui.session
    session.append_scrollback("\n".join(f"line {n:03d}" for n in range(120)))
    session.flush()
    session.scroll_transcript(-40)
    position = session._scrollback.cursor_position
    assert session._auto_scroll is False

    base = session._scrollback.text
    session._commit_partial(base, "bloque que se está escribiendo")
    plain = session._scrollback.text
    # The growing block lands below the viewport; the cursor keeps the line
    # the operator was reading instead of jumping to the end.
    assert plain.startswith(base)
    assert session._scrollback.cursor_position == position
    assert session._scrollback.cursor_position < len(plain)
