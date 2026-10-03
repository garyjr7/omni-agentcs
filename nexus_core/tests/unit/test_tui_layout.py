from prompt_toolkit.formatted_text import fragment_list_to_text


def test_layout_has_four_regions(tui_factory):
    ui = tui_factory()
    assert len(ui.session._app.layout.container.content.children) == 4


def test_full_screen_false_by_default(tui_factory):
    assert tui_factory().session._app.full_screen is False


def test_full_screen_opt_in(tui_factory):
    assert tui_factory(full_screen=True).session._app.full_screen is True


def test_full_screen_layout_renders(tui_factory):
    ui = tui_factory(full_screen=True)
    ui.pipe.send_text("hi\r")
    assert ui.session.prompt() == "hi"
    ui.session.set_status(engagement="lab")
    ui.session.print("out")
    ui.session.flush()
    assert "out" in ui.session._scrollback.text
    assert ui.session._app.full_screen is True


def test_expand_cards_toggles(tui_factory):
    ui = tui_factory()
    assert ui.session.expand_cards is False
    assert ui.session.set_expand(True) is True
    assert ui.session.expand_cards is True
    assert ui.session.set_expand(False) is False


def test_status_bar_at_bottom(tui_factory):
    ui = tui_factory()
    assert ui.session._regions[-1] is ui.session._status_window


def test_input_between_busy_and_status(tui_factory):
    ui = tui_factory()
    assert ui.session._regions[1:] == [ui.session._busy_window, ui.session._input_window, ui.session._status_window]


def test_scrollback_grows_independently(tui_factory):
    ui = tui_factory()
    ui.session.append_scrollback("line\n" * 2200)
    assert ui.session._scrollback.text.count("line") == 2200
    assert ui.session._input.text == ""


def test_layout_renders_all_regions(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("begin\r")
    ui.session.prompt()
    ui.session.set_status(engagement="lab")
    ui.session.set_busy()
    ui.session.print("output")
    ui.session.flush()
    assert "output" in ui.session._scrollback.text
    assert "Working" in fragment_list_to_text(ui.session._render_busy())
    assert "lab" in fragment_list_to_text(ui.session._toolbar())
    assert ui.session._app.layout.current_buffer is ui.session._input


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
