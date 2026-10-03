"""Per-block accordion and the live ReAct thinking overlay."""


def _card(prefix: str, count: int) -> dict:
    return {"success": True, "stdout": "\n".join(f"{prefix}{n}" for n in range(count))}


def test_card_expands_and_collapses_by_click(tui_factory):
    ui = tui_factory()
    ui.session.append_card(_card("l", 10))
    ui.session.flush()
    assert "▼ mostrar" in ui.session._scrollback.text
    line = min(ui.session._toggle_rows)
    assert ui.session.toggle_card_at_line(line) is True
    assert "▲ mostrar menos" in ui.session._scrollback.text
    # Expanding moves the footer: use the refreshed click target to collapse.
    assert ui.session.toggle_card_at_line(min(ui.session._toggle_rows)) is True
    assert "▼ mostrar" in ui.session._scrollback.text


def test_two_cards_toggle_independently(tui_factory):
    ui = tui_factory()
    ui.session.append_card(_card("a", 8))
    ui.session.append_card(_card("b", 8))
    ui.session.flush()
    rows = sorted(ui.session._toggle_rows)
    assert len(rows) == 2
    ui.session.toggle_card_at_line(rows[0])
    text = ui.session._scrollback.text
    assert text.count("▲ mostrar menos") == 1
    assert text.count("▼ mostrar") == 1


def test_small_card_has_no_click_target(tui_factory):
    ui = tui_factory()
    ui.session.append_card({"success": True, "stdout": "solo una línea"})
    ui.session.flush()
    assert "mostrar" not in ui.session._scrollback.text
    assert ui.session._toggle_rows == {}
    assert ui.session.toggle_card_at_line(0) is False


def test_click_on_plain_line_is_not_consumed(tui_factory):
    ui = tui_factory()
    ui.session.append_scrollback("texto normal\n")
    ui.session.append_card(_card("x", 9))
    ui.session.flush()
    toggle = min(ui.session._toggle_rows)
    assert ui.session.toggle_card_at_line(toggle - 1) is False
    assert ui.session.toggle_card_at_line(toggle) is True


def test_cards_survive_a_rebuild_with_other_text(tui_factory):
    ui = tui_factory()
    ui.session.append_scrollback("intro\n")
    ui.session.append_card(_card("c", 7))
    ui.session.append_scrollback("outro\n")
    ui.session.flush()
    line = min(ui.session._toggle_rows)
    ui.session.toggle_card_at_line(line)
    text = ui.session._scrollback.text
    assert "intro" in text and "outro" in text
    assert "▲ mostrar menos" in text


def test_scrollback_control_turns_click_into_toggle(tui_factory):
    from prompt_toolkit.data_structures import Point
    from prompt_toolkit.mouse_events import MouseButton, MouseEvent, MouseEventType

    ui = tui_factory()
    ui.session.append_card(_card("z", 9))
    ui.session.flush()
    control = ui.session._scrollback_window.content
    line = min(ui.session._toggle_rows)
    event = MouseEvent(
        position=Point(x=0, y=line),
        event_type=MouseEventType.MOUSE_DOWN,
        button=MouseButton.LEFT,
        modifiers=frozenset(),
    )
    assert control.mouse_handler(event) is None
    assert "▲ mostrar menos" in ui.session._scrollback.text


def test_thought_overlay_streams_and_closes(tui_factory):
    ui = tui_factory()
    assert ui.session.thought_active is False
    ui.session.set_thought("escaneando el puerto 80")
    assert ui.session.thought_active is True
    rendered = "".join(part[1] for part in ui.session._thought_formatted())
    assert "escaneando el puerto 80" in rendered
    assert ui.session._thought_float is not None
    ui.session.end_thought()
    assert ui.session.thought_active is False
