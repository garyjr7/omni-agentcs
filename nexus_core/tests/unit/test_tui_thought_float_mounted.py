"""Live reasoning row: visible only while the model streams a thought."""

from prompt_toolkit.formatted_text import fragment_list_to_text


def _row_visible(ui) -> bool:
    return bool(ui.session._thought_row.filter())


def test_live_thought_row_is_mounted_and_shows_reasoning(tui_factory):
    ui = tui_factory()
    assert ui.session._thought_row in ui.session._rows
    assert not _row_visible(ui)
    ui.session.set_thought("enumero el 445 y luego pruebo SMB")
    assert _row_visible(ui)
    assert ui.session.thought_height() >= 1
    text = fragment_list_to_text(ui.session._thought_formatted())
    assert "Razonando" in text and "445" in text


def test_live_thought_row_hides_when_the_turn_ends(tui_factory):
    ui = tui_factory()
    ui.session.set_thought("razonando")
    ui.session.end_thought()
    assert not _row_visible(ui)


def test_the_legacy_float_is_kept_but_never_mounted(tui_factory):
    """test_tui_accordion pins the attribute; the live surface is the row."""
    ui = tui_factory()
    assert ui.session._thought_float is not None
    assert ui.session._thought_float not in ui.session._app.layout.container.floats
