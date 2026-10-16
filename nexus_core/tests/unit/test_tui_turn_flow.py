"""Codex-style turns: quoted prompts, upward scrollback and a fixed prompt dock.

The transcript grows at the tail (pushing history up), while the badge row,
input bar and helper hints keep their rows.
"""

from __future__ import annotations

from typing import Any

from prompt_toolkit.formatted_text import fragment_list_to_text

from nexus_core.cli.tui.session import PROMPT_PREFIX, TuiSession


def test_the_prompt_prefix_is_the_codex_chevron(tui_factory: Any) -> None:
    ui = tui_factory(enable_completion=False)
    assert PROMPT_PREFIX == "> "
    assert ui.session.prompt_text == "> "


def test_echoed_turn_keeps_the_chevron_and_does_not_reprint_the_chips(tui_factory: Any) -> None:
    ui = tui_factory(enable_completion=False).session
    ui.prompt_text = "[TRUST MODE]\n" + PROMPT_PREFIX
    ui._input.insert_text("Entiendo continua por favor")
    ui._accept(ui._input)
    assert ui._answers.get_nowait() == "Entiendo continua por favor"
    ui.flush()
    # One clean line per turn: the chevron, never the header chips again.
    from nexus_core.cli.tui.presentation import clean_text
    assert clean_text(ui.transcript) == "▌ > Entiendo continua por favor\n\n"
    assert "[TRUST MODE]" not in ui.transcript


def test_turn_history_spaces_user_thought_and_response(tui_factory: Any) -> None:
    from nexus_core.cli.tui.presentation import clean_text

    ui = tui_factory(enable_completion=False).session
    ui._input.insert_text("revisa el resultado")
    ui._accept(ui._input)
    ui._answers.get_nowait()
    ui.append_card({}, thought="Estoy revisando la evidencia.")
    ui.append_scrollback("Respuesta verificada.\n\n")
    ui.flush()
    transcript = clean_text(ui.transcript)
    assert "▌ > revisa el resultado\n\n• Thinking..." in transcript
    assert "[ Show thinking ]\n\nRespuesta verificada." in transcript


def test_streamed_results_push_history_up_while_the_frame_stays_fixed(tui_factory: Any) -> None:
    ui = tui_factory(enable_completion=False).session
    for index in range(3):
        ui._input.insert_text(f"objetivo {index}")
        ui._accept(ui._input)
        ui._input.reset()
        ui.append_card({"success": True, "stdout": f"salida {index}"})
    ui.flush()
    transcript = ui.transcript
    # Turns and results keep their order: older turns move up, nothing is
    # re-rendered in place.
    assert (
        transcript.index("> objetivo 0")
        < transcript.index("> objetivo 1")
        < transcript.index("> objetivo 2")
    )
    assert transcript.index("salida 0") < transcript.index("salida 1") < transcript.index("salida 2")
    # The live tail stays visible (auto-follow) and the region list is intact.
    assert ui._scrollback.cursor_position == len(ui._scrollback.text)
    assert ui._regions == [ui._scrollback_window, ui._input_window] and len(ui._styled_lines) > 6
    children = ui._session.app.layout.container.content.children
    assert children[0] is ui._badge_window and children[-3] is ui._hints_top_margin
    # Tool output stays in the scrollable transcript, never in the prompt dock.
    assert fragment_list_to_text(ui._header_badge()) == "BW · OMNI [ workspace ]"
    assert "salida" not in fragment_list_to_text(ui._workspace_footer())
    assert "salida" not in fragment_list_to_text(ui._toolbar())


def test_alert_row_collapses_when_there_is_nothing_to_alert(tui_factory: Any) -> None:
    """The model/directory moved into the panel, so the bar is alerts-only."""
    ui = tui_factory().session
    ui.set_status(workspace_path='/tmp/workspace', provider_model='DeepSeekV4.1-flash')
    assert fragment_list_to_text(ui._toolbar()) == ''
    assert ui._status_window.height() == 0
    ui.set_status(trust_mode=True)
    assert fragment_list_to_text(ui._toolbar()) == 'TRUST'
    assert ui._status_window.height() == 1


def test_fallback_prompt_is_the_chevron_too(monkeypatch: Any) -> None:
    """The static (no-tui) path must not keep the old prompt behind."""
    calls: list[str] = []

    def fake_input(prompt: str) -> str:
        calls.append(prompt)
        return "line"

    monkeypatch.setattr("builtins.input", fake_input)
    ui = TuiSession(use_tui=False)
    try:
        assert ui.prompt() == "line"
        assert calls == ["> "]
    finally:
        ui.close()
