"""Codex-style turns: quoted prompts, upward scrollback and a fixed prompt dock.

The transcript grows at the tail (pushing history up), while the badge row,
input bar and helper hints keep their rows.
"""

from __future__ import annotations

from typing import Any

from prompt_toolkit.formatted_text import fragment_list_to_text

from nexus_core.cli import render
from nexus_core.cli.tui.output import capture_output
from nexus_core.cli.tui.presentation import clean_text
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
    # One block per turn: the rail with a 12-hour stamp, then the task itself.
    # The contextual chips are never reprinted into the transcript.
    from nexus_core.cli.tui.presentation import clean_text
    transcript = clean_text(ui.transcript)
    assert transcript == "▌ [08:56 AM]\n▌ Entiendo continua por favor\n\n" or transcript.endswith(
        "▌ Entiendo continua por favor\n\n"
    )
    lines = transcript.splitlines()
    assert lines[0].startswith("▌ [") and lines[0].endswith(("AM]", "PM]"))
    assert lines[1] == "▌ Entiendo continua por favor"
    assert "[TRUST MODE]" not in ui.transcript


def test_a_silent_slash_command_never_reaches_the_transcript(tui_factory: Any) -> None:
    ui = tui_factory(enable_completion=False).session
    ui._input.insert_text("/engage_use eng-missing")
    ui._accept(ui._input)
    assert ui._answers.get_nowait() == "/engage_use eng-missing"
    ui.flush()
    assert clean_text(ui.transcript) == ""


def test_a_silent_slash_command_shows_its_error_without_the_echo(tui_factory: Any) -> None:
    ui = tui_factory(enable_completion=False).session
    ui._input.insert_text("/engage_use eng-missing")
    ui._accept(ui._input)
    ui._answers.get_nowait()
    with capture_output(ui):
        render.render_error("engagement no encontrado: eng-missing")
    ui.flush()
    transcript = clean_text(ui.transcript)
    assert "engagement no encontrado: eng-missing" in transcript
    assert "/engage_use" not in transcript


def test_an_explicit_output_command_keeps_its_echo_and_output(tui_factory: Any) -> None:
    ui = tui_factory(enable_completion=False).session
    ui._input.insert_text("/status")
    ui._accept(ui._input)
    ui._answers.get_nowait()
    with capture_output(ui):
        render.render_status("status bar: ON")
    ui.flush()
    transcript = clean_text(ui.transcript)
    assert "▌ /status" in transcript
    assert "status bar: ON" in transcript


def test_the_masthead_is_separated_from_the_first_turn(tui_factory: Any) -> None:
    from nexus_core.cli.tui.presentation import clean_text, startup_banner

    ui = tui_factory(enable_completion=False).session
    ui.print(startup_banner("scanme-lab", "3.0.0", no_color=True), end="")
    ui.mark_startup_banner()
    ui._input.insert_text("revisa el objetivo")
    ui._accept(ui._input)
    ui.flush()
    transcript = clean_text(ui.transcript)
    # The masthead is its own block: the echoed turn begins after one blank
    # line instead of being glued to the last metadata row.
    assert "[+] [ scanme-lab ] [+]\n\n▌ [" in transcript
    assert "\n▌ revisa el objetivo" in transcript
    assert "\n\n\n" not in transcript


def test_execution_blocks_are_separated_by_one_blank_line(tui_factory: Any) -> None:
    from nexus_core.cli.tui.presentation import clean_text

    ui = tui_factory(enable_completion=False).session
    ui.print("Reviso el servicio 80/tcp.")
    ui.append_execution_block("• nexus.recon.nmap  nmap -sV -p 80 lab")
    ui.append_card({"success": True, "tool_id": "nexus.recon.nmap",
                    "stdout": "80/tcp open http"})
    ui.append_execution_block("• nexus.web.curl  http://lab/")
    ui.append_card({}, thought="El puerto responde.")
    ui.print("Confirmado el servicio web.")
    ui.flush()
    transcript = clean_text(ui.transcript)
    assert "Reviso el servicio 80/tcp.\n\n• nexus.recon.nmap" in transcript
    # The call and its result are distinct blocks, one blank line apart...
    assert "nmap -sV -p 80 lab\n\n✓ nmap: 80/tcp open http" in transcript
    # ...while each following block starts after exactly one blank line.
    assert "80/tcp open http\n\n• nexus.web.curl" in transcript
    assert "• nexus.web.curl  http://lab/\n\n  ▸ Razonamiento" in transcript
    assert "▸ Razonamiento\n\nConfirmado el servicio web." in transcript
    assert "\n\n\n" not in transcript


def test_toggling_a_card_keeps_the_block_separation(tui_factory: Any) -> None:
    from nexus_core.cli.tui.presentation import clean_text

    ui = tui_factory(enable_completion=False).session
    ui.print("intro")
    ui.append_card({}, thought="razonamiento")
    ui.flush()
    assert "intro\n\n  ▸ Razonamiento" in clean_text(ui.transcript)
    assert ui.toggle_card_at_line(max(ui._toggle_rows))
    # The rebuilt transcript reproduces the same paragraph break and body.
    assert "intro\n\n  ▾ Razonamiento" in clean_text(ui.transcript)
    assert "ctrl+t colapsar" in clean_text(ui.transcript)


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
    assert "▌ revisa el resultado\n\n  ▸ Razonamiento" in transcript
    assert "▸ Razonamiento\n\nRespuesta verificada." in transcript


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
        transcript.index("▌ objetivo 0")
        < transcript.index("▌ objetivo 1")
        < transcript.index("▌ objetivo 2")
    )
    assert transcript.index("salida 0") < transcript.index("salida 1") < transcript.index("salida 2")
    # The live tail stays visible (auto-follow) and the region list is intact.
    assert ui._scrollback.cursor_position == len(ui._scrollback.text)
    assert ui._regions == [ui._scrollback_window, ui._input_window] and len(ui._styled_lines) > 6
    children = ui._session.app.layout.container.content.children
    assert children[0] is ui._badge_window and children[-3] is ui._hints_top_margin
    # Tool output stays in the scrollable transcript, never in the prompt dock.
    # The header row is reserved but silent while the masthead is on screen.
    from nexus_core.cli.tui.frame import header_text
    assert ui._badge_window.height == 1
    assert fragment_list_to_text(ui._header_badge()) == ""
    assert header_text("workspace") == "BW • OMNI [ workspace ]"
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
