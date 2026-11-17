"""P0: one geometry, redrawn on resize; one title per subagent."""
from __future__ import annotations

from typing import Any

from prompt_toolkit.utils import get_cwidth

from nexus_core.cli.tui.presentation import (
    ADVISOR_TITLE,
    answer_panel,
    result_panel,
    subagent_title,
    thinking_block,
    tool_result_block,
    user_message,
)


def _width(text: str) -> int:
    return max(get_cwidth(line) for line in text.splitlines())


def _framed_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith(("╭", "│", "╰"))]


def test_every_panel_fills_the_transcript_width() -> None:
    """Operador, Pensamiento, Ejecución and Respuesta share one geometry."""
    body = "Una respuesta suficientemente larga " * 8
    for columns in (80, 120, 200):
        width = columns - 2
        blocks = {
            "operador": user_message("revisa el objetivo", width=width, no_color=True),
            "pensamiento": thinking_block(body, width=width, no_color=True),
            "ejecucion": tool_result_block(
                "✓ nmap: 3 puertos abiertos", success=True,
                width=width, no_color=True,
            ),
            "respuesta": answer_panel(
                body, width=width, no_color=True,
            ),
            "resultado": result_panel(
                body, width=width, no_color=True,
            ),
        }
        for name, block in blocks.items():
            widths = {get_cwidth(line) for line in _framed_lines(block)}
            assert widths == {width}, (name, columns, widths)


def test_wide_terminal_does_not_cap_the_answer_at_100_columns() -> None:
    """The old ``min(100, columns - 8)`` cap is gone: 200 columns reads at 200."""
    body = "x" * 160
    panel = answer_panel(body, width=198, no_color=True)
    content = [line for line in panel.splitlines() if line.startswith("│")]
    assert _width(panel) == 198
    assert max(get_cwidth(line) for line in content) > 100


def test_subagent_titles_map_each_discipline() -> None:
    assert subagent_title("nexus.recon.nmap") == "OMNI · Recon"
    assert subagent_title("nexus.web.nuclei") == "OMNI · Vulnerability Assessment"
    assert subagent_title("nexus.exploit.sqlmap") == "OMNI · Explot"
    assert subagent_title("nexus.web.sqlmap") == "OMNI · Vulnerability Assessment"
    assert subagent_title("nexus.web.curl") == "OMNI · Scanning & Enum"
    assert subagent_title("nexus.post.ssh_exec") == "OMNI · Post-Explot"
    assert subagent_title("nexus.c2.sliver_loot") == "OMNI · Post-Explot"
    assert subagent_title("nexus.report.generate") == "OMNI · Reporting"
    assert subagent_title("nexus.workspace.read") == "OMNI · Dev"
    assert subagent_title("nexus.system.install_tool") == "OMNI · Dev"
    # An unknown discipline is never attributed to the wrong subagent.
    assert subagent_title("nexus.example.foo") is None
    assert subagent_title("") is None


def test_a_failure_and_a_guardrail_keep_their_own_title() -> None:
    failed = tool_result_block(
        "× timeout", success=False, width=80, no_color=True,
        title="OMNI · Vulnerability Assessment",
    )
    guardrail = tool_result_block(
        "corrige el plan", success=True, width=80, no_color=True,
        guardrail=True, title="OMNI · Recon",
    )
    assert "Fallo" in failed and "Vulnerability" not in failed
    assert "Corrección" in guardrail and "Recon" not in guardrail
    assert ADVISOR_TITLE == "OMNI · Asesor"


def _sized_output(columns: int, rows: int = 24) -> Any:
    from prompt_toolkit.data_structures import Size
    from prompt_toolkit.output import DummyOutput

    class _Sized(DummyOutput):
        width = columns

        def get_size(self) -> Size:
            return Size(rows=rows, columns=self.width)

    return _Sized()


def test_a_resize_repaints_the_borders_at_the_new_width(tui_factory: Any) -> None:
    ui = tui_factory(no_color=True, enable_completion=False)
    session = ui.session
    output = _sized_output(80)
    session._session.output = output
    session.append_user_turn("revisa el objetivo")
    session.append_answer_block("# Resultado\n" + "una línea larga " * 10)
    session.flush()

    before = session.transcript
    assert _width(before) == 78

    output.width = 120
    session.handle_resize()
    after = session.transcript

    assert _width(after) == 118
    assert session._last_render_width == 118
    # The border is data, not a frozen 80-column string.
    assert max(get_cwidth(line) for line in after.splitlines()) == 118
    assert all(get_cwidth(line) <= 118 for line in after.splitlines())


def test_a_full_width_panel_keeps_one_screen_row(tui_factory: Any) -> None:
    """Panel rows are exactly ``columns - 2`` wide: no cursor cell may wrap them."""
    import time

    ui = tui_factory(no_color=True, enable_completion=False)
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    ui.session.append_user_turn("revisa el objetivo")
    ui.session.flush()
    time.sleep(0.4)

    info = ui.session._scrollback_window.render_info
    assert info is not None
    # Every logical line is one terminal row: the full-width bordered panel is
    # not pushed onto a second, blank row by BufferControl's cursor cell.
    heights = [info.get_height_for_line(i) for i in range(info.content_height)]
    assert set(heights) == {1}


def test_a_resize_during_a_reveal_is_deferred_not_lost(tui_factory: Any) -> None:
    ui = tui_factory(no_color=True, enable_completion=False)
    session = ui.session
    output = _sized_output(80)
    session._session.output = output
    session.append_answer_block("respuesta")
    session.flush()
    before = session._scrollback.text

    session._typing_active = True
    output.width = 140
    session.handle_resize()
    assert session._resize_pending is True
    # The reveal owns the document; the repaint waits instead of interleaving.
    assert session._scrollback.text == before
    session._typing_active = False
    session._resize_pending = False
    session.handle_resize()
    assert _width(session.transcript) == 138
