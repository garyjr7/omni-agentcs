"""The transcript reveals agent output like it is being written.

Two contracts are pinned here:

* the reveal is *additive* - ``''.join(typewriter_steps(value)) == value`` - so
  the styled transcript can always be rebuilt from the same string, and no
  character is ever lost, duplicated or reordered while it types;
* the pulse/completion row is fixed (``test_tui_busy``/``test_tui_frame``), so
  nothing here may add or remove a row of the layout.
"""

from __future__ import annotations

import re
import time

import pytest

from nexus_core.cli.tui.presentation import (
    TYPEWRITER_MAX_CHARS,
    render_rich,
    thinking,
    typewriter_steps,
)
from nexus_core.cli.tui.stream import format_tool_invocation, render_tool_result

pytestmark = pytest.mark.unit

ANSI = re.compile(r"\x1b\[[0-9;]*m")

GREEN = "\x1b[38;2;86;230;150m"
RED = "\x1b[38;2;255;64;84m"
AQUA = "\x1b[38;2;0;229;255m"


# -- the reveal is lossless ----------------------------------------------------
@pytest.mark.parametrize(
    "value",
    [
        "una línea",
        "  leading and trailing  ",
        "con\nsaltos\n\nde línea",
        "sin_espacios_ni_palabras_largas" * 3,
        "emoji 🚩 y acentos áéíóú",
        "\n\n",
        "",
    ],
)
def test_the_steps_always_rebuild_the_exact_original_text(value: str) -> None:
    steps = typewriter_steps(value)
    assert "".join(steps) == value


def test_the_reveal_is_paced_by_words_and_bounded() -> None:
    value = " ".join(f"palabra{index}" for index in range(500))
    steps = typewriter_steps(value, max_steps=40)
    assert len(steps) <= 40
    # Several words per step once the block is longer than the step budget, so
    # a big dump cannot hold the transcript hostage.
    assert any(" " in step.strip() for step in steps)


def test_a_huge_output_is_never_paced() -> None:
    value = "x" * (TYPEWRITER_MAX_CHARS + 1)
    assert typewriter_steps(value) == [value]


# -- the command is the accent element, the result carries the verdict -------
def test_the_tool_name_is_aqua_and_thinking_stays_muted() -> None:
    call = format_tool_invocation("nexus.recon.nmap", {"target": "lab"})
    # A real argv reads as a shell command: a green prompt, no cyan tool chip.
    assert AQUA not in call and GREEN in call
    assert ANSI.sub("", call).splitlines()[0] == "$ nmap -oX - lab"
    thought = render_rich(thinking("enumero el 445", expanded=True))
    # The note itself is dim and italic; the header is dim only.
    assert "\x1b[2;3;38;2;120;126;134m  enumero el 445" in thought


def test_tool_output_is_indented_under_a_branch_and_coloured_by_verdict() -> None:
    ok = render_tool_result({"success": True, "stdout": "a\nb"}, no_color=False)
    assert "└ a" in ANSI.sub("", ok)
    assert GREEN in ok and RED not in ok
    failed = render_tool_result(
        {"success": False, "stdout": "boom", "tool_id": "nexus.recon.smb"},
        no_color=False,
    )
    assert "└ boom" in ANSI.sub("", failed)
    assert RED in failed and GREEN not in failed


# -- end to end through the live session ---------------------------------------
def _running_session(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("objetivo\r")
    assert ui.session.prompt() == "objetivo"
    return ui


def test_the_transcript_shows_the_block_being_typed(tui_factory) -> None:
    ui = _running_session(tui_factory)
    block = " ".join(f"w{index:03d}" for index in range(60)) + "\n\n"
    ui.session.append_scrollback(block, typed=True)
    seen: list[int] = []
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        count = ui.session._scrollback.text.count("w0")
        seen.append(count)
        if count == 60:
            break
        time.sleep(0.005)
    assert seen[-1] == 60, "the block finished being typed"
    # It grew: the operator saw the words arrive instead of one dump.
    assert any(0 < count < 60 for count in seen)
    ui.session.flush()
    assert ui.session._scrollback.text.count("w000") == 1
    assert ui.session.transcript.count("w0") == 60


def test_flush_commits_a_half_typed_block_exactly_once(tui_factory) -> None:
    ui = _running_session(tui_factory)
    block = "\n".join(f"line {index}" for index in range(12)) + "\n"
    ui.session.append_scrollback(block, typed=True)
    time.sleep(0.03)  # the reveal is open
    ui.session.flush()
    text = ui.session._scrollback.text
    assert text.count("line 11") == 1
    assert text.count("line 0\n") == 1
    assert ui.session._typing_queue == []
    # The rows of the layout did not change: the transcript is a buffer.
    assert ui.session._busy_window.height() == 0


def test_a_card_is_revealed_and_then_behaves_like_any_other(tui_factory) -> None:
    ui = _running_session(tui_factory)
    ui.session.append_card({"success": True, "stdout": "\n".join(f"l{n}" for n in range(10))})
    assert "l0" not in ui.session.transcript  # not dumped into the log yet
    ui.session.flush()
    assert "└ l0" in ui.session._scrollback.text
    assert ui.session.toggle_card_at_line(min(ui.session._toggle_rows)) is True
    ui.session.flush()  # the rebuild is committed on the UI loop
    assert "ctrl+o colapsar" in ui.session._scrollback.text


def test_the_env_switch_writes_whole_blocks(tui_factory, monkeypatch) -> None:
    monkeypatch.setenv("NEXUS_TUI_TYPEWRITER", "0")
    ui = _running_session(tui_factory)
    ui.session.append_scrollback("completo de una vez\n", typed=True)
    ui.session.flush()  # a whole block is still a queued write
    assert "completo de una vez" in ui.session._scrollback.text
    assert ui.session._typing_queue == []
