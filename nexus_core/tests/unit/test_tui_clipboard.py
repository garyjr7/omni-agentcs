"""P0: ``/copy`` uses OSC 52 first and degrades to a native helper."""
from __future__ import annotations

import base64
import subprocess
from types import SimpleNamespace
from typing import Any

from nexus_core.cli.tui.clipboard import (
    MAX_OSC52_TEXT_BYTES,
    copy_to_clipboard,
    osc52_sequence,
)


class _Output:
    def __init__(self) -> None:
        self.raw: list[str] = []
        self.flushed = 0

    def write_raw(self, data: str) -> None:
        self.raw.append(data)

    def flush(self) -> None:
        self.flushed += 1


def test_osc52_payload_is_base64_and_uses_the_clipboard_selection() -> None:
    sequence = osc52_sequence("hola ✓", environ={})
    assert sequence.startswith("\x1b]52;c;") and sequence.endswith("\x07")
    encoded = sequence[len("\x1b]52;c;"):-1]
    assert base64.b64decode(encoded).decode("utf-8") == "hola ✓"


def test_osc52_is_wrapped_for_tmux_and_screen() -> None:
    tmux = osc52_sequence("x", environ={"TMUX": "/tmp/tmux-1000/default,1,0"})
    assert tmux.startswith("\x1bPtmux;\x1b\x1b]52;c;")
    assert tmux.endswith("\x1b\\")
    screen = osc52_sequence("x", environ={"STY": "1.pts-0.host"})
    assert screen.startswith("\x1bP\x1b]52;c;") and screen.endswith("\x1b\\")


def test_a_terminal_output_prefers_osc52() -> None:
    output = _Output()
    assert copy_to_clipboard("texto", output=output) == "OSC 52"
    assert output.raw and output.flushed == 1
    encoded = output.raw[0][len("\x1b]52;c;"):-1]
    assert base64.b64decode(encoded).decode() == "texto"


def test_an_oversized_payload_falls_back_to_the_native_helper(monkeypatch: Any) -> None:
    output = _Output()
    calls: list[tuple[list[str], bytes]] = []

    def fake_which(name: str) -> str | None:
        return "/usr/bin/xclip" if name == "xclip" else None

    def fake_run(command: list[str], **kwargs: Any) -> Any:
        calls.append((command, kwargs["input"]))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("nexus_core.cli.tui.clipboard.shutil.which", fake_which)
    monkeypatch.setattr("nexus_core.cli.tui.clipboard.subprocess.run", fake_run)

    text = "x" * (MAX_OSC52_TEXT_BYTES + 1)
    assert copy_to_clipboard(text, output=output) == "xclip"
    assert not output.raw
    assert calls and calls[0][0] == ["xclip", "-selection", "clipboard"]
    assert len(calls[0][1]) == len(text.encode())


def test_a_failing_helper_does_not_raise(monkeypatch: Any) -> None:
    def fake_which(name: str) -> str | None:
        return "/usr/bin/xclip" if name == "xclip" else None

    def fake_run(command: list[str], **kwargs: Any) -> Any:
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr("nexus_core.cli.tui.clipboard.shutil.which", fake_which)
    monkeypatch.setattr("nexus_core.cli.tui.clipboard.subprocess.run", fake_run)
    assert copy_to_clipboard("texto", stream=None) is None


def test_copy_candidates_are_newest_first_and_strip_markdown(
    tui_factory: Any,
) -> None:
    ui = tui_factory(no_color=True, enable_completion=False)
    session = ui.session
    session.append_answer_block("# Hola\n**mundo**")
    session.append_card({
        "success": True, "tool_id": "nexus.recon.nmap",
        "stdout": "80/tcp open http",
    }, typed=False)
    session.flush()

    candidates = session.copy_candidates()
    assert [item["kind"] for item in candidates] == ["tool", "answer"]
    assert candidates[0]["title"] == "OMNI · Recon"
    assert "80/tcp open http" in candidates[0]["text"]
    assert "Hola" in candidates[1]["text"] and "mundo" in candidates[1]["text"]
    assert "#" not in candidates[1]["text"] and "**" not in candidates[1]["text"]


def test_plain_transcript_removes_frames_and_ansi(tui_factory: Any) -> None:
    ui = tui_factory(no_color=False, enable_completion=False)
    session = ui.session
    session.append_user_turn("revisa el objetivo")
    session.append_answer_block("# Hola\n**mundo**")
    session.flush()

    text = session.plain_transcript()
    assert "revisa el objetivo" in text
    assert "Hola" in text and "mundo" in text
    assert "\x1b" not in text
    assert "╭" not in text and "│" not in text


def test_cmd_copy_reports_the_backend_and_the_character_count(
    tui_factory: Any, capsys: Any,
) -> None:
    from nexus_core.cli.commands import cmd_copy

    ui = tui_factory(no_color=True, enable_completion=False)
    ui.session.append_answer_block("# Hola\nrespuesta")
    ui.session.flush()
    owner: Any = SimpleNamespace(_tui=ui.session)

    cmd_copy(owner, [])
    out = capsys.readouterr().out
    assert "copiado OMNI · Asesor (#1)" in out
    assert "OSC 52" in out

    cmd_copy(owner, ["99"])  # out of range: reports, never raises
    assert "no existe la respuesta 99" in capsys.readouterr().out

    cmd_copy(owner, ["all"])
    assert "la conversación completa" in capsys.readouterr().out
