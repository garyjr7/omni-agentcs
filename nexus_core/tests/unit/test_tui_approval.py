"""Unit tests for the dedicated approval modal and its fallback."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from nexus_core.cli import render
from nexus_core.cli.tui.panels import approval_lines, approval_style

pytestmark = pytest.mark.unit


def decision(reason="requiere aprobación humana", requires_approval=True):
    return SimpleNamespace(reason=reason, requires_approval=requires_approval)


def test_approval_lines_without_payload_is_tolerant():
    lines = approval_lines(None)
    assert lines
    assert any("PERMISO" in text for _, text in lines)


def test_approval_lines_show_tool_risk_reason_and_arguments():
    payload = {
        "tool_id": "nexus.c2.sliver_exec",
        "risk": "high",
        "reason": "post-explotación",
        "arguments": {"session_id": "abc123", "command": "id"},
    }
    text = "\n".join(t for _, t in approval_lines(payload))
    assert "nexus.c2.sliver_exec" in text
    assert "high" in text
    assert "post-explotación" in text
    assert "session_id: abc123" in text
    assert "command: id" in text
    assert "[+] ¿Puedo ejecutar id?" in text
    assert "Sí, siempre en este engagement" in text
    assert "Sí, solo esta vez" in text
    # Selecting and submitting are two separate steps; editing and the tool
    # definition keep the keys they already had.
    assert "↑↓ elegir · Enter seleccionar" in text
    assert "[e] editar" in text and "[?] definición" in text


def test_the_armed_menu_states_which_option_enter_would_submit():
    payload = {"tool_id": "nexus.c2.sliver_exec", "arguments": {"command": "id"}}
    text = "\n".join(t for _, t in approval_lines(payload, selected=1, armed=True))
    assert "Submit: Sí, solo esta vez" in text
    assert "Enter enviar" in text and "Esc cancelar" in text
    assert "Enter seleccionar" not in text


def test_approval_style_defines_every_used_rule():
    defined = set(approval_style())
    payload = {"tool_id": "t", "arguments": {"a": 1}}
    used = {
        style.split("class:", 1)[1]
        for armed in (False, True)
        for style, _ in approval_lines(payload, armed=armed)
        if style.startswith("class:")
    }
    assert used <= defined


class _FakeTui:
    """Minimal TUI stand-in exposing the bound ``prompt`` the modal path uses."""

    use_tui = True

    def __init__(self, answer="y"):
        self.answer = answer
        self.approval = None
        self.seen = None
        self.set_calls = 0

    def set_approval(self, payload):
        self.set_calls += 1
        self.approval = payload if isinstance(payload, dict) else None
        return self.approval is not None

    def clear_approval(self):
        self.approval = None

    def prompt(self, question):
        # The modal must be visible while the operator is answering.
        self.seen = dict(self.approval or {})
        return self.answer


def test_render_approval_prompt_uses_modal_and_hides_it_afterwards():
    owner = _FakeTui(answer="y")
    answer = render.render_approval_prompt(
        "nexus.c2.sliver_exec",
        {"session_id": "abc", "command": "id", "password": "hunter2"},
        decision(),
        reader=owner.prompt,
        risk="high",
    )
    assert answer == "y"
    assert owner.seen["tool_id"] == "nexus.c2.sliver_exec"
    assert owner.seen["risk"] == "high"
    # The invocation reaches the modal, but no value under a secret term does
    # (V1-30): the operator who needs the raw value uses the `[e]` editor, which
    # prints each current value. The modal is a glance, not a leak.
    assert owner.seen["arguments"]["command"] == "id"
    assert owner.seen["arguments"]["password"] == "[REDACTED]"
    assert owner.seen["arguments"]["session_id"] == "[REDACTED]"
    assert owner.set_calls == 1
    # The modal is transient: gone once the operator answered.
    assert owner.approval is None


def test_render_approval_prompt_modal_is_hidden_even_if_reader_raises():
    class _Raising(_FakeTui):
        def prompt(self, question):
            raise KeyboardInterrupt

    owner = _Raising()
    with pytest.raises(KeyboardInterrupt):
        render.render_approval_prompt("t", {}, decision(), reader=owner.prompt, risk="high")
    assert owner.approval is None


def test_render_approval_prompt_falls_back_to_plain_writes(capsys):
    owner = _FakeTui(answer="n")
    owner.use_tui = False
    answer = render.render_approval_prompt(
        "nexus.recon.nmap", {"target": "10.0.0.5"}, decision(), reader=owner.prompt
    )
    out = capsys.readouterr().out
    assert answer == "n"
    assert "APROBACIÓN HUMANA REQUERIDA" in out
    assert "nexus.recon.nmap" in out
    assert owner.set_calls == 0  # the plain path never sets the modal


def test_approval_modal_flows_through_the_real_tui(tui_factory):
    import threading
    import time

    from nexus_core.cli.tui.output import TuiOutput, route_output

    ui = tui_factory()
    observed = {}

    def answer():
        for _ in range(200):
            if ui.session.approval_active and ui.session._ready.is_set():
                observed["active"] = True
                break
            time.sleep(0.01)
        ui.pipe.send_text("y\r")

    thread = threading.Thread(target=answer)
    thread.start()
    try:
        with route_output(TuiOutput(ui.session)):
            result = render.render_approval_prompt(
                "nexus.c2.sliver_exec",
                {"command": "id"},
                decision(),
                reader=ui.session.prompt,
                risk="high",
            )
    finally:
        thread.join(3)
    assert result == "y"
    assert observed.get("active") is True
    assert ui.session.approval_active is False
    ui.session.flush()
    # The request is the dock's menu only: no raw "[y/n/a/e/?]" question and no
    # duplicate warning are interleaved with the conversation.
    assert "aprobación pendiente" not in ui.session.transcript
    assert "Opción [y/n" not in ui.session.transcript


def test_modal_state_toggles_on_the_tui_session(tui_factory):
    from prompt_toolkit.layout import FloatContainer

    ui = tui_factory()
    root = ui.session._session.app.layout.container
    assert isinstance(root, FloatContainer)
    # The permission menu is a row of the prompt dock, not an overlay: the
    # input panel expands upward instead of a modal floating over the log.
    assert ui.session._approval_panel in ui.session._rows
    assert ui.session.approval_active is False
    assert ui.session._approval_panel.height() == 0
    assert ui.session.set_approval({"tool_id": "t", "arguments": {}}) is True
    assert ui.session.approval_active is True
    assert ui.session._approval_panel.height() >= 4
    ui.session.clear_approval()
    assert ui.session.approval_active is False
    assert ui.session._approval_panel.height() == 0


# -- operator interaction (two-step confirm, Esc/Ctrl+C, narrow terminal) ------
def _wait(predicate, timeout: float = 4.0) -> bool:
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def _answer_in_thread(ui) -> tuple[dict, object]:
    """Read one answer through the real input bar, like the operator does."""
    import threading

    result: dict = {}

    def run() -> None:
        try:
            result["value"] = ui.session.prompt()
        except BaseException as exc:  # noqa: BLE001 - re-raised by the test
            result["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert _wait(lambda: ui.session._accepting)
    return result, thread


def test_the_default_option_is_single_use_and_unarmed(tui_factory):
    from nexus_core.cli.tui.frame import APPROVAL_DEFAULT, APPROVAL_TOKENS

    ui = tui_factory()
    ui.session.set_approval({"tool_id": "t", "arguments": {"command": "id"}})
    assert ui.session._approval_selected == APPROVAL_DEFAULT
    assert APPROVAL_TOKENS[ui.session._approval_selected] == "y"
    assert ui.session._approval_armed is False


def test_the_first_enter_only_selects_and_the_second_submits(tui_factory):
    ui = tui_factory()
    ui.session.set_approval(
        {"tool_id": "nexus.c2.sliver_exec", "risk": "high", "arguments": {"command": "id"}}
    )
    result, thread = _answer_in_thread(ui)
    ui.pipe.send_text("\r")
    assert _wait(lambda: ui.session._approval_armed)
    # Selected, not sent: the dock states the option the next Enter would use.
    assert "value" not in result and thread.is_alive()
    panel = "\n".join(text for _, text in ui.session._approval_formatted())
    assert "Submit: Sí, solo esta vez" in panel
    ui.pipe.send_text("\r")
    assert _wait(lambda: "value" in result)
    assert result["value"] == "y"


def test_arrows_move_the_choice_and_withdraw_the_armed_submit(tui_factory):
    ui = tui_factory()
    ui.session.set_approval({"tool_id": "t", "arguments": {"command": "id"}})
    result, _thread = _answer_in_thread(ui)
    ui.pipe.send_bytes(b"\x1b[B")  # down
    assert _wait(lambda: ui.session._approval_selected == 2)
    ui.pipe.send_text("\r")
    assert _wait(lambda: ui.session._approval_armed)
    ui.pipe.send_bytes(b"\x1b[A")  # up: the selection changed, so it must re-arm
    assert _wait(lambda: ui.session._approval_selected == 1
                 and ui.session._approval_armed is False)
    ui.pipe.send_text("n\r")
    assert _wait(lambda: "value" in result)
    assert result["value"] == "n"


def test_typed_tokens_still_submit_with_one_enter(tui_factory):
    ui = tui_factory()
    ui.session.set_approval({"tool_id": "t", "arguments": {"command": "id"}})
    result, _thread = _answer_in_thread(ui)
    ui.pipe.send_text("e\r")
    assert _wait(lambda: "value" in result)
    assert result["value"] == "e"


def test_escape_refuses_instead_of_authorizing(tui_factory):
    ui = tui_factory()
    ui.session.set_approval(
        {"tool_id": "nexus.c2.sliver_exec", "risk": "high", "arguments": {"command": "id"}}
    )
    result, _thread = _answer_in_thread(ui)
    ui.pipe.send_bytes(b"\x1b")
    assert _wait(lambda: "value" in result, timeout=6)
    # Esc never picks the highlighted option: it reads as an explicit refusal.
    assert result["value"] == "n"


def test_ctrl_c_interrupts_the_request_instead_of_approving(tui_factory):
    ui = tui_factory()
    ui.session.set_approval({"tool_id": "t", "arguments": {"command": "id"}})
    result, _thread = _answer_in_thread(ui)
    ui.pipe.send_bytes(b"\x03")
    assert _wait(lambda: "error" in result or "value" in result)
    # The approval callback treats KeyboardInterrupt as a refusal.
    assert isinstance(result.get("error"), KeyboardInterrupt)


def test_the_permission_panel_never_renders_a_secret(tui_factory):
    from nexus_core.cli.render import display_arguments

    ui = tui_factory()
    ui.session.set_approval({
        "tool_id": "nexus.c2.sliver_exec",
        "risk": "high",
        "arguments": display_arguments({"command": "id", "password": "hunter2"}),
    })
    text = "\n".join(part for _, part in ui.session._approval_formatted())
    assert "hunter2" not in text
    assert "[REDACTED]" in text
    assert "command: id" in text


def test_a_realistic_request_fits_the_dock_on_an_eighty_by_twenty_four_terminal(
    tui_factory, monkeypatch
):
    from prompt_toolkit.data_structures import Size

    ui = tui_factory()
    monkeypatch.setattr(ui.session._session.output, "get_size",
                        lambda: Size(rows=24, columns=80))
    ui.session.set_approval({
        "tool_id": "nexus.c2.sliver_exec", "risk": "high",
        "reason": "post-explotación en laboratorio",
        "arguments": {"command": "id", "password": "[REDACTED]"},
    })
    rows = ui.session._approval_lines()
    assert len(rows) <= 12
    assert ui.session._approval_panel.height() == len(rows)
    ui.session._approval_armed = True
    armed = "\n".join(part for _, part in ui.session._approval_lines())
    # The keys and the Submit line survive: Window would clip them otherwise.
    assert "Submit: Sí, solo esta vez" in armed
    assert "Esc cancelar" in armed
    assert len(ui.session._approval_lines()) <= 12


def test_an_oversized_request_folds_detail_but_keeps_the_decision(tui_factory):
    ui = tui_factory()
    ui.session.set_approval({
        "tool_id": "nexus.c2.sliver_exec", "risk": "high",
        "reason": " ".join(["motivo largo"] * 12),
        "arguments": {f"arg{index}": "valor" for index in range(1, 9)},
    })
    text = "\n".join(part for _, part in ui.session._approval_lines())
    assert "línea(s) de detalle · [e] las muestra" in text
    assert "Sí, solo esta vez" in text and "[?] definición" in text
    assert "arg8" not in text  # folded, and the marker says so


def test_each_menu_row_is_its_own_line(tui_factory):
    """FormattedTextControl concatenates fragments: rows need a separator.

    Without it the whole request rendered as one glued paragraph (``tool:``
    followed by ``riesgo:``) that wrapped mid-word, which is exactly what a PTY
    showed before this regression test existed.
    """
    ui = tui_factory()
    ui.session.set_approval({
        "tool_id": "nexus.c2.sliver_exec", "risk": "high",
        "reason": "post-explotación", "arguments": {"command": "id"},
    })
    text = "".join(part for _, part in ui.session._approval_formatted())
    lines = text.split("\n")
    assert len(lines) == len(ui.session._approval_lines())
    assert ui.session._approval_panel.height() == len(lines)
    tool_line = next(line for line in lines if "tool:" in line)
    risk_line = next(line for line in lines if "riesgo:" in line)
    assert "riesgo:" not in tool_line and "tool:" not in risk_line
    assert lines.index(risk_line) == lines.index(tool_line) + 1


def test_the_menu_fits_a_narrow_and_a_wide_terminal(tui_factory, monkeypatch):
    from prompt_toolkit.data_structures import Size

    ui = tui_factory()
    ui.session.set_approval({
        "tool_id": "nexus.c2.sliver_exec", "risk": "high",
        "reason": "post-explotación", "arguments": {"command": "id" * 40},
    })
    monkeypatch.setattr(ui.session._session.output, "get_size",
                        lambda: Size(rows=24, columns=80))
    assert ui.session._approval_width() == 62
    assert all(len(text) <= 62 for _, text in ui.session._approval_formatted())
    assert ui.session._approval_panel.height() <= 12
    # A narrower terminal shrinks the menu instead of clipping it.
    monkeypatch.setattr(ui.session._session.output, "get_size",
                        lambda: Size(rows=24, columns=60))
    assert ui.session._approval_width() == 56
    assert all(len(text) <= 56 for _, text in ui.session._approval_formatted())
    # A short terminal gives rows back so the editor stays on screen.
    monkeypatch.setattr(ui.session._session.output, "get_size",
                        lambda: Size(rows=14, columns=80))
    assert ui.session._approval_panel.height() <= 6
