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
    assert any("AUTORIZACIÓN" in text for _, text in lines)


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
    assert "Sí / aprobar" in text and "No / rechazar" in text and "Custom / editar" in text
    assert "Submit" in text and "↑↓ navigate · Enter select" in text


def test_approval_style_defines_every_used_rule():
    defined = set(approval_style())
    used = {
        style.split("class:", 1)[1]
        for style, _ in approval_lines({"tool_id": "t", "arguments": {"a": 1}})
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
    assert "aprobación pendiente" in ui.session.transcript


def test_modal_state_toggles_on_the_tui_session(tui_factory):
    from prompt_toolkit.layout import FloatContainer

    ui = tui_factory()
    root = ui.session._session.app.layout.container
    assert isinstance(root, FloatContainer)
    assert ui.session._approval_float in root.floats
    assert ui.session.approval_active is False
    assert ui.session.set_approval({"tool_id": "t", "arguments": {}}) is True
    assert ui.session.approval_active is True
    ui.session.clear_approval()
    assert ui.session.approval_active is False
