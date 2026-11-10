import json
import re
from pathlib import Path
from unittest.mock import patch

from rich.cells import cell_len

from nexus_core.cli.tui.stream import format_tool_invocation, render_tool_result, render_message

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text):
    return ANSI.sub("", text)


def _port(number, service, product="", version=""):
    return {"port": str(number), "protocol": "tcp", "state": "open",
            "service": service, "product": product, "version": version}


def _scan(ports):
    return {"success": True, "tool_id": "nexus.recon.nmap",
            "evidence": {"ports_open_total": len(ports), "hosts_up": 1},
            "output": {"scan": {"hosts": [{"ip": "10.0.0.5", "state": "up",
                                           "ports": ports}]}}}


def test_expanded_scan_shows_a_real_port_table():
    ports = [_port(22, "ssh", "OpenSSH", "9.6"), _port(443, "https", "nginx", "1.24.0")]
    text = _plain(render_tool_result(_scan(ports), expanded=True, width=100, no_color=True))
    assert "Puerto" in text and "Servicio" in text and "Versión" in text
    assert "22" in text and "OpenSSH 9.6" in text
    assert "nginx 1.24.0" in text


def test_expanded_table_is_bounded_and_counts_the_rest():
    ports = [_port(1000 + index, f"svc{index}") for index in range(15)]
    text = _plain(render_tool_result(_scan(ports), expanded=True, width=80, no_color=True))
    assert all(cell_len(line) <= 80 for line in text.splitlines())
    assert "y 3 puerto(s) más" in text
    assert "svc0" in text and "svc12" not in text


def test_collapsed_scan_stays_one_line_without_the_table():
    ports = [_port(1000 + index, f"svc{index}") for index in range(15)]
    text = _plain(render_tool_result(_scan(ports), width=100, no_color=True))
    assert len(text.splitlines()) == 1
    assert "Servicio" not in text


def test_tool_invocation_is_a_single_conversational_line():
    text = format_tool_invocation("nexus.recon.nmap", {"target": "lab", "flags": ["-sV", "-p", "80"]})
    lines = _plain(text).splitlines()
    # Fase 3: una línea de texto plano, no una cabecera de dashboard.
    assert len(lines) == 1
    assert lines[0] == "> Ejecutando nmap en lab..."
    structured = _plain(format_tool_invocation(
        "nexus.web.upload", {"target": "lab", "path": "shell.php"}))
    assert structured == "> Ejecutando upload en lab..."


def test_a_long_invocation_stays_one_line_and_keeps_the_target():
    command = "nmap -sV -p- " + " ".join(["10.0.0.5"] * 25)
    text = _plain(format_tool_invocation("nexus.session.interact", {"command": command}))
    assert len(text.splitlines()) == 1
    assert text.startswith("> Ejecutando interact en nmap -sV -p- 10.0.0.5")


def test_structured_arguments_never_leak_a_json_blob():
    text = _plain(format_tool_invocation(
        "nexus.web.upload", {"target": "10.0.0.5", "path": "shell.php"}))
    line = text.splitlines()[0]
    assert line == "> Ejecutando upload en 10.0.0.5..."
    assert "{" not in line and '"' not in line


def test_invocation_line_keeps_the_secret_redaction():
    text = _plain(format_tool_invocation(
        "nexus.cred.bruteforce", {"target": "10.0.0.5", "password": "hunter2"}))
    assert "hunter2" not in text
    assert text == "> Probando credenciales en 10.0.0.5..."


def test_internal_plumbing_is_named_as_one_step():
    command = (
        "cd ~/Desktop/salas/eng && jq '.engagement.lhost = \"10.0.0.5\"' "
        "memory.json > memory.new && mv memory.new memory.json && echo 'ok'"
    )
    text = _plain(format_tool_invocation("nexus.shell.exec", {"command": command}))
    assert text == "> Ejecutando comando en preparando el entorno..."
    assert "jq" not in text and "memory.json" not in text


def test_plumbing_heredoc_hides_the_rc_payload():
    command = "cd ~/eng && cat > exploit.rc <<'EOF'\nuse exploit/windows/smb/ms17_010\nset RHOSTS 10.0.0.5\nEOF"
    text = _plain(format_tool_invocation("nexus.shell.exec", {"command": command}))
    assert text == "> Ejecutando comando en preparando el entorno..."
    assert "exploit.rc" not in text


def test_a_real_command_after_plumbing_stays_visible():
    command = "jq '.a=1' memory.json && nmap -sV -p 445 10.0.0.5"
    text = _plain(format_tool_invocation("nexus.shell.exec", {"command": command}))
    assert "nmap -sV -p 445 10.0.0.5" in text


def test_nmap_flags_cannot_leak_a_credential():
    text = _plain(format_tool_invocation(
        "nexus.recon.nmap",
        {"target": "10.0.0.5",
         "flags": ["-sV", "--script-args=user=admin,password=hunter2"]}))
    assert "hunter2" not in text
    assert text == "> Ejecutando nmap en 10.0.0.5..."


def test_a_file_operation_redacts_a_credential_inside_the_path():
    text = _plain(format_tool_invocation(
        "nexus.workspace.read", {"path": "loot/password=hunter2.txt"}))
    assert text.startswith("> Leyendo") and "hunter2" not in text


def test_a_narrow_width_crops_with_a_cell_accurate_ellipsis():
    command = "nmap -sV -p- " + " ".join(["10.0.0.5"] * 12)
    text = _plain(format_tool_invocation(
        "nexus.session.interact", {"command": command}, width=60))
    assert len(text.splitlines()) == 1
    assert cell_len(text) <= 60
    assert text.endswith("…")


def test_a_wide_character_line_is_measured_in_cells():
    command = "日本語" * 30
    text = _plain(format_tool_invocation(
        "nexus.session.interact", {"command": command}, width=40))
    assert len(text.splitlines()) == 1
    assert cell_len(text) <= 40


def test_file_operations_name_the_action_and_the_path():
    assert _plain(format_tool_invocation("nexus.workspace.read", {"path": "a.txt"})) == "> Leyendo en a.txt..."
    assert _plain(format_tool_invocation("nexus.workspace.create", {"path": "b.txt"})) == "> Ejecutando create en b.txt..."
    assert _plain(format_tool_invocation("nexus.file.edit", {"path": "c.txt"})) == "> Ejecutando edit en c.txt..."


def test_tool_complete_is_one_plain_line_by_default():
    text = render_tool_result({"success": True, "tool_id": "nexus.shell.exec",
                               "stdout": "\n".join(f"l{n}" for n in range(10))})
    assert len(text.splitlines()) == 1
    assert text.startswith("✓ shell: ")


def test_the_full_body_is_available_when_expanded():
    text = render_tool_result({"success": True, "stdout": "\n".join(f"l{n}" for n in range(10))},
                              expanded=True)
    assert len([line for line in text.splitlines() if "└ " in line]) == 10
    assert "Ver " not in text


def test_tool_complete_summary_line():
    text = render_tool_result({"success": True, "tool_id": "nexus.recon.nmap",
                               "evidence": {"ports_open_total": 4, "noise_level": "low", "elapsed_seconds": 4.2}})
    assert text == "✓ nmap: 4 puertos abiertos · ruido: low · 4.2s"


def test_tool_failed_shows_error():
    text = render_tool_result({"success": False, "tool_id": "nexus.recon.nmap",
                               "output": {"error": "timeout 120s"},
                               "verification_method": "nmap_timeout"})
    assert text == (
        "× nmap: timeout 120s · verification_method=nmap_timeout · Ver 3 líneas más"
    )


def test_collapsed_card_is_a_single_plain_line():
    text = render_tool_result({"success": True, "stdout": "\n".join(f"l{n}" for n in range(10))})
    assert len(text.splitlines()) == 1
    assert "✓ tool: l0" in text and "Ver 6 líneas más" in text
    assert "└ " not in text
    assert "Show more" not in text and "[ Show " not in text
    assert "F3" not in text


def test_collapsed_line_reserves_the_footer_and_never_exceeds_the_width():
    """D1: the footer must not push the verdict past the transcript width."""
    from rich.cells import cell_len

    ports = [
        {"port": port, "protocol": "tcp", "state": "open", "service": service}
        for port, service in (
            (21, "ftp"), (22, "ssh"), (25, "smtp"), (80, "http"), (110, "pop3"),
            (143, "imap"), (443, "https"), (993, "imaps"), (995, "pop3s"),
            (3306, "mysql"), (5432, "postgresql"), (6379, "redis"),
            (8080, "http-proxy"), (8443, "https-alt"), (9200, "elasticsearch"),
        )
    ]
    result = {
        "success": True, "tool_id": "nexus.recon.nmap",
        "evidence": {"ports_open_total": 15, "hosts_up": 1, "elapsed_seconds": 12.4},
        "output": {"scan": {"hosts": [{"state": "up", "ip": "45.33.32.156", "ports": ports}],
                            "hosts_up": 1, "elapsed_seconds": 12.4}},
    }
    line = render_tool_result(result, width=100, no_color=True)
    assert cell_len(line) <= 100
    assert line.count("(") == line.count(")")
    assert line.endswith("· Ver 13 líneas más")


def test_report_result_summarizes_the_path_and_keeps_the_json_in_the_detail():
    result = {"success": True, "tool_id": "nexus.report.generate",
              "output": {"directory": "/tmp/eng",
                         "report_path_md": "/tmp/eng/report.md",
                         "report_sha256": "a" * 64}}
    collapsed = render_tool_result(result, no_color=True)
    assert "informe guardado: /tmp/eng/report.md" in collapsed
    assert "sha256: aaaaaaaaaaaa…" in collapsed
    # The JSON is the detail: the collapsed card does not dump it.
    assert '"report_path_md"' not in collapsed
    assert '"report_path_md": "/tmp/eng/report.md"' in render_tool_result(
        result, expanded=True, no_color=True)


def test_a_negative_but_verified_result_keeps_its_own_words():
    result = {"success": True, "tool_id": "nexus.cred.bruteforce",
              "output": {"verified": True, "message": "ninguna credencial válida",
                         "attempts": 12}}
    collapsed = render_tool_result(result, no_color=True)
    assert "ninguna credencial válida" in collapsed
    # Not interpreted: a negative verification is still a successful call.
    assert "✓" in collapsed and "× falló" not in collapsed
    assert '"attempts"' not in collapsed
    assert '"attempts": 12' in render_tool_result(result, expanded=True, no_color=True)


def test_a_structured_error_keeps_its_text_and_defers_the_json():
    result = {"success": False, "tool_id": "nexus.web.request",
              "output": {"error": "connection refused", "host": "10.0.0.5"}}
    collapsed = render_tool_result(result, no_color=True)
    assert collapsed == "× request: connection refused · Ver 4 líneas más"
    assert "× failed" not in collapsed
    assert '"host"' not in collapsed
    assert '"host": "10.0.0.5"' in render_tool_result(result, expanded=True, no_color=True)


def test_unknown_structured_output_is_summarized_in_one_line():
    result = {"success": True, "tool_id": "nexus.example", "output": {"foo": "bar"}}
    collapsed = render_tool_result(result, no_color=True)
    assert collapsed == "✓ example: resultado estructurado · 1 campo(s) · Ver 3 líneas más"
    assert "└ foo" not in collapsed
    assert '"foo": "bar"' in render_tool_result(result, expanded=True, no_color=True)


def test_expanded_card_shows_every_line():
    text = render_tool_result(
        {"success": True, "stdout": "\n".join(f"l{n}" for n in range(10))}, expanded=True
    )
    assert text.count("└ ") == 10
    assert "oculta" not in text


def test_expanded_card_has_no_ellipsis_marker():
    text = render_tool_result({"success": True, "stdout": "a\nb\nc\nd"}, expanded=True)
    assert "..." not in text
    assert "✓" in text


def test_no_run_in_terminal_calls():
    cli = Path(__file__).parents[2] / "cli"
    assert not [p for p in cli.rglob("*.py") if "run_in_terminal" in p.read_text()]


def test_scrollback_autoscrolls(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    ui.session.append_scrollback("line\n" * 100)
    ui.session.flush()
    assert ui.session._scrollback.cursor_position == len(ui.session._scrollback.text)


def test_scrollback_not_invalidated_per_write(tui_factory):
    ui = tui_factory()
    with patch.object(ui.session, "invalidate") as redraw:
        for _ in range(20):
            ui.session.append_scrollback("event\n")
    redraw.assert_not_called()


def test_thought_is_rendered_before_the_tool_call():
    message = {"metadata": {"kind": "react.action", "action": "tool_call", "thought": "escaneo los web", "tool_id": "nexus.recon.nmap", "arguments": {"target": "lab"}}}
    text = render_message(message, expanded=True)
    plain = _plain(text)
    assert "Razonamiento" in plain and "escaneo los web" in plain
    assert "> Ejecutando nmap en lab..." in plain
    assert plain.index("Razonamiento") < plain.index("> Ejecutando nmap")
    # Collapsed, the finished turn costs one row: the note is one click away.
    collapsed = _plain(render_message(message))
    assert collapsed.splitlines()[0] == "  ▸ Razonamiento"
    assert "escaneo los web" not in collapsed


def test_thought_is_rendered_for_task_complete():
    message = {"metadata": {"kind": "react.action", "action": "task_complete", "thought": "ya tengo la evidencia"}}
    plain = _plain(render_message(message, expanded=True))
    assert "Razonamiento" in plain and "ya tengo la evidencia" in plain


def test_missing_thought_produces_no_line():
    message = {"metadata": {"kind": "react.action", "action": "tool_call", "tool_id": "nexus.recon.nmap", "arguments": {}}}
    assert not render_message(message).startswith("💭")


def test_durable_observation_uses_real_body():
    message = {"metadata": {"kind": "react.observation", "tool_result": {"success": True}},
               "content": json.dumps({"output": "real output", "evidence": {"ports_open_total": 2}})}
    # Fase 3: por defecto una línea; el cuerpo completo está a una expansión.
    assert "2 puertos abiertos" in render_message(message)
    assert "real output" in render_message(message, expanded=True)


def test_daemon_uses_compact_messages_in_tui(tui_factory):
    from types import SimpleNamespace
    from nexus_core.cli.session import OmniSession, _drain_stream
    from nexus_core.cli.tui.output import TuiOutput
    ui = tui_factory()
    session = OmniSession(store=None, use_tui=False)
    session._tui, session._output = ui.session, TuiOutput(ui.session)
    session.run_id, session.conversation_id = "r", "c"
    messages = [{"sequence": 7, "metadata": {"kind": "react.action", "action": "tool_call", "tool_id": "nexus.recon.nmap", "arguments": {"target": "lab"}}}]
    cursors: list[int | None] = []

    def list_messages(*args, after_sequence=None, **kwargs):
        cursors.append(after_sequence)
        return [
            message for message in messages
            if after_sequence is None or message.get("sequence", 0) > after_sequence
        ]

    session.store = SimpleNamespace(
        list_run_events=lambda *a, **k: [],
        list_messages=list_messages,
    )
    state = {"run_id": "r", "sequence": 0, "message_sequence": None, "turn": 0}
    _drain_stream(session, state)
    _drain_stream(session, state)
    assert _plain(ui.session.transcript).count("> Ejecutando nmap") == 1
    # The second poll asks the store only for what follows the last row it saw.
    assert cursors == [None, 7]


class _RecordingTui:
    """Minimal TUI facade: records the blocks and cards the stream emits."""

    use_tui = True
    expand_cards = False
    text_width = 80
    no_color = True

    def __init__(self):
        self.blocks = []
        self.cards = []
        self._pending_reasoning = None

    def task_event(self, event):
        pass

    def set_status(self, **kwargs):
        pass

    def append_execution_block(self, text):
        self.blocks.append(text)

    def append_card(self, result, **kwargs):
        self.cards.append((result, kwargs))


def _action(sequence, thought, target="lab"):
    return {
        "sequence": sequence,
        "metadata": {
            "kind": "react.action",
            "action": "tool_call",
            "tool_id": "nexus.recon.nmap",
            "arguments": {"target": target},
            "thought": thought,
        },
    }


def test_the_first_turn_has_no_step_header_and_the_second_does():
    from types import SimpleNamespace

    from nexus_core.cli.session import _drain_stream

    tui = _RecordingTui()
    session = SimpleNamespace(
        store=SimpleNamespace(
            list_run_events=lambda *a, **k: [],
            list_messages=lambda *a, **k: [_action(1, "primero"), _action(2, "segundo", "lab2")],
        ),
        tenant_id="system",
        conversation_id="c",
        run_id="r",
        _tui=tui,
    )
    _drain_stream(session, {"run_id": "r", "sequence": 0, "message_sequence": None, "turn": 0})

    joined = "\n".join(_plain(block) for block in tui.blocks)
    assert "paso 1" not in joined
    assert "paso 2" in joined


def test_the_reasoning_event_reaches_the_reasoning_card():
    from types import SimpleNamespace

    from nexus_core.cli.session import _drain_stream, _render_run_event

    tui = _RecordingTui()
    session = SimpleNamespace(
        store=SimpleNamespace(
            list_run_events=lambda *a, **k: [],
            list_messages=lambda *a, **k: [_action(1, "reviso el puerto 445")],
        ),
        tenant_id="system",
        conversation_id="c",
        run_id="r",
        _tui=tui,
    )
    _render_run_event(
        session,
        {"event_type": "react.reasoning", "payload": {"reasoning": "El SMB está abierto."}},
    )
    assert tui._pending_reasoning == "El SMB está abierto."

    state = {"run_id": "r", "sequence": 0, "message_sequence": None, "turn": 0}
    _drain_stream(session, state)

    assert tui._pending_reasoning is None
    assert tui.cards
    _result, kwargs = tui.cards[0]
    assert kwargs["thought"] == "reviso el puerto 445"
    assert kwargs["reasoning"] == "El SMB está abierto."
