import json
import re
from pathlib import Path
from unittest.mock import patch

from rich.cells import cell_len

from nexus_core.cli.tui.stream import format_tool_invocation, render_tool_result, render_message

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text):
    return ANSI.sub("", text)


def test_tool_invocation_is_a_single_clean_line():
    text = format_tool_invocation("nexus.recon.nmap", {"target": "lab", "flags": ["-sV", "-p", "80"]})
    lines = _plain(text).splitlines()
    # One header. A handler that builds an argv is shown as the command it will
    # run: no phase chip, no bracket prefix and no duplicated tool id.
    assert len(lines) == 1
    assert lines[0] == "$ nmap -sV -p 80 -oX - lab"
    # A structured call keeps its honest key=value request under the tool id.
    structured = _plain(format_tool_invocation(
        "nexus.web.upload", {"target": "lab", "path": "shell.php"}))
    assert structured.startswith("• nexus.web.upload  path=shell.php · target=lab")


def test_a_long_invocation_keeps_every_argument():
    command = "nmap -sV -p- " + " ".join(["10.0.0.5"] * 25)
    text = _plain(format_tool_invocation("nexus.session.interact", {"command": command}))
    # Nothing is clipped: the scrollback wraps the block at the real width.
    assert command in text and "…" not in text


def test_structured_arguments_are_pairs_not_a_json_blob():
    text = _plain(format_tool_invocation(
        "nexus.web.upload", {"target": "10.0.0.5", "path": "shell.php"}))
    line = text.splitlines()[0]
    assert "target=10.0.0.5" in line and "path=shell.php" in line
    assert "{" not in line and '"' not in line


def test_invocation_arguments_keep_the_secret_redaction():
    text = _plain(format_tool_invocation(
        "nexus.cred.bruteforce", {"target": "10.0.0.5", "password": "hunter2"}))
    assert "hunter2" not in text and "REDACTED" in text


def test_nmap_flags_cannot_leak_a_credential():
    text = _plain(format_tool_invocation(
        "nexus.recon.nmap",
        {"target": "10.0.0.5",
         "flags": ["-sV", "--script-args=user=admin,password=hunter2"]}))
    # The special Nmap branch reads the redacted arguments like any other.
    assert "hunter2" not in text and "[REDACTED]" in text
    assert "password=[REDACTED]" in text
    # Still the real argv, target included: nothing invented, nothing lost.
    assert "nmap -sV" in text and "-oX - 10.0.0.5" in text


def test_a_file_operation_redacts_a_credential_inside_the_path():
    text = _plain(format_tool_invocation(
        "nexus.workspace.read", {"path": "loot/password=hunter2.txt"}))
    assert text.startswith("• nexus.workspace.read  loot/") and "hunter2" not in text


def test_a_wrapped_invocation_indents_its_continuations():
    command = "nmap -sV -p- " + " ".join(["10.0.0.5"] * 12)
    text = _plain(format_tool_invocation(
        "nexus.session.interact", {"command": command}, width=60))
    rows = text.splitlines()
    assert len(rows) > 1
    assert rows[0].startswith("• nexus.session.interact  ")
    assert all(row.startswith("  ↳ ") for row in rows[1:])
    assert all(cell_len(row) <= 60 for row in rows)
    # Nothing was dropped to make it fit.
    assert "…" not in text
    joined = " ".join(rows)
    assert all(token in joined for token in command.split())


def test_a_wrapped_invocation_measures_cells_not_characters():
    command = "日本語" * 30
    text = _plain(format_tool_invocation(
        "nexus.session.interact", {"command": command}, width=40))
    rows = text.splitlines()
    assert all(cell_len(row) <= 40 for row in rows)
    # Wide characters count as the cells they paint: the whole value survives.
    rebuilt = rows[0].removeprefix("• nexus.session.interact  ") + "".join(
        row.removeprefix("  ↳ ") for row in rows[1:])
    assert rebuilt == "command=" + command


def test_file_operations_name_the_tool_and_the_path():
    assert _plain(format_tool_invocation("nexus.workspace.read", {"path": "a.txt"})) == "• nexus.workspace.read  a.txt"
    assert _plain(format_tool_invocation("nexus.workspace.create", {"path": "b.txt"})) == "• nexus.workspace.create  b.txt"
    assert _plain(format_tool_invocation("nexus.file.edit", {"path": "c.txt"})) == "• nexus.file.edit  c.txt"


def test_tool_complete_folds_at_four_data_lines():
    text = render_tool_result({"success": True, "stdout": "\n".join(f"l{n}" for n in range(10))})
    assert len([line for line in text.splitlines() if "└ " in line]) == 4


def test_tool_complete_reports_the_hidden_data_lines():
    text = render_tool_result({"stdout": "\n".join(f"l{n}" for n in range(9))})
    assert "Ver 5 líneas más" in text


def test_tool_complete_summary_line():
    text = render_tool_result({"success": True, "evidence": {"ports_open_total": 4, "noise_level": "low", "elapsed_seconds": 4.2}})
    assert "✓ 4 puertos abiertos · ruido: low · 4.2s" in text


def test_tool_failed_shows_error():
    text = render_tool_result({"success": False, "output": {"error": "timeout 120s"}, "verification_method": "nmap_timeout"})
    assert "× timeout 120s · verification_method=nmap_timeout" in text


def test_collapsed_card_reports_hidden_lines():
    text = render_tool_result({"success": True, "stdout": "\n".join(f"l{n}" for n in range(10))})
    assert "Ver 6 líneas más" in text
    assert "Show more" not in text and "[ Show " not in text
    assert "F3" not in text


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
    assert "× connection refused" in collapsed
    assert "× failed" not in collapsed
    # The JSON stays behind one click instead of being dumped field by field.
    assert "Ver " in collapsed and "líneas más" in collapsed
    assert '"host"' not in collapsed
    assert '"host": "10.0.0.5"' in render_tool_result(result, expanded=True, no_color=True)


def test_unknown_structured_output_previews_its_fields():
    result = {"success": True, "tool_id": "nexus.example", "output": {"foo": "bar"}}
    collapsed = render_tool_result(result, no_color=True)
    # One verdict line, then the size of the document behind the toggle: the
    # field tree is exactly what used to dump forty rows for report.generate.
    assert "└ foo" not in collapsed
    assert "Ver 3 líneas más" in collapsed
    assert '"foo"' not in collapsed
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
    assert "$ nmap" in plain
    assert plain.index("Razonamiento") < plain.index("$ nmap")
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
    assert "real output" in render_message(message)
    assert "2 puertos abiertos" in render_message(message)


def test_daemon_uses_compact_messages_in_tui(tui_factory):
    from types import SimpleNamespace
    from nexus_core.cli.session import OmniSession, _drain_stream
    from nexus_core.cli.tui.output import TuiOutput
    ui = tui_factory()
    session = OmniSession(store=None, use_tui=False)
    session._tui, session._output = ui.session, TuiOutput(ui.session)
    session.run_id, session.conversation_id = "r", "c"
    messages = [{"metadata": {"kind": "react.action", "action": "tool_call", "tool_id": "nexus.recon.nmap", "arguments": {"target": "lab"}}}]
    session.store = SimpleNamespace(
        list_run_events=lambda *a, **k: [],
        list_messages=lambda *a, after_sequence=None, **k: [
            message for message in messages
            if after_sequence is None or message.get("sequence", 0) > after_sequence
        ],
    )
    state = {"run_id": "r", "sequence": 0, "message_sequence": None, "turn": 0}
    _drain_stream(session, state)
    _drain_stream(session, state)
    assert _plain(ui.session.transcript).count("$ nmap") == 1
