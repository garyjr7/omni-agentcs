"""Fallback retains the previous prompt, banner and command dispatch."""

from unittest.mock import patch

from nexus_core.cli import commands, render
from nexus_core.cli.main import build_parser
from nexus_core.cli.session import OmniSession
from nexus_core.cli.tui.session import TuiSession


def test_existing_input_contract_in_fallback_mode(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    session = OmniSession(store=None, use_tui=False)
    with patch("builtins.input", side_effect=[KeyboardInterrupt, "", "/help", EOFError]):
        session.run_repl()
    text = capsys.readouterr().out
    assert "Ctrl+C interrumpe" in text
    assert "Comandos disponibles" in text
    assert "sesión terminada" in text


def test_banner_render_unchanged_in_fallback(monkeypatch, capsys):
    session = OmniSession(store=None, use_tui=False, no_color=True)
    monkeypatch.setattr("nexus_core.cli.session._stdout_is_tty", lambda: False)
    session._show_banner()
    assert capsys.readouterr().out == ""


def test_prompt_string_unchanged():
    render.set_color_enabled(False)
    try:
        session = OmniSession(store=None, use_tui=False)
        assert session.prompt == "┌──(OmniAgentCS)─[(sin engagement)]\n└─$ "
        session.trust_mode = True
        session.active_session_uuid = "abc"
        session.active_session_info = {"type": "shell"}
        assert session.prompt == "┌──(OmniAgentCS)─[(sin engagement)]─[TRUST MODE]─[session abc/shell]\n└─$ "
    finally:
        render.set_color_enabled(True)


def test_all_existing_commands_still_work_in_fallback():
    previous = {"/scope", "/tools", "/history", "/clear", "/export", "/approvals",
                "/sessions", "/session", "/detach", "/kill-session", "/findings",
                "/report", "/timeline", "/ask", "/chat", "/trust", "/help", "/exit", "/quit"}
    assert previous <= set(commands.COMMANDS)
    session = OmniSession(store=None, use_tui=False)
    for name in previous:
        with patch.dict(commands.COMMANDS, {name: lambda s, args: s.history.append(name)}):
            assert commands.run_command(session, name)
    assert set(session.history) == previous


def test_no_tui_flag_parsed():
    assert build_parser().parse_args(["--no-tui"]).no_tui


def test_fallback_never_imports_prompt_toolkit():
    import builtins

    original = builtins.__import__
    def reject(name, *args, **kwargs):
        if name.startswith("prompt_toolkit"):
            raise ImportError("optional dependency missing")
        return original(name, *args, **kwargs)
    with patch("builtins.__import__", side_effect=reject), patch("builtins.input", return_value="line"):
        session = TuiSession(use_tui=False)
        assert session.prompt() == "line"
        session.close()
