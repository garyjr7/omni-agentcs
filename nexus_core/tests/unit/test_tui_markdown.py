"""The Markdown subset is stable regardless of optional Rich availability."""

import builtins
from types import SimpleNamespace
from unittest.mock import patch

from nexus_core.cli import commands, render
from nexus_core.cli.session import OmniSession
from nexus_core.cli.tui.markdown import render_markdown
from nexus_core.cli.tui.output import TuiOutput, route_output


def test_markdown_headers_render_bold():
    text = render_markdown("# Title\n## Section")
    # H1: bold + underline + cyan. H2: bold + cyan.
    assert "\x1b[1;4;36mTitle" in text and "\x1b[1;36mSection" in text


def test_markdown_bold_italic():
    text = render_markdown("**bold** *italic*")
    assert "\x1b[1mbold" in text and "\x1b[3mitalic" in text


def test_markdown_inline_code():
    assert "\x1b[100mcode" in render_markdown("`code`")


def test_markdown_code_block():
    text = render_markdown("```python\nprint('**literal**')\n```", no_color=True)
    assert "  print('**literal**')" in text and "----" in text and "```" not in text


def test_markdown_list_unordered():
    assert "  • first" in render_markdown("- first", no_color=True)


def test_markdown_list_ordered():
    assert "  1. first" in render_markdown("1. first", no_color=True)


def test_markdown_table_renders_ascii():
    text = render_markdown("| Tool | State |\n| --- | --- |\n| nmap | ready |", no_color=True, max_width=40)
    assert "+" in text and "| nmap" in text and "ready" in text
    assert all(len(line) <= 40 for line in text.splitlines())


def test_markdown_links():
    assert render_markdown("[docs](https://example.test)", no_color=True) == "docs (https://example.test)"


def test_markdown_table_with_empty_column():
    text = render_markdown("| | Value |\n| --- | --- |\n| | data |", no_color=True)
    assert "data" in text and "|   |" in text


def test_markdown_no_color_strips_ansi():
    assert "\x1b" not in render_markdown("# Title\n**bold** `code` *italic*", no_color=True)


def test_markdown_preserves_plain_text_when_rich_absent():
    original = builtins.__import__
    def no_rich(name, *args, **kwargs):
        if name.startswith("rich"):
            raise ImportError("rich absent")
        return original(name, *args, **kwargs)
    with patch("builtins.__import__", side_effect=no_rich):
        assert render_markdown("first\n\nsecond", no_color=True) == "first\n\nsecond"


def test_markdown_pipe_output_uses_router(tui_factory):
    ui = tui_factory(no_color=True)
    ui.pipe.send_text("/ask demo\r")
    ui.session.prompt()
    with route_output(TuiOutput(ui.session)):
        render.render_answer("# Title\n- item", markdown=True, no_color=True)
    ui.session.flush()
    assert "Title" in ui.session.transcript and "• item" in ui.session.transcript
    assert "# Title" not in ui.session.transcript


def test_fallback_answer_keeps_original_markdown(capsys):
    render.render_answer("**literal**", markdown=False)
    assert "**literal**" in capsys.readouterr().out


def test_report_previews_generated_markdown(tui_factory, tmp_path, monkeypatch):
    ui = tui_factory(no_color=True)
    path = tmp_path / "report.md"
    path.write_text("# Report\n\n| Finding | Count |\n| --- | --- |\n| test | 1 |")
    session = OmniSession(store=None, engagement=SimpleNamespace(name="lab", engagement_id="eng"), use_tui=False)
    session._tui = ui.session
    session._output = TuiOutput(ui.session)
    monkeypatch.setattr(commands, "_run_report_tool", lambda *a: {"output": {"report_path_md": str(path)}, "evidence": {}})
    ui.pipe.send_text("/report\r")
    ui.session.prompt()
    with route_output(session._output):
        commands.cmd_report(session, [])
    ui.session.flush()
    assert "| test" in ui.session.transcript
    assert "# Report" not in ui.session.transcript
