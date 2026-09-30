"""Input styles preserve exact text and respect no-color."""

from prompt_toolkit.document import Document

from nexus_core.cli.tui.lexer import OmniLexer


def fragments(text):
    result = OmniLexer().lex_document(Document(text))(0)
    assert "".join(value for _, value in result) == text
    return result


def test_lexer_colors_slash_command():
    assert ("ansicyan bold", "/help") in fragments("/help")


def test_lexer_colors_nexus_tool():
    assert ("ansimagenta", "nexus.recon.nmap") in fragments("nexus.recon.nmap")


def test_lexer_colors_argument_key():
    assert ("ansiyellow", "target=") in fragments("target=host")


def test_lexer_colors_quoted_string():
    assert ("ansigreen", '"text"') in fragments('"text"')


def test_lexer_default_for_plain_text():
    assert fragments("hello world") == [("", "hello world")]


def test_lexer_no_color_when_disabled(tui_factory):
    ui = tui_factory(no_color=True)
    ui.pipe.send_text("/help\r")
    assert ui.session.prompt() == "/help"
    assert ui.session._session.lexer.lex_document(Document("/help"))(0) == [("", "/help")]


def test_lexer_colors_paths():
    assert ("ansicyan underline", "./reports/report.md") in fragments("./reports/report.md")
