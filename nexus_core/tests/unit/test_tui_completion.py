"""Deterministic catalog completion, including a real pipe-driven Tab."""

import threading
from types import SimpleNamespace

import pytest
from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import fragment_list_to_text

from nexus_core.cli.tui.completion import OmniCompleter
from nexus_core.cli.tui.session import TuiSession


def help_command():
    """Muestra esta ayuda."""


def history_command():
    """Muestra el historial."""


@pytest.fixture
def catalog():
    return dict(commands={"/help": help_command, "/history": history_command, "/ask": help_command},
                tools={"nexus.recon.nmap": {"properties": {"target": {"type": "string"}, "flags": {"type": "array"}}},
                       "nexus.recon.httpx": {"properties": {}}}, engagements=["scanme-lab", "internal"])


def complete(catalog, text):
    return list(OmniCompleter(**catalog).get_completions(Document(text), CompleteEvent(completion_requested=True)))


def test_completer_suggests_commands_starting_with_slash(catalog):
    assert {c.text for c in complete(catalog, "/")} == {"/help", "/history", "/ask"}


def test_completer_lists_all_commands_with_help(catalog):
    assert all(fragment_list_to_text(c.display_meta) for c in complete(catalog, "/"))


def test_completer_filters_by_prefix(catalog):
    assert [c.text for c in complete(catalog, "/he")] == ["/help"]


def test_completer_suggests_tools_after_nexus_dot(catalog):
    assert {c.text for c in complete(catalog, "nexus.recon.")} == set(catalog["tools"])


def test_completer_suggests_tool_arguments_after_space(catalog):
    assert {c.text for c in complete(catalog, "nexus.recon.nmap ")} == {"target=", "flags="}
    assert [c.text for c in complete(catalog, "nexus.recon.nmap target=host f")] == ["flags="]


def test_completer_suggests_engagements_with_at_sign(catalog):
    assert [c.text for c in complete(catalog, "@scan")] == ["@scanme-lab"]


def test_completer_falls_back_to_file_paths(catalog, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "report.md").touch()
    text = "./rep"
    values = complete(catalog, text)
    assert any(text[:len(text) + c.start_position] + c.text == "./report.md" for c in values)


def test_completer_no_suggestions_for_random_text(catalog):
    assert not complete(catalog, "what is this")


def test_absolute_path_fallback_when_no_command_matches(catalog):
    assert any(c.text == "mp" for c in complete(catalog, "/t"))


def test_path_after_tool_name(catalog, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "report.md").touch()
    assert any(c.text == "ort.md" for c in complete(catalog, "nexus.recon.nmap ./rep"))


def test_completer_respects_no_color(tui_factory, catalog):
    ui = tui_factory(no_color=True, **catalog)
    items = list(ui.session._completer.get_completions(Document("/he"), CompleteEvent()))
    assert all("\x1b" not in fragment_list_to_text(c.display_meta) for c in items)
    assert ui.session._session.lexer.lex_document(Document("/he"))(0) == [("", "/he")]


def test_completer_disabled_when_no_tty(catalog):
    assert TuiSession(use_tui=False, **catalog)._completer is None


def test_completer_with_pipe_input_full_flow(tui_factory, catalog):
    ui = tui_factory(**catalog)
    completed = threading.Event()
    result = []
    buffer = ui.session._session.default_buffer
    buffer.on_text_changed += lambda _: completed.set() if buffer.text == "/help" else None
    def read():
        try:
            result.append(ui.session.prompt())
        except EOFError:
            pass
    thread = threading.Thread(target=read)
    thread.start()
    try:
        assert ui.session._ready.wait(2)
        ui.pipe.send_text("/he\t")
        assert completed.wait(3)
        ui.pipe.send_text("\r")
        thread.join(3)
        assert result == ["/help"]
    finally:
        ui.session.close()
        thread.join(2)


def test_completer_with_empty_document(catalog):
    assert not complete(catalog, "")


def test_completer_with_quoted_string(catalog, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "my report.md").touch()
    text = '/report export "./my r'
    assert any(c.text.endswith("eport.md") for c in complete(catalog, text))
    assert not complete(catalog, '/ask "nexus.recon.')


def test_completer_caches_commands_dict(catalog):
    completer = OmniCompleter(**catalog)
    catalog["commands"]["/new"] = help_command
    assert "/new" not in {c.text for c in completer.get_completions(Document("/"), CompleteEvent())}


def test_completer_reads_real_definition_schema(catalog):
    catalog["tools"] = {"nexus.test": (SimpleNamespace(input_schema={"properties": {"timeout_seconds": {"type": "integer"}}}), None)}
    assert [c.text for c in complete(catalog, "nexus.test ")] == ["timeout_seconds="]


def test_completion_can_be_disabled_in_tui(tui_factory):
    assert tui_factory(enable_completion=False).session._session.completer is None


def test_completion_menu_can_use_space_above_prompt(tui_factory):
    from prompt_toolkit.layout import FloatContainer

    ui = tui_factory()
    root = ui.session._session.app.layout.container
    assert isinstance(root, FloatContainer)
    assert len(root.floats) == 2
    assert len(root.content.children) == 2
