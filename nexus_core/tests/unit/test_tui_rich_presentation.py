"""Rich output contracts and integration with the sole terminal writer."""
from __future__ import annotations

from typing import Any

from prompt_toolkit.formatted_text import fragment_list_to_text
from prompt_toolkit.utils import get_cwidth

from nexus_core.cli.tui.paste import InputDocument, paste_threshold
from nexus_core.cli.tui.presentation import (
    PANEL_BAR_STYLE,
    PANEL_STYLE,
    WorkingIndicator,
    clean_text,
    diff_block,
    fold_lines,
    input_chip,
    render_rich,
    startup_banner,
    wrap_terminal_text,
)
from nexus_core.cli.tui.status import StatusState, render_status_bar
from nexus_core.cli.tui.stream import output_text, render_tool_result


def test_exact_four_line_boundary_and_three_head_one_tail() -> None:
    four = '\n'.join(str(i) for i in range(4))
    assert fold_lines(four).hidden == 0
    folded = fold_lines(four + '\n4')
    assert folded.head == ('0', '1', '2')
    assert folded.tail == ('4',) and folded.hidden == 1
    assert fold_lines(four + '\n4', expanded=True).hidden == 0


def test_trace_keeps_stdout_and_stderr_and_literal_markup() -> None:
    result = {'success': False, 'tool_id': 'nexus.example',
              'stdout': '[bold]literal[/bold]', 'stderr': 'failure detail'}
    text = render_tool_result(result, no_color=True)
    assert output_text(result) == '[stdout]\n[bold]literal[/bold]\n[stderr]\nfailure detail'
    assert '× falló' in text and 'nexus.example' not in text
    assert '[bold]literal[/bold]' in text and 'failure detail' in text
    assert '\x1b' not in text and '\r' not in text


def test_diff_additions_and_removals_are_colored_and_plain_export_is_exact() -> None:
    diff = '--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n+new'
    colored = render_rich(diff_block(diff))
    assert '\x1b[' in colored and '-old' in colored and '+new' in colored
    assert render_rich(diff_block(diff), no_color=True) == diff
    routed = render_tool_result({'success': True, 'output': {'diff': diff}}, no_color=True)
    assert '@@ -1 +1 @@' in routed and '"diff"' not in routed


def test_untrusted_output_cannot_send_terminal_commands() -> None:
    hostile = '\x1b[2J\x1b]52;c;secret\x07[red]literal[/red]\rtext'
    safe = clean_text(hostile)
    assert '\x1b' not in safe and '\x07' not in safe and '\r' not in safe
    assert '[red]literal[/red]' in safe and 'secret' not in safe


def test_startup_masthead_is_unframed_and_shows_metadata() -> None:
    banner = startup_banner('rootme', '3.0.0', no_color=True)
    assert 'Omni Agent CS v3.0.0' in banner
    assert 'BAJIOWARE • Red Team' in banner and '[+] [ rootme ] [+]' in banner
    assert all(border not in banner for border in ('╭', '╮', '╰', '╯', '│'))


def test_chips_preserve_every_input_character() -> None:
    short, long = 'x' * 500, '世' * 501
    assert input_chip(short).plain == short
    assert '501 characters' in input_chip(long).plain and long not in input_chip(long).plain
    assert not paste_threshold(short) and paste_threshold(long)
    document = InputDocument()
    document.insert_paste(0, long)
    assert document.reconstruct() == long


def test_scrollback_wraps_at_words_and_preserves_ansi_styles() -> None:
    wrapped = wrap_terminal_text("tokens per minute has a limit", width=12, no_color=True)
    assert wrapped.splitlines() == ["tokens per", "minute has a", "limit"]
    assert "token\ns" not in wrapped
    colored = wrap_terminal_text("\x1b[31mtokens per minute\x1b[0m", width=12)
    assert "\x1b[" in colored and "tokens per\nminute" in clean_text(colored)


def test_large_typed_input_history_is_compact_but_submission_is_intact(tui_factory: Any) -> None:
    ui = tui_factory(enable_completion=False).session
    text = 'a' * 10_778
    ui._input.insert_text(text)
    ui._accept(ui._input)
    assert ui._answers.get_nowait() == text
    assert '10,778 characters' in ui.transcript and text not in ui.transcript
    assert '▌ > [ 📋 Pasted Input' in clean_text(ui.transcript)


def test_thought_card_can_be_expanded_and_collapsed(tui_factory: Any) -> None:
    ui = tui_factory().session
    thought = 'first\nsecond\n' + 'detail ' * 50
    ui.append_card({}, thought=thought)
    ui.flush()
    assert 'Razonamiento' in ui._scrollback.text
    assert 'ctrl+t mostrar todo' in ui._scrollback.text
    assert '…' in ui._scrollback.text
    assert ui.toggle_card_at_line(min(ui._toggle_rows))
    assert 'ctrl+t colapsar' in ui._scrollback.text
    assert ui.toggle_card_at_line(min(ui._toggle_rows))
    assert 'ctrl+t mostrar todo' in ui._scrollback.text


def test_indicator_is_a_pure_frame_renderer_with_no_cursor_controls() -> None:
    spinner = WorkingIndicator()
    first = spinner.frame('', now=0.0, elapsed=0, width=100)
    second = spinner.frame('', now=0.4, elapsed=1, width=100)
    # The required literal stays intact and the red block advances between frames.
    assert '[+][+][+][+][+][+][+] · esc para interrumpir' in clean_text(first)
    assert first != second
    assert '\r' not in first and '\x1b[2J' not in first


def test_indicator_names_the_operation_between_the_pulse_and_the_keys() -> None:
    text = clean_text(WorkingIndicator().frame('Ejecutando nmap', now=0.0, elapsed=0, width=100))
    # The pulse and the keys hint are literal; the operation sits between them,
    # so a planning turn and a running tool no longer look identical.
    assert text == '[+][+][+][+][+][+][+] · Ejecutando nmap · esc para interrumpir'
    assert clean_text(WorkingIndicator().frame('', now=0.0, elapsed=0, width=100)) == (
        '[+][+][+][+][+][+][+] · esc para interrumpir')


def test_indicator_clips_a_long_operation_without_losing_the_keys_hint() -> None:
    text = clean_text(WorkingIndicator().frame(
        'Ejecutando ' + 'x' * 200, now=0.0, elapsed=0, width=80))
    # One screen line: the row never wraps the label over ``esc interrupt``.
    assert text.startswith('[+][+][+][+][+][+][+] · Ejecutando')
    assert text.endswith('… · esc para interrumpir')
    assert len(text) <= 80


def test_header_badge_shows_the_active_engagement_id(tui_factory: Any) -> None:
    ui = tui_factory().session
    ui.bind_engagement_source(lambda: 'eng-7f3a91')
    assert fragment_list_to_text(ui._header_badge()) == 'BW • OMNI [ eng-7f3a91 ]'
    assert not ui._show_engagement_badge()


def test_header_badge_uses_the_id_never_the_name_nor_the_folder(tui_factory: Any) -> None:
    """The bracket carries the engagement id; model and folder stay in the footer."""
    ui = tui_factory().session
    ui.set_status(engagement='scanme-lab', provider_model='deepseek-v4',
                  workspace_path='/home/operator/lab')
    footer = fragment_list_to_text(ui._workspace_footer())
    assert 'deepseek-v4' in footer and 'lab' in footer
    hints = ui._hints_window.content.text
    # A status push names the engagement but never its id, so it cannot fill
    # the badge: without an id the header says there is no engagement.
    assert fragment_list_to_text(ui._header_badge()) == 'BW • OMNI [ workspace ]'
    assert 'scanme-lab' not in fragment_list_to_text(ui._header_badge())
    # An engagement initialized/loaded after the first frame is reflected at once.
    ui.bind_engagement_source(lambda: 'eng-scanme')
    assert fragment_list_to_text(ui._header_badge()) == 'BW • OMNI [ eng-scanme ]'
    # Switching engagement is reflected on the next frame.
    ui.bind_engagement_source(lambda: 'eng-other')
    assert fragment_list_to_text(ui._header_badge()) == 'BW • OMNI [ eng-other ]'
    # The footer and the helper hints never move with the badge.
    assert fragment_list_to_text(ui._workspace_footer()) == footer
    assert hints == ui._hints_window.content.text == '← historial · ? ayuda'


def test_cli_session_badge_follows_the_active_engagement(tui_factory: Any, monkeypatch: Any) -> None:
    """End to end: the CLI binds the badge to its own engagement state."""
    from types import SimpleNamespace

    from prompt_toolkit.application import create_app_session

    from nexus_core.cli import session as module
    from nexus_core.cli.session import OmniSession

    ui = tui_factory()
    scope = SimpleNamespace(engagement_id='eng-1', name='scanme-lab')
    with create_app_session(input=ui.pipe, output=ui.output):
        monkeypatch.setattr(module, 'should_use_tui', lambda: True)
        session = OmniSession(store=None, engagement=scope)
    try:
        assert fragment_list_to_text(session._tui._header_badge()) == 'BW • OMNI [ eng-1 ]'
        session.engagement = SimpleNamespace(engagement_id='eng-2', name='renamed')
        assert fragment_list_to_text(session._tui._header_badge()) == 'BW • OMNI [ eng-2 ]'
    finally:
        session._tui.close()


def test_input_panel_has_a_red_left_bar_and_no_horizontal_rule(tui_factory: Any) -> None:
    from prompt_toolkit.layout import HSplit, VSplit, Window

    ui = tui_factory().session
    # Styles first: narrowing ``ui`` attribute expressions through identity
    # comparisons below would blind mypy to their real (Any) type.
    assert ui._bar_window.style == PANEL_BAR_STYLE == 'fg:#ff0055 bg:#2a2a2a'
    assert ui._footer_window.style == PANEL_STYLE == 'bg:#2a2a2a'
    panel = ui._input_window
    assert isinstance(panel, VSplit)
    outer_gap, bar, gap, body = panel.get_children()
    assert outer_gap.width == 2 and outer_gap.char == " "
    assert isinstance(bar, Window) and isinstance(body, HSplit)
    # The only border is the solid red vertical bar on the left edge.
    assert bar.char == '│' and bar.width == 1
    assert not any(getattr(child, 'char', None) == '─' for child in panel.get_children())
    # Inside the panel: the prompt input first, then the footer line.
    assert gap.width == 1 and gap.char == ' '
    children = body.get_children()
    assert children[0].height == 1 and children[2].height == 1 and children[4].height == 1
    assert children[1] is ui._editor_window and children[3] is ui._footer_window
    assert panel.get_children() == [outer_gap, bar, gap, body]


def test_helper_hints_render_outside_the_panel(tui_factory: Any) -> None:
    ui = tui_factory().session
    hints = ui._hints_window
    assert hints.content.text == '← historial · ? ayuda'
    assert hints.style == '#ffffff'
    # The hint line is a sibling of the panel, painted right underneath it.
    rows = ui._rows
    assert rows.index(hints) == rows.index(ui._input_window) + 2


def test_panel_footer_names_model_and_directory_without_the_build_word(tui_factory: Any,
                                                                      tmp_path: Any) -> None:
    ui = tui_factory().session
    # Before an engagement/workspace is bound the footer shows the model alone.
    assert fragment_list_to_text(ui._workspace_footer()) == 'unconfigured'
    ui.set_status(workspace_path=str(tmp_path), provider_model='DeepSeekV4.1-flash')
    footer = fragment_list_to_text(ui._workspace_footer())
    assert footer == f'DeepSeekV4.1-flash · {tmp_path}'
    assert ui._workspace_footer()[0][0] == '#00d7ff'
    assert 'Build' not in footer


def test_workspace_line_shortens_home_and_never_says_build(monkeypatch: Any, tmp_path: Any) -> None:
    from nexus_core.cli.tui.status import workspace_line

    nested = tmp_path / 'Desktop' / 'salas' / 'tryhackme' / 'rootme'
    nested.mkdir(parents=True)
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    state = StatusState(workspace_path=str(nested), provider_model='DeepSeekV4.1-flash')
    assert workspace_line(state) == 'DeepSeekV4.1-flash · ~/Desktop/salas/tryhackme/rootme'
    assert 'Build' not in workspace_line(state)
    assert workspace_line(StatusState()) == 'unconfigured'


def test_workspace_bar_keeps_alerts_only(tmp_path: Any) -> None:
    """The model and the directory live in the panel: the bar is alerts-only."""
    state = StatusState(workspace_path=str(tmp_path), provider_model='DeepSeekV4.1-flash')
    assert fragment_list_to_text(render_status_bar(state, width=400)) == ''
    state.trust_mode = True
    state.plan_phase = 'Recon'
    state.plan_progress = '1/5'
    assert fragment_list_to_text(render_status_bar(state, width=400)) == 'TRUST'
    assert 'Build' not in fragment_list_to_text(render_status_bar(state, width=400))


def test_tactical_phases_replace_raw_tool_ids_in_traces() -> None:
    from nexus_core.cli.tui.presentation import tactical_phase

    assert tactical_phase('nexus.recon.nmap') == 'Enumeration'
    assert tactical_phase('nexus.exploit.msf_exploit') == 'Exploitation'
    assert tactical_phase('nexus.post.enum_system') == 'Post-exploitation'
    assert tactical_phase('nexus.cred.hydra') == 'Credential assessment'
    assert tactical_phase('nexus.report.generate') == 'Reporting'
    assert tactical_phase('nexus.web.upload') == 'Weaponization'
    assert tactical_phase('nexus.unknown.thing') == 'Working'


def test_fixed_hud_has_truthful_budget_and_running_state(tui_factory: Any) -> None:
    state = StatusState(scope_targets=3, provider_model='provider/model', tokens_input=12_345, busy=True)
    text = fragment_list_to_text(render_status_bar(state, width=200))
    for segment in ('BAJIOWARE · OMNI-AGENTCS', 'Alcance: 3 objetivos', 'Modelo: provider/model',
                    'Tokens: 12,345', 'Presupuesto: $—', 'Estado: EN CURSO'):
        assert segment in text
    state.budget_usd = 5
    assert 'Presupuesto: $5.00' in fragment_list_to_text(render_status_bar(state, width=200))
    for width in range(80):
        assert get_cwidth(fragment_list_to_text(render_status_bar(state, width=width))) <= width
    ui = tui_factory().session
    ui.set_busy('Working')
    assert 'EN CURSO' in fragment_list_to_text(ui._toolbar())
    ui.clear_busy()
    assert 'INACTIVO' in fragment_list_to_text(ui._toolbar())


def test_before_after_payload_is_rendered_as_a_real_diff() -> None:
    text = render_tool_result({'success': True, 'output': {
        'path': 'settings.txt', 'before': 'timeout=5', 'after': 'timeout=10'}}, no_color=True)
    assert '--- a/settings.txt' in text and '+++ b/settings.txt' in text
    assert '-timeout=5' in text and '+timeout=10' in text


def test_history_chip_never_modifies_persisted_message(capsys: Any) -> None:
    from types import SimpleNamespace

    from nexus_core.cli.commands import cmd_history
    from nexus_core.cli.session import OmniSession
    content = 'history ' * 1000
    messages = [{'role': 'user', 'content': content}]
    session = OmniSession(store=SimpleNamespace(list_messages=lambda *a, **kw: messages), use_tui=False)
    session.conversation_id = 'conversation'
    cmd_history(session, [])
    text = capsys.readouterr().out
    assert 'Pasted Input' in text and content not in text
    assert messages[0]['content'] == content


def test_ci_disables_automatic_fullscreen(monkeypatch: Any) -> None:
    from nexus_core.cli.tui.session import should_use_tui
    monkeypatch.setenv('CI', 'true')
    assert not should_use_tui()


def test_diff_never_hides_stderr_diagnostics() -> None:
    text = render_tool_result({'success': False, 'stderr': 'permission denied',
                               'output': {'diff': '-old\n+new'}}, no_color=True)
    assert 'permission denied' in text and '-old' in text and '+new' in text


def test_wrapped_footer_remains_clickable(tui_factory: Any, monkeypatch: Any) -> None:
    from prompt_toolkit.data_structures import Size
    ui = tui_factory().session
    monkeypatch.setattr(ui._session.output, 'get_size', lambda: Size(rows=24, columns=10))
    ui.append_card({'success': True, 'stdout': '\n'.join(str(i) for i in range(10))})
    ui.flush()
    assert ui.toggle_card_at_line(min(ui._toggle_rows))
    assert '└ 4' in ui._scrollback.text
