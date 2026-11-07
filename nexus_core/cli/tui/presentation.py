"""Pure Rich renderables. Rendering never owns stdout, a cursor or a thread."""
from __future__ import annotations

import difflib
import io
import json
import re
import textwrap
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from rich import box
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

from ..theme import THEME

_CONTROLS = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]')

#: Input panel (OpenCode-Zen style): dark grey textarea background with a solid
#: red vertical bar as its only border. There is no top/bottom horizontal rule.
PANEL_STYLE = THEME.panel_style
PANEL_BAR_STYLE = THEME.panel_bar_style

#: Compatibility aliases over the single palette. A renderer names a role,
#: never a hex value; the values live in :mod:`nexus_core.cli.theme`.
ACCENT_STYLE = THEME.primary
SECONDARY_STYLE = THEME.secondary_style
OK_STYLE = THEME.ok
ERROR_STYLE = THEME.error
WARN_STYLE = THEME.warn

#: Hierarchy of the log (Codex style): reasoning is muted italic, the tool is
#: bold text, a verified result is green and a failure is red. The branch glyph
#: indents tool output under its invocation so a card reads as a tree.
THINKING_STYLE = THEME.thinking_style
TOOL_STYLE = ''
RESULT_OK_STYLE = OK_STYLE
RESULT_ERROR_STYLE = ERROR_STYLE
GUARDRAIL_STYLE = WARN_STYLE
TURN_STYLE = SECONDARY_STYLE
BRANCH = '└'

#: Typewriter pacing of the transcript: one reveal every 12 ms, at most 96 per
#: block, so a block never lags more than about a second behind the agent. A
#: backlog of more than two blocks is committed whole (the log must not fall
#: behind the run) and very large outputs are never paced at all.
TYPEWRITER_INTERVAL = 0.012
TYPEWRITER_MAX_STEPS = 96
TYPEWRITER_MAX_CHARS = 12_000
TYPEWRITER_MAX_BACKLOG = 2
_WORD = re.compile(r'\s*\S+\s*')


def startup_banner(engagement: str, version: str, *, width: int = 80,
                   no_color: bool = False) -> str:
    """One branded row for the first frame: the masthead costs a line, not a screen.

    The block-letter art was removed from the TUI: on an 80x24 terminal it spent
    ten rows before the first prompt and pushed the transcript off the screen.
    The full ASCII banner is still available on demand (``omni --about``); the
    startup row names the mark, the version, the team and the engagement.
    """
    name = clean_text(str(engagement or 'workspace'))[:24]
    line = Text()
    line.append('██', style=THEME.primary_bold)
    line.append(f' Omni Agent CS v{clean_text(version)}', style=THEME.title_style)
    line.append(' · BAJIOWARE • Red Team · ', style=THEME.muted)
    line.append(f'[+] [ {name} ] [+]', style=THEME.offwhite)
    # One row plus the blank line that keeps the masthead its own block: the
    # first echoed turn is never glued to the brand.
    return render_rich(line, width=max(40, width), no_color=no_color) + '\n\n'


def clean_text(value: str) -> str:
    """Keep literal content, remove terminal commands before styling it."""
    value = _CONTROLS.sub('', value.replace('\r\n', '\n'))
    return ''.join(char for char in value if char in '\n\t' or char.isprintable())


def render_rich(value: RenderableType, *, width: int = 100, no_color: bool = False) -> str:
    stream = io.StringIO()
    console = Console(file=stream, width=max(1, width), force_terminal=not no_color,
                      color_system=None if no_color else 'truecolor', no_color=no_color,
                      markup=False, highlight=False, legacy_windows=False, soft_wrap=False)
    console.print(value, end='', overflow='fold', no_wrap=False)
    return stream.getvalue().rstrip('\n')


def wrap_terminal_text(value: str, *, width: int, no_color: bool = False) -> str:
    """Wrap ANSI/plain scrollback on whitespace before prompt_toolkit sees it."""
    stream = io.StringIO()
    console = Console(file=stream, width=max(1, width), force_terminal=not no_color,
                      color_system=None if no_color else 'truecolor', no_color=no_color,
                      markup=False, highlight=False, legacy_windows=False)
    text = Text.from_ansi(value)
    lines = text.wrap(console, max(1, width), overflow='fold', no_wrap=False)
    for index, line in enumerate(lines):
        line.rstrip()
        console.print(line, end='', overflow='fold', no_wrap=False)
        if index + 1 < len(lines):
            stream.write('\n')
    return stream.getvalue()


@dataclass(frozen=True)
class FoldedLines:
    head: tuple[str, ...]
    tail: tuple[str, ...]
    hidden: int


def fold_lines(value: str, *, expanded: bool = False, limit: int = 4) -> FoldedLines:
    """Head and tail of a card body, with the hidden count.

    The split is explicit (3 head + 1 tail for the product's limit of four),
    never the old ``(limit+1)//2`` rounding: a card has to read the same on
    every width.
    """
    if limit < 1:
        raise ValueError('line limit must be positive')
    lines = clean_text(value).splitlines()
    if expanded or len(lines) <= limit:
        return FoldedLines(tuple(lines), (), 0)
    head_count = min(3, limit)
    tail_count = limit - head_count
    return FoldedLines(tuple(lines[:head_count]), tuple(lines[-tail_count:]) if tail_count else (),
                       len(lines) - limit)


def input_chip(value: str, *, threshold: int = 500) -> Text:
    if len(value) > threshold:
        return Text(f'[ 📋 Pasted Input · {len(value):,} characters ]', style=SECONDARY_STYLE)
    return Text(clean_text(value))


def input_quote(value: str, *, width: int = 100, no_color: bool = False) -> str:
    """Render an operator turn as a clean quote block with a red left rail."""
    lines = clean_text(value).splitlines() or [""]
    rows: list[RenderableType] = []
    for line in lines:
        rows.append(Text("▌ ", style=THEME.primary_bold) + Text(line))
    return render_rich(Group(*rows), width=width, no_color=no_color)


def user_message(value: str, *, width: int = 100, no_color: bool = False,
                 now: datetime | None = None) -> str:
    """One operator turn: red rail, 12-hour stamp, then the task itself.

    The REPL used to echo the line twice (the editor's ``>`` and the run's
    ``❯``). The transcript carries exactly one block per turn: the rail, the
    time the operator submitted it and the task wrapped to the transcript
    width, so a long objective cannot overflow the terminal.
    """
    when = (now or datetime.now()).strftime("%I:%M %p")
    rows: list[RenderableType] = [
        Text("▌ ", style=ACCENT_STYLE) + Text(f"[{when}]", style=SECONDARY_STYLE)
    ]
    body = clean_text(str(value or "")).strip() or ""
    for raw in body.splitlines() or [""]:
        for row in textwrap.wrap(raw, width=max(8, int(width) - 2),
                                 break_long_words=False, break_on_hyphens=False) or [""]:
            rows.append(Text("▌ ", style=ACCENT_STYLE) + Text(row))
    return render_rich(Group(*rows), width=width, no_color=no_color)


_SERVICE_KEY = re.compile(
    r'^(?P<host>.+?):(?P<port>\d+)(?:(?::|/)(?P<proto>[A-Za-z0-9]+))?$'
)


def _service_table(facts: Any) -> list[str]:
    """Markdown table of the verified ``service`` facts, newest data first.

    Facts are the blackboard's own records; the renderer invents no port or
    service. Both key spellings nmap has used (``host:port/proto`` and
    ``host:port:proto``) are accepted, and a repeated service is shown once.
    """
    rows: dict[tuple[str, int, str], tuple[str, str, str, str]] = {}
    for fact in facts or ():
        if not isinstance(fact, dict) or str(fact.get("fact_type") or "") != "service":
            continue
        match = _SERVICE_KEY.match(str(fact.get("key") or "").strip())
        if match is None:
            continue
        value = fact.get("value") if isinstance(fact.get("value"), dict) else {}
        host = match.group("host")
        port = int(match.group("port"))
        proto = str(match.group("proto") or value.get("protocol") or "tcp").lower()
        service = str(value.get("service") or value.get("product") or "?").strip()
        state = str(value.get("state") or "open").strip()
        rows[(host, port, proto)] = (host, str(port), service, state)
    if not rows:
        return []
    lines = [
        "", "### Servicios", "",
        "| Puerto | Servicio | Estado |",
        "| --- | --- | --- |",
    ]
    for _, port, service, state in sorted(rows.values(), key=lambda row: (row[0], int(row[1]))):
        lines.append(f"| {port} | {service.replace('|', '/')} | {state.replace('|', '/')} |")
    return lines


def summary_markdown(result: Any, *, service_facts: Any = None,
                     report_path: str | None = None) -> str:
    """Final result as clean Markdown, for the TUI transcript.

    A bordered box fragments on a wide terminal: the border and the wrapped
    body stop agreeing at 200 columns. The dedicated screen renders the same
    facts as a Markdown block instead, while ``--no-tui`` keeps the box.
    Only data the result already carries is listed: the final summary, the
    services discovered, the findings, the phases still open and the run's
    status/iteration count. ``report_path`` is rendered only when a report was
    really written, and no report is generated here.
    """
    status = str(getattr(result, "status", "") or "")
    iterations = getattr(result, "iterations", None)
    findings = list(getattr(result, "findings", None) or [])
    plan = getattr(result, "plan", None) or {}
    phases = plan.get("phases") if isinstance(plan, dict) else None
    pending = [
        item for item in (phases or [])
        if isinstance(item, dict) and str(item.get("status") or "") != "done"
        and not item.get("optional")
    ]
    lines: list[str] = ["## Resultado", ""]
    summary = str(getattr(result, "final_summary", "") or "").strip()
    lines.extend((summary or "_(sin resumen)_").splitlines())
    lines.extend(_service_table(service_facts))
    if findings:
        lines.extend(["", "### Hallazgos", ""])
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "info")
            title = str(finding.get("title") or finding.get("summary") or "").strip()
            if title:
                lines.append(f"- **[{severity}]** {title}")
    if pending:
        lines.extend(["", "### Ramas abiertas", ""])
        lines.extend(f"- {item.get('label') or item.get('id')}" for item in pending)
    if report_path:
        lines.extend(["", f"*Informe completo en {report_path}*"])
    lines.extend(["", "### Estado", ""])
    lines.append(f"- estado: {status or '?'}")
    if iterations is not None:
        lines.append(f"- iteraciones: {iterations}")
    return "\n".join(lines)


def result_panel(body: str, *, width: int = 100,
                 no_color: bool = False) -> str:
    """Frame the final Markdown in a quiet, full-width surface.

    The body arrives already rendered by :func:`nexus_core.cli.tui.markdown`.
    ``Text.from_ansi`` turns those styles back into a Rich renderable so the
    panel background covers the whole block without re-parsing the Markdown.
    A square, muted border separates the result from the execution stream; the
    caller wraps the body first so the border and the content never disagree
    at wide terminal widths.
    """
    content = Text.from_ansi(str(body or ''))
    panel = Panel(
        content, box=box.SQUARE, border_style=THEME.result_border_style,
        style=THEME.result_panel_style, padding=(1, 2), expand=True,
        width=max(20, int(width)),
    )
    return render_rich(panel, width=max(20, int(width)), no_color=no_color)


def typewriter_steps(text: str, *, max_steps: int = TYPEWRITER_MAX_STEPS,
                     max_chars: int = TYPEWRITER_MAX_CHARS) -> list[str]:
    """Split ``text`` into the word groups a revealer prints one step at a time.

    ``''.join(typewriter_steps(value)) == value`` always holds: a reveal never
    loses, duplicates or reorders a character, so the transcript can be rebuilt
    from the same string. Pacing is skipped (a single step) for outputs larger
    than ``max_chars``; whitespace-only values are one step too.
    """
    value = str(text or '')
    if not value:
        return []
    if len(value) > max_chars or max_steps < 1:
        return [value]
    tokens = _WORD.findall(value)
    if not tokens:
        return [value]
    step = max(1, -(-len(tokens) // max_steps))
    return [''.join(tokens[index:index + step]) for index in range(0, len(tokens), step)]


#: Characters that end the opening sentence of a ``thought``. The persisted
#: action carries no separate "what this call is for" field, so the collapsed
#: row can only quote the first sentence of the model's own note.
_SENTENCE_END = re.compile(r'(?<=[.!?])\s+|\n+')


def thought_purpose(value: str, *, limit: int = 100) -> str:
    """One short line naming the purpose of the action, from the model's note.

    Limitation, deliberate: the durable ``react.action`` metadata carries the
    free-form ``thought`` and no structured ``expected_outcome``, so the
    transcript cannot tell a one-line action note from a paragraph of internal
    reasoning. What it can do safely is show only the opening sentence of that
    note, on one line and capped, and keep the rest behind the existing card
    toggle. Tool, phase and state come from the invocation block itself, never
    from this text.
    """
    text = ' '.join(clean_text(str(value or '')).split())
    if not text:
        return ''
    first = _SENTENCE_END.split(text, maxsplit=1)[0].strip() or text
    return first[:limit] + ('…' if len(first) > limit else '')


def _thought_lines(value: str, width: int) -> list[str]:
    """Physical lines of a note, wrapped to the card's usable width."""
    body = clean_text(str(value or '')).strip()
    if not body:
        return []
    limit = max(20, int(width) - 2)
    lines: list[str] = []
    for raw in body.splitlines():
        if not raw.strip():
            lines.append('')
            continue
        lines.extend(textwrap.wrap(raw, width=limit, break_long_words=False,
                                   break_on_hyphens=False) or [''])
    return lines


#: Rows of the live reasoning row before it starts dropping the oldest lines.
LIVE_THOUGHT_LINES = 5


def thinking(value: str, *, expanded: bool = False, width: int = 100,
             reasoning: str | None = None) -> Text:
    """Durable reasoning card: one collapsed line, or the whole note.

    Collapsed it is exactly ``▸ Razonamiento`` -no preview, no footer- so a
    finished turn costs one row; the arrow is the affordance and the header is
    the clickable line. Expanded it is ``▾ Razonamiento`` plus the note in dim
    italic. The provider's native reasoning travels as a separate dim block
    only when the model's own note is too short to be useful (<50 characters).
    """
    from .strings import HIDE_REASONING, THINKING_CARD

    text = Text(no_wrap=False, overflow='fold')
    text.append(f'  {"▾" if expanded else "▸"} {THINKING_CARD}', style=SECONDARY_STYLE)
    if not expanded:
        return text
    for line in _thought_lines(value, width):
        text.append('\n  ' + line, style=THINKING_STYLE)
    if reasoning and len(clean_text(str(value or '')).strip()) < 50:
        text.append('\n  ---', style=SECONDARY_STYLE)
        for line in _thought_lines(reasoning, width)[:10]:
            text.append('\n  ' + line, style=THINKING_STYLE)
    text.append('\n  ' + HIDE_REASONING, style=SECONDARY_STYLE)
    return text


def live_thought(value: str, *, width: int = 100) -> Text:
    """At most ``LIVE_THOUGHT_LINES`` wrapped rows under ``Razonando``.

    The provider streams a paragraph, not pre-wrapped lines. Wrapping happens
    here, before Rich: the label rides the first row and every row fits the
    width the live row actually owns. A longer note is cut after five rows and
    the last one ends in ``…``; it never becomes one horizontal line.
    """
    from .strings import THINKING_LIVE

    body = clean_text(str(value or '')).strip()
    if not body:
        return Text(THINKING_LIVE, style=THINKING_STYLE)
    limit = max(20, int(width))
    label = f'{THINKING_LIVE} '
    lines: list[str] = []
    first = True
    for raw in body.splitlines():
        if not raw.strip():
            lines.append('')
            continue
        wrapped = textwrap.wrap(
            raw,
            width=limit,
            initial_indent=label if first else '  ',
            subsequent_indent='  ',
            break_long_words=False,
            break_on_hyphens=False,
        ) or [label.rstrip() if first else '  ']
        lines.extend(wrapped)
        first = False
    if len(lines) > LIVE_THOUGHT_LINES:
        lines = lines[:LIVE_THOUGHT_LINES]
        last = lines[-1].rstrip()
        if len(last) >= limit:
            last = last[: max(0, limit - 1)]
        lines[-1] = last + '…'
    return Text('\n'.join(lines), style=THINKING_STYLE)


def turn_header(step: int, phase: str, *, width: int = 80) -> Text:
    """``── paso N · phase ───`` filling the transcript width."""
    label = f'── paso {int(step)} · {str(phase or "Trabajo")} '
    room = max(0, int(width) - len(label))
    return Text(label + '─' * room, style=TURN_STYLE, no_wrap=True, overflow='crop')


def diff_block(value: str) -> Syntax:
    return Syntax(clean_text(value), 'diff', theme=THEME.syntax_theme,
                  background_color=THEME.syntax_background,
                  word_wrap=True, line_numbers=False)


def result_diff(result: dict[str, Any]) -> str | None:
    output = result.get('output')
    for container in (result, output if isinstance(output, dict) else {}):
        value = container.get('diff') or container.get('patch')
        if isinstance(value, str) and value.strip():
            return value
    if isinstance(output, dict) and isinstance(output.get('before'), str) and isinstance(output.get('after'), str):
        path = clean_text(str(output.get('path') or 'file')).replace('\n', ' ')
        return '\n'.join(difflib.unified_diff(output['before'].splitlines(), output['after'].splitlines(),
                                               fromfile='a/' + path, tofile='b/' + path, lineterm=''))
    return None


def _compact_value(value: Any) -> str:
    """One JSON value as a single readable line for the collapsed preview."""
    if isinstance(value, (dict, list)):
        raw = json.dumps(value, ensure_ascii=False, default=str)
    else:
        raw = str(value)
    return ' '.join(clean_text(raw).split())


def _summary_lines(summary: str, *, success: bool, width: int) -> list[str]:
    mark = '✓' if success else '×'
    body = ' '.join(clean_text(str(summary or '')).split())
    if not body:
        from .strings import FAILED
        body = 'completado' if success else FAILED
    return textwrap.wrap(
        body, width=max(20, int(width)), initial_indent=f'  {mark} ',
        subsequent_indent='    ', break_long_words=False, break_on_hyphens=False,
    ) or [f'  {mark}']


def trace_block(value: str, *, success: bool, tool_id: str, summary: str,
                expanded: bool = False, limit: int = 4, diff: bool = False,
                defer_detail: bool = False, structured: Any = None,
                guardrail: bool = False, guidance: str = '', width: int = 100) -> Group:
    """Tool card: verdict first, then the folded body.

    A guardrail is an orchestrator correction, not a tool failure: it reads in
    amber, carries the whole ``guidance`` and has no summary line and no
    clickable footer. A real failure keeps a single red ``×`` in its summary.
    """
    from .strings import GUARDRAIL

    body: list[RenderableType] = []
    if guardrail:
        header = f'  ⚠ {clean_text(tool_id) or "tool"} · {GUARDRAIL}'
        body.append(Text(header, style=f'bold {GUARDRAIL_STYLE}'))
        detail = guidance or summary
        wrapped = textwrap.wrap(
            ' '.join(clean_text(str(detail or '')).split()), width=max(20, int(width) - 2),
            initial_indent='  ', subsequent_indent='  ',
            break_long_words=False, break_on_hyphens=False,
        ) or ['  ']
        body.extend(Text(line) for line in wrapped)
        return Group(*body)

    color = RESULT_OK_STYLE if success else RESULT_ERROR_STYLE
    # A failure names the tool that failed: the verdict line alone used to read
    # ``× timeout 120s``, so the operator could not tell which call it was. It
    # appears once, before the reason, and never adds a second failure mark.
    label = clean_text(str(tool_id or ''))
    summary_text = summary
    if not success and label and label not in str(summary):
        summary_text = f'{label} · {summary}'
    body.extend(Text(line, style=f'bold {color}')
                for line in _summary_lines(summary_text, success=success, width=width))

    if structured is not None and not expanded:
        # A structured payload used to be dumped as a ``└─ field: value`` tree
        # (report.generate printed about forty rows). The summary line above
        # already says what it is; one click reveals the whole document.
        if isinstance(structured, (dict, list, tuple)) and structured:
            import json as _json

            hidden = len(_json.dumps(structured, ensure_ascii=False, indent=2,
                                     default=str).splitlines())
            body.append(Text(f'  Ver {hidden} líneas más', style=THEME.link_style))
        else:
            body.append(Text('  (sin campos)', style=SECONDARY_STYLE))
        return Group(*body)

    # A diff spends three lines on ``---``/``+++``/``@@``; folding it at the
    # normal limit hid the removals behind the headers. Keep the headers plus
    # the same number of data lines.
    folded = fold_lines(value, expanded=expanded, limit=limit + 3 if diff else limit)
    lines = clean_text(value)

    def emit(rows: tuple[str, ...]) -> None:
        if not rows:
            return
        if diff:
            body.append(diff_block('\n'.join(rows)))
            return
        # Output is content, not a verdict: it reads in the terminal's own
        # colour, under a dim branch glyph. Only the summary carries a colour.
        for row in rows:
            wrapped = textwrap.wrap(
                row, width=max(20, int(width)), initial_indent=f'  {BRANCH} ',
                subsequent_indent='    ', break_long_words=False,
                break_on_hyphens=False,
            ) or [f'  {BRANCH}']
            body.extend(Text(line) for line in wrapped)

    emit(folded.head)
    if folded.hidden:
        body.append(Text('  …', style=SECONDARY_STYLE))
    emit(folded.tail)
    if folded.hidden:
        body.append(Text(f'  Ver {folded.hidden} líneas más', style=THEME.link_style))
    elif expanded and len(lines.splitlines()) > limit:
        body.append(Text('  ctrl+o colapsar', style=SECONDARY_STYLE))
    return Group(*body)


class WorkingIndicator:
    """Pure spinner frames sampled by the existing terminal refresh loop.

    The braille frame lives in :mod:`nexus_core.cli.tui.frame`, so the marker
    and the header timer stay in sync. ``message`` names the operation the run
    is in, the only thing that tells "waiting for the model" from "running a
    tool"; ``elapsed`` stays in the signature because the loop samples this
    every frame, but the header already owns the timer. The hint is painted as
    a small ``esc`` keycap rather than as one more sentence of chrome.
    """

    def frame(self, message: str, *, now: float, elapsed: int, width: int,
              no_color: bool = False) -> str:
        from .frame import (
            BUSY_ACTION,
            BUSY_KEYCAP,
            BUSY_SEPARATOR,
            BUSY_TAIL,
            busy_cells,
            busy_label,
        )
        from .strings import WORKING

        del elapsed
        text = Text()
        cells = 0
        for style, cell in busy_cells(now):
            text.append(cell, style=style)
            cells += len(cell)
        label = busy_label(message, room=width - cells - len(BUSY_TAIL) - 3)
        if not label or label.casefold() in {'working', WORKING}:
            label = WORKING
        text.append(f' {label}', style=THEME.muted)
        text.append(BUSY_SEPARATOR, style=THEME.dim_style)
        text.append(f' {BUSY_KEYCAP} ', style=THEME.keycap_style)
        text.append(BUSY_ACTION, style=THEME.dim_style)
        return render_rich(text, width=width, no_color=no_color).split('\n')[0]


def tactical_phase(tool_id: str) -> str:
    """Presentation labels only: never change dispatch or policy identifiers."""
    if tool_id in {'nexus.web.upload', 'nexus.web.git_dump'}:
        return 'Weaponization' if tool_id.endswith('upload') else 'Enumeration'
    family = tool_id.split('.')[1] if '.' in tool_id else ''
    return {'recon': 'Enumeration', 'web': 'Enumeration', 'exploit': 'Exploitation',
            'post': 'Post-exploitation', 'cred': 'Credential assessment',
            'report': 'Reporting'}.get(family, 'Working')


#: What the conversational line says the agent is doing, per tool. The default
#: is the tool's own short name, so an unmapped tool still reads honestly.
_TOOL_ACTIONS: dict[str, str] = {
    'nexus.recon.nmap': 'Ejecutando nmap',
    'nexus.recon.dns': 'Resolviendo DNS',
    'nexus.recon.httpx': 'Sondeando HTTP',
    'nexus.shell.exec': 'Ejecutando comando',
    'nexus.system.execute_and_parse': 'Ejecutando y parseando',
    'nexus.system.discover_tools': 'Descubriendo tools',
    'nexus.workspace.read': 'Leyendo',
    'nexus.workspace.search': 'Buscando',
    'nexus.skill.load': 'Cargando skill',
    'nexus.orchestrator.create_plan': 'Creando plan',
    'nexus.orchestrator.update_plan': 'Actualizando plan',
    'nexus.cred.bruteforce': 'Probando credenciales',
    'nexus.post.ssh_exec': 'Ejecutando por SSH',
    'nexus.web.request': 'Haciendo petición web',
}

#: Arguments that name *where* the action happens, most specific first.
_TARGET_KEYS = ('target', 'url', 'target_url', 'host', 'domain', 'path', 'file')


#: Short human names where the last id segment would mislead (``shell.exec`` →
#: ``exec`` reads as an unknown verb; ``shell`` is the channel).
_TOOL_SHORT_NAMES = {
    'nexus.shell.exec': 'shell',
    'nexus.system.execute_and_parse': 'parse',
    'nexus.system.discover_tools': 'discover',
    'nexus.workspace.read': 'read',
    'nexus.orchestrator.create_plan': 'plan',
}


def _short_tool_name(tool_id: str) -> str:
    """``nexus.recon.nmap`` → ``nmap`` (what a human would call it)."""
    tool = str(tool_id or 'tool')
    known = _TOOL_SHORT_NAMES.get(tool)
    if known:
        return known
    return tool.rsplit('.', 1)[-1].replace('_', ' ')


def _fit_line(text: str, width: int | None) -> str:
    """One clean line, cropped at *width* cells with an honest ellipsis."""
    value = ' '.join(str(text).split())
    if not width:
        return value
    from rich.cells import cell_len, chop_cells

    limit = max(1, int(width))
    if cell_len(value) <= limit:
        return value
    chunks = chop_cells(value, max(1, limit - 1))
    return (chunks[0] if chunks else '') + '…'


def _action_target(safe: dict[str, Any]) -> str:
    """Where the action goes: a target/host/url, or the command itself."""
    for key in _TARGET_KEYS:
        value = safe.get(key)
        if isinstance(value, str) and value.strip():
            return ' '.join(clean_text(value).split())[:120]
    command = safe.get('command')
    if isinstance(command, str) and command.strip():
        return ' '.join(clean_text(command).split())[:120]
    return ''


def tool_call_line(tool_id: str, arguments: Any, *, width: int | None = None) -> str:
    """One plain line: ``> Ejecutando nmap en 10.0.0.1...``

    This is the default voice of a tool call: conversational, one row, no
    dashboard chrome. ``detailed_tool_invocation`` in ``stream.py`` keeps the
    full argv/key=value request for the operator who expands a passed card.
    Secrets are masked by the same ``display_arguments`` policy as everywhere.
    """
    from ..render import display_arguments

    safe = display_arguments(arguments if isinstance(arguments, dict) else {})
    tool = str(tool_id or '')
    action = _TOOL_ACTIONS.get(tool)
    if action is None:
        action = f'Ejecutando {_short_tool_name(tool)}'
    target = _action_target(safe)
    return _fit_line(f'> {action}' + (f' en {target}' if target else '') + '...', width)


#: Rows of the expanded port table before it summarises the remainder.
PORT_TABLE_LIMIT = 12


def scan_ports(result: dict[str, Any]) -> list[tuple[str, str, str]]:
    """``(puerto, servicio, versión)`` of every open port a parsed scan reports.

    The scan is the parser's own structure (``output.scan.hosts[].ports[]``),
    so the table never invents a port, a service or a version. ``-sV`` data is
    what an operator cannot read from the folded body: the product and version
    strings live next to the port, not in the summary.
    """
    output = result.get('output') if isinstance(result.get('output'), dict) else {}
    scan = output.get('scan') if isinstance(output, dict) else None
    rows: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    if isinstance(scan, dict):
        for host in scan.get('hosts') or []:
            if not isinstance(host, dict):
                continue
            for port in host.get('ports') or []:
                if not isinstance(port, dict):
                    continue
                if str(port.get('state') or 'open').lower() != 'open':
                    continue
                number = port.get('port', port.get('portid'))
                if number in (None, ''):
                    continue
                protocol = str(port.get('protocol') or 'tcp').lower()
                label = str(number) if protocol == 'tcp' else f'{number}/{protocol}'
                service = ' '.join(clean_text(str(port.get('service') or '')).split()) or '?'
                version = ' '.join(
                    part for part in (
                        ' '.join(clean_text(str(port.get(key) or '')).split())
                        for key in ('product', 'version', 'extra_info')
                    ) if part
                )
                row = (label, service, version)
                if row not in seen:
                    seen.add(row)
                    rows.append(row)
    return rows


def render_port_table(result: dict[str, Any], *, width: int = 100,
                      no_color: bool = False, limit: int = PORT_TABLE_LIMIT) -> str:
    """Expanded scan as a real table, bounded to ``limit`` rows and the width.

    A one-line result cannot carry fifteen ports: the collapsed card keeps the
    count and the table appears when the operator expands it. Every cell is
    cropped by cells, so a long ``nginx/1.24.0`` never pushes the table past the
    transcript. ``Estado`` is deliberately absent: every row here is ``open``,
    and the version column is the information the folded body hides.
    """
    rows = scan_ports(result)
    if len(rows) < 2:
        return ''
    from rich.table import Table

    table = Table(box=None, show_header=True, header_style=f'bold {THEME.primary}',
                  padding=(0, 1), pad_edge=False)
    table.add_column('Puerto', style=THEME.offwhite, no_wrap=True)
    table.add_column('Servicio', style=THEME.muted, no_wrap=True)
    table.add_column('Versión', style=THEME.dim_style, no_wrap=True)
    version_budget = max(12, int(width) - 36)
    for port, service, version in rows[:max(1, int(limit))]:
        table.add_row(port, _fit_line(service, 22), _fit_line(version or '—', version_budget))
    rendered = render_rich(table, width=width, no_color=no_color)
    hidden = len(rows) - max(1, int(limit))
    if hidden > 0:
        rendered += f'\n  … y {hidden} puerto(s) más'
    return rendered


def _open_ports(result: dict[str, Any]) -> list[str]:
    """Open ports a parsed scan reports (``[]`` for anything else)."""
    ports = [port for port, _, _ in scan_ports(result)]
    if not ports:
        evidence = result.get('evidence') if isinstance(result.get('evidence'), dict) else {}
        ports = [str(port) for port in evidence.get('open_ports') or [] if str(port)]
    return ports


def tool_result_line(result: dict[str, Any], *, summary: str = '',
                     width: int | None = None) -> str:
    """One plain verdict: ``✓ nmap: 3 puertos abiertos (21, 22, 80)``.

    ``summary`` is the existing evidence-based sentence; this only adds the
    open-port list when a scan produced one, so the operator reads the result
    without expanding a card. Failures keep their own words.
    """
    success = bool(result.get('success'))
    name = _short_tool_name(str(result.get('tool_id') or 'tool'))
    body = ' '.join(clean_text(str(summary or '')).split())
    if not body:
        body = 'completado' if success else 'falló'
    ports = _open_ports(result) if success else []
    plain_body = body
    if ports:
        if 'puertos abiertos' in body and '(' not in body:
            body = body.replace(
                'puertos abiertos', f"puertos abiertos ({', '.join(ports)})", 1
            )
        elif 'puertos abiertos' not in body:
            body += f" · {len(ports)} puerto(s) abierto(s) ({', '.join(ports)})"
    mark = '✓' if success else '×'
    line = f'{mark} {name}: {body}'
    if success and ports and width:
        from rich.cells import cell_len

        if cell_len(line) > int(width):
            # Crop the list mid-number and ``8443`` reads as a truncated scan,
            # which is worse than not showing it: keep the count and leave the
            # per-port detail to the expansion.
            line = f'{mark} {name}: {plain_body}'
    # Un fallo nunca se recorta: la razón (``sliver_auth_missing``) es lo que el
    # operador necesita leer. El éxito es una línea corta por contrato.
    return line if not success else _fit_line(line, width)
