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

from rich.console import Console, Group, RenderableType
from rich.syntax import Syntax
from rich.text import Text

_CONTROLS = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]')

#: Input panel (OpenCode-Zen style): dark grey textarea background with a solid
#: red vertical bar as its only border. There is no top/bottom horizontal rule.
PANEL_STYLE = 'bg:#2a2a2a'
PANEL_BAR_STYLE = 'fg:#ff0055 bg:#2a2a2a'

#: The semantic palette. One accent only -the header, the operator's rail and
#: the work pulse-, everything else is either uncoloured text or a verdict.
#: Defined here and nowhere else: a renderer names a role, never a hex value.
ACCENT_STYLE = '#ff0055'
SECONDARY_STYLE = 'dim #787e86'
OK_STYLE = '#56e696'
ERROR_STYLE = '#ff4054'
WARN_STYLE = '#ffc950'

#: Hierarchy of the log (Codex style): reasoning is muted italic, the tool is
#: bold text, a verified result is green and a failure is red. The branch glyph
#: indents tool output under its invocation so a card reads as a tree.
THINKING_STYLE = 'dim'
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
    """Render the first-frame OMNI masthead and three operator metadata rows."""
    glyphs = (
        (" █████ ", "██   ██", "██   ██", "██   ██", "██   ██", " █████ "),
        ("███   ███", "████ ████", "██ ███ ██", "██  █  ██", "██     ██", "██     ██"),
        ("███    ██", "████   ██", "██ ██  ██", "██  ██ ██", "██   ████", "██    ███"),
        ("███████", "  ██   ", "  ██   ", "  ██   ", "  ██   ", "███████"),
    )
    rows = tuple("  ".join(letter[line] for letter in glyphs) for line in range(6))
    logo = Text("\n".join(rows), style="#ff0055 bold")
    metadata = Group(
        Text(f"[+] [ Omni Agent CS v{clean_text(version)} ] [+]", style="bold white"),
        Text("[+] [ BAJIOWARE • Red Team ] [+]", style="bold #ff0055"),
        Text(f"[+] [ {clean_text(engagement)} ] [+]", style="bold white"),
    )
    # The official masthead floats freely. Rich styles the contents, but no
    # Panel/Rule/box renderable is used around the art or metadata. It closes
    # with a blank line: the masthead is its own block, so the first echoed
    # turn cannot be glued to its last metadata row.
    return render_rich(Group(logo, Text(""), metadata),
                       width=max(40, width), no_color=no_color) + "\n\n"


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
        return Text(f'[ 📋 Pasted Input · {len(value):,} characters ]', style='dim cyan')
    return Text(clean_text(value))


def input_quote(value: str, *, width: int = 100, no_color: bool = False) -> str:
    """Render an operator turn as a clean quote block with a red left rail."""
    lines = clean_text(value).splitlines() or [""]
    rows: list[RenderableType] = []
    for line in lines:
        rows.append(Text("▌ ", style="#ff0055 bold") + Text(line))
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


def summary_markdown(result: Any) -> str:
    """Final result as clean Markdown, for the TUI transcript.

    A bordered box fragments on a wide terminal: the border and the wrapped
    body stop agreeing at 200 columns. The dedicated screen renders the same
    facts as a Markdown block instead, while ``--no-tui`` keeps the box.
    Only data the result already carries is listed: the final summary, the
    findings, the phases still open and the run's status/iteration count.
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
    lines.extend(["", "### Estado", ""])
    lines.append(f"- estado: {status or '?'}")
    if iterations is not None:
        lines.append(f"- iteraciones: {iterations}")
    return "\n".join(lines)


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


def thinking(value: str, *, expanded: bool = False, width: int = 100,
             reasoning: str | None = None) -> Text:
    """Durable reasoning card: header, preview (5 lines) and a toggle footer.

    Collapsed shows the last five physical lines preceded by an ellipsis, so a
    long note reads as its conclusion instead of as its introduction. The
    provider's native reasoning travels as a separate dim block only when the
    model's own note is too short to be useful (fewer than 50 characters).
    """
    from .strings import HIDE_REASONING, SHOW_FULL_REASONING, THINKING_CARD

    text = Text(f'  {THINKING_CARD}', style=THINKING_STYLE, no_wrap=False, overflow='fold')
    lines = _thought_lines(value, width)
    if lines:
        if not expanded and len(lines) > 5:
            text.append('\n  …', style=THINKING_STYLE)
            lines = lines[-5:]
        for line in lines:
            text.append('\n  ' + line, style=THINKING_STYLE)
    if reasoning and len(clean_text(str(value or '')).strip()) < 50:
        text.append('\n  ---', style='dim')
        for line in _thought_lines(reasoning, width)[:10]:
            text.append('\n  ' + line, style='dim')
    text.append('\n  ' + (HIDE_REASONING if expanded else SHOW_FULL_REASONING),
                style='dim cyan')
    return text


def live_thought(value: str, *, width: int = 100) -> Text:
    """Up to three lines of the streamed note, prefixed with ``Razonando``."""
    from .strings import THINKING_LIVE

    lines = [line for line in _thought_lines(value, width) if line.strip()][-3:]
    if not lines:
        return Text(THINKING_LIVE, style=THINKING_STYLE)
    text = Text(f'{THINKING_LIVE} {lines[0]}', style=THINKING_STYLE)
    for line in lines[1:]:
        text.append('\n  ' + line, style=THINKING_STYLE)
    return text


def turn_header(step: int, phase: str, *, width: int = 80) -> Text:
    """``── paso N · phase ───`` filling the transcript width."""
    label = f'── paso {int(step)} · {str(phase or "Trabajo")} '
    room = max(0, int(width) - len(label))
    return Text(label + '─' * room, style=TURN_STYLE, no_wrap=True, overflow='crop')


def diff_block(value: str) -> Syntax:
    return Syntax(clean_text(value), 'diff', theme='ansi_dark', background_color='default',
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
    body.extend(Text(line, style=f'bold {color}')
                for line in _summary_lines(summary, success=success, width=width))

    if structured is not None and not expanded:
        if isinstance(structured, dict):
            items = list(structured.items())
            for key, item in items[:4]:
                body.append(Text(f'  {BRANCH} {key}: {_compact_value(item)}', style=color))
            hidden = max(0, len(items) - 4)
            if hidden:
                body.append(Text(f'  … {hidden} campos más · ctrl+o', style='dim'))
            elif not items:
                body.append(Text('  (sin campos)', style='dim'))
        else:
            total = len(structured) if isinstance(structured, (list, tuple)) else 1
            body.append(Text(f'  {total} elementos · ctrl+o', style='dim'))
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
        for row in rows:
            wrapped = textwrap.wrap(
                row, width=max(20, int(width)), initial_indent=f'  {BRANCH} ',
                subsequent_indent='    ', break_long_words=False,
                break_on_hyphens=False,
            ) or [f'  {BRANCH}']
            body.extend(Text(line, style=color) for line in wrapped)

    emit(folded.head)
    if folded.hidden:
        body.append(Text('  …', style='dim'))
    emit(folded.tail)
    if folded.hidden:
        body.append(Text(f'  … {folded.hidden} líneas más · ctrl+o', style='dim'))
    elif expanded and len(lines.splitlines()) > limit:
        body.append(Text('  ctrl+o colapsar', style='dim'))
    return Group(*body)


class WorkingIndicator:
    """Pure pulse frames sampled by the existing terminal refresh loop.

    The seven cells and their sweep live in :mod:`nexus_core.cli.tui.frame`, so
    the pulse the transcript shows and the one the header timer accompanies are
    the same widget. ``message`` names the operation the run is in, which is the
    only thing that tells "waiting for the model" from "running a tool";
    ``elapsed`` stays in the signature because the loop samples this every
    frame, but the header already owns the timer.
    """

    def frame(self, message: str, *, now: float, elapsed: int, width: int,
              no_color: bool = False) -> str:
        from .frame import BUSY_TAIL, busy_cells, busy_label

        del elapsed
        text = Text()
        cells = 0
        for style, cell in busy_cells(now):
            text.append(cell, style=style)
            cells += len(cell)
        label = busy_label(message, room=width - cells - len(BUSY_TAIL) - 3)
        if label:
            text.append(f' · {label}', style='dim')
        text.append(BUSY_TAIL, style='dim')
        return render_rich(text, width=width, no_color=no_color).split('\n')[0]


def tactical_phase(tool_id: str) -> str:
    """Presentation labels only: never change dispatch or policy identifiers."""
    if tool_id in {'nexus.web.upload', 'nexus.web.git_dump'}:
        return 'Weaponization' if tool_id.endswith('upload') else 'Enumeration'
    family = tool_id.split('.')[1] if '.' in tool_id else ''
    return {'recon': 'Enumeration', 'web': 'Enumeration', 'exploit': 'Exploitation',
            'post': 'Post-exploitation', 'cred': 'Credential assessment',
            'report': 'Reporting'}.get(family, 'Working')
