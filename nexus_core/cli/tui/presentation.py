"""Pure Rich renderables. Rendering never owns stdout, a cursor or a thread."""
from __future__ import annotations

import difflib
import io
import re
from dataclasses import dataclass
from typing import Any

from rich.console import Console, Group, RenderableType
from rich.syntax import Syntax
from rich.text import Text

_CONTROLS = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]')

#: Input panel (OpenCode-Zen style): dark grey textarea background with a solid
#: red vertical bar as its only border. There is no top/bottom horizontal rule.
PANEL_STYLE = 'bg:#2a2a2a'
PANEL_BAR_STYLE = 'fg:#ff0055 bg:#2a2a2a'

#: Semantic hierarchy of the log (Codex style): reasoning is muted, the tool
#: being invoked is aqua, a verified result is green and a failure is red. The
#: branch glyph indents tool output under its invocation so a card reads as a
#: tree instead of a wall of text.
THINKING_STYLE = 'dim'
TOOL_STYLE = '#00e5ff'
RESULT_OK_STYLE = '#56e696'
RESULT_ERROR_STYLE = '#ff4054'
BRANCH = '└─'

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


def fold_lines(value: str, *, expanded: bool = False, limit: int = 5) -> FoldedLines:
    if limit < 1:
        raise ValueError('line limit must be positive')
    lines = clean_text(value).splitlines()
    if expanded or len(lines) <= limit:
        return FoldedLines(tuple(lines), (), 0)
    head_count = (limit + 1) // 2
    tail_count = limit // 2
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


def thinking(value: str, *, expanded: bool = False) -> Text:
    text = Text('• Thinking...', style=THINKING_STYLE, no_wrap=False, overflow='fold')
    if expanded and value.strip():
        text.append('\n' + clean_text(value), style=THINKING_STYLE)
    elif value.strip():
        summary = ' '.join(clean_text(value).split())
        text.append(' ' + summary[:100] + ('…' if len(summary) > 100 else ''))
    return text


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


def trace_block(value: str, *, success: bool, tool_id: str, summary: str,
                expanded: bool = False, limit: int = 5, diff: bool = False) -> Group:
    folded = fold_lines(value, expanded=expanded, limit=limit)
    # One semantic colour for the whole card: green when the run produced a
    # usable result, red when it failed. Never mixed, so the verdict is read
    # before the text.
    color = RESULT_OK_STYLE if success else RESULT_ERROR_STYLE
    body: list[RenderableType] = []
    if not success:
        body.append(Text(f'× failed · {clean_text(tool_id) or "tool"}',
                         style=f'bold {RESULT_ERROR_STYLE}'))
    for index, lines in enumerate((folded.head, folded.tail)):
        if index and folded.hidden:
            body.append(Text('   ...', style='dim'))
        if diff and lines:
            body.append(diff_block('\n'.join(lines)))
        else:
            body.extend(Text(f'   {BRANCH} ' + line, style=color) for line in lines)
    body.append(Text(f'   {"✓" if success else "×"} {clean_text(summary)}',
                     style=f'bold {color}'))
    if folded.hidden:
        body.append(Text(f'   [ Show more... · {folded.hidden} lines ]', style='dim cyan'))
    elif expanded and len(clean_text(value).splitlines()) > limit:
        body.append(Text('   [ Show less ]', style='dim cyan'))
    return Group(*body)


class WorkingIndicator:
    """Pure pulse frames sampled by the existing terminal refresh loop.

    The seven cells and their sweep live in :mod:`nexus_core.cli.tui.frame`, so
    the pulse the transcript shows and the one the header timer accompanies are
    the same widget. ``message`` and ``elapsed`` stay in the signature because
    the loop samples this every frame; the mock keeps the label static.
    """

    def frame(self, message: str, *, now: float, elapsed: int, width: int,
              no_color: bool = False) -> str:
        from .frame import busy_cells

        del message, elapsed
        text = Text()
        for style, cell in busy_cells(now):
            text.append(cell, style=style)
        text.append(' · esc interrupt', style='dim')
        return render_rich(text, width=width, no_color=no_color).split('\n')[0]


def tactical_phase(tool_id: str) -> str:
    """Presentation labels only: never change dispatch or policy identifiers."""
    if tool_id in {'nexus.web.upload', 'nexus.web.git_dump'}:
        return 'Weaponization' if tool_id.endswith('upload') else 'Enumeration'
    family = tool_id.split('.')[1] if '.' in tool_id else ''
    return {'recon': 'Enumeration', 'web': 'Enumeration', 'exploit': 'Exploitation',
            'post': 'Post-exploitation', 'cred': 'Credential assessment',
            'report': 'Reporting'}.get(family, 'Working')
