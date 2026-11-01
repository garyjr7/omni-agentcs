"""The prompt frame: header, work pulse, completion line and permission menu.

One module owns the chrome the operator sees on every turn, so the header
timer, the working pulse, the "Worked for" line and the permission menu cannot
drift apart. Everything here is pure formatting: no terminal, no thread and no
cursor control. ``TuiSession`` samples these strings from the refresh loop that
already exists (4 Hz while working, 0.5 Hz idle), ``prompt_toolkit`` paints
them and Rich only styles the text.

``rich.live.Live`` is deliberately absent. The session owns the terminal
through one persistent ``prompt_toolkit`` Application; a second writer would
fight it for the cursor and the two would repaint over each other. The same
four pieces are rows of that Application instead: fixed header, transcript,
pulse/completion line, then the input panel with the permission menu growing
upward out of it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

#: ``BW • OMNI [ engagement ]`` - the brand is the frame's top row.
BRAND = "BW"
SEPARATOR = " • "
DEFAULT_ENGAGEMENT = "workspace"

#: Seven cells and one bright sweep. The literal text never changes between
#: frames (``[+][+][+][+][+][+][+]``); only which cell is bright moves.
PULSE_CELLS = 7
PULSE_STEP_SECONDS = 0.18
PULSE_BRIGHT = "#ff0055 bold"
PULSE_DIM = "#a3003a"

#: ``(label, token)`` in reading order. The default selection is the single-use
#: authorization, never the engagement-wide one: pressing Enter must never
#: grant more than the operator asked for.
APPROVAL_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Sí, siempre en este engagement", "a"),
    ("Sí, solo esta vez", "y"),
    ("No", "n"),
)
APPROVAL_TOKENS = tuple(token for _, token in APPROVAL_OPTIONS)
APPROVAL_DEFAULT = APPROVAL_TOKENS.index("y")


def format_elapsed(seconds: float) -> str:
    """``50m 14s`` / ``1h 05m`` / ``12s`` for the header and completion lines."""
    total = max(0, int(seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def header_text(engagement: str | None, *, elapsed_seconds: float | None = None) -> str:
    """Fixed header line; the timer exists only while the agent is working."""
    name = " ".join(str(engagement or "").split()) or DEFAULT_ENGAGEMENT
    text = f"{BRAND}{SEPARATOR}OMNI [ {name} ]"
    if elapsed_seconds is not None:
        text += f"   {format_elapsed(elapsed_seconds)}"
    return text


def pulse_index(now: float) -> int:
    """Which of the seven cells is bright at ``now`` (monotonic seconds)."""
    return int(max(0.0, float(now)) / PULSE_STEP_SECONDS) % PULSE_CELLS


def busy_cells(now: float) -> list[tuple[str, str]]:
    """``(style, text)`` per cell: the sweep advances, the text never changes."""
    active = pulse_index(now)
    return [
        (PULSE_BRIGHT if index == active else PULSE_DIM, "[+]")
        for index in range(PULSE_CELLS)
    ]


def busy_marker() -> str:
    """Plain seven-cell marker as it enters the transcript."""
    return "[+]" * PULSE_CELLS


def busy_text() -> str:
    """The line that replaces the prompt while the agent works."""
    return f"{busy_marker()} · esc interrupt"


def completion_text(seconds: float, *, now: datetime | None = None) -> str:
    """``Worked for 3m 12s • 04:35 PM``, shown where the pulse was."""
    stamp = (now or datetime.now()).strftime("%I:%M %p")
    return f"Worked for {format_elapsed(seconds)}{SEPARATOR}{stamp}"


def approval_command(payload: Any, *, width: int = 60) -> str:
    """The exact thing being authorized, as short as the menu needs it.

    Arguments arrive already redacted (``render.display_arguments``), so this
    only decides *what to name*: the command when there is one, the target
    otherwise, and never an invented invocation.
    """
    data: dict[str, Any] = payload if isinstance(payload, dict) else {}
    raw = data.get("arguments")
    arguments: dict[str, Any] = raw if isinstance(raw, dict) else {}
    for key in ("command", "cmd", "argv", "line"):
        value = arguments.get(key)
        if isinstance(value, (list, tuple)) and value:
            return _clip(" ".join(str(part) for part in value), width)
        if isinstance(value, str) and value.strip():
            return _clip(value.strip(), width)
    tool_id = str(data.get("tool_id") or "?").strip() or "?"
    rendered = ", ".join(f"{key}={arguments[key]}" for key in sorted(arguments))
    return _clip(f"{tool_id} {rendered}".strip(), width)


def approval_question(command: str) -> str:
    """``[+] ¿Puedo ejecutar <comando>?``"""
    return f"[+] ¿Puedo ejecutar {command}?"


def _clip(text: str, width: int) -> str:
    value = " ".join(str(text).split())
    return value if len(value) <= width else value[: max(0, width - 1)] + "…"


__all__ = [
    "APPROVAL_DEFAULT",
    "APPROVAL_OPTIONS",
    "APPROVAL_TOKENS",
    "BRAND",
    "DEFAULT_ENGAGEMENT",
    "SEPARATOR",
    "approval_command",
    "approval_question",
    "busy_cells",
    "busy_marker",
    "busy_text",
    "completion_text",
    "format_elapsed",
    "header_text",
    "pulse_index",
]
