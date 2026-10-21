"""V9 (Hijack): waiting is never an action.

The agent ran ``sleep 170`` to "give the reverse shell time": nothing changed on
the target, the turn was spent, and the budget that paid for it could not be
recovered. A wait is only ever a bet that something happens *outside* the run,
and every legitimate version of that bet already has a tool:

* a reverse shell -> ``nexus.post.listener`` (it waits with its own timeout);
* a long process -> ``nexus.post.job`` / ``setsid`` in ``nexus.shell.exec``;
* an unknown next step -> a barrier and a pivot.

The guard is lexical on purpose: it inspects simple commands (``;``/``&&``/
``|`` separated, quotes honoured), accepts environment prefixes, and recurses
into ``bash -c``/``sh -c`` because that is how the measured command travelled.
It is applied by the shell handlers *before* anything runs, and it answers
``outcome="denied"`` - the same vocabulary as the local deny list, so the loop
counts it as a determinate refusal instead of a broken tool.
"""

from __future__ import annotations

import re
import shlex

#: Programs that do nothing but wait.
PASSIVE_WAIT_PROGRAMS: frozenset[str] = frozenset({"sleep", "wait"})

#: A ``timeout`` is an active command (it runs something) up to this bound.
PASSIVE_WAIT_MAX_TIMEOUT_SECONDS = 10.0

#: The observation the model reads when it tried to wait. It names the tools
#: that replace each legitimate reason to wait, so the next turn can act.
PASSIVE_WAIT_GUIDANCE = (
    "Los comandos de espera pasiva están prohibidos. Si esperas un reverse "
    "shell, usa nexus.post.listener. Si esperas un proceso, usa nexus.post.job. "
    "Si no sabes qué hacer, documenta un barrier y pivota."
)

_DURATION_RE = re.compile(r"^(?P<value>\d+(?:\.\d+)?)(?P<unit>[smhd]?)$")
_DURATION_FACTORS = {"": 1.0, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}

#: Shells whose ``-c`` payload is another command line the guard must inspect.
_NESTED_SHELLS = frozenset({"bash", "sh", "dash", "zsh", "ksh"})


#: Prefixes that do not change which program actually runs.
_COMMAND_PREFIXES = frozenset({"command", "exec", "nohup", "time", "stdbuf"})


def _segments(command: str) -> list[str]:
    """Split *command* into simple commands, honouring quotes and escapes."""
    segments: list[str] = []
    buffer: list[str] = []
    quote = ""
    escaped = False
    for char in str(command or ""):
        if escaped:
            buffer.append(char)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            buffer.append(char)
            escaped = True
            continue
        if quote:
            buffer.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            buffer.append(char)
            continue
        if char in ";&|\n":
            segments.append("".join(buffer))
            buffer = []
            continue
        buffer.append(char)
    segments.append("".join(buffer))
    return [segment.strip() for segment in segments if segment.strip()]


def _code(command: str) -> str:
    """*command* with quoted regions blanked (the shell grammar is outside them)."""
    out: list[str] = []
    quote = ""
    escaped = False
    for char in str(command or ""):
        if escaped:
            escaped = False
            out.append(" ")
            continue
        if char == "\\" and quote != "'":
            escaped = True
            out.append(" ")
            continue
        if quote:
            if char == quote:
                quote = ""
            out.append(" ")
            continue
        if char in "\"'":
            quote = char
            out.append(" ")
            continue
        out.append(char)
    return "".join(out)


def is_background_command(command: str) -> bool:
    """Whether *command* detaches its work with ``&``.

    A backgrounded wait is not a passive wait: the call returns at once with a
    PID, so the turn is not spent -and ``(sleep 30; callback) &`` is a real
    technique (a delayed reverse shell), not a hallucination. ``nohup`` alone is
    *not* enough: without ``&`` it still blocks the channel it runs on.
    """
    code = _code(command)
    for index, char in enumerate(code):
        if char != "&":
            continue
        previous = code[index - 1] if index else ""
        following = code[index + 1] if index + 1 < len(code) else ""
        if following in {"&", ">"} or previous in {"&", ">"}:
            continue
        return True
    return False


def _tokens(segment: str) -> list[str]:
    """Tokens of one simple command; a quoting error falls back to ``split``."""
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _strip_prefixes(tokens: list[str]) -> list[str]:
    """Drop ``VAR=value`` and the transparent command prefixes."""
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
            index += 1
            continue
        if token.rsplit("/", 1)[-1] in _COMMAND_PREFIXES:
            index += 1
            # ``stdbuf -oL`` / ``time -p``: skip the prefix's own options.
            while index < len(tokens) and tokens[index].startswith("-"):
                index += 1
            continue
        break
    return tokens[index:]


def duration_seconds(value: str) -> float | None:
    """Seconds in a ``timeout``-style duration (``10``, ``10s``, ``1.5m``)."""
    match = _DURATION_RE.match(str(value or "").strip().lower())
    if match is None:
        return None
    number = float(match.group("value"))
    return number * _DURATION_FACTORS[match.group("unit")]


def _timeout_reason(tokens: list[str]) -> str | None:
    """Reason a ``timeout`` call exceeds the bound (``None`` when it does not)."""
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            break
        if token.startswith("-") and len(token) > 1:
            index += 1
            continue
        break
    if index >= len(tokens):
        return None
    seconds = duration_seconds(tokens[index])
    if seconds is not None and seconds > PASSIVE_WAIT_MAX_TIMEOUT_SECONDS:
        return f"timeout {tokens[index]}"
    return None


def passive_wait_reason(command: str, *, depth: int = 0) -> str | None:
    """Name the passive wait in *command*, or ``None`` when it is not one.

    ``depth`` bounds the ``bash -c`` recursion so a hostile one-liner cannot
    turn the guard into a stack overflow. A backgrounded command is not a
    passive wait: it returns immediately (see :func:`is_background_command`).
    """
    if depth > 4 or not command or is_background_command(command):
        return None
    for segment in _segments(command):
        tokens = _strip_prefixes(_tokens(segment))
        if not tokens:
            continue
        program = tokens[0].rsplit("/", 1)[-1].lower()
        if program in PASSIVE_WAIT_PROGRAMS:
            return program
        if program == "timeout":
            reason = _timeout_reason(tokens)
            if reason:
                return reason
            continue
        if program in _NESTED_SHELLS:
            for index, token in enumerate(tokens):
                if token == "-c" and index + 1 < len(tokens):
                    nested = passive_wait_reason(tokens[index + 1], depth=depth + 1)
                    if nested:
                        return nested
    return None


__all__ = [
    "PASSIVE_WAIT_GUIDANCE",
    "PASSIVE_WAIT_MAX_TIMEOUT_SECONDS",
    "PASSIVE_WAIT_PROGRAMS",
    "duration_seconds",
    "is_background_command",
    "passive_wait_reason",
]
