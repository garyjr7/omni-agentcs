"""Clipboard delivery for ``/copy``: OSC 52 first, native tools as fallback.

OSC 52 is the only mechanism that survives an SSH session, tmux or a VM: the
text travels inside the terminal stream and the *local* emulator owns the
clipboard. When the payload is too large for a sane escape sequence (or no
terminal is attached) the usual local helpers take over, in order of
specificity. No helper is a hard dependency: every failure degrades to ``None``
and the caller reports it without breaking the REPL.
"""
from __future__ import annotations

import base64
import os
import shutil
import subprocess
from typing import Any

#: Terminals truncate or drop very large OSC 52 payloads. Base64 grows the text
#: by a third, and tmux/screen wrap it again, so 100 KB of source text is the
#: point where a native helper is more honest than a silent truncation.
MAX_OSC52_TEXT_BYTES = 100_000

#: Native helpers, most specific first. Each entry is the command plus a label.
_NATIVE_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("wl-copy", ("wl-copy",)),
    ("xclip", ("xclip", "-selection", "clipboard")),
    ("xsel", ("xsel", "--clipboard", "--input")),
    ("pbcopy", ("pbcopy",)),
    ("clip", ("clip",)),
)


def osc52_sequence(text: str, *, environ: dict[str, str] | None = None) -> str:
    """The escape sequence for ``text``, wrapped for tmux/screen when needed.

    tmux and GNU screen only forward an OSC 52 sequence inside a DCS passthrough
    and require the inner escape to be doubled; a bare OSC is swallowed. The
    wrapping is what makes the clipboard work *from inside* the multipelxer
    instead of only from the outer terminal.
    """
    payload = base64.b64encode(str(text).encode("utf-8")).decode("ascii")
    writable = f"\x1b]52;c;{payload}\x07"
    env = os.environ if environ is None else environ
    if env.get("TMUX"):
        return f"\x1bPtmux;\x1b\x1b]52;c;{payload}\x07\x1b\\"
    if env.get("STY"):
        return f"\x1bP\x1b]52;c;{payload}\x07\x1b\\"
    return writable


def _write_osc52(text: str, output: Any) -> bool:
    """Write the sequence to the terminal output; False when not possible."""
    if len(str(text).encode("utf-8")) > MAX_OSC52_TEXT_BYTES:
        return False
    writer = getattr(output, "write_raw", None)
    if writer is None:
        return False
    try:
        writer(osc52_sequence(text))
        flush = getattr(output, "flush", None)
        if flush is not None:
            flush()
    except Exception:  # noqa: BLE001 - clipboard is best-effort, never fatal
        return False
    return True


def _copy_native(text: str) -> str | None:
    """Try the local helpers; return the one that worked, or ``None``."""
    data = str(text).encode("utf-8")
    for name, command in _NATIVE_COMMANDS:
        if shutil.which(command[0]) is None:
            continue
        try:
            completed = subprocess.run(
                list(command), input=data, timeout=5, check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if completed.returncode == 0:
            return name
    try:  # optional, never a declared dependency
        import pyperclip

        pyperclip.copy(str(text))
    except Exception:  # noqa: BLE001 - missing module or no display
        return None
    return "pyperclip"


def copy_to_clipboard(text: str, *, output: Any | None = None,
                      stream: Any | None = None) -> str | None:
    """Copy ``text`` and return the backend that handled it, or ``None``.

    ``output`` is the prompt_toolkit output of the running application: when it
    is present the OSC 52 sequence is written through it, so the copy never
    races the renderer's own writes. Without a terminal the native helpers are
    tried directly (useful from a script or a test).
    """
    value = str(text or "")
    if not value:
        return None
    interactive = output is not None or bool(
        stream is not None and getattr(stream, "isatty", lambda: False)()
    )
    if interactive and _write_osc52(value, output):
        return "OSC 52"
    return _copy_native(value)


def clipboard_backend(stream: Any | None = None) -> str:
    """Human label of the mechanism that would be used (for diagnostics)."""
    if stream is not None and getattr(stream, "isatty", lambda: False)():
        return "OSC 52"
    for name, command in _NATIVE_COMMANDS:
        if shutil.which(command[0]) is not None:
            return name
    return "pyperclip" if _has_pyperclip() else "ninguno"


def _has_pyperclip() -> bool:
    try:
        import pyperclip  # noqa: F401

        return True
    except Exception:  # noqa: BLE001 - optional dependency
        return False


__all__ = [
    "MAX_OSC52_TEXT_BYTES",
    "clipboard_backend",
    "copy_to_clipboard",
    "osc52_sequence",
]
