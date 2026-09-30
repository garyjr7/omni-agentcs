"""Status state, terminal-cell-aware formatting and XDG display preferences."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import tempfile
import time


@dataclass
class StatusState:
    engagement_name: str | None = None
    session_uuid: str | None = None
    session_type: str | None = None
    trust_mode: bool = False
    provider_model: str = ""
    tokens_input: int = 0
    tokens_output: int = 0
    cost_usd: float = 0.0
    cost_known: bool = True
    started_at: float = field(default_factory=time.monotonic)
    audit_chain_valid: bool = True
    msfrpcd_version: str | None = None
    busy: bool = False
    busy_message: str = ""
    busy_started_at: float = field(default_factory=time.monotonic)

    @property
    def elapsed_seconds(self) -> int:
        return max(0, int(time.monotonic() - self.started_at))

    @property
    def elapsed_human(self) -> str:
        seconds = self.elapsed_seconds
        if seconds < 60:
            return f"{seconds}s"
        minutes, seconds = divmod(seconds, 60)
        if minutes < 60:
            return f"{minutes}m{seconds:02d}s"
        hours, minutes = divmod(minutes, 60)
        return f"{hours}h{minutes:02d}m"


def _safe(value) -> str:
    return "".join(c if c.isprintable() else " " for c in str(value))


def _parts(state: StatusState):
    parts = [("ansiyellow", state.engagement_name or "(sin engagement)")]
    if state.trust_mode:
        parts.append(("ansired bold", "TRUST"))
    if state.session_uuid:
        parts.append(("ansimagenta", f"session {state.session_uuid}/{state.session_type or 'session'}"))
    parts.append(("ansicyan", state.provider_model or "(sin modelo)"))
    tokens = state.tokens_input + state.tokens_output
    parts.append(("ansigreen", f"{tokens / 1000:.1f}k tok" if tokens >= 1000 else f"{tokens} tok"))
    parts.append(("ansigreen", f"~${state.cost_usd:.4f}" if state.cost_known else "$—"))
    parts.append(("dim", state.elapsed_human))
    if state.busy:
        elapsed = max(0, int(time.monotonic() - state.busy_started_at))
        frame = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[elapsed % 10]
        parts.append(("ansiyellow", f"{frame} {state.busy_message} [{elapsed}s]"))
    return [(style, _safe(text)) for style, text in parts]


def render_status_plain(state: StatusState) -> str:
    return " · ".join(text for _, text in _parts(state))


def render_status_bar(state: StatusState, *, width: int):
    from prompt_toolkit.formatted_text import FormattedText
    from prompt_toolkit.utils import get_cwidth

    fragments = []
    remaining = max(0, width)
    for index, (style, text) in enumerate(_parts(state)):
        if index:
            text = " · " + text
        kept = ""
        for char in text:
            size = max(0, get_cwidth(char))
            if size > remaining:
                return FormattedText(fragments + [(style, kept)])
            kept += char
            remaining -= size
        fragments.append((style, kept))
    return FormattedText(fragments)


def preferences_path() -> Path:
    from nexus_core.config.xdg import resolve_xdg_paths

    return resolve_xdg_paths().config_dir / "tui.json"


def load_status_preference(default: bool = True) -> bool:
    try:
        value = json.loads(preferences_path().read_text(encoding="utf-8"))["status_bar_enabled"]
        return value if type(value) is bool else default
    except (OSError, ValueError, KeyError, TypeError):
        return default


def save_status_preference(enabled: bool) -> None:
    path = preferences_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".tui-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump({"status_bar_enabled": bool(enabled)}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
