"""Status state, terminal-cell-aware formatting and XDG display preferences.

The status bar is *priority-aware*: when the terminal is narrow it drops the
least important segment first instead of blindly truncating from the right. The
active alert (trust/session) and the engagement phase are never dropped; the
engagement name is dropped first because the compact header already shows it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import tempfile
import time

#: Drop priority per segment key (higher = more important, dropped last).
#: Ordering encodes the product rule: alerts and phase survive; engagement dies
#: first (it already lives in the compact header).
PRIORITY = {
    "alert": 7,
    "phase": 6,
    "provider": 5,
    "tokens": 4,
    "cost": 3,
    "time": 2,
    "facts": 1,
    "engagement": 0,
}

#: Segments that must survive any width: the active alert and the phase.
#: They are cell-truncated as a last resort instead of being dropped, because
#: losing them would hide the engagement's safety state.
PROTECTED_PRIORITIES = frozenset({PRIORITY["alert"], PRIORITY["phase"]})


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
    #: Distinct facts recorded in the engagement blackboard (None = unknown).
    facts_count: int | None = None
    #: Current kill-chain phase label and "done/total" progress (planner).
    plan_phase: str | None = None
    plan_progress: str | None = None
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


def _parts(state: StatusState) -> list[tuple[int, str, str]]:
    """Return ``(priority, style, text)`` segments in display order.

    Display order (left to right): alert · phase · provider · tokens · cost ·
    time · facts · engagement. The engagement is last on purpose: it is the
    first to fall when the terminal is narrow.
    """
    parts: list[tuple[int, str, str]] = []
    if state.trust_mode:
        parts.append((PRIORITY["alert"], "ansired bold", "TRUST"))
    if state.session_uuid:
        parts.append(
            (
                PRIORITY["alert"],
                "ansimagenta",
                f"session {state.session_uuid}/{state.session_type or 'session'}",
            )
        )
    if state.plan_phase:
        progress = f" {state.plan_progress}" if state.plan_progress else ""
        parts.append((PRIORITY["phase"], "ansicyan bold", f"▸ {state.plan_phase}{progress}"))
    parts.append((PRIORITY["provider"], "ansicyan", state.provider_model or "(sin modelo)"))
    tokens = state.tokens_input + state.tokens_output
    parts.append(
        (
            PRIORITY["tokens"],
            "ansigreen",
            f"{tokens / 1000:.1f}k tok" if tokens >= 1000 else f"{tokens} tok",
        )
    )
    parts.append(
        (
            PRIORITY["cost"],
            "ansigreen",
            f"~${state.cost_usd:.4f}" if state.cost_known else "$—",
        )
    )
    parts.append((PRIORITY["time"], "dim", state.elapsed_human))
    if state.facts_count:
        parts.append((PRIORITY["facts"], "ansiblue", f"{state.facts_count} facts"))
    parts.append(
        (
            PRIORITY["engagement"],
            "ansiyellow",
            state.engagement_name or "(sin engagement)",
        )
    )
    if state.busy:
        elapsed = max(0, int(time.monotonic() - state.busy_started_at))
        frame = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[elapsed % 10]
        parts.append((8, "ansiyellow", f"{frame} {state.busy_message} [{elapsed}s]"))
    return [(priority, style, _safe(text)) for priority, style, text in parts]


def _join(items: list[tuple[int, str, str]]) -> str:
    return " · ".join(text for _, _, text in items)


def render_status_plain(state: StatusState) -> str:
    """Full one-line status (all segments, display order) for ``/status show``."""
    return _join(_parts(state))


def render_status_bar(state: StatusState, *, width: int):
    """Cell-aware status bar that drops the least important segments first."""
    from prompt_toolkit.formatted_text import FormattedText
    from prompt_toolkit.utils import get_cwidth

    items = list(_parts(state))
    # Drop the lowest-priority segments until the line fits or only protected
    # segments remain. alert (trust/session) and phase are drop-protected: they
    # are cell-truncated below rather than removed.
    while len(items) > 1 and get_cwidth(_join(items)) > width:
        droppable = [
            index
            for index, (priority, _, _) in enumerate(items)
            if priority not in PROTECTED_PRIORITIES
        ]
        if not droppable:
            break
        items.pop(min(droppable, key=lambda index: items[index][0]))

    fragments = []
    remaining = max(0, width)
    for index, (_, style, text) in enumerate(items):
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
