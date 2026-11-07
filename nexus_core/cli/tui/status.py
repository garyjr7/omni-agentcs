"""Status state, terminal-cell-aware formatting and XDG display preferences.

The fixed operational status bar is *priority-aware*: when the terminal is narrow it drops the
least important segment first instead of blindly truncating from the right. The
active alert (trust/session) and the engagement phase are never dropped; the
engagement name is dropped first because the compact header already shows it.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..theme import THEME

if TYPE_CHECKING:
    from prompt_toolkit.formatted_text import FormattedText

#: Drop priority per segment key (higher = more important, dropped last).
#: Ordering encodes the product rule: alerts and phase survive; engagement dies
#: first (it already lives in the compact header).
PRIORITY = {
    "brand": -1,
    "scope": 5.2,
    "budget": 3.2,
    "status": 6.5,
    "alert": 7,
    "phase": 6,
    "provider": 5,
    "ctx": 4.5,
    "rate": 2.5,
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
    workspace_path: str = ""
    engagement_name: str | None = None
    session_uuid: str | None = None
    session_type: str | None = None
    trust_mode: bool = False
    provider_model: str = ""
    context_tokens: int | None = None
    context_window: int | None = None
    context_source: str = 'provider'
    rate_remaining: int | None = None
    fields: tuple[str, ...] | None = None
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
    scope_targets: int | None = None
    budget_usd: float | None = None
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


def _safe(value: Any) -> str:
    return "".join(c if c.isprintable() else " " for c in str(value))


def _parts(state: StatusState) -> list[tuple[float, str, str]]:
    """Return ``(priority, style, text)`` segments in display order.

    Display order (left to right): alert · phase · provider · tokens · cost ·
    time · facts · engagement. The engagement is last on purpose: it is the
    first to fall when the terminal is narrow.
    """
    parts: list[tuple[float, str, str]] = []
    if state.trust_mode:
        parts.append((PRIORITY["alert"], f"fg:{THEME.error} bold", "TRUST"))
    if state.session_uuid:
        parts.append(
            (
                PRIORITY["alert"],
                f"fg:{THEME.magenta}",
                f"session {state.session_uuid}/{state.session_type or 'session'}",
            )
        )
    if state.plan_phase:
        progress = f" {state.plan_progress}" if state.plan_progress else ""
        parts.append((PRIORITY["phase"], f"fg:{THEME.aqua} bold", f"▸ {state.plan_phase}{progress}"))
    parts.append((PRIORITY["brand"], "dim", "BAJIOWARE · OMNI-AGENTCS"))
    scope = f"{state.scope_targets} objetivos" if state.scope_targets is not None else "—"
    parts.append((PRIORITY["scope"], f"fg:{THEME.aqua}", "Alcance: " + scope))
    parts.append((PRIORITY["provider"], f"fg:{THEME.aqua}", "Modelo: " + (state.provider_model or "—")))
    tokens = state.tokens_input + state.tokens_output
    parts.append((PRIORITY["tokens"], f"fg:{THEME.ok}", f"Tokens: {tokens:,}"))
    budget = f"${state.budget_usd:.2f}" if state.budget_usd is not None else "$—"
    parts.append((PRIORITY["budget"], f"fg:{THEME.ok}", "Presupuesto: " + budget))
    parts.append((PRIORITY["status"], f"fg:{THEME.warn}" if state.busy else "dim",
                  "Estado: EN CURSO" if state.busy else "Estado: INACTIVO"))
    if state.context_window and state.context_window > 0 and state.context_tokens is not None:
        percent = max(0, int(100 * state.context_tokens / state.context_window))
        style = (f'fg:{THEME.ok}' if percent < 50
                 else f'fg:{THEME.warn}' if percent <= 80 else f'fg:{THEME.error}')
        approx = '~' if state.context_source == 'estimate' else ''
        label = f'ctx {approx}{percent}% usado'
        if percent >= 80:
            label += ' · revisar compactación'
    else:
        style, label = 'dim', 'ctx ~?%'
    parts.append((PRIORITY['ctx'], style, label))
    if state.rate_remaining is not None:
        parts.append((PRIORITY['rate'], 'dim', f'tasa {state.rate_remaining} restantes'))
    # Tokens already have their own segment above: printing them again as
    # ``run N tok`` duplicated the number in ``/status show`` (D2).
    parts.append(
        (
            PRIORITY["cost"],
            f"fg:{THEME.ok}",
            f"coste ~${state.cost_usd:.4f}" if state.cost_known else "coste $—",
        )
    )
    parts.append((PRIORITY["time"], "dim", state.elapsed_human))
    if state.facts_count:
        parts.append((PRIORITY["facts"], f"fg:{THEME.blue}", f"{state.facts_count} datos"))
    parts.append(
        (
            PRIORITY["engagement"],
            f"fg:{THEME.warn}",
            state.engagement_name or "(sin engagement)",
        )
    )
    if state.busy:
        elapsed = max(0, int(time.monotonic() - state.busy_started_at))
        frame = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[elapsed % 10]
        parts.append((8, f"fg:{THEME.warn}", f"{frame} {state.busy_message} [{elapsed}s]"))
    if state.fields is not None:
        allowed = {PRIORITY[name] for name in state.fields if name in PRIORITY} | set(PROTECTED_PRIORITIES) | {8, PRIORITY["status"]}
        parts = [part for part in parts if part[0] in allowed]
    return [(priority, style, _safe(text)) for priority, style, text in parts]


def _join(items: list[tuple[float, str, str]]) -> str:
    return " | ".join(text for _, _, text in items)


def render_status_plain(state: StatusState) -> str:
    """Full one-line status (all segments, display order) for ``/status show``."""
    return _join(_parts(state))


def _workspace_metrics(state: StatusState) -> list[str]:
    """Tokens, cost and context: what the alerts-only bar cannot show."""
    metrics: list[str] = []
    tokens = state.tokens_input + state.tokens_output
    if tokens >= 1000:
        metrics.append(f"{tokens / 1000:.1f}k tok")
    elif tokens:
        metrics.append(f"{tokens} tok")
    if state.cost_known and state.cost_usd:
        metrics.append(f"~${state.cost_usd:.2f}")
    if state.context_window and state.context_tokens is not None:
        percent = max(0, int(100 * state.context_tokens / state.context_window))
        metrics.append(f"ctx {percent}%")
    return metrics


def workspace_line(state: StatusState) -> str:
    """``model · metrics · ~/cwd`` for the input panel footer.

    The model, the run's numbers and the working directory are the prompt's own
    context, so they live in the textarea container instead of the operational
    bar. Metrics come before the path on purpose: a long directory clips at the
    right edge, never the tokens or the cost (D3). The word ``Build`` was
    retired with the old fixed workspace line.
    """
    from .presentation import clean_text

    bits = [state.provider_model or "unconfigured", *_workspace_metrics(state)]
    if state.workspace_path:
        root = Path(state.workspace_path)
        try:
            bits.append('~/' + str(root.relative_to(Path.home())))
        except ValueError:
            bits.append(str(root))
    return clean_text(' · '.join(bits)).replace('\n', ' ')


def render_status_bar(state: StatusState, *, width: int) -> FormattedText:
    """Cell-aware status bar that drops the least important segments first.

    Inside a workspace the model and working directory live in the input
    footer, and plan progress lives in the engagement panel. This row therefore
    carries only trust/session alerts. Without a workspace it retains the
    compact operational fields, excluding the redundant phase chip.
    """
    from prompt_toolkit.formatted_text import FormattedText
    from prompt_toolkit.utils import get_cwidth

    if state.workspace_path:
        items = [part for part in _parts(state) if part[0] == PRIORITY["alert"]]
    else:
        core = {PRIORITY[key] for key in ("brand", "scope", "provider", "tokens", "budget", "status", "alert", "ctx")}
        items = [part for part in _parts(state) if part[0] in core]
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

    fragments: list[tuple[str, str]] = []
    remaining = max(0, width)
    for index, (_, style, text) in enumerate(items):
        if index:
            text = " | " + text
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

    return Path(resolve_xdg_paths().config_dir) / "tui.json"


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
            json.dump({**_preferences(), "status_bar_enabled": bool(enabled)}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _preferences() -> dict[str, Any]:
    try:
        data = json.loads(preferences_path().read_text())
        return dict(data) if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def load_status_fields() -> tuple[str, ...] | None:
    fields = _preferences().get('status_fields')
    return tuple(fields) if isinstance(fields, list) and all(v in PRIORITY for v in fields) else None


def save_status_fields(fields: list[str]) -> None:
    from .history import atomic_private
    if any(name not in PRIORITY for name in fields):
        raise ValueError('unknown HUD field')
    atomic_private(preferences_path(), json.dumps({**_preferences(), 'status_fields': list(fields)}).encode())
