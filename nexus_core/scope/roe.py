"""Rules of Engagement (RoE) as enforceable code, not prose.

The signed engagement scope answers *where* a tool may go. The RoE answers
*when*, *how fast*, *how many*, and *stop now*:

* **Time windows** -- actions run only inside the declared local windows
  (weekday set + ``HH:MM`` range, wrapping midnight), so an engagement cannot
  silently drift outside the agreed hours.
* **Rate and concurrency** -- a ceiling on actions per minute and on concurrent
  actions, so a scan cannot stampede a client network.
* **Forbidden targets** -- a second, stricter exclusion list (patterns and
  categories) checked *in addition* to the signed scope.
* **Emergency contact** -- who to reach when something goes wrong.
* **Kill switch** -- a sentinel file or an in-process event that stops every
  action immediately, current and future.

The policy itself is immutable and signable, exactly like
:class:`~nexus_core.scope.models.EngagementScope`. The mutable runtime state (the
sliding action window, the concurrency count and the stop flag) lives in
:class:`RoEEnforcer`, so a signed RoE never changes behind the operator's back.

A RoE can only ever *narrow* what the scope allows: it runs after the scope
validator and can deny, never permit.
"""

from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Iterator

_TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


class RoEViolation(Exception):
    """Raised when an action would break the Rules of Engagement."""

    def __init__(self, reason: str, engagement_id: str = ""):
        self.reason = reason
        self.engagement_id = engagement_id
        super().__init__(f"RoEViolation: {reason}")


class RoEKillSwitch(RoEViolation):
    """Raised when the kill switch is engaged: no action may proceed."""


def _parse_hhmm(value: str) -> tuple[int, int]:
    match = _TIME_RE.match(str(value).strip())
    if match is None:
        raise ValueError(f"invalid HH:MM time: {value!r}")
    return int(match.group(1)), int(match.group(2))


def _minutes(value: str) -> int:
    hours, minutes = _parse_hhmm(value)
    return hours * 60 + minutes


@dataclass(frozen=True)
class TimeWindow:
    """A recurring local-time window, inclusive of both ends.

    ``days`` uses ``0=Monday .. 6=Sunday``; an empty tuple means every day. An
    ``end`` earlier than ``start`` is a window that wraps midnight (e.g.
    ``22:00``-``02:00``).
    """

    start: str
    end: str
    days: tuple[int, ...] = ()

    def allows(self, moment: datetime) -> bool:
        if self.days and moment.weekday() not in self.days:
            return False
        now = moment.hour * 60 + moment.minute
        start = _minutes(self.start)
        end = _minutes(self.end)
        if start <= end:
            return start <= now <= end
        # Wraps midnight: allowed late at night OR early in the morning.
        return now >= start or now <= end

    def to_dict(self) -> dict[str, Any]:
        return {"start": self.start, "end": self.end, "days": list(self.days)}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TimeWindow:
        return cls(
            start=str(value.get("start") or "00:00"),
            end=str(value.get("end") or "23:59"),
            days=tuple(int(day) for day in (value.get("days") or ())),
        )


@dataclass(frozen=True)
class RulesOfEngagement:
    """Signed, immutable RoE for one engagement."""

    engagement_id: str
    tenant_id: str
    name: str = ""
    windows: tuple[TimeWindow, ...] = ()
    #: 0 means unlimited.
    max_actions_per_minute: int = 0
    #: 0 means unlimited.
    max_concurrent_actions: int = 0
    forbidden_targets: tuple[str, ...] = ()
    forbidden_categories: tuple[str, ...] = ()
    emergency_contact: str = ""
    #: Sentinel file that, when present, stops every action.
    kill_switch_file: str = ""
    notes: str = ""
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "windows": [window.to_dict() for window in self.windows],
            "max_actions_per_minute": self.max_actions_per_minute,
            "max_concurrent_actions": self.max_concurrent_actions,
            "forbidden_targets": list(self.forbidden_targets),
            "forbidden_categories": list(self.forbidden_categories),
            "emergency_contact": self.emergency_contact,
            "kill_switch_file": self.kill_switch_file,
            "notes": self.notes,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RulesOfEngagement:
        return cls(
            engagement_id=str(value["engagement_id"]),
            tenant_id=str(value["tenant_id"]),
            name=str(value.get("name") or ""),
            windows=tuple(
                TimeWindow.from_dict(item) for item in (value.get("windows") or ())
            ),
            max_actions_per_minute=int(value.get("max_actions_per_minute") or 0),
            max_concurrent_actions=int(value.get("max_concurrent_actions") or 0),
            forbidden_targets=tuple(value.get("forbidden_targets") or ()),
            forbidden_categories=tuple(value.get("forbidden_categories") or ()),
            emergency_contact=str(value.get("emergency_contact") or ""),
            kill_switch_file=str(value.get("kill_switch_file") or ""),
            notes=str(value.get("notes") or ""),
            signature=str(value.get("signature") or ""),
        )

    def canonical_form(self) -> str:
        payload = self.to_dict()
        payload.pop("signature", None)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def sign(self, secret: str) -> RulesOfEngagement:
        """Return a copy signed with HMAC-SHA256 over the canonical form."""
        digest = hmac.new(
            secret.encode("utf-8"), self.canonical_form().encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return RulesOfEngagement(**{**self.__dict__, "signature": digest})

    def signature_valid(self, secret: str | None) -> bool:
        if not self.signature or secret is None:
            return True
        expected = hmac.new(
            secret.encode("utf-8"), self.canonical_form().encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, self.signature)

    def describe(self) -> str:
        """Human-readable summary for ``/roe`` and ``omni --roe``."""
        lines = [
            f"RoE de {self.engagement_id}" + (f" · {self.name}" if self.name else ""),
        ]
        if self.windows:
            for window in self.windows:
                days = _days_label(window.days)
                lines.append(f"  ventana: {days} {window.start}-{window.end}")
        else:
            lines.append("  ventana: sin restricción horaria")
        rate = self.max_actions_per_minute or "sin límite"
        concurrency = self.max_concurrent_actions or "sin límite"
        lines.append(f"  rate: {rate} acciones/min · concurrencia: {concurrency}")
        if self.forbidden_targets:
            lines.append("  prohibidos: " + ", ".join(self.forbidden_targets))
        if self.forbidden_categories:
            lines.append("  categorías prohibidas: " + ", ".join(self.forbidden_categories))
        lines.append(f"  contacto de emergencia: {self.emergency_contact or '(sin definir)'}")
        if self.kill_switch_file:
            lines.append(f"  kill switch: {self.kill_switch_file}")
        if self.notes:
            lines.append(f"  notas: {self.notes}")
        return "\n".join(lines)


_DAY_NAMES = ("lun", "mar", "mié", "jue", "vie", "sáb", "dom")


def _days_label(days: Iterable[int]) -> str:
    values = tuple(sorted({int(day) for day in days}))
    if not values:
        return "todos los días"
    return ",".join(_DAY_NAMES[day] for day in values if 0 <= day <= 6) or "todos los días"


def _target_matches(target: str, pattern: str) -> bool:
    """Match a target against a forbidden pattern (exact or ``*.suffix``)."""
    candidate = str(target).strip().lower().rstrip(".")
    rule = str(pattern).strip().lower().rstrip(".")
    if not rule:
        return False
    if rule.startswith("*."):
        base = rule[2:]
        return bool(base) and candidate != base and candidate.endswith("." + base)
    if rule.startswith("."):
        base = rule[1:]
        return bool(base) and (candidate == base or candidate.endswith("." + base))
    return candidate == rule


class RoEEnforcer:
    """Runtime state for one RoE: sliding rate window, concurrency and stop.

    Kept separate from the immutable policy so the signed RoE never mutates.
    All state is guarded by a lock, so it is safe to share across the UI thread
    and the worker thread.
    """

    def __init__(
        self,
        roe: RulesOfEngagement,
        *,
        stop_event: threading.Event | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] | None = None,
    ):
        self.roe = roe
        self._stop = stop_event or threading.Event()
        self._clock = clock
        self._wall_clock = wall_clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._recent: deque[float] = deque()
        self._active = 0

    # -------------------------------------------------------------- kill switch
    @property
    def stopped(self) -> bool:
        if self._stop.is_set():
            return True
        path = self.roe.kill_switch_file
        return bool(path) and os.path.exists(path)

    def trigger_kill_switch(self) -> None:
        """Stop every action immediately (the sentinel file is the durable form)."""
        self._stop.set()

    def reset(self) -> None:
        """Re-arm: clear the in-process stop flag and the rate window."""
        with self._lock:
            self._stop.clear()
            self._recent.clear()

    # ------------------------------------------------------------------ checks
    def ensure_alive(self) -> None:
        """Raise :class:`RoEKillSwitch` when the kill switch is engaged."""
        if self.stopped:
            raise RoEKillSwitch(
                "kill switch engaged; every action is halted", self.roe.engagement_id
            )

    def check(
        self,
        *,
        targets: Iterable[str] = (),
        category: str | None = None,
        now: datetime | None = None,
    ) -> None:
        """Gate one action; raise :class:`RoEViolation` to deny it.

        Performs, in order: kill switch, forbidden targets/category, time window,
        then rate limit. A rate is recorded only when the action is admitted.
        """
        self.ensure_alive()
        self._check_forbidden(targets, category)
        self._check_window(now)
        self._check_rate()

    def _check_forbidden(self, targets: Iterable[str], category: str | None) -> None:
        if category and str(category).strip().lower() in {
            str(item).strip().lower() for item in self.roe.forbidden_categories
        }:
            raise RoEViolation(
                f"category '{category}' is forbidden by the RoE", self.roe.engagement_id
            )
        for target in targets:
            for pattern in self.roe.forbidden_targets:
                if _target_matches(str(target), pattern):
                    raise RoEViolation(
                        f"target '{target}' is forbidden by the RoE",
                        self.roe.engagement_id,
                    )

    def _check_window(self, now: datetime | None) -> None:
        if not self.roe.windows:
            return
        moment = now or self._wall_clock()
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        if not any(window.allows(moment) for window in self.roe.windows):
            raise RoEViolation(
                "outside the authorized engagement window", self.roe.engagement_id
            )

    def _check_rate(self) -> None:
        limit = self.roe.max_actions_per_minute
        with self._lock:
            now = self._clock()
            while self._recent and now - self._recent[0] >= 60.0:
                self._recent.popleft()
            if limit and len(self._recent) >= limit:
                raise RoEViolation(
                    f"rate limit reached ({limit} acciones/min)", self.roe.engagement_id
                )
            self._recent.append(now)
            if self.roe.max_concurrent_actions:
                if self._active >= self.roe.max_concurrent_actions:
                    raise RoEViolation(
                        "concurrency limit reached", self.roe.engagement_id
                    )

    # ------------------------------------------------------------- concurrency
    @contextmanager
    def slot(
        self,
        *,
        targets: Iterable[str] = (),
        category: str | None = None,
        now: datetime | None = None,
    ) -> Iterator[None]:
        """Gate and hold a concurrency slot for the duration of the block."""
        self.check(targets=targets, category=category, now=now)
        with self._lock:
            self._active += 1
        try:
            yield
        finally:
            with self._lock:
                self._active = max(0, self._active - 1)

    def snapshot(self, *, now: datetime | None = None) -> dict[str, Any]:
        """Read-only state for ``omni --roe`` / ``/roe``."""
        with self._lock:
            window_open = True
            if self.roe.windows:
                moment = now or self._wall_clock()
                window_open = any(window.allows(moment) for window in self.roe.windows)
            return {
                "engagement_id": self.roe.engagement_id,
                "stopped": self.stopped,
                "window_open": window_open,
                "actions_last_minute": len(self._recent),
                "active": self._active,
                "max_actions_per_minute": self.roe.max_actions_per_minute,
                "max_concurrent_actions": self.roe.max_concurrent_actions,
            }


def make_roe_validator(
    enforcer: RoEEnforcer,
) -> Callable[[Any, Any, dict[str, Any]], None]:
    """Build the callable consumed by ``ToolGateway(roe_validator=...)``.

    The kill switch is absolute, so it is checked for *every* tool. The time
    window, forbidden targets and rate limit apply only to target-bearing
    (offensive) tools: a report or a blackboard write at 02:00 is not an
    engagement action.
    """

    def _validator(context: Any, definition: Any, arguments: dict[str, Any]) -> None:
        offensive = bool(
            getattr(definition, "scope_required", False)
            or getattr(definition, "scope_target_field", None)
        )
        if not offensive:
            enforcer.ensure_alive()
            return
        field = getattr(definition, "scope_target_field", None)
        raw = arguments.get(field) if field else None
        if isinstance(raw, (list, tuple)):
            targets: tuple[str, ...] = tuple(str(item) for item in raw)
        elif raw is None:
            targets = ()
        else:
            targets = (str(raw),)
        enforcer.check(targets=targets)

    return _validator


# --------------------------------------------------------------------- store
ROE_DIRNAME = "roe"
_SAFE_ID = re.compile(r"[^A-Za-z0-9_.-]")


def _safe_id(engagement_id: str) -> str:
    return _SAFE_ID.sub("_", str(engagement_id)) or "engagement"


def roe_dir(paths: Any = None) -> Path:
    """Directory holding the durable RoE files (XDG state, ``omni/roe``)."""
    from nexus_core.config.xdg import resolve_xdg_paths

    resolved = paths if paths is not None else resolve_xdg_paths()
    base = getattr(resolved, "state_dir", None) or Path(resolved)
    return Path(base) / ROE_DIRNAME


def roe_path(engagement_id: str, paths: Any = None) -> Path:
    return roe_dir(paths) / f"{_safe_id(engagement_id)}.json"


def kill_switch_path(engagement_id: str, paths: Any = None) -> Path:
    """Sentinel file whose mere existence stops every action."""
    return roe_dir(paths) / f"{_safe_id(engagement_id)}.kill"


def save_roe(roe: RulesOfEngagement, paths: Any = None) -> Path:
    """Persist a RoE atomically with ``0600`` permissions; returns its path."""
    target = roe_path(roe.engagement_id, paths)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = target.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(roe.to_dict(), sort_keys=True, indent=2))
    tmp.chmod(0o600)
    os.replace(tmp, target)
    return target


def load_roe(engagement_id: str, paths: Any = None) -> RulesOfEngagement | None:
    """Load a RoE, or ``None`` when none is configured (RoE is opt-in)."""
    target = roe_path(engagement_id, paths)
    if not target.exists():
        return None
    try:
        return RulesOfEngagement.from_dict(json.loads(target.read_text()))
    except (OSError, ValueError, KeyError, TypeError):
        # A corrupt RoE must fail closed at the caller, never crash a run.
        return None


def delete_roe(engagement_id: str, paths: Any = None) -> bool:
    target = roe_path(engagement_id, paths)
    if not target.exists():
        return False
    target.unlink()
    return True


def load_enforcer(engagement_id: str | None, paths: Any = None) -> RoEEnforcer | None:
    """Build an enforcer for ``engagement_id`` (``None`` slices through to no RoE)."""
    if not engagement_id:
        return None
    roe = load_roe(engagement_id, paths)
    return RoEEnforcer(roe) if roe is not None else None


__all__ = [
    "ROE_DIRNAME",
    "RoEEnforcer",
    "RoEKillSwitch",
    "RoEViolation",
    "RulesOfEngagement",
    "TimeWindow",
    "delete_roe",
    "kill_switch_path",
    "load_enforcer",
    "load_roe",
    "make_roe_validator",
    "roe_dir",
    "roe_path",
    "save_roe",
]
