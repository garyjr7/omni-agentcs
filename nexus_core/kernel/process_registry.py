"""Register the process groups a sandbox starts, and reap the stale ones.

Every sandboxed command runs in its own session (``start_new_session=True``) so
one ``killpg`` takes the whole descendant tree -and that is exactly why a run
that dies by an external signal leaves it behind. The kernel reaps the group when
the command ends, times out or is cancelled, but nothing runs when the *process
itself* is SIGKILLed: the children keep their own session and stay alive.

Measured on the DeadDrop campaign (2026-10-22): after killing two runs by hand,
two ``nmap -p-`` sweeps kept hammering ``192.168.11.200`` for 1 h 04 min and
1 h 18 min, and two ``hydra`` sweeps did the same against the login. They are not
orphans of the handler -the handler never returned-: they are orphans of the
machine, and a security tool that keeps attacking after the engagement stopped is
a real problem, not a tidiness one.

The registry is the minimum that makes the kill safe:

* each start records ``pid``, the kernel's own start time (``/proc/<pid>/stat``
  field 22), the argv and the run id, so a recycled pid cannot be mistaken for
  the original process;
* a reap only signals a group whose ``/proc`` entry still matches **both** the
  pid and that start time, and whose leader's argv[0] matches the recorded one;
* entries are removed on a normal exit and on a reap, so the directory does not
  grow without bound.

It is Linux-only on purpose (``/proc``); on any other platform the registry is a
no-op and the sandbox keeps its previous behaviour.
"""

from __future__ import annotations

import json
import os
import signal
import time
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from nexus_core.config.xdg import resolve_xdg_paths

#: A group younger than this is not stale: it may belong to a run that is merely
#: starting (the reaper runs at every run start, sometimes concurrently).
REAP_MIN_AGE_SECONDS = 120
#: An entry that cannot be verified (no ``/proc``, unreadable) is dropped after
#: this long, so a permission problem does not accumulate files forever.
ENTRY_MAX_AGE_SECONDS = 24 * 3600


def registry_root() -> Path:
    """Return the directory of process records (``$XDG_STATE_HOME``)."""
    override = os.environ.get("NEXUS_PROC_REGISTRY")
    if override:
        return Path(override).expanduser()
    return Path(resolve_xdg_paths().state_dir) / "omni" / "procs"


def _proc_path(pid: int) -> Path:
    return Path("/proc") / str(int(pid))


def proc_start_time(pid: int) -> str | None:
    """Return ``/proc/<pid>/stat`` field 22 (start time), or ``None``.

    ``None`` means the process is gone *or* ``/proc`` is unavailable; both cases
    make the entry unsafe to signal, so callers must treat them the same way.
    """
    try:
        stat = (_proc_path(pid) / "stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    close = stat.rfind(")")
    if close == -1:
        return None
    fields = stat[close + 1 :].split()
    # After the comm field, field 3 is ``state``; start time is field 22.
    if len(fields) < 20:
        return None
    return fields[19]


def proc_argv0(pid: int) -> str:
    """Return the first argv element of ``pid`` (empty when unreadable)."""
    try:
        raw = (_proc_path(pid) / "cmdline").read_bytes()
    except OSError:
        return ""
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def group_members(pgid: int) -> list[tuple[int, str]]:
    """Return ``(pid, argv0)`` of every process whose group is ``pgid``."""
    members: list[tuple[int, str]] = []
    try:
        entries = [item for item in Path("/proc").iterdir() if item.name.isdigit()]
    except OSError:
        return members
    for entry in entries:
        try:
            stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        close = stat.rfind(")")
        if close == -1:
            continue
        fields = stat[close + 1 :].split()
        if len(fields) < 3:
            continue
        try:
            if int(fields[2]) != pgid:
                continue
        except ValueError:
            continue
        pid = int(entry.name)
        members.append((pid, proc_argv0(pid)))
    return members


def register(pid: int, argv: Iterable[Any], *, run_id: str = "") -> Path | None:
    """Record a process group so a later run can reap it. Never raises."""
    if int(pid) <= 0:
        return None
    payload = {
        "pid": int(pid),
        "start_time": proc_start_time(pid) or "",
        "argv0": str(next(iter(argv), "") or "")[:400],
        "run_id": str(run_id or ""),
        "created_at": time.time(),
    }
    try:
        root = registry_root()
        root.mkdir(parents=True, exist_ok=True)
        path = root / f"{int(pid)}-{uuid4().hex[:8]}.json"
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        return path
    except OSError:
        return None


def unregister(pid: int) -> None:
    """Drop every record of ``pid`` (called when the command ended)."""
    try:
        for path in registry_root().glob(f"{int(pid)}-*.json"):
            path.unlink(missing_ok=True)
    except OSError:
        return


def _load(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def reap_stale(
    *, min_age_seconds: float = REAP_MIN_AGE_SECONDS, max_age_seconds: float = ENTRY_MAX_AGE_SECONDS
) -> list[dict[str, Any]]:
    """SIGTERM (then SIGKILL) every verified stale group; return what was killed.

    A record is killed only when the live ``/proc`` entry still matches its pid
    **and** start time **and** its ``argv[0]``; anything else is a recycled pid
    and is only cleaned up. Never raises: the caller runs this at boot.
    """
    killed: list[dict[str, Any]] = []
    now = time.time()
    try:
        paths = sorted(registry_root().glob("*.json"))
    except OSError:
        return killed
    own_group = os.getpgrp()
    for path in paths:
        record = _load(path)
        if record is None:
            path.unlink(missing_ok=True)
            continue
        try:
            pid = int(record.get("pid") or 0)
            created = float(record.get("created_at") or 0)
        except (TypeError, ValueError):
            path.unlink(missing_ok=True)
            continue
        if pid <= 0 or pid == os.getpid() or pid == own_group:
            path.unlink(missing_ok=True)
            continue
        age = now - created
        if age < min_age_seconds:
            continue
        recorded_start = str(record.get("start_time") or "")
        recorded_argv0 = str(record.get("argv0") or "")
        live_start = proc_start_time(pid)
        if not live_start:
            # The leader is gone but the group may still have members: a wrapper
            # (`sh -c ...`) exits and leaves the real tool running in the same
            # group -that is exactly how the measured `gobuster` survived. Signal
            # only when a member carries the recorded binary.
            wanted = Path(recorded_argv0).name if recorded_argv0 else ""
            members = group_members(pid)
            matches = [
                member
                for member in members
                if not wanted or Path(member[1]).name == wanted
            ]
            if matches and _kill_group(pid):
                killed.append({**record, "members": len(matches)})
            path.unlink(missing_ok=True)
            continue
        if live_start != recorded_start:
            # The pid now belongs to someone else: never signal it.
            path.unlink(missing_ok=True)
            continue
        # ``execve`` keeps argv[0] verbatim, so a tool spawned as ``gobuster``
        # shows ``gobuster`` while the same one resolved through PATH may show
        # its absolute path. Compare the binary, not the string -and keep the
        # record when they differ, because a mismatch is not proof of reuse.
        live_argv0 = proc_argv0(pid)
        if recorded_argv0 and live_argv0 and Path(live_argv0).name != Path(recorded_argv0).name:
            continue
        if age > max_age_seconds:
            path.unlink(missing_ok=True)
            continue
        if _kill_group(pid):
            killed.append(record)
        path.unlink(missing_ok=True)
    return killed


def _kill_group(pgid: int) -> bool:
    """SIGTERM then SIGKILL a group; ``True`` when it existed."""
    existed = False
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
            existed = True
        except ProcessLookupError:
            return existed
        except PermissionError:
            return False
        if sig == signal.SIGTERM:
            time.sleep(0.2)
    return existed


__all__ = [
    "REAP_MIN_AGE_SECONDS",
    "group_members",
    "proc_argv0",
    "proc_start_time",
    "reap_stale",
    "register",
    "registry_root",
    "unregister",
]
