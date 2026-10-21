"""Persistent PTY sessions backed by ``tmux`` (WP1).

Why ``tmux`` and not another process table
------------------------------------------
A shell is useful only if it *survives the call that created it*. ``msfconsole``,
``nc -lvnp``, ``ssh -L`` and ``responder`` are interactive programs: the next
model turn has to write into the same process, not start a new one. ``tmux``
already solves detachment, a scrollback ring buffer and clean teardown, and its
client is a normal argv process, so every operation still goes through
:func:`sandbox_for_environment` (no ``shell=True``, no raw spawn).

Isolation
---------
Each run gets its own tmux **socket** (``tmux -L omni-<run>``) and its own
session prefix (``omni-<run>-<name>``), so two engagements never share a server
and never see each other's panes. Sessions live under the sandbox's ephemeral
HOME; killing the last one also tears the server down.

Ownership
---------
The plan's rule is "una sesión, un dueño": the manager is built from the
engine's ``run_id`` (never from a tool argument), so an agent cannot address a
session that belongs to another run.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from nexus_core.kernel.sandbox import SandboxResult, sandbox_for_environment

#: Programs the sandbox is allowed to start. Only the tmux *client*; the pane
#: command is executed by the tmux server, which is the whole point of a PTY.
PTY_ALLOWED_PROGRAMS: tuple[str, ...] = ("tmux",)

#: Hard limits of the session surface.
PTY_MAX_NAME = 48
PTY_MAX_LINES = 2000
PTY_CAPTURE_RING = 2000
PTY_WAIT_POLL_SECONDS = 0.25
PTY_COMMAND_TIMEOUT_SECONDS = 20
#: A wait is never the agent's way to burn a turn: 60 s is the hard ceiling.
PTY_MAX_WAIT_SECONDS = 60
#: Sessions outlive a call, not the engagement shift. The run-end reaper removes
#: them anyway; this TTL catches a run that died without firing ``session_end``.
PTY_SESSION_TTL_SECONDS = 3600

_TMUX_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_NAME_UNSAFE = re.compile(r"[^A-Za-z0-9_-]+")


@dataclass(frozen=True)
class PtyResult:
    """Outcome of one session operation."""

    session_id: str
    alive: bool
    output: str = ""
    exit_code: int | None = None
    timed_out: bool = False
    error: str | None = None
    #: ``start`` is idempotent: an existing live session is reported, not failed.
    already_running: bool = False

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def _safe_run(run_id: str) -> str:
    text = _NAME_UNSAFE.sub("-", str(run_id or "")).strip("-")
    return text[-12:] or "run"


class PtySessionManager:
    """Start, drive, read and stop persistent tmux sessions for one run."""

    def __init__(
        self,
        workspace_root: str | Path,
        run_id: str,
        *,
        allowed_programs: tuple[str, ...] = PTY_ALLOWED_PROGRAMS,
    ) -> None:
        self.root = str(Path(workspace_root).resolve())
        self.run_id = str(run_id or "")
        safe = _safe_run(self.run_id)
        # The same suffix for the socket and the session prefix: two runs never
        # share a server, and a session id is traceable to its run.
        self.socket = f"omni-{safe}"[:32]
        self.prefix = f"omni-{safe}-"
        self.allowed_programs = allowed_programs

    # --------------------------------------------------------------- identity
    def session_id(self, name: str) -> str:
        """Map the model's label to a deterministic, run-owned tmux session id."""
        text = str(name or "").strip()
        if not text:
            raise ValueError("name is required")
        if text.startswith("omni-") and _TMUX_ID.fullmatch(text):
            return text
        slug = _NAME_UNSAFE.sub("-", text).strip("-")[:24] or "pty"
        return f"{self.prefix}{slug}"[:PTY_MAX_NAME]

    # ---------------------------------------------------------------- plumbing
    def sandbox(self):
        """The effective sandbox for this run (PTY needs a persistent one)."""
        return sandbox_for_environment(self.root, allowed_programs=self.allowed_programs)

    async def _tmux(self, *args: str, timeout_seconds: float = PTY_COMMAND_TIMEOUT_SECONDS) -> SandboxResult:
        sandbox = self.sandbox()
        # ``TERM`` is not a sandbox control: tmux needs a terminal description
        # even for a detached session.
        return await sandbox.run(
            ["tmux", "-L", self.socket, *args],
            cwd=".",
            timeout_seconds=timeout_seconds,
            extra_env={"TERM": "xterm-256color"},
        )

    @staticmethod
    def _error(result: SandboxResult, fallback: str) -> str | None:
        if result.timed_out:
            return "tmux_timeout"
        if result.exit_code == 0:
            return None
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        return (detail[0][:300] if detail else fallback) or fallback

    def owns(self, session_ref: str) -> bool:
        """Whether ``session_ref`` is a tmux session of *this* run.

        A ref read from the durable registry is data, not a capability: before it
        is handed to ``tmux`` it must still belong to this run's prefix, otherwise
        a forged row could address another engagement's pane on the host.
        """
        text = str(session_ref or "")
        return bool(_TMUX_ID.fullmatch(text)) and text.startswith(self.prefix)

    async def exists(self, name: str) -> bool:
        """Whether the run-owned session is still alive."""
        session = self.session_id(name)
        result = await self._tmux("has-session", "-t", session)
        return result.exit_code == 0 and not result.timed_out

    async def list_sessions(self) -> list[dict[str, object]]:
        """Live sessions of this run (name and tmux creation epoch)."""
        try:
            listed = await self._tmux(
                "list-sessions", "-F", "#{session_name}\t#{session_created}"
            )
        except Exception:  # noqa: BLE001 - inventory never breaks the caller
            return []
        if listed.exit_code != 0:
            return []
        sessions: list[dict[str, object]] = []
        for line in listed.stdout.splitlines():
            name, _, created = line.partition("\t")
            name = name.strip()
            if not name.startswith(self.prefix):
                continue
            try:
                created_at = float(created)
            except (TypeError, ValueError):
                created_at = None
            sessions.append({"name": name, "created": created_at})
        return sessions

    async def reap(self, *, older_than_seconds: int | None = None) -> int:
        """Kill this run's tmux sessions (all, or only those past a TTL).

        Best-effort by construction: a missing tmux, a dead server or a session
        that disappears between ``list-sessions`` and ``kill-session`` must never
        turn a cleanup into a run failure. Only names under this run's prefix are
        touched, so another engagement's server is invisible.
        """
        try:
            listed = await self._tmux(
                "list-sessions", "-F", "#{session_name}\t#{session_created}"
            )
        except Exception:  # noqa: BLE001 - cleanup never blocks the caller
            return 0
        if listed.exit_code != 0 or not listed.stdout.strip():
            return 0
        now = time.time()
        killed = 0
        for line in listed.stdout.splitlines():
            name, _, created = line.partition("\t")
            name = name.strip()
            if not name.startswith(self.prefix):
                continue
            if older_than_seconds is not None:
                try:
                    age = now - float(created)
                except (TypeError, ValueError):
                    continue
                if age < max(0, int(older_than_seconds)):
                    continue
            try:
                result = await self._tmux("kill-session", "-t", name)
            except Exception:  # noqa: BLE001 - one wedged session is not fatal
                continue
            if result.exit_code == 0:
                killed += 1
        return killed

    # ---------------------------------------------------------------- actions
    async def start(self, cmd: str, name: str) -> PtyResult:
        """Create a detached session running ``cmd`` with the workspace as cwd."""
        command = str(cmd or "").strip()
        if not command:
            raise ValueError("start requires cmd")
        session = self.session_id(name)
        if await self.exists(name):
            # Idempotent start: the model retrying a kickoff turn must not lose
            # the session it already owns (or pay a second ``msfconsole``).
            return PtyResult(session_id=session, alive=True, already_running=True)
        result = await self._tmux(
            "new-session", "-d", "-s", session, "-c", self.root,
            "-x", "200", "-y", "50",
            "bash", "-lc", command,
            timeout_seconds=PTY_COMMAND_TIMEOUT_SECONDS,
        )
        error = self._error(result, "session_start_failed")
        alive = await self.exists(name)
        return PtyResult(
            session_id=session,
            alive=alive,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            error=error if error else (None if alive else "session_exited_immediately"),
        )

    async def send(self, name: str, text: str) -> PtyResult:
        """Type ``text`` literally into the session and press Enter."""
        if text is None or text == "":
            raise ValueError("send requires text")
        session = self.session_id(name)
        if not await self.exists(name):
            return PtyResult(session_id=session, alive=False, error="session_not_found")
        literal = await self._tmux(
            "send-keys", "-t", session, "-l", "--", str(text),
            timeout_seconds=PTY_COMMAND_TIMEOUT_SECONDS,
        )
        error = self._error(literal, "session_send_failed")
        if error:
            return PtyResult(
                session_id=session, alive=await self.exists(name),
                exit_code=literal.exit_code, timed_out=literal.timed_out, error=error,
            )
        enter = await self._tmux(
            "send-keys", "-t", session, "Enter",
            timeout_seconds=PTY_COMMAND_TIMEOUT_SECONDS,
        )
        error = self._error(enter, "session_send_failed")
        return PtyResult(
            session_id=session,
            alive=await self.exists(name),
            exit_code=enter.exit_code,
            timed_out=enter.timed_out,
            error=error,
        )

    async def capture(self, name: str, *, lines: int = 200) -> PtyResult:
        """Return the last ``lines`` of the pane's ring buffer."""
        limit = max(1, min(int(lines), PTY_MAX_LINES))
        session = self.session_id(name)
        if not await self.exists(name):
            return PtyResult(session_id=session, alive=False, error="session_not_found")
        result = await self._tmux(
            "capture-pane", "-p", "-t", session, "-S", f"-{PTY_CAPTURE_RING}",
            timeout_seconds=PTY_COMMAND_TIMEOUT_SECONDS,
        )
        error = self._error(result, "session_capture_failed")
        captured = result.stdout.splitlines()
        return PtyResult(
            session_id=session,
            alive=True,
            output="\n".join(captured[-limit:]),
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            error=error,
        )

    async def wait(
        self, name: str, pattern: str, *, timeout_seconds: int = 30
    ) -> PtyResult:
        """Poll the pane until ``pattern`` appears, the deadline expires or it dies."""
        text = str(pattern or "")
        if not text:
            raise ValueError("wait requires pattern")
        timeout_seconds = max(1, min(int(timeout_seconds), PTY_MAX_WAIT_SECONDS))
        try:
            # MULTILINE so ``^``/``$`` mean "line" in a captured pane, which is
            # what an operator writing a prompt pattern expects.
            matcher = re.compile(text, re.MULTILINE)
        except re.error as exc:
            raise ValueError(f"invalid wait pattern: {exc}") from exc
        deadline = time.monotonic() + timeout_seconds
        latest = await self.capture(name)
        while True:
            if latest.error == "session_not_found":
                return latest
            if matcher.search(latest.output or ""):
                return latest
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return PtyResult(
                    session_id=latest.session_id,
                    alive=latest.alive,
                    output=latest.output,
                    exit_code=latest.exit_code,
                    timed_out=True,
                    error="wait_timeout",
                )
            await asyncio.sleep(min(PTY_WAIT_POLL_SECONDS, remaining))
            latest = await self.capture(name)

    async def kill(self, name: str) -> PtyResult:
        """Terminate the session (the tmux server exits with its last session)."""
        session = self.session_id(name)
        if not await self.exists(name):
            return PtyResult(session_id=session, alive=False, error="session_not_found")
        result = await self._tmux(
            "kill-session", "-t", session,
            timeout_seconds=PTY_COMMAND_TIMEOUT_SECONDS,
        )
        error = self._error(result, "session_kill_failed")
        return PtyResult(
            session_id=session,
            alive=await self.exists(name),
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            error=error,
        )


__all__ = [
    "PTY_ALLOWED_PROGRAMS",
    "PTY_CAPTURE_RING",
    "PTY_MAX_LINES",
    "PTY_MAX_NAME",
    "PTY_MAX_WAIT_SECONDS",
    "PTY_SESSION_TTL_SECONDS",
    "PtyResult",
    "PtySessionManager",
]
