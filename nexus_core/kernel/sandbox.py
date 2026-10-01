"""Constrained local process runner for development.

Production deployments should replace this implementation with an OCI or
microVM runtime. Shell parsing is deliberately unsupported.
"""

from __future__ import annotations

import asyncio
import os
import signal
import time
from collections.abc import Iterable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4


#: Directory (inside the workspace) that hosts the ephemeral sandbox HOME.
SANDBOX_HOME_DIRNAME = ".sandbox_home"

#: Minimal environment of sandboxed children, before the ephemeral HOME is added.
SANDBOX_BASE_ENV: dict[str, str] = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "NEXUS_SANDBOX": "1",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
}


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    #: ``True`` when the run was stopped by an external ``cancel_event``.
    cancelled: bool = False
    #: Process-group members still alive after the forced kill (0 = clean).
    orphans_detected: int = 0
    #: Wall-clock duration of the run, in seconds.
    duration_seconds: float = 0.0


def _count_process_group(pgid: int) -> int:
    """Best-effort count of live processes whose process group is ``pgid``.

    Linux-only (/proc); any other platform or error degrades to a liveness
    probe (1 alive / 0 dead) so callers still get a usable signal.
    """
    if pgid <= 0:
        return 0
    total = 0
    proc_dir = Path("/proc")
    try:
        entries = [item for item in proc_dir.iterdir() if item.name.isdigit()]
    except OSError:
        entries = []
    for entry in entries:
        try:
            stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # ``pid (comm) state ppid pgrp ...``; comm may contain spaces/parens.
        close = stat.rfind(")")
        if close == -1:
            continue
        fields = stat[close + 1 :].split()
        if len(fields) < 3:
            continue
        try:
            if int(fields[2]) == pgid:
                total += 1
        except ValueError:
            continue
    if total:
        return total
    try:
        os.killpg(pgid, 0)
        return 1
    except ProcessLookupError:
        return 0
    except PermissionError:
        return 1


async def _terminate_process_group(
    process: asyncio.subprocess.Process, grace_seconds: float
) -> int:
    """SIGTERM the group, wait ``grace_seconds``, then SIGKILL. Returns orphans.

    ``process`` must have been started with ``start_new_session=True`` so its
    pid is also its process-group id and the whole descendant tree is signaled.
    """
    pgid = process.pid
    if process.returncode is not None:
        return _count_process_group(pgid)
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGTERM)
    deadline = time.monotonic() + max(0.0, float(grace_seconds))
    while process.returncode is None and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    if process.returncode is None:
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(pgid, signal.SIGKILL)
        # Give the kernel a moment to tear the tree down before counting.
        for _ in range(20):
            if process.returncode is not None:
                break
            await asyncio.sleep(0.05)
    return _count_process_group(pgid)


class LocalSandbox:
    def __init__(
        self,
        workspace_root: str | Path,
        allowed_programs: Iterable[str] = ("python3", "git", "rg"),
        max_output_bytes: int = 1_000_000,
    ):
        self.workspace_root = Path(workspace_root).resolve()
        self.allowed_programs = frozenset(allowed_programs)
        self.max_output_bytes = max_output_bytes

    @property
    def sandbox_home(self) -> Path:
        """Ephemeral HOME of this workspace (created on first ``run``)."""
        return self.workspace_root / SANDBOX_HOME_DIRNAME

    def _is_within_sandbox_home(self, candidate: Path) -> bool:
        home = self.sandbox_home
        return candidate == home or home in candidate.parents

    def resolve_workspace(self, relative: str = ".") -> Path:
        candidate = (self.workspace_root / relative).resolve()
        if candidate != self.workspace_root and self.workspace_root not in candidate.parents:
            raise PermissionError("sandbox path escapes workspace")
        if self._is_within_sandbox_home(candidate):
            # The ephemeral HOME is sandbox plumbing, not agent-visible data.
            raise PermissionError("sandbox path points at the ephemeral HOME")
        return candidate

    def _sandbox_env(self, home_dir: str | Path | None = None) -> dict[str, str]:
        """Build the child environment with an ephemeral HOME.

        Hardened CLI tools (ProjectDiscovery among them) resolve ``HOME`` via
        ``/etc/passwd`` when it is unset and then dump config/caches into their
        cwd, i.e. into the agent workspace. Pointing ``HOME`` and the XDG
        directories at a workspace-local, git-ignored directory keeps the real
        user home untouched and the workspace clean. ``home_dir`` only exists to
        override the location (tests, isolated evaluations).
        """
        resolved_home = (
            Path(home_dir).expanduser().resolve()
            if home_dir is not None
            else self.sandbox_home
        )
        env = dict(SANDBOX_BASE_ENV)
        env["HOME"] = str(resolved_home)
        env["XDG_CONFIG_HOME"] = str(resolved_home / ".config")
        env["XDG_CACHE_HOME"] = str(resolved_home / ".cache")
        env["XDG_DATA_HOME"] = str(resolved_home / ".local" / "share")
        for path in (
            resolved_home,
            Path(env["XDG_CONFIG_HOME"]),
            Path(env["XDG_CACHE_HOME"]),
            Path(env["XDG_DATA_HOME"]),
        ):
            path.mkdir(parents=True, exist_ok=True)
        return env

    async def terminate(
        self, process: asyncio.subprocess.Process, *, grace_seconds: float = 3.0
    ) -> int:
        """Stop a running sandbox process tree; return how many orphans remain."""
        return await _terminate_process_group(process, grace_seconds)

    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str = ".",
        timeout_seconds: float = 30,
        home_dir: str | Path | None = None,
        cancel_event: asyncio.Event | None = None,
        grace_seconds: float = 3.0,
    ) -> SandboxResult:
        """Run ``argv`` in its own process group, honouring timeout and cancel.

        The child is started with ``start_new_session=True`` so the whole
        descendant tree shares one process group. On a timeout or a set
        ``cancel_event`` the group gets SIGTERM, then SIGKILL after
        ``grace_seconds``; an external ``task.cancel()`` is treated the same
        way before the ``CancelledError`` is re-raised.
        """
        if not argv or argv[0] not in self.allowed_programs:
            raise PermissionError("program is not allowed in this sandbox")
        working_directory = self.resolve_workspace(cwd)
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(working_directory),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._sandbox_env(home_dir),
            start_new_session=True,
        )
        communicate = asyncio.ensure_future(process.communicate())
        cancel_waiter = (
            asyncio.ensure_future(cancel_event.wait())
            if cancel_event is not None
            else None
        )
        drained: bytes | None = None
        drained_err: bytes | None = None
        timed_out = cancelled = False
        try:
            waiters: set[Any] = {communicate}
            if cancel_waiter is not None:
                waiters.add(cancel_waiter)
            done, _ = await asyncio.wait(
                waiters,
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if communicate in done:
                drained, drained_err = await communicate
            elif cancel_waiter is not None and cancel_waiter in done:
                cancelled = True
            else:
                timed_out = True
        except asyncio.CancelledError:
            # External cancellation: kill the tree, then let cancellation flow.
            if cancel_waiter is not None:
                cancel_waiter.cancel()
                await asyncio.gather(cancel_waiter, return_exceptions=True)
            await self.terminate(process, grace_seconds=grace_seconds)
            communicate.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await communicate
            raise
        finally:
            if cancel_waiter is not None and not cancel_waiter.done():
                cancel_waiter.cancel()
                await asyncio.gather(cancel_waiter, return_exceptions=True)

        orphans = 0
        if cancelled or timed_out:
            orphans = await self.terminate(process, grace_seconds=grace_seconds)
            try:
                drained, drained_err = await asyncio.wait_for(
                    communicate, timeout=grace_seconds + 5.0
                )
            except Exception:  # noqa: BLE001 - the kill already happened
                drained, drained_err = b"", b""
        elif drained is None:
            drained, drained_err = await communicate
        return SandboxResult(
            exit_code=process.returncode if process.returncode is not None else -1,
            stdout=(drained or b"")[: self.max_output_bytes].decode("utf-8", errors="replace"),
            stderr=(drained_err or b"")[: self.max_output_bytes].decode("utf-8", errors="replace"),
            timed_out=timed_out,
            cancelled=cancelled,
            orphans_detected=orphans,
            duration_seconds=round(time.monotonic() - started, 3),
        )


class OCISandbox:
    """Ephemeral Docker/Podman sandbox for untrusted agent commands."""

    def __init__(
        self,
        workspace_root: str | Path,
        allowed_images: Iterable[str],
        runtime: str = "docker",
        memory: str = "512m",
        cpus: str = "1.0",
        pids_limit: int = 128,
    ):
        if runtime not in {"docker", "podman"}:
            raise ValueError("OCI runtime must be docker or podman")
        self.workspace_root = Path(workspace_root).resolve()
        self.allowed_images = frozenset(allowed_images)
        self.runtime = runtime
        self.memory = memory
        self.cpus = cpus
        self.pids_limit = pids_limit

    def build_argv(self, image: str, command: Sequence[str]) -> list[str]:
        if image not in self.allowed_images:
            raise PermissionError("sandbox image is not allowlisted")
        if not command:
            raise ValueError("sandbox command is required")
        name = f"nexus-sandbox-{uuid4().hex[:12]}"
        return [
            self.runtime, "run", "--rm", "--name", name,
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(self.pids_limit),
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--user", "65532:65532",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            # Ephemeral HOME: keeps tool config/caches off the bind-mounted
            # workspace. Trade-off: a tmpfs is writable by the unprivileged
            # --user only with mode=1777 (sticky, like /tmp), and unlike a real
            # home it is thrown away with the container -- nothing persists, so
            # tools that need a warm cache (nuclei templates) must ship it in
            # the image or get it mounted read-only.
            "--tmpfs", "/home/sandbox:rw,nosuid,nodev,mode=1777,size=32m",
            "--env", "HOME=/home/sandbox",
            "--env", "XDG_CONFIG_HOME=/home/sandbox/.config",
            "--env", "XDG_CACHE_HOME=/home/sandbox/.cache",
            "--env", "XDG_DATA_HOME=/home/sandbox/.local/share",
            "--mount", f"type=bind,src={self.workspace_root},dst=/workspace,rw",
            "--workdir", "/workspace",
            image,
            *command,
        ]

    async def run(
        self,
        image: str,
        command: Sequence[str],
        timeout_seconds: float = 120,
        cancel_event: asyncio.Event | None = None,
        grace_seconds: float = 3.0,
    ) -> SandboxResult:
        argv = self.build_argv(image, command)
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
            start_new_session=True,
        )
        communicate = asyncio.ensure_future(process.communicate())
        cancel_waiter = (
            asyncio.ensure_future(cancel_event.wait())
            if cancel_event is not None
            else None
        )
        drained: bytes | None = None
        drained_err: bytes | None = None
        timed_out = cancelled = False
        try:
            waiters: set[Any] = {communicate}
            if cancel_waiter is not None:
                waiters.add(cancel_waiter)
            done, _ = await asyncio.wait(
                waiters,
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if communicate in done:
                drained, drained_err = await communicate
            elif cancel_waiter is not None and cancel_waiter in done:
                cancelled = True
            else:
                timed_out = True
        except asyncio.CancelledError:
            if cancel_waiter is not None:
                cancel_waiter.cancel()
                await asyncio.gather(cancel_waiter, return_exceptions=True)
            await _terminate_process_group(process, grace_seconds)
            communicate.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await communicate
            raise
        finally:
            if cancel_waiter is not None and not cancel_waiter.done():
                cancel_waiter.cancel()
                await asyncio.gather(cancel_waiter, return_exceptions=True)

        orphans = 0
        if cancelled or timed_out:
            orphans = await _terminate_process_group(process, grace_seconds)
            try:
                drained, drained_err = await asyncio.wait_for(
                    communicate, timeout=grace_seconds + 5.0
                )
            except Exception:  # noqa: BLE001
                drained, drained_err = b"", b""
        elif drained is None:
            drained, drained_err = await communicate
        return SandboxResult(
            process.returncode if process.returncode is not None else -1,
            (drained or b"").decode("utf-8", errors="replace")[:1_000_000],
            (drained_err or b"").decode("utf-8", errors="replace")[:1_000_000],
            timed_out,
            cancelled,
            orphans,
            round(time.monotonic() - started, 3),
        )


def sandbox_for_environment(
    workspace_root: str | Path,
    allowed_programs: Iterable[str] | None = None,
):
    environment = os.getenv("NEXUS_ENV", "development").lower()
    if environment == "production":
        images = [item.strip() for item in os.getenv(
            "NEXUS_SANDBOX_IMAGES", "python:3.12-alpine"
        ).split(",") if item.strip()]
        return OCISandbox(
            workspace_root, images, runtime=os.getenv("NEXUS_OCI_RUNTIME", "docker")
        )
    if allowed_programs is None:
        return LocalSandbox(workspace_root)
    return LocalSandbox(workspace_root, allowed_programs)
