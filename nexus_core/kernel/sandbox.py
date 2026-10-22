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
from contextlib import suppress, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Awaitable, Callable
from typing import Any

from .output_capture import BoundedCapture, StreamManifest
from .process_registry import register as register_process_group
from .process_registry import unregister as unregister_process_group
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

#: Overrides the extra directory prepended to the sandbox PATH.
TOOL_BIN_DIR_ENV = "NEXUS_TOOL_BIN_DIR"


def tool_bin_dir() -> Path | None:
    """Directory holding user-installed tools (``pipx`` / ``pip --user``).

    ``NEXUS_TOOL_BIN_DIR`` overrides the default ``~/.local/bin``. Returns
    ``None`` when no home directory can be resolved.
    """
    override = os.getenv(TOOL_BIN_DIR_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    try:
        return Path.home() / ".local" / "bin"
    except (RuntimeError, OSError):  # pragma: no cover - no home resolvable
        return None


def sandbox_path(base: str | None = None) -> str:
    """PATH of sandboxed children: the minimal base **plus** the user tool dir.

    The ephemeral HOME keeps tool config out of the real home, but the
    *executables* installed by ``pipx``/``pip --user`` live in the operator's
    ``~/.local/bin``. Without it, a binary the detector calls "present" is not
    runnable from the sandbox (audit H3). A non-existent directory on PATH is
    harmless, so it is always prepended for a deterministic result.
    """
    resolved = base if base is not None else SANDBOX_BASE_ENV["PATH"]
    extra = tool_bin_dir()
    if extra is None:
        return resolved
    text = str(extra)
    entries = resolved.split(":")
    if text in entries:
        return resolved
    return ":".join([text, *entries])


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
    stdout_manifest: StreamManifest | None = None
    stderr_manifest: StreamManifest | None = None


def merge_extra_env(env: dict[str, str], extra_env: dict[str, str] | None) -> dict[str, str]:
    """Merge caller-provided variables into a sandbox environment, safely.

    Sandboxed children get a fixed environment (``PATH``, ``HOME``, the XDG
    dirs). A handler may still need to hand a tool-specific variable to the
    child -- ``KRB5CCNAME`` for the Kerberos tooling is the measured case
    (RUN_sala10 §7.6) -- so unknown keys are accepted while the sandbox's own
    controls stay non-overridable (fail closed, never silently ignore).
    """
    extra = {str(key): str(value) for key, value in (extra_env or {}).items()}
    if any(key in env or key.startswith("XDG_") for key in extra):
        raise PermissionError("cannot override sandbox environment controls")
    env.update(extra)
    return env


def _insert_oci_env(command: list[str], image: str, extra_env: dict[str, str] | None) -> None:
    """Insert ``--env`` pairs before the image, refusing sandbox controls."""
    for key, value in (extra_env or {}).items():
        if key in {"HOME", "PATH"} or str(key).startswith("XDG_"):
            raise PermissionError("cannot override sandbox environment controls")
    position = command.index(image)
    for key, value in (extra_env or {}).items():
        command[position:position] = ["--env", f"{key}={value}"]
        position += 2


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
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGTERM)
    deadline = time.monotonic() + max(0.0, float(grace_seconds))
    while process.returncode is None and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    if process.returncode is None or _count_process_group(pgid):
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(pgid, signal.SIGKILL)
        # Give the kernel a moment to tear the tree down before counting.
        for _ in range(20):
            if process.returncode is not None:
                break
            await asyncio.sleep(0.05)
    return _count_process_group(pgid)


async def _capture_process(
    process: asyncio.subprocess.Process, limit: int, timeout: float,
    cancel_event: asyncio.Event | None, grace: float, started: float,
    cleanup: Callable[[], Awaitable[None]] | None = None,
    *, input_data: bytes | None = None,
) -> SandboxResult:
    assert process.stdout is not None and process.stderr is not None
    stdout, stderr = BoundedCapture(limit), BoundedCapture(limit)
    # Start draining stdout/stderr *before* writing stdin: a child that writes
    # more than a pipe buffer before reading its input would otherwise deadlock
    # against a full stdout pipe on both ends.
    readers = [asyncio.create_task(stdout.drain(process.stdout)),
               asyncio.create_task(stderr.drain(process.stderr))]
    stdin_task: asyncio.Task[None] | None = None
    if input_data is not None and process.stdin is not None:
        async def _feed_stdin() -> None:
            assert process.stdin is not None
            try:
                process.stdin.write(input_data)
                await process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                # The child exited without consuming stdin; that is its answer,
                # not a transport failure of the sandbox.
                pass
            finally:
                process.stdin.close()
                with suppress(BrokenPipeError, ConnectionResetError):
                    await process.stdin.wait_closed()

        # A child that never reads stdin must not stall the call: the feed runs
        # concurrently with the timeout/cancel waiters below.
        stdin_task = asyncio.create_task(_feed_stdin())
    completed = asyncio.gather(process.wait(), *readers)
    cancel = asyncio.create_task(cancel_event.wait()) if cancel_event else None
    timed_out = cancelled = False
    orphans = 0
    try:
        waiters: set[asyncio.Future[Any]] = {completed}
        if cancel is not None:
            waiters.add(cancel)
        done, _ = await asyncio.wait(waiters, timeout=timeout,
                                     return_when=asyncio.FIRST_COMPLETED)
        if completed not in done:
            cancelled = cancel is not None and cancel in done
            timed_out = not cancelled
            if cleanup is not None:
                await cleanup()
            orphans = await _terminate_process_group(process, grace)
            try:
                await asyncio.wait_for(asyncio.shield(completed), grace + 5)
            except asyncio.TimeoutError:
                pass
        else:
            await completed
    except BaseException:
        try:
            if cleanup is not None:
                await cleanup()
        finally:
            await _terminate_process_group(process, grace)
        raise
    finally:
        if cancel is not None:
            cancel.cancel()
            await asyncio.gather(cancel, return_exceptions=True)
        if not completed.done():
            completed.cancel()
        await asyncio.gather(completed, return_exceptions=True)
        if stdin_task is not None:
            if not stdin_task.done():
                stdin_task.cancel()
            await asyncio.gather(stdin_task, return_exceptions=True)
    return SandboxResult(
        process.returncode if process.returncode is not None else -1,
        stdout.text(), stderr.text(), timed_out, cancelled, orphans,
        round(time.monotonic() - started, 3), stdout.manifest(), stderr.manifest(),
    )


class LocalSandbox:
    def __init__(
        self,
        workspace_root: str | Path,
        allowed_programs: Iterable[str] = ("python3", "git", "rg"),
        max_output_bytes: int = 1_000_000,
    ):
        self.workspace_root = Path(workspace_root).resolve()
        self.allowed_programs = frozenset(allowed_programs)
        if max_output_bytes < 0:
            raise ValueError("capture limit must be nonnegative")
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
        # Include the operator's user bin dir so tools installed by pipx are
        # runnable (audit H3); the ephemeral HOME above is set afterwards.
        env["PATH"] = sandbox_path()
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

    @asynccontextmanager
    async def open_stdio(self, argv, *, cwd=".", extra_env=None):
        """Streaming child with the same argv/cwd/env policy as run()."""
        if not argv or argv[0] not in self.allowed_programs:
            raise PermissionError("program is not allowed in this sandbox")
        env = merge_extra_env(self._sandbox_env(), extra_env)
        process = await asyncio.create_subprocess_exec(
            *argv, cwd=str(self.resolve_workspace(cwd)), env=env,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, start_new_session=True,
            limit=self.max_output_bytes,
        )
        try:
            yield process
        finally:
            await _terminate_process_group(process, 1.0)
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            await process.wait()

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
        extra_env: dict[str, str] | None = None,
        cancel_event: asyncio.Event | None = None,
        grace_seconds: float = 3.0,
        input_data: bytes | str | None = None,
    ) -> SandboxResult:
        """Run ``argv`` in its own process group, honouring timeout and cancel.

        The child is started with ``start_new_session=True`` so the whole
        descendant tree shares one process group. On a timeout or a set
        ``cancel_event`` the group gets SIGTERM, then SIGKILL after
        ``grace_seconds``; an external ``task.cancel()`` is treated the same
        way before the ``CancelledError`` is re-raised. ``extra_env`` adds
        tool-specific variables (never PATH/HOME/XDG). ``input_data`` feeds
        stdin (used by the universal shell); the handlers cap its size.
        """
        if not argv or argv[0] not in self.allowed_programs:
            raise PermissionError("program is not allowed in this sandbox")
        working_directory = self.resolve_workspace(cwd)
        encoded = (input_data.encode("utf-8") if isinstance(input_data, str)
                   else input_data)
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(working_directory),
            stdin=asyncio.subprocess.PIPE if encoded is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=merge_extra_env(self._sandbox_env(home_dir), extra_env),
            start_new_session=True,
        )
        # The command runs in its own session, so a run that dies by signal
        # leaves the group behind; record it so the next run can reap it.
        register_process_group(process.pid, argv)
        try:
            return await _capture_process(
                process, self.max_output_bytes, timeout_seconds, cancel_event,
                grace_seconds, started, input_data=encoded,
            )
        finally:
            unregister_process_group(process.pid)



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
        max_output_bytes: int = 1_000_000,
    ):
        if runtime not in {"docker", "podman"}:
            raise ValueError("OCI runtime must be docker or podman")
        self.workspace_root = Path(workspace_root).resolve()
        self.allowed_images = frozenset(allowed_images)
        self.runtime = runtime
        self.memory = memory
        self.cpus = cpus
        self.pids_limit = pids_limit
        if max_output_bytes < 0:
            raise ValueError("capture limit must be nonnegative")
        self.max_output_bytes = max_output_bytes

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

    @asynccontextmanager
    async def open_stdio(self, argv, *, image, extra_env=None):
        """Interactive OCI process; stop the daemon-owned container on exit."""
        command = self.build_argv(image, argv)
        command.insert(2, "--interactive")
        _insert_oci_env(command, image, extra_env)
        name = command[command.index("--name") + 1]
        process = await asyncio.create_subprocess_exec(
            *command, cwd=str(self.workspace_root), env=dict(SANDBOX_BASE_ENV),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, start_new_session=True,
        )
        try:
            yield process
        finally:
            cleanup = await asyncio.create_subprocess_exec(
                self.runtime, "rm", "--force", name,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                env=dict(SANDBOX_BASE_ENV), start_new_session=True,
            )
            try:
                await asyncio.wait_for(cleanup.wait(), 10)
            except asyncio.TimeoutError:
                await _terminate_process_group(cleanup, 1)
            await _terminate_process_group(process, 1)
            await process.wait()

    async def run(
        self,
        image: str,
        command: Sequence[str],
        timeout_seconds: float = 120,
        extra_env: dict[str, str] | None = None,
        cancel_event: asyncio.Event | None = None,
        grace_seconds: float = 3.0,
        input_data: bytes | str | None = None,
    ) -> SandboxResult:
        argv = self.build_argv(image, command)
        _insert_oci_env(argv, image, extra_env)
        encoded = (input_data.encode("utf-8") if isinstance(input_data, str)
                   else input_data)
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if encoded is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
            start_new_session=True,
        )
        register_process_group(process.pid, argv)

        async def cleanup_container() -> None:
            unregister_process_group(process.pid)
            cleanup = await asyncio.create_subprocess_exec(
                self.runtime, "rm", "--force", argv[argv.index("--name") + 1],
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                await asyncio.wait_for(cleanup.wait(), 10)
            except asyncio.TimeoutError:
                await _terminate_process_group(cleanup, 1)

        return await _capture_process(process, self.max_output_bytes, timeout_seconds,
                                      cancel_event, grace_seconds, started, cleanup_container,
                                      input_data=encoded)


def sandbox_for_environment(
    workspace_root: str | Path,
    allowed_programs: Iterable[str] | None = None,
):
    from .sandbox_modes import SandboxPolicy

    return SandboxPolicy.resolve(workspace_root=workspace_root, allowed_programs=allowed_programs)[1]
