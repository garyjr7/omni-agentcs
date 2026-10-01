"""Read-only OS, manager and binary detection."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
import asyncio
import platform
import re
import shutil
import tempfile
from pathlib import Path


@dataclass(frozen=True)
class OsInfo:
    system: str
    distro: str
    version: str
    arch: str


@dataclass(frozen=True)
class ToolStatus:
    name: str
    present: bool
    path: str | None
    version: str | None
    recipes_available: tuple[str, ...]


class SandboxToolState(str, Enum):
    """How far a tool got: filesystem detection vs. real sandbox execution."""

    ABSENT = "absent"        # not on the user's PATH
    DETECTED = "detected"    # on PATH, not yet verified in the sandbox
    RUNNABLE = "runnable"    # exits 0 inside the sandbox
    FAILED = "failed"        # on PATH but fails inside the sandbox


@dataclass(frozen=True)
class SandboxVerification:
    """Outcome of running a tool's verify command inside the sandbox."""

    name: str
    state: str
    path: str | None
    exit_code: int | None
    output: str
    sandbox_mode: str = ""

    @property
    def runnable(self) -> bool:
        return self.state == SandboxToolState.RUNNABLE.value


def detect_os() -> OsInfo:
    system = platform.system()
    release = {}
    if system == "Linux":
        try:
            release = platform.freedesktop_os_release()
        except OSError:
            pass
    return OsInfo(
        system,
        release.get("ID", system.lower()),
        release.get("VERSION_ID", platform.release()),
        platform.machine(),
    )


def detect_managers() -> tuple[str, ...]:
    system = platform.system()
    names = {
        "Linux": ("apt", "dnf", "yum", "pacman", "zypper", "snap", "flatpak"),
        "Darwin": ("brew", "port"),
    }.get(system, ())
    return tuple(name for name in (*names, "go", "cargo", "pipx", "pip") if shutil.which(name))


def check_tool(name: str) -> ToolStatus:
    from .recipes import find_tool_recipe
    from .installer import probe_command

    recipe = find_tool_recipe(name)
    if recipe is None:
        raise ValueError("unknown tool")
    candidates = [
        recipe["verify"],
        *[r["verify"] for r in recipe["recipes"].values() if "verify" in r],
    ]
    for verify in candidates:
        path = shutil.which(verify[0])
        if path:
            outcome = probe_command([path, *verify[1:]], timeout=3)
            text = re.sub(
                r"\x1b\[[0-?]*[ -/]*[@-~]",
                "",
                (outcome.stdout or "") + "\n" + (outcome.stderr or ""),
            ).strip()
            lines = text.splitlines()
            line = next(
                (line for line in lines if re.search(r"version.*\d|^v?\d+\.\d+", line, re.I)),
                lines[0] if lines else "",
            )
            version = line[:300] if line and outcome.returncode == 0 else None
            # The unrelated Python httpx CLI must not satisfy the PD binary check.
            present = not (name == "httpx" and outcome.returncode != 0)
            return ToolStatus(name, present, path, version, tuple(recipe["recipes"]))
    return ToolStatus(name, False, None, None, tuple(recipe["recipes"]))


def check_all_tools() -> dict[str, ToolStatus]:
    from .recipes import load_recipes

    names = list(load_recipes())
    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(zip(names, pool.map(check_tool, names)))


async def verify_tool_in_sandbox(
    tool_name: str,
    *,
    sandbox_mode: str | None = None,
    workspace_root: str | Path | None = None,
    timeout_seconds: float = 10.0,
) -> SandboxVerification:
    """Run a present tool's verify command inside the sandbox.

    ``DETECTED`` means the binary is on the user's PATH but was never executed
    the way handlers execute it (same allowlist, PATH, HOME and workspace).
    ``RUNNABLE`` means its verify command exits 0 under those exact conditions;
    ``FAILED`` covers a present binary whose dependencies are broken.
    """
    from nexus_core.kernel.sandbox import LocalSandbox
    from nexus_core.kernel.sandbox_modes import active_mode
    from .recipes import find_tool_recipe

    resolved_mode = sandbox_mode or active_mode().value
    status = await asyncio.to_thread(check_tool, tool_name)
    if not status.present or not status.path:
        return SandboxVerification(
            tool_name, SandboxToolState.ABSENT.value, status.path, None, "", resolved_mode
        )
    recipe = find_tool_recipe(tool_name)
    verify = list(recipe["verify"]) if recipe and recipe.get("verify") else [status.path]
    argv = [status.path, *verify[1:]]
    root = (
        Path(workspace_root)
        if workspace_root is not None
        else Path(tempfile.mkdtemp(prefix="nexus-verify-"))
    )
    root.mkdir(parents=True, exist_ok=True)
    sandbox = LocalSandbox(root, allowed_programs=(status.path,))
    try:
        result = await sandbox.run(
            argv, timeout_seconds=timeout_seconds, grace_seconds=2.0
        )
    except Exception as exc:  # noqa: BLE001 - a broken binary must not crash diagnostics
        return SandboxVerification(
            tool_name,
            SandboxToolState.FAILED.value,
            status.path,
            None,
            f"{type(exc).__name__}: {exc}"[:300],
            resolved_mode,
        )
    state = (
        SandboxToolState.RUNNABLE if result.exit_code == 0 else SandboxToolState.FAILED
    )
    output = (result.stdout + "\n" + result.stderr).strip()[:300]
    return SandboxVerification(
        tool_name, state.value, status.path, result.exit_code, output, resolved_mode
    )
