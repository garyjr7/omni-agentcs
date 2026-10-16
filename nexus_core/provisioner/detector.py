"""Read-only OS, manager and binary detection."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
import asyncio
import platform
import re
import shutil
import tempfile
import os
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
    state: str = "detected"
    detail: str = ""
    verify_argv: tuple[str, ...] = ()


class SandboxToolState(str, Enum):
    """How far a tool got: filesystem detection vs. real sandbox execution."""

    ABSENT = "absent"  # not on the user's PATH
    DETECTED = "detected"  # on PATH, not yet verified in the sandbox
    RUNNABLE = "runnable"  # exits 0 inside the sandbox
    FAILED = "failed"  # on PATH but fails inside the sandbox


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
    from .binaries import BINARY_IDENTITIES_BY_NAME, classify_identity, default_version_runner

    try:
        recipe = find_tool_recipe(name)
        if recipe is None:
            return ToolStatus(name, False, None, None, (), "unsupported", "unknown tool")
        managers = tuple(recipe["recipes"])
        candidates = [
            recipe["verify"],
            *[r["verify"] for r in recipe["recipes"].values() if "verify" in r],
        ]
        failed: ToolStatus | None = None
        for verify in candidates:
            path = shutil.which(verify[0])
            if not path:
                continue
            code, text = default_version_runner([path, *verify[1:]], timeout=3)
            text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text).strip()
            identity = BINARY_IDENTITIES_BY_NAME.get(verify[0])
            ok = code == 0 and (
                identity is None
                or classify_identity(
                    identity, path=path, present=True, output=text, exit_code=code
                ).ok
            )
            lines = text.splitlines()
            line = next(
                (line for line in lines if re.search(r"version.*\d|^v?\d+\.\d+", line, re.I)),
                lines[0] if lines else "",
            )
            status = ToolStatus(
                name,
                True,
                path,
                line[:300] if ok and line else None,
                managers,
                "runnable" if ok else "failed",
                "" if ok else "version/identity probe failed",
                tuple([path, *verify[1:]]),
            )
            if ok:
                return status
            failed = status
        return failed or ToolStatus(name, False, None, None, managers, "absent")
    except Exception as exc:
        return ToolStatus(name, False, None, None, (), "failed", type(exc).__name__)


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
    from nexus_core.kernel.sandbox_modes import SandboxPolicy
    from nexus_core.kernel.sandbox import OCISandbox
    from .recipes import find_tool_recipe
    from .binaries import BINARY_IDENTITIES_BY_NAME, classify_identity

    mode: str = str(sandbox_mode or os.getenv("NEXUS_SANDBOX_MODE", ""))
    try:
        recipe = find_tool_recipe(tool_name)
        if not recipe:
            return SandboxVerification(tool_name, "failed", None, None, "unknown tool", mode)
        # OCI verification requires an explicit image: host PATH is not evidence
        # about the contents of an image. Never fall back to a local executor.
        env = dict(os.environ)
        if sandbox_mode:
            env["NEXUS_SANDBOX_MODE"] = sandbox_mode
        with tempfile.TemporaryDirectory(prefix="nexus-verify-") as temporary:
            root = Path(workspace_root) if workspace_root is not None else Path(temporary)
            root.mkdir(parents=True, exist_ok=True)
            verify = list(recipe["verify"])
            resolved, sandbox, _ = SandboxPolicy.resolve(
                env, workspace_root=root, allowed_programs=(verify[0],)
            )
            mode = str(resolved.value)
            if isinstance(sandbox, OCISandbox):
                image_keys = {
                    "nmap": "NEXUS_NMAP_IMAGE", "ffuf": "NEXUS_FFUF_IMAGE",
                    "nuclei": "NEXUS_NUCLEI_IMAGE", "httpx": "NEXUS_HTTPX_IMAGE",
                    "subfinder": "NEXUS_SUBFINDER_IMAGE", "sqlmap": "NEXUS_SQLMAP_IMAGE",
                    "gobuster": "NEXUS_GOBUSTER_IMAGE", "nikto": "NEXUS_NIKTO_IMAGE",
                    "whatweb": "NEXUS_WHATWEB_IMAGE", "dalfox": "NEXUS_DALFOX_IMAGE",
                    "searchsploit": "NEXUS_SEARCHSPLOIT_IMAGE", "nxc": "NEXUS_NETEXEC_IMAGE",
                    "bloodhound-python": "NEXUS_BLOODHOUND_IMAGE",
                }
                image_key = image_keys.get(verify[0], "")
                image = env.get(image_key, "")
                if not image:
                    return SandboxVerification(
                        tool_name,
                        "detected",
                        None,
                        None,
                        "configure the handler image variable and allowlist; container not verified",
                        mode,
                    )
                result = await sandbox.run(image, verify, timeout_seconds=timeout_seconds)
                path = verify[0]
            else:
                status = await asyncio.to_thread(check_tool, tool_name)
                if not status.present or not status.path:
                    return SandboxVerification(
                        tool_name, status.state, status.path, None, status.detail, mode
                    )
                from nexus_core.kernel.sandbox import LocalSandbox

                path = status.path
                sandbox = LocalSandbox(root, allowed_programs=(path,))
                result = await sandbox.run(
                    list(status.verify_argv), timeout_seconds=timeout_seconds
                )
            complete = not (result.timed_out or result.cancelled) and all(
                m is None or (m.complete and not m.truncated and not m.error)
                for m in (result.stdout_manifest, result.stderr_manifest)
            )
            output = (result.stdout + "\n" + result.stderr).strip()
            identity = BINARY_IDENTITIES_BY_NAME.get(verify[0])
            ok = result.exit_code == 0 and complete
            if identity:
                ok = ok and classify_identity(identity, path=path, present=True, output=output).ok
            # Version output may contain environment secrets; return a verdict only.
            return SandboxVerification(
                tool_name,
                "runnable" if ok else "failed",
                path,
                result.exit_code,
                "verified" if ok else "probe failed",
                mode,
            )
    except Exception as exc:
        return SandboxVerification(tool_name, "failed", None, None, type(exc).__name__, mode)
