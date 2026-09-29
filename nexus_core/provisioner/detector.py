"""Read-only OS, manager and binary detection."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import platform
import re
import shutil


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
