"""Only process-execution boundary for onboarding and administrative tools.

Installation callers must obtain approval for the immutable plan first.
No shell evaluation, arbitrary model commands, or implicit package-manager fallback.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import time


@dataclass(frozen=True)
class InstallPlan:
    tool_name: str
    manager: str
    command: tuple[str, ...]
    requires_sudo: bool
    verify_command: tuple[str, ...]
    installs_to: str | None
    post_install_notes: str


@dataclass(frozen=True)
class InstallResult:
    tool_name: str
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    verify_passed: bool


def probe_command(command, *, timeout=3, interactive=False):
    """Run fixed argv and turn OS errors/timeouts into bounded diagnostics."""
    try:
        return subprocess.run(
            list(command),
            shell=False,
            timeout=timeout,
            capture_output=not interactive,
            text=True,
            check=False,
            stdin=None if interactive else subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, "", "command timed out")
    except OSError as exc:
        return subprocess.CompletedProcess(
            command, 127, "", f"command unavailable ({type(exc).__name__})"
        )


def plan_install(tool_name: str, manager: str | None = None) -> InstallPlan:
    from nexus_core.config.loader import load_config
    from .detector import detect_managers
    from .recipes import available_recipes, find_tool_recipe, preferred_manager

    recipe = find_tool_recipe(tool_name)
    if recipe is None:
        raise ValueError("tool is not in the install catalog")
    config = load_config().provisioning
    managers = detect_managers()
    chosen = manager or preferred_manager(tool_name, managers, config.prefer_user_install)
    if chosen not in available_recipes(tool_name, managers):
        raise ValueError("no supported package manager available for this tool")
    spec = recipe["recipes"][chosen]
    executable = shutil.which(spec["command"][0])
    if executable is None:
        raise ValueError("package manager disappeared")
    command = [executable, *spec["command"][1:]]
    installs_to = str(Path(spec["installs_to"]).expanduser()) if spec.get("installs_to") else None
    if chosen == "go":
        directory = Path(config.install_dir or "~/.local/bin").expanduser().resolve()
        installs_to = str(directory / tool_name)
        command = [shutil.which("env") or "/usr/bin/env", f"GOBIN={directory}", *command]
    if spec["sudo"]:
        command = [shutil.which("sudo") or "sudo", "-n", *command]
    verify = list(spec.get("verify", recipe["verify"]))
    if installs_to:
        verify[0] = installs_to
    return InstallPlan(
        tool_name,
        chosen,
        tuple(command),
        spec["sudo"],
        tuple(verify),
        installs_to,
        recipe.get("post_install_notes", ""),
    )


def approval_action(plan: InstallPlan, *, dry_run=False) -> str:
    encoded = json.dumps({"plan": asdict(plan), "dry_run": dry_run}, sort_keys=True).encode()
    return "execute:tool:nexus.system.install_tool:" + hashlib.sha256(encoded).hexdigest()


def format_plan(plan: InstallPlan) -> str:
    text = shlex.join(plan.command)
    if plan.installs_to:
        text += f"\nPATH: añadir {Path(plan.installs_to).parent} a la configuración del shell"
    if plan.post_install_notes:
        text += "\n" + plan.post_install_notes
    return text


def execute_install(plan: InstallPlan, *, dry_run: bool = False) -> InstallResult:
    start = time.monotonic()
    if dry_run:
        return InstallResult(plan.tool_name, True, 0, "", "", 0, False)
    # Defense in depth: a caller cannot manufacture an arbitrary argv plan.
    if plan != plan_install(plan.tool_name, plan.manager):
        raise ValueError("install plan changed; a new approval is required")
    if plan.installs_to:
        Path(plan.installs_to).parent.mkdir(parents=True, exist_ok=True)
    outcome = probe_command(plan.command, timeout=600)
    verified = False
    if outcome.returncode == 0:
        verified = probe_command(plan.verify_command, timeout=10).returncode == 0
    return InstallResult(
        plan.tool_name,
        outcome.returncode == 0 and verified,
        outcome.returncode,
        (outcome.stdout or "")[-2_000_000:],
        (outcome.stderr or "")[-2_000_000:],
        time.monotonic() - start,
        verified,
    )


def update_shell_path(
    installs_to: str, *, home: Path | None = None, shell: str | None = None
) -> bool:
    """Append the install directory to the user's shell rc file, idempotently.

    The target rc file depends on the login shell (``.zshrc`` for zsh, otherwise
    ``.bashrc``) inside ``home``. Both ``home`` and ``shell`` default to the real
    environment; they are injectable so callers and tests can pin the target rc
    file regardless of the host's ``$SHELL``.
    """
    directory = str(Path(installs_to).expanduser().resolve().parent)
    if any(c in directory for c in "\n\r\x00"):
        raise ValueError("invalid installation path")
    base = Path(home) if home is not None else Path.home()
    shell_name = Path(shell if shell is not None else os.getenv("SHELL", "")).name
    rc = base / (".zshrc" if shell_name == "zsh" else ".bashrc")
    line = f'export PATH={shlex.quote(directory)}:"$PATH" # omni provisioner'
    text = rc.read_text() if rc.exists() else ""
    changed = line not in text.splitlines()
    if changed:
        with rc.open("a") as stream:
            stream.write(("\n" if text and not text.endswith("\n") else "") + line + "\n")
    entries = os.environ.get("PATH", "").split(os.pathsep)
    if directory not in entries:
        os.environ["PATH"] = os.pathsep.join([directory, *entries])
    return changed


def open_editor(path: Path) -> int:
    command = shlex.split(os.getenv("EDITOR", "nano"))
    if not command:
        return 1
    return probe_command([*command, str(path)], timeout=3600, interactive=True).returncode
