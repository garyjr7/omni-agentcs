"""``omni update`` and the non-blocking startup version check.

Two halves, one source of truth:

* :func:`fetch_latest_release` / :func:`check_for_update` answer "is there a
  newer version?" from the GitHub Releases API, and fall back to the ``version``
  field of the remote ``pyproject.toml`` when the repo has no published release
  yet (which is the normal state of this project).
* :func:`run_update_command` asks, then runs the upgrade as a **separate
  process** -``git pull --ff-only`` plus a ``pip install`` into the environment
  that owns the interpreter-, never by downloading code and importing it into
  the running one.

The one invariant the update must not break: the operator's configuration lives
in ``<XDG_CONFIG>/omni`` (``secrets.json``, ``config.toml``), and the code lives
somewhere else entirely. The command fingerprints that directory before running
the upgrade and compares it afterwards, so a future step that accidentally
writes there fails loudly instead of silently replacing a key file.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GITHUB_REPO = "garyjr7/omni-agentcs"
RELEASES_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
PYPROJECT_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/pyproject.toml"
#: Point the check at another endpoint (a local manifest, an internal mirror).
#: It is how the updater is exercised without publishing the repository.
RELEASES_URL_ENV = "OMNI_UPDATE_URL"
#: No request may hold the startup banner for longer than this.
DEFAULT_TIMEOUT = 2.0
#: Set to 1/true/yes to skip the network check entirely (offline, CI).
DISABLE_ENV = "OMNI_NO_UPDATE_CHECK"
PACKAGE_NAME = "omniagentcs"
USAGE = "uso: omni update [--check]"

#: Answers accepted as "yes" (the prompt is documented as ``[y/N]``).
YES_ANSWERS = {"y", "yes", "s", "si", "sí"}


@dataclass(frozen=True)
class Release:
    """A published version, or the ``pyproject.toml`` fallback."""

    version: str
    url: str = ""
    source: str = "github"

    @property
    def display(self) -> str:
        return f"v{self.version.lstrip('vV')}"


def parse_version(text: str) -> tuple[int, ...]:
    """``"v3.1.0"`` -> ``(3, 1, 0)`` so versions compare numerically, not as text."""
    numbers = re.findall(r"\d+", str(text or ""))
    return tuple(int(number) for number in numbers) if numbers else ()


def installed_version() -> str:
    """The version of the code that is running right now."""
    from .main import PROGRAM_VERSION

    return str(PROGRAM_VERSION)


def config_dir_path() -> Path:
    """Where the operator's configuration and keys live (never touched here)."""
    from nexus_core.config.xdg import resolve_xdg_paths

    return resolve_xdg_paths().config_dir


def project_root() -> Path:
    """The installation root: the parent of the ``nexus_core`` package."""
    import nexus_core

    return Path(nexus_core.__file__).resolve().parent.parent


def _get(url: str, timeout: float) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"{PACKAGE_NAME}-update-check",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return response.read().decode("utf-8", "replace")


def releases_url() -> str:
    """The endpoint to ask: ``$OMNI_UPDATE_URL`` when set, GitHub otherwise."""
    return str(os.getenv(RELEASES_URL_ENV) or "").strip() or RELEASES_URL


def fetch_latest_release(
    timeout: float = DEFAULT_TIMEOUT,
    *,
    getter: Callable[[str, float], str] | None = None,
) -> Release | None:
    """The newest published version, or ``None`` when nothing can be read.

    Releases first (the intended path once tags exist); ``pyproject.toml`` on
    ``main`` second, because the project ships from the repository and may not
    have a release object yet. Any network or parsing failure is ``None``: an
    update check must never be the reason a command fails.
    """
    get = getter or _get
    url = releases_url()
    try:
        payload = json.loads(get(url, timeout))
    except Exception:  # noqa: BLE001 - offline, 404, rate-limited, HTML error page
        payload = None
    if isinstance(payload, dict):
        tag = str(payload.get("tag_name") or payload.get("name") or "").strip()
        if parse_version(tag):
            return Release(
                version=tag.lstrip("vV"), url=str(payload.get("html_url") or "")
            )
    if url != RELEASES_URL:
        # An explicit manifest has no pyproject sibling to fall back to.
        return None
    try:
        text = get(PYPROJECT_URL, timeout)
    except Exception:  # noqa: BLE001 - same reasons as above
        return None
    match = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', text)
    if not match or not parse_version(match.group(1)):
        return None
    return Release(
        version=match.group(1),
        url=f"https://github.com/{GITHUB_REPO}",
        source="pyproject",
    )


def check_for_update(
    current: str | None = None,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    fetch: Callable[[float], Release | None] | None = None,
) -> Release | None:
    """The release to offer, or ``None`` when up to date / unreachable."""
    latest = (fetch or fetch_latest_release)(timeout)
    if latest is None:
        return None
    now = current if current is not None else installed_version()
    if not parse_version(now):
        return None
    return latest if parse_version(latest.version) > parse_version(now) else None


def update_notice(release: Release) -> str:
    """The one line the TUI prints when a newer version exists."""
    return (
        f"[!] Actualización disponible: {release.display}. "
        "Ejecuta 'omni update' para instalar."
    )


def config_fingerprint(config_dir: Path) -> dict[str, str]:
    """sha256 of every file under ``config_dir``, keyed by relative path.

    Content, not just mtime: an upgrade that rewrote ``secrets.json`` with the
    same size and a restored timestamp still has to be detected.
    """
    if not config_dir.is_dir():
        return {}
    digest: dict[str, str] = {}
    for path in sorted(config_dir.rglob("*")):
        if not path.is_file():
            continue
        key = str(path.relative_to(config_dir))
        try:
            digest[key] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            digest[key] = "unreadable"
    return digest


def _is_pipx_install(prefix: str | None = None) -> bool:
    parts = str(prefix if prefix is not None else sys.prefix).replace("\\", "/").split("/")
    return "pipx" in parts


def update_steps(
    root: Path,
    *,
    python: str | None = None,
    prefix: str | None = None,
) -> list[list[str]]:
    """The commands that bring an existing installation up to date.

    ``git pull --ff-only`` cannot rewrite history or silently merge; a declined
    fast-forward is reported instead of forced. The pip step targets the
    environment that owns the current interpreter -the installer's venv or a
    pipx venv-, never the system Python.
    """
    steps: list[list[str]] = []
    if (root / ".git").exists():
        steps.append(["git", "-C", str(root), "pull", "--ff-only"])
    executable = python or sys.executable
    if _is_pipx_install(prefix):
        steps.append(["pipx", "upgrade", PACKAGE_NAME])
        return steps
    requirements = root / "requirements-prod.in"
    if requirements.is_file():
        steps.append(
            [executable, "-m", "pip", "install", "--upgrade", "-r", str(requirements)]
        )
    else:
        steps.append([executable, "-m", "pip", "install", "--upgrade", str(root)])
    return steps


def _default_runner(argv: Sequence[str]) -> Any:
    return subprocess.run(list(argv), check=False, capture_output=True, text=True)


def _config_untouched(
    config_dir: Path,
    before: dict[str, str],
    after: dict[str, str],
    out: Callable[[str], None],
) -> bool:
    if before == after:
        return True
    changed = sorted(
        set(before) ^ set(after)
        | {key for key in before.keys() & after.keys() if before[key] != after[key]}
    )
    out(f"✗ ALERTA: {config_dir} cambió durante la actualización: {', '.join(changed)}")
    out("  los valores no se han sobrescrito desde aquí: revisa esos ficheros y")
    out("  restaura tu copia si el cambio no fue intencionado.")
    return False


def run_update_command(
    argv: Sequence[str],
    *,
    current: str | None = None,
    fetch: Callable[[float], Release | None] | None = None,
    prompt: Callable[[str], str] | None = None,
    out: Callable[[str], None] = print,
    runner: Callable[[Sequence[str]], Any] | None = None,
    root: Path | None = None,
    config_dir: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> int:
    """``omni update [--check]``; returns the process exit code.

    0 = up to date, updated, or cancelled; 1 = unreachable or a step failed;
    2 = bad usage / install layout; 3 = the configuration directory changed.
    """
    options = [str(item) for item in argv]
    unknown = [item for item in options if item not in {"--check", "-c"}]
    if unknown:
        out(f"argumento desconocido: {unknown[0]}")
        out(USAGE)
        return 2
    check_only = bool(options)

    now = current or installed_version()
    latest = (fetch or fetch_latest_release)(timeout)
    if latest is None:
        out("✗ no se pudo consultar la última versión (sin red o la API no responde).")
        out("  vuelve a intentarlo, o actualiza desde el repositorio con `git pull`.")
        return 1
    if parse_version(latest.version) <= parse_version(now):
        out(f"✓ ya estás en la última versión (v{now}).")
        return 0

    out(f"Nueva versión {latest.display} disponible (actual v{now}).")
    if latest.url:
        out(f"  referencia: {latest.url}")
    if check_only:
        out("  --check: no se ha modificado nada. Ejecuta `omni update` para actualizar.")
        return 0

    answer = str(
        (prompt or input)(
            f"Nueva versión {latest.display} disponible. ¿Deseas actualizar ahora? [y/N] "
        )
    ).strip().lower()
    if answer not in YES_ANSWERS:
        out("actualización cancelada; no se ha modificado nada.")
        return 0

    config_root = Path(config_dir) if config_dir is not None else config_dir_path()
    install_root = Path(root) if root is not None else project_root()
    try:
        install_root.resolve().relative_to(config_root.resolve())
    except ValueError:
        pass
    else:
        # Guard against a misconfigured installation that put the code inside
        # the config directory: pulling there could overwrite config.toml.
        out(f"✗ el código está dentro de {config_root}; me niego a actualizar ahí.")
        return 2

    before = config_fingerprint(config_root)
    out(f"  configuración del operador (no se toca): {config_root}")

    run = runner or _default_runner
    for step in update_steps(install_root):
        out(f"→ {' '.join(step)}")
        try:
            completed = run(step)
        except OSError as exc:
            out(f"✗ no se pudo ejecutar: {exc}")
            _config_untouched(config_root, before, config_fingerprint(config_root), out)
            return 1
        code = int(getattr(completed, "returncode", 1))
        if code != 0:
            details = (
                str(getattr(completed, "stdout", "") or "")
                + str(getattr(completed, "stderr", "") or "")
            ).strip()
            out(f"✗ falló (código {code}).")
            for line in details.splitlines()[-10:]:
                out(f"   {line}")
            _config_untouched(config_root, before, config_fingerprint(config_root), out)
            return 1

    if not _config_untouched(config_root, before, config_fingerprint(config_root), out):
        return 3

    out(f"✓ actualizado a {latest.display}. Reinicia `omni` para usar el código nuevo.")
    out(f"  tus claves y tu configuración siguen intactas en {config_root}.")
    return 0


__all__ = [
    "DEFAULT_TIMEOUT",
    "DISABLE_ENV",
    "GITHUB_REPO",
    "RELEASES_URL_ENV",
    "Release",
    "check_for_update",
    "config_dir_path",
    "config_fingerprint",
    "fetch_latest_release",
    "installed_version",
    "parse_version",
    "project_root",
    "releases_url",
    "run_update_command",
    "update_notice",
    "update_steps",
]
