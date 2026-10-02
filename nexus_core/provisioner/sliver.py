"""Verified installation of the Sliver team server.

Sliver is not in any distro repository, so the only responsible automated path
is the one the project already trusts for every other binary: a fixed,
reproducible plan that ends in a *verification*:

download the pinned release asset and its ``.minisig``, verify the signature
with the official Minisign public key, install the binary, then (optionally)
start the team server and generate the operator config.

Every side effect (``which``/download/``run``/``port_open``/``spawn``) is
injectable so the whole module is unit-testable without touching the network.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
import platform as _platform
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

#: Pinned release. Bump deliberately: a moving ``latest`` would defeat the pin.
SLIVER_VERSION = "v1.7.7"
#: Official Minisign public key published at https://sliver.sh/install.
SLIVER_MINISIGN_PUB_KEY = "RWTZPg959v3b7tLG7VzKHRB1/QT+d3c71Uzetfa44qAoX5rH7mGoQTTR"
SLIVER_RELEASE_BASE = "https://github.com/BishopFox/sliver/releases/download"
DEFAULT_TEAM_SERVER_PORT = 31337
OPERATOR_NAME = "omni"

#: Status codes returned by :func:`install_sliver_verified`.
STATUS_INSTALLED = "installed"
STATUS_ALREADY = "already_installed"
STATUS_UNSUPPORTED = "unsupported_platform"
STATUS_NO_MINISIGN = "minisign_missing"
STATUS_DOWNLOAD_FAILED = "download_failed"
STATUS_SIGNATURE_INVALID = "signature_invalid"
STATUS_INSTALL_FAILED = "install_failed"


@dataclass(frozen=True)
class SliverInstall:
    ok: bool
    status: str
    detail: str = ""
    path: str = ""
    version: str = SLIVER_VERSION
    sha256: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "status": self.status,
            "detail": self.detail,
            "path": self.path,
            "version": self.version,
            "sha256": self.sha256,
        }


_MACHINE_TAGS = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
_SYSTEM_TAGS = {"Linux": "linux", "Darwin": "darwin"}


def platform_tag(machine: str | None = None, system: str | None = None) -> str | None:
    """Return the release suffix (``linux-amd64``) or ``None`` if unsupported."""
    machine_tag = _MACHINE_TAGS.get(str(machine or _platform.machine()).lower())
    system_tag = _SYSTEM_TAGS.get(str(system or _platform.system()))
    if machine_tag is None or system_tag is None:
        return None
    return f"{system_tag}-{machine_tag}"


def sliver_urls(version: str = SLIVER_VERSION, tag: str = "linux-amd64") -> tuple[str, str]:
    """Return ``(binary_url, signature_url)`` for one release asset."""
    name = f"sliver-server_{tag}"
    base = f"{SLIVER_RELEASE_BASE}/{version}/{name}"
    return base, f"{base}.minisig"


def install_plan_text(version: str = SLIVER_VERSION) -> str:
    """Human-readable, reproducible plan shown before any execution."""
    binary_url, _ = sliver_urls(version, platform_tag() or "linux-amd64")
    return (
        f"descarga {binary_url} + .minisig, verifica con "
        f"`minisign -P {SLIVER_MINISIGN_PUB_KEY}` e instala en ~/.local/bin/sliver-server"
    )


def _download(url: str, destination: Path, *, timeout: float) -> None:
    """Stream one URL to ``destination`` (stdlib only)."""
    request = urllib.request.Request(url, headers={"User-Agent": "omniagentcs"})
    with urllib.request.urlopen(request, timeout=timeout) as response, destination.open("wb") as handle:
        shutil.copyfileobj(response, handle)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _default_spawn(argv: list[str]) -> None:
    """Start a detached process that survives this one."""
    subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _default_port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def install_sliver_verified(
    *,
    target_dir: Path,
    version: str = SLIVER_VERSION,
    machine: str | None = None,
    system: str | None = None,
    which=shutil.which,
    download=_download,
    run=subprocess.run,
    echo=lambda *a: None,
) -> SliverInstall:
    """Download, verify and install ``sliver-server``; never raises on failure."""
    target = Path(target_dir).expanduser() / "sliver-server"
    tag = platform_tag(machine, system)
    if tag is None:
        return SliverInstall(False, STATUS_UNSUPPORTED, "no hay asset para esta plataforma")

    existing = which("sliver-server")
    if existing:
        return SliverInstall(True, STATUS_ALREADY, f"ya presente: {existing}", existing)

    minisign = which("minisign")
    if not minisign:
        return SliverInstall(
            False, STATUS_NO_MINISIGN,
            "minisign no está disponible para verificar la firma; instálalo primero",
        )

    binary_url, signature_url = sliver_urls(version, tag)
    with tempfile.TemporaryDirectory(prefix="omni-sliver-") as tmp:
        binary = Path(tmp) / f"sliver-server_{tag}"
        signature = Path(tmp) / f"sliver-server_{tag}.minisig"
        echo(f"[sliver] descargando {version} ({tag})…")
        try:
            download(binary_url, binary, timeout=600)
            download(signature_url, signature, timeout=60)
        except Exception as exc:  # noqa: BLE001 - network failures must not crash setup
            return SliverInstall(False, STATUS_DOWNLOAD_FAILED, f"{type(exc).__name__}: {exc}")

        echo("[sliver] verificando firma minisign…")
        try:
            outcome = run(
                [minisign, "-Vm", str(binary), "-x", str(signature), "-P", SLIVER_MINISIGN_PUB_KEY],
                capture_output=True, text=True, check=False,
            )
        except OSError as exc:
            return SliverInstall(False, STATUS_INSTALL_FAILED, f"minisign no ejecutable: {exc}")
        if getattr(outcome, "returncode", 1) != 0:
            stderr = (getattr(outcome, "stderr", "") or "").strip()[-300:]
            return SliverInstall(False, STATUS_SIGNATURE_INVALID, stderr or "firma no verificada")

        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(binary), str(target))
            os.chmod(target, 0o755)
        except OSError as exc:
            return SliverInstall(False, STATUS_INSTALL_FAILED, f"{type(exc).__name__}: {exc}")
        digest = _sha256(target)

    echo(f"[sliver] instalado en {target} (sha256 {digest[:16]}…)")
    return SliverInstall(True, STATUS_INSTALLED, str(target), str(target), version, digest)


def team_server_running(
    *, host: str = "127.0.0.1", port: int = DEFAULT_TEAM_SERVER_PORT,
    port_open=_default_port_open, timeout: float = 0.5,
) -> bool:
    return bool(port_open(host, port, timeout))


#: Name of the per-user systemd unit that keeps the team server alive.
USER_SERVICE_NAME = "omni-sliver.service"


def user_unit_path() -> Path:
    """Path of the user unit, honouring ``XDG_CONFIG_HOME``."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "systemd" / "user" / USER_SERVICE_NAME


def user_unit_text(binary: str) -> str:
    """The systemd **user** unit for the team server (no root required)."""
    return (
        "[Unit]\n"
        "Description=Sliver C2 team server (OmniAgentCS)\n"
        "After=network.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={binary} daemon\n"
        "Restart=on-failure\n"
        "RestartSec=5\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def user_service_available(*, run=subprocess.run) -> bool:
    """Whether a usable ``systemctl --user`` instance exists."""
    try:
        outcome = run(
            ["systemctl", "--user", "is-system-running"],
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    # "running" (0) and "degraded" (1) are both usable; "offline"/"unknown" fail.
    state = (getattr(outcome, "stdout", "") or "").strip().splitlines()[:1]
    return bool(state) and state[0] in {"running", "degraded"}


def install_user_service(
    *,
    binary: str | None = None,
    path: Path | None = None,
    which=shutil.which,
    run=subprocess.run,
    linger: bool = True,
    echo=lambda *a: None,
) -> bool:
    """Install and enable a per-user systemd unit for the team server."""
    binary = binary or which("sliver-server")
    if not binary or not user_service_available(run=run):
        return False
    unit = Path(path) if path is not None else user_unit_path()
    try:
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(user_unit_text(binary), encoding="utf-8")
    except OSError:
        return False
    for argv in (
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "--now", USER_SERVICE_NAME],
    ):
        try:
            outcome = run(argv, capture_output=True, text=True, check=False, timeout=60)
        except (OSError, subprocess.SubprocessError):
            return False
        if getattr(outcome, "returncode", 1) != 0:
            return False
    if linger:
        # Best effort: keep the service running after logout. Needs no root.
        try:
            run(["loginctl", "enable-linger"], capture_output=True, text=True,
                check=False, timeout=15)
        except (OSError, subprocess.SubprocessError):
            pass
    echo(f"[sliver] servicio de usuario {USER_SERVICE_NAME} habilitado")
    return True


def start_team_server(
    *,
    binary: str | None = None,
    host: str = "127.0.0.1",
    port: int = DEFAULT_TEAM_SERVER_PORT,
    port_open=_default_port_open,
    spawn=_default_spawn,
    attempts: int = 30,
    sleep=time.sleep,
    which=shutil.which,
    service_installer=None,
    echo=lambda *a: None,
) -> bool:
    """Start the team server, preferring a persistent user service.

    Falls back to a detached ``sliver-server daemon`` when there is no user
    systemd instance, so a bare container still works.
    """
    binary = binary or which("sliver-server")
    if not binary:
        return False
    if team_server_running(host=host, port=port, port_open=port_open):
        return True
    installer = install_user_service if service_installer is None else service_installer
    started = False
    try:
        started = bool(installer(binary=binary, which=which, echo=echo))
    except Exception:  # noqa: BLE001 - a broken unit must not abort setup
        started = False
    if not started:
        try:
            spawn([binary, "daemon"])
        except OSError:
            return False
    for _ in range(max(1, attempts)):
        if team_server_running(host=host, port=port, port_open=port_open):
            echo("[sliver] team server escuchando en el puerto {}…".format(port))
            return True
        sleep(1)
    return False


def ensure_operator_config(
    *,
    path: Path,
    binary: str | None = None,
    lhost: str = "127.0.0.1",
    name: str = OPERATOR_NAME,
    run=subprocess.run,
    which=shutil.which,
    echo=lambda *a: None,
) -> bool:
    """Generate the mTLS operator config when it does not exist yet."""
    target = Path(path).expanduser()
    if target.exists():
        return True
    binary = binary or which("sliver-server")
    if not binary:
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        outcome = run(
            [binary, "operator", "--name", name, "--lhost", lhost,
             "--permissions", "all", "--save", str(target)],
            capture_output=True, text=True, check=False, timeout=120,
        )
    except OSError:
        return False
    return getattr(outcome, "returncode", 1) == 0 and target.exists()


__all__ = [
    "DEFAULT_TEAM_SERVER_PORT",
    "OPERATOR_NAME",
    "SLIVER_MINISIGN_PUB_KEY",
    "SLIVER_VERSION",
    "STATUS_ALREADY",
    "STATUS_DOWNLOAD_FAILED",
    "STATUS_INSTALLED",
    "STATUS_INSTALL_FAILED",
    "STATUS_NO_MINISIGN",
    "STATUS_SIGNATURE_INVALID",
    "STATUS_UNSUPPORTED",
    "SliverInstall",
    "USER_SERVICE_NAME",
    "ensure_operator_config",
    "install_plan_text",
    "install_sliver_verified",
    "install_user_service",
    "platform_tag",
    "sliver_urls",
    "start_team_server",
    "team_server_running",
    "user_service_available",
    "user_unit_path",
    "user_unit_text",
]
