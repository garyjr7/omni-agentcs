"""Shared CLI/worker startup: shell > .env > secret store; no import side effects."""
import os
import re
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path


def env_file(root) -> Path:
    """The ``.env`` the runtime actually loads (loaded with ``override=False``)."""
    return Path(root) / ".env"


def set_env_values(root, values: Mapping[str, str]) -> Path:
    """Set or update ``KEY=value`` lines in ``<root>/.env``, atomically (0600).

    Operator settings the wizard collects (``MSF_LHOST``/``MSF_LPORT``) are read
    from this file -not from the XDG config- because that is where
    :func:`bootstrap_secrets_and_config` looks for them. Existing lines keep
    their place and comments stay untouched; a missing key is appended. Written
    through a ``0600`` temporary file and ``os.replace``, so an interrupted write
    never leaves a half ``.env`` behind.
    """
    path = env_file(root)
    pending = {str(key): str(value) for key, value in (values or {}).items() if str(key)}
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    updated: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        if key in pending and not stripped.startswith("#"):
            updated.append(f"{key}={pending.pop(key)}")
        else:
            updated.append(line)
    if pending:
        if updated and updated[-1].strip():
            updated.append("")
        updated.extend(f"{key}={value}" for key, value in pending.items())
    text = "\n".join(updated) + "\n"
    handle, temporary = tempfile.mkstemp(prefix=".env-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if Path(temporary).exists():
            Path(temporary).unlink()
    return path


def detect_tun0_ipv4() -> str | None:
    """Return the current IPv4 address on Kali's VPN interface, when available.

    The Metasploit callback is session-specific: persisting the address detected
    during installation leaves a stale LHOST after reconnecting to the VPN. Read
    it at process startup instead, and leave explicit shell/.env configuration
    available for hosts that use a different route or interface.
    """
    try:
        completed = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "dev", "tun0"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    match = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)/", completed.stdout)
    if not match or match.group(1).startswith("127."):
        return None
    return match.group(1)


def configure_runtime_callbacks(*, shell_lhost: str = "") -> None:
    """Fill safe Metasploit callback defaults for this process, without writes.

    Explicit shell variables win. Otherwise the current tun0 address takes
    priority over a potentially stale .env value. If the VPN is down, retain the
    operator's .env value. LPORT has the same 4444 default as the MSF handler.
    """
    explicit_lhost = str(shell_lhost or "").strip()
    if explicit_lhost:
        os.environ["MSF_LHOST"] = explicit_lhost
    else:
        detected = detect_tun0_ipv4()
        if detected:
            os.environ["MSF_LHOST"] = detected
    if str(os.getenv("MSF_LHOST") or "").strip():
        if not str(os.getenv("MSF_LPORT") or "").strip():
            os.environ["MSF_LPORT"] = "4444"


def bootstrap_secrets_and_config(root, *, load_configuration=True):
    from dotenv import load_dotenv
    from .secrets import load_secrets_into_env
    from .loader import load_config, apply_environment
    from .xdg import resolve_xdg_paths

    shell_lhost = str(os.getenv("MSF_LHOST") or "").strip()
    load_dotenv(Path(root) / ".env", override=False)
    configure_runtime_callbacks(shell_lhost=shell_lhost)
    load_secrets_into_env()
    if not load_configuration:
        return None
    paths = resolve_xdg_paths()
    config = load_config(paths)
    apply_environment(config, paths)
    return paths, config
