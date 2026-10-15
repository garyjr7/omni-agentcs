"""Shared CLI/worker startup: shell > .env > secret store; no import side effects."""
import os
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


def bootstrap_secrets_and_config(root, *, load_configuration=True):
    from dotenv import load_dotenv
    from .secrets import load_secrets_into_env
    from .loader import load_config, apply_environment
    from .xdg import resolve_xdg_paths

    load_dotenv(Path(root) / ".env", override=False)
    load_secrets_into_env()
    if not load_configuration:
        return None
    paths = resolve_xdg_paths()
    config = load_config(paths)
    apply_environment(config, paths)
    return paths, config
