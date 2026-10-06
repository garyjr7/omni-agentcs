"""Secret storage for provider API keys and the scope signing secret (H2).

API keys used to live in clear text inside the ``.env`` file. This module keeps
them in the **OS keyring** when the ``keyring`` package is available, and
otherwise in a ``0600`` JSON file under the XDG config directory. Values are
never logged, never written to the audit chain and never printed: the CLI only
ever shows secret *names*.

The rest of the system keeps reading environment variables unchanged:
:func:`load_secrets_into_env` copies stored secrets into the environment at
process start, but only for variables the shell or ``.env`` left **unset**, so
an explicit value always wins.

Rotation is the same as a first write: ``omni secrets set NAME`` (or
``/secrets rotate NAME``) overwrites the value. After rotating an exposed key,
restart any process that already read the old one.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Protocol

#: Logical service name used for every keyring entry.
SERVICE_NAME = "omni-agentcs"
#: File backend payload (name -> value).
SECRETS_FILENAME = "secrets.json"
#: Keyring backend name index (names are not secret).
INDEX_FILENAME = "secrets.index.json"

#: Environment variables ``import_from_env`` migrates by default.
IMPORTABLE_KEYS = (
    "GROQ_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "ANTHROPIC_API_KEY",
    "NEXUS_SCOPE_SIGNING_SECRET",
)


class SecretBackend(Protocol):
    """Minimal contract every backend implements."""

    name: str

    def get(self, name: str) -> str | None: ...
    def set(self, name: str, value: str) -> None: ...
    def delete(self, name: str) -> bool: ...
    def names(self) -> list[str]: ...


def _config_dir() -> Path:
    from nexus_core.config.xdg import resolve_xdg_paths

    return resolve_xdg_paths().config_dir


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict) -> None:
    """Atomically write ``data`` as a 0600 JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".secrets-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class FileBackend:
    """Secrets in a 0600 JSON file next to the rest of the user config."""

    name = "file"

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else _config_dir() / SECRETS_FILENAME

    def _load(self) -> dict[str, str]:
        return {str(k): str(v) for k, v in _read_json(self.path).items()}

    def get(self, name: str) -> str | None:
        return self._load().get(name)

    def set(self, name: str, value: str) -> None:
        data = self._load()
        data[name] = value
        _write_json(self.path, data)

    def delete(self, name: str) -> bool:
        data = self._load()
        if name not in data:
            return False
        del data[name]
        if data:
            _write_json(self.path, data)
        else:
            try:
                self.path.unlink()
            except OSError:
                pass
        return True

    def names(self) -> list[str]:
        return sorted(self._load())


class KeyringBackend:
    """Secrets in the OS keychain; names kept in a small index file."""

    name = "keyring"

    def __init__(self, index_path: Path | None = None) -> None:
        import keyring  # noqa: PLC0415 - optional dependency, probed on purpose

        self._keyring = keyring
        self.index_path = Path(index_path) if index_path else _config_dir() / INDEX_FILENAME

    def _index(self) -> list[str]:
        names = _read_json(self.index_path).get("names")
        return sorted({str(item) for item in names}) if isinstance(names, list) else []

    def _save_index(self, names: list[str]) -> None:
        _write_json(self.index_path, {"names": sorted(set(names))})

    def get(self, name: str) -> str | None:
        try:
            return self._keyring.get_password(SERVICE_NAME, name)
        except Exception:  # noqa: BLE001 - a locked/unavailable keyring reads as absent
            return None

    def set(self, name: str, value: str) -> None:
        self._keyring.set_password(SERVICE_NAME, name, value)
        self._save_index([*self._index(), name])

    def delete(self, name: str) -> bool:
        try:
            self._keyring.delete_password(SERVICE_NAME, name)
        except Exception:  # noqa: BLE001 - deleting a missing entry is not an error
            pass
        names = self._index()
        if name not in names:
            return False
        self._save_index([item for item in names if item != name])
        return True

    def names(self) -> list[str]:
        return self._index()


def select_backend(*, prefer_keyring: bool = True) -> SecretBackend:
    """Prefer the OS keyring; fall back to the 0600 file backend."""
    if prefer_keyring:
        try:
            return KeyringBackend()
        except Exception:  # noqa: BLE001 - keyring absent or unusable
            pass
    return FileBackend()


class SecretStore:
    """High-level accessor used by the CLI and the entry point."""

    def __init__(self, backend: SecretBackend | None = None) -> None:
        self.backend: SecretBackend = backend or select_backend()

    @property
    def backend_name(self) -> str:
        return self.backend.name

    def get(self, name: str) -> str | None:
        return self.backend.get(str(name))

    def set(self, name: str, value: str) -> None:
        clean = str(name).strip()
        if not clean:
            raise ValueError("secret name is required")
        if not str(value):
            raise ValueError("secret value is required")
        self.backend.set(clean, str(value))

    def delete(self, name: str) -> bool:
        return self.backend.delete(str(name))

    def names(self) -> list[str]:
        return self.backend.names()


def load_secrets_into_env(env: dict[str, str] | None = None, *, store: SecretStore | None = None) -> list[str]:
    """Copy stored secrets into the environment for unset variables only.

    Returns the names that were applied. Explicit shell/``.env`` values always
    win, so adopting the store is opt-in per variable.
    """
    target = os.environ if env is None else env
    resolved_store = store or SecretStore()
    applied: list[str] = []
    for name in resolved_store.names():
        if not name or name in target:
            continue
        value = resolved_store.get(name)
        if value:
            target[name] = value
            applied.append(name)
    return applied


def import_from_env(
    env: dict[str, str] | None = None,
    *,
    store: SecretStore | None = None,
    names: tuple[str, ...] = IMPORTABLE_KEYS,
) -> list[str]:
    """Move the known keys present in the environment into the store.

    Values are not removed from the environment: the operator decides when to
    drop them from ``.env`` (this command only makes the store authoritative
    for the next start).
    """
    source = os.environ if env is None else env
    resolved_store = store or SecretStore()
    imported: list[str] = []
    for name in names:
        value = str(source.get(name) or "").strip()
        if not value:
            continue
        resolved_store.set(name, value)
        imported.append(name)
    return imported


__all__ = [
    "IMPORTABLE_KEYS",
    "INDEX_FILENAME",
    "SECRETS_FILENAME",
    "SERVICE_NAME",
    "FileBackend",
    "KeyringBackend",
    "SecretBackend",
    "SecretStore",
    "import_from_env",
    "load_secrets_into_env",
    "select_backend",
]
