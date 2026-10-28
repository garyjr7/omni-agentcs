"""Secret storage for provider API keys and the scope signing secret (H2).

API keys used to live in clear text inside the ``.env`` file. This module keeps
them in the **OS keyring** when ``keyring`` is installed *and* backed by a real
store -a headless box ships the package with its ``fail`` backend-, and otherwise
in a ``0600`` JSON file under ``<XDG_CONFIG_HOME>/omni/secrets.json``
(``~/.config/omni/secrets.json`` by default). Values are never logged, never
written to the audit chain and never printed: the CLI only ever shows secret
*names*.

Two access paths exist, on purpose:

* :func:`resolve_api_key` is what the LLM clients use. It answers the **store
  first** and the environment second, so a key typed once through
  ``omni auth login`` wins over a stale value exported in the operator's shell
  or left behind in ``.env``.
* :func:`load_secrets_into_env` copies stored secrets into the environment at
  process start, but only for variables the shell or ``.env`` left **unset**.
  It keeps the older, env-first consumers (and ``available_providers``) working
  without changing what an explicit shell value means.

Rotation is the same as a first write: ``omni auth login <proveedor>`` (or
``/secrets rotate NAME``) overwrites the value. After rotating an exposed key,
restart any process that already read the old one.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Protocol

#: Logical service name used for every keyring entry.
SERVICE_NAME = "omni-agentcs"
#: Directory component the XDG helper appends under the config root.
CONFIG_DIRNAME = "omni"
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
    "DEEPSEEK_API_KEY",
    "NEXUS_SCOPE_SIGNING_SECRET",
)

#: Provider name -> environment variable the runtime reads for its key.
PROVIDER_ENV_VARS = {
    "openai": "OPENAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "groq": "GROQ_API_KEY",
}
#: Providers offered by ``omni auth login`` (the ones the operator asked for).
LOGIN_PROVIDERS = ("openai", "deepseek", "gemini", "anthropic")


class SecretBackend(Protocol):
    """Minimal contract every backend implements."""

    name: str

    def get(self, name: str) -> str | None: ...
    def set(self, name: str, value: str) -> None: ...
    def delete(self, name: str) -> bool: ...
    def names(self) -> list[str]: ...


def _config_dir() -> Path:
    """``<XDG_CONFIG_HOME>/omni``: the private directory every omni file lives in.

    ``XdgPaths.config_dir`` already appends the ``omni`` component, so the store
    resolves to ``~/.config/omni/secrets.json`` and never parks a generic
    ``secrets.json`` at the top of ``~/.config`` (which is what ``doctor``
    reports and what the ``0600`` check looks at).
    """
    from nexus_core.config.xdg import resolve_xdg_paths

    return resolve_xdg_paths().config_dir


def default_secrets_path() -> Path:
    """The path of the ``0600`` JSON file backend (no I/O)."""
    return _config_dir() / SECRETS_FILENAME


def _private_dir(path: Path, *, owned: bool) -> None:
    """Create ``path``; drop group/other permissions when omni owns the directory.

    ``mkdir(mode=0o700)`` is filtered by the process umask and does nothing at
    all when the directory already exists, so an inherited ``~/.config/omni``
    with ``0755`` would keep exposing the file names. Only the bits that make it
    world-traversable are cleared; the owner's are left as the operator set them.

    ``owned`` is false when the caller passed an explicit path
    (``FileBackend('/some/where/secrets.json')``): chmod-ing the parent of a path
    we were handed -``$HOME``, a shared directory- would be a surprise with real
    consequences, so only the default ``~/.config/omni`` is tightened.
    """
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not owned:
        return
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            os.chmod(path, mode & ~0o077)
    except OSError:  # pragma: no cover - a filesystem without chmod
        pass


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict, *, owned: bool = False) -> None:
    """Atomically write ``data`` as a 0600 JSON file in a private directory."""
    _private_dir(path.parent, owned=owned)
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
        #: An explicit path belongs to the caller: only the default location is
        #: omni-owned, and only that one gets its directory tightened to 0700.
        self.owned_directory = path is None
        self.path = Path(path) if path else default_secrets_path()

    def _load(self) -> dict[str, str]:
        return {str(k): str(v) for k, v in _read_json(self.path).items()}

    def get(self, name: str) -> str | None:
        return self._load().get(name)

    def set(self, name: str, value: str) -> None:
        data = self._load()
        data[name] = value
        _write_json(self.path, data, owned=self.owned_directory)

    def delete(self, name: str) -> bool:
        data = self._load()
        if name not in data:
            return False
        del data[name]
        if data:
            _write_json(self.path, data, owned=self.owned_directory)
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
        self.owned_directory = index_path is None
        self.index_path = Path(index_path) if index_path else _config_dir() / INDEX_FILENAME

    def _index(self) -> list[str]:
        names = _read_json(self.index_path).get("names")
        return sorted({str(item) for item in names}) if isinstance(names, list) else []

    def _save_index(self, names: list[str]) -> None:
        _write_json(
            self.index_path,
            {"names": sorted(set(names))},
            owned=self.owned_directory,
        )

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


def _keyring_usable() -> bool:
    """Whether ``keyring`` is importable **and** backed by a real store.

    Importing the package is not enough: a headless box (SSH, container, CI) has
    ``keyring`` installed and still resolves to its ``fail`` backend, which
    raises ``NoKeyringError`` on every write. Checking only the import made
    ``omni auth login`` fail there instead of using the ``0600`` file, which is
    exactly the fallback the module promises.
    """
    import keyring  # noqa: PLC0415 - optional dependency, probed on purpose

    backend = keyring.get_keyring()
    fail_module = getattr(getattr(keyring, "backends", None), "fail", None)
    fail_class = getattr(fail_module, "Keyring", None)
    if fail_class is not None and isinstance(backend, fail_class):
        return False
    return callable(getattr(backend, "get_password", None))


def select_backend(*, prefer_keyring: bool = True) -> SecretBackend:
    """Prefer a usable OS keyring; fall back to the 0600 file backend."""
    if prefer_keyring:
        try:
            if _keyring_usable():
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


def provider_env_var(provider: str) -> str:
    """Map a provider name (``openai``) to its environment variable.

    ``ValueError`` instead of ``KeyError``: the caller is a CLI command that has
    to print the accepted names, not a lookup that may return ``None``.
    """
    name = str(provider or "").strip().lower()
    env_var = PROVIDER_ENV_VARS.get(name)
    if not env_var:
        accepted = ", ".join(sorted(PROVIDER_ENV_VARS))
        raise ValueError(f"proveedor desconocido: {provider!r} (usa uno de: {accepted})")
    return env_var


def set_secret(provider: str, key: str, *, store: SecretStore | None = None) -> str:
    """Store ``key`` for ``provider``; returns the variable it is stored under."""
    env_var = provider_env_var(provider)
    resolved = store or SecretStore()
    resolved.set(env_var, str(key).strip())
    return env_var


def get_secret(provider: str, *, store: SecretStore | None = None) -> str | None:
    """The stored key for ``provider``, or ``None`` when it is not there."""
    return (store or SecretStore()).get(provider_env_var(provider))


def delete_secret(provider: str, *, store: SecretStore | None = None) -> bool:
    """Remove ``provider``'s key; ``True`` when something was removed."""
    return (store or SecretStore()).delete(provider_env_var(provider))


def resolve_api_key(
    provider: str,
    *,
    store: SecretStore | None = None,
    env: dict[str, str] | None = None,
) -> str | None:
    """The key the LLM client must use: **store first**, environment second.

    The order is the point of the whole module. A key typed through
    ``omni auth login`` is the operator's current intent; an ``.env`` line or an
    export in the shell is the leftover of an older one (and the reason the key
    ended up in the repository history in the first place). Reading the store
    first means rotating a key in one place is enough, without also hunting the
    copy that the shell inherited.

    A backend that is locked or unavailable reads as absent, so the environment
    is still consulted and a run does not die because the keyring was busy.
    """
    env_var = provider_env_var(provider)
    try:
        stored = (store or SecretStore()).get(env_var)
    except Exception:  # noqa: BLE001 - a broken backend must not block the fallback
        stored = None
    if stored and str(stored).strip():
        return str(stored).strip()
    source = os.environ if env is None else env
    value = str(source.get(env_var) or "").strip()
    return value or None


def secrets_file_report(*, store: SecretStore | None = None) -> dict:
    """Describe the file backend for ``omni doctor``, without reading a value.

    ``secure`` means "no permission for group or others" rather than an exact
    ``0600``: a ``0400`` file is stricter than what we ask for, and warning about
    it would train the operator to ignore the warning.
    """
    path = default_secrets_path()
    report: dict = {
        "path": str(path),
        "exists": False,
        "mode": None,
        "secure": None,
        "backend": None,
        "names": 0,
    }
    try:
        if path.is_file():
            mode = stat.S_IMODE(path.stat().st_mode)
            report["exists"] = True
            report["mode"] = format(mode, "04o")
            report["secure"] = (mode & 0o077) == 0
    except OSError:  # pragma: no cover - unreadable path on exotic filesystems
        pass
    try:
        resolved = store or SecretStore()
        report["backend"] = resolved.backend_name
        report["names"] = len(resolved.names())
    except Exception:  # noqa: BLE001 - the report must never fail the doctor
        pass
    return report


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
    "CONFIG_DIRNAME",
    "IMPORTABLE_KEYS",
    "INDEX_FILENAME",
    "LOGIN_PROVIDERS",
    "PROVIDER_ENV_VARS",
    "SECRETS_FILENAME",
    "SERVICE_NAME",
    "FileBackend",
    "KeyringBackend",
    "SecretBackend",
    "SecretStore",
    "default_secrets_path",
    "delete_secret",
    "get_secret",
    "import_from_env",
    "load_secrets_into_env",
    "provider_env_var",
    "resolve_api_key",
    "secrets_file_report",
    "select_backend",
    "set_secret",
]
