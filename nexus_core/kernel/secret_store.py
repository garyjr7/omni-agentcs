"""Durable vault for the secrets a tool discovers (V1-29).

Measured in rerun 8 (``run_9b6103075b9e4347ac298cba3bd21081``): ``hydra``
validated ``lin``'s SSH password, the verifier recorded the ``credential`` fact,
and the plaintext was gone before the agent could use it. ``blackboard.py``
redacts any dict key named in ``redaction.SECRET_TERMS`` —by design— so the fact
reached the model as ``"password": "[REDACTED]"``, the model had no way to
recover it (the agent asked for it: *«El sistema redacta la contraseña en el
blackboard, así que no puedo leerla directamente»*) and it burned the rest of the
subagent budget guessing wordlist entries. The ``access`` fact that closed
``exploitation`` was equally hollow: a validated credential is not a session.

The fix is a *handle*, not a weaker redaction. A discovered secret is written to
this store and the tool, the blackboard and the prompt only ever carry
``vault:<32 hex>``. Consumers resolve the reference in-process, right before they
build the subprocess, so the plaintext never enters a result, an observation or
the model's context. ``password`` keeps working for manual use.

The vault is a small filesystem store, deliberately *not* the artifact CAS: an
artifact is content-addressed and readable by whoever can read the engagement,
while a secret must be opaque, individually addressed and revocable. Same
interface shape as the artifact store (``put`` returns a reference, ``get``
reads it back), no shared storage.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any
from uuid import uuid4

from .models import utc_now

#: Scheme of a secret reference: ``vault:<32 hex characters>``.
VAULT_SCHEME = "vault"
VAULT_PREFIX = f"{VAULT_SCHEME}:"
SECRET_REF_RE = re.compile(rf"^{VAULT_SCHEME}:[a-f0-9]{{32}}$")

#: A credential is small; anything larger is not a secret this store should hold.
MAX_SECRET_BYTES = 64 * 1024
DEFAULT_TENANT = "system"
#: Default kind of a stored secret (the only one the chain produces today).
DEFAULT_SECRET_KIND = "credential"

#: Root of the vault. ``--config``/XDG default is ``<state>/omni/vault``.
VAULT_ROOT_ENV = "NEXUS_VAULT_ROOT"

_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def is_secret_ref(value: Any) -> bool:
    """Whether ``value`` is a well-formed secret reference (never reads it)."""
    return isinstance(value, str) and bool(SECRET_REF_RE.match(value))


def secret_ref(token: str) -> str:
    """Return the reference of a vault token (``<hex>`` → ``vault:<hex>``)."""
    return f"{VAULT_PREFIX}{token}"


class SecretStore:
    """Per-host store of discovered secrets, addressed by opaque references.

    Every file is written ``0600`` and atomically (temp file + ``os.replace``),
    the directory is ``0700`` and symlinks are refused: the vault is not a place
    another local user can follow into. Files are read back only through
    :meth:`get`, which validates the reference shape first.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser()

    # ---------------------------------------------------------------- helpers
    def _ensure_root(self) -> Path:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.root, 0o700)
        except OSError:  # pragma: no cover - read-only or exotic filesystem
            pass
        return self.root

    def _token(self, ref: str) -> str:
        if not is_secret_ref(ref):
            raise ValueError(f"invalid secret reference: {ref!r}")
        return ref[len(VAULT_PREFIX):]

    def _paths(self, token: str) -> tuple[Path, Path]:
        return self.root / f"{token}.secret", self.root / f"{token}.json"

    @staticmethod
    def _write_private(path: Path, content: bytes) -> None:
        """Atomically publish ``content`` at ``path`` with mode ``0600``."""
        directory = path.parent
        descriptor, temporary = tempfile.mkstemp(prefix=".vault-", dir=directory)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    # ------------------------------------------------------------------- API
    def put(
        self,
        plaintext: bytes | str,
        *,
        kind: str = DEFAULT_SECRET_KIND,
        tenant_id: str = DEFAULT_TENANT,
    ) -> str:
        """Store ``plaintext`` and return its ``vault:<uuid>`` reference.

        The plaintext is written once and never returned: callers keep the
        reference, not the secret.
        """
        if isinstance(plaintext, str):
            payload = plaintext.encode("utf-8")
        elif isinstance(plaintext, (bytes, bytearray)):
            payload = bytes(plaintext)
        else:
            raise ValueError("secret must be bytes or str")
        if not payload:
            raise ValueError("secret is empty")
        if len(payload) > MAX_SECRET_BYTES:
            raise ValueError("secret exceeds the vault size limit")
        if not _TENANT_RE.match(str(tenant_id or "")):
            raise ValueError("invalid secret tenant")
        kind = str(kind or DEFAULT_SECRET_KIND).strip()[:64] or DEFAULT_SECRET_KIND
        self._ensure_root()
        token = uuid4().hex
        metadata = {
            "kind": kind,
            "tenant_id": str(tenant_id),
            "size_bytes": len(payload),
            "created_at": utc_now(),
        }
        secret_path, meta_path = self._paths(token)
        self._write_private(secret_path, payload)
        try:
            self._write_private(
                meta_path, json.dumps(metadata, sort_keys=True).encode("utf-8")
            )
        except Exception:
            # A secret without its metadata is unusable; never leave it behind.
            secret_path.unlink(missing_ok=True)
            raise
        return secret_ref(token)

    def get(self, ref: str, *, tenant_id: str | None = None) -> bytes:
        """Read the plaintext of ``ref``; raises when it is unknown.

        ``tenant_id`` is optional: a reference is already unguessable, and the
        stored metadata is checked against it when the caller knows its tenant.
        """
        token = self._token(ref)
        secret_path, meta_path = self._paths(token)
        try:
            descriptor = os.open(secret_path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            raise KeyError(f"unknown secret reference: {ref}") from None
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SECRET_BYTES:
                raise RuntimeError("secret file rejected")
            payload = stream.read(MAX_SECRET_BYTES + 1)
        if len(payload) > MAX_SECRET_BYTES:
            raise RuntimeError("secret exceeds the read limit")
        if tenant_id is not None:
            stored = self.metadata(ref).get("tenant_id")
            if stored is not None and str(stored) != str(tenant_id):
                raise KeyError(f"unknown secret reference: {ref}")
        if not meta_path.exists():  # pragma: no cover - defensive
            raise RuntimeError("secret metadata is missing")
        return payload

    def metadata(self, ref: str) -> dict[str, Any]:
        """Return the non-secret metadata of ``ref`` (kind, tenant, size, date)."""
        token = self._token(ref)
        _secret_path, meta_path = self._paths(token)
        try:
            return json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def has(self, ref: str) -> bool:
        """Whether ``ref`` is a well-formed reference this store can read."""
        if not is_secret_ref(ref):
            return False
        secret_path, _meta = self._paths(self._token(ref))
        return secret_path.is_file()


def vault_root() -> Path:
    """Resolve the vault root (``NEXUS_VAULT_ROOT`` override, else XDG state)."""
    override = os.environ.get(VAULT_ROOT_ENV)
    if override:
        return Path(override).expanduser()
    from nexus_core.config.xdg import resolve_xdg_paths

    return Path(resolve_xdg_paths().state_dir) / "omni" / "vault"


_STORES: dict[str, SecretStore] = {}


def default_secret_store() -> SecretStore:
    """Return the process-wide vault for the configured root (cheap, cached)."""
    root = str(vault_root())
    store = _STORES.get(root)
    if store is None:
        store = SecretStore(root)
        _STORES[root] = store
    return store


def resolve_secret_reference(
    arguments: dict[str, Any],
    *,
    ref_field: str = "credential_ref",
    field: str = "password",
    tenant_id: str | None = None,
    store: SecretStore | None = None,
) -> dict[str, Any]:
    """Return ``arguments`` with the referenced secret resolved into ``field``.

    A tool that consumes a credential accepts ``credential_ref`` (the agent's
    form, preferred) or ``field`` (plaintext, for manual use). When the reference
    is present it is read here —in the tool's own process, before the handler
    builds its subprocess— and injected under ``field``. Without a reference the
    arguments are returned untouched, so the manual interface is unchanged.
    """
    ref = arguments.get(ref_field)
    if not ref:
        return arguments
    if not is_secret_ref(ref):
        raise ValueError(f"invalid {ref_field}: {ref!r}")
    vault = store or default_secret_store()
    try:
        plaintext = vault.get(str(ref), tenant_id=tenant_id).decode("utf-8")
    except KeyError:
        raise ValueError(f"unknown {ref_field}: {ref}") from None
    resolved = dict(arguments)
    resolved.setdefault(field, plaintext)
    return resolved


__all__ = [
    "DEFAULT_SECRET_KIND",
    "DEFAULT_TENANT",
    "MAX_SECRET_BYTES",
    "SECRET_REF_RE",
    "VAULT_PREFIX",
    "VAULT_ROOT_ENV",
    "VAULT_SCHEME",
    "SecretStore",
    "default_secret_store",
    "is_secret_ref",
    "resolve_secret_reference",
    "secret_ref",
    "vault_root",
]
