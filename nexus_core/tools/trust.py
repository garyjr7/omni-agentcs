"""Operator trust for third-party tool plugins (SEC-05).

An entry point under ``nexus.tools`` is code shipped by a distribution the
operator may never have reviewed. Discovery used to import every published
entry point, so installing a package was enough to run code with the operator's
privileges. This module holds the approval:

* a private ``tools-trust.json`` (0600) pins the SHA-256 of **every file of the
  distribution**, so a change in any module revokes the trust;
* discovery asks :func:`is_trusted` *before* importing the entry point, and a
  missing or changed hash means the plugin is skipped, never loaded;
* the target is part of the record, so another distribution cannot reuse the
  name of a trusted plugin.

The pin covers the distribution itself, not its dependencies. A trusted plugin
that imports a compromised dependency is still a supply-chain risk outside this
boundary; that is stated in ``SECURITY.md`` instead of being implied.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

from nexus_core.cli.tui.history import atomic_private
from nexus_core.config.xdg import resolve_xdg_paths

#: Entry-point group third-party distributions publish tools under.
ENTRY_POINT_GROUP = "nexus.tools"
#: Private file (0600) with the approved plugin digests.
TRUST_FILENAME = "tools-trust.json"


def trust_path() -> Path:
    """``~/.config/omni/tools-trust.json`` (honours ``XDG_CONFIG_HOME``)."""
    return resolve_xdg_paths().config_dir / TRUST_FILENAME


def _read_trust() -> dict[str, Any]:
    try:
        data = json.loads(trust_path().read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def installed_entry_points() -> list[Any]:
    """Entry points in :data:`ENTRY_POINT_GROUP`, without loading them."""
    try:
        return list(entry_points(group=ENTRY_POINT_GROUP))
    except TypeError:  # pragma: no cover - importlib pre-3.10 API
        return list(entry_points().select(group=ENTRY_POINT_GROUP))


def entry_digest(entry: Any) -> str | None:
    """SHA-256 of the entry point's distribution, without importing it.

    Every file listed by the distribution is hashed, which also covers modules
    the entry point imports later. When metadata lists no files (a fake entry
    point in a test, a single-file plugin), only a **top-level** module is
    resolved: ``find_spec`` on a dotted name imports its parent package, and
    that is exactly the code that must not run before approval.
    """
    dist = getattr(entry, "dist", None)
    files = list(getattr(dist, "files", None) or []) if dist is not None else []
    if dist is not None and files:
        digest = hashlib.sha256()
        try:
            for member in sorted(files, key=str):
                if str(member).endswith((".pyc", ".pyo")):
                    continue
                path = Path(dist.locate_file(member)).resolve()
                if not path.is_file():
                    continue
                digest.update(str(member).encode("utf-8"))
                digest.update(b"\0")
                digest.update(path.read_bytes())
                digest.update(b"\0")
        except OSError:
            return None
        return digest.hexdigest()
    module = str(getattr(entry, "value", "") or "").split(":", 1)[0].strip()
    if not module or "." in module:
        return None
    try:
        spec = importlib.util.find_spec(module)
    except (ImportError, AttributeError, ValueError):
        return None
    origin = getattr(spec, "origin", None)
    if not origin or not Path(origin).is_file():
        return None
    return hashlib.sha256(Path(origin).read_bytes()).hexdigest()


def is_trusted(entry: Any) -> bool:
    """Whether the entry point's distribution matches an approved digest."""
    record = _read_trust().get(str(getattr(entry, "name", "")))
    if not isinstance(record, dict):
        return False
    if record.get("target") != str(getattr(entry, "value", "")):
        return False
    digest = entry_digest(entry)
    return digest is not None and record.get("sha256") == digest


def approve_plugin(
    name: str,
    entry: Any,
    operator: Any,
    *,
    expected_hash: str | None = None,
    approved_at: str | None = None,
) -> dict[str, Any]:
    """Record a human operator's approval of one entry point (fail closed)."""
    if operator.kind != "human" or not set(operator.roles) & {"operator", "admin"}:
        raise PermissionError("human operator approval required for tool plugins")
    digest = entry_digest(entry)
    if digest is None:
        raise ValueError("cannot hash this distribution: plugin stays untrusted")
    if expected_hash is not None and str(expected_hash).lower() != digest:
        raise ValueError("plugin hash does not match the reviewed revision")
    from nexus_core.kernel.models import utc_now

    record = {
        "sha256": digest,
        "target": str(getattr(entry, "value", "")),
        "operator_id": operator.subject_id,
        "tenant_id": operator.tenant_id,
        "approved_at": approved_at or utc_now(),
    }
    data = _read_trust()
    data[str(name)] = record
    atomic_private(trust_path(), json.dumps(data).encode())
    return record


def trusted_plugins() -> list[dict[str, str]]:
    """Approved plugins, newest data first by name."""
    return [
        {
            "name": name,
            **{
                key: str(record.get(key, ""))
                for key in ("sha256", "target", "operator_id", "approved_at")
            },
        }
        for name, record in sorted(_read_trust().items())
        if isinstance(record, dict)
    ]


def revoke_plugin(name: str) -> bool:
    """Remove one approval; returns whether it existed."""
    data = _read_trust()
    if str(name) not in data:
        return False
    del data[str(name)]
    atomic_private(trust_path(), json.dumps(data).encode())
    return True


__all__ = [
    "ENTRY_POINT_GROUP",
    "TRUST_FILENAME",
    "approve_plugin",
    "entry_digest",
    "installed_entry_points",
    "is_trusted",
    "revoke_plugin",
    "trust_path",
    "trusted_plugins",
]
