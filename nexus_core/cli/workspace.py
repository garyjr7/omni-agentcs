"""Stable, tenant-scoped local engagements; no network authorization is inferred."""
from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from nexus_core.scope import EngagementScope, EngagementStore


def _same_workspace(scope: EngagementScope, root: Path) -> bool:
    return (
        getattr(scope, 'client', '') == 'local-workspace'
        and getattr(scope, 'notes', '') == str(root)
    )


def bind_workspace(store: Any, tenant_id: str, root: Path) -> EngagementScope:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('El workspace debe ser un directorio')
    identity = hashlib.sha256((tenant_id + '\0' + str(root)).encode()).hexdigest()
    engagement_id = 'local-' + identity
    scopes = EngagementStore(store)
    existing = scopes.get(tenant_id, engagement_id)
    if existing is not None:
        return existing

    # Local engagements are named after the folder, but ``(tenant_id, name)`` is
    # unique: two checkouts called ``bountyv1`` under different parents must not
    # crash startup. The first keeps the plain name; later ones get a hash
    # suffix. A same-name row pointing at this exact path is the same workspace
    # (e.g. a legacy id), so it is reused instead of duplicated.
    base_name = root.name or str(root)
    candidates = (base_name, f'{base_name} [{identity[:12]}]', f'{base_name} [{identity}]')
    last_error: sqlite3.IntegrityError | None = None
    for name in candidates:
        same_name = scopes.get_by_name(tenant_id, name)
        if same_name is not None:
            if _same_workspace(same_name, root):
                return same_name
            continue
        now = datetime.now(UTC)
        scope = EngagementScope(
            engagement_id=engagement_id, tenant_id=tenant_id, name=name,
            client='local-workspace', owner_id='operator', valid_from=now.isoformat(),
            valid_until=(now + timedelta(days=3650)).isoformat(), cidrs=(), domains=(),
            urls=(), exclusions=(), notes=str(root), created_at=now.isoformat(),
        )
        try:
            return scopes.create(scope)
        except sqlite3.IntegrityError as exc:
            last_error = exc
            # A simultaneous startup may win the primary key or the name. If it
            # was this path, reuse it; otherwise try the next candidate.
            existing = scopes.get(tenant_id, engagement_id)
            if existing is not None:
                return existing
            same_name = scopes.get_by_name(tenant_id, name)
            if same_name is not None and _same_workspace(same_name, root):
                return same_name
    if last_error is not None:
        raise last_error
    raise RuntimeError('no se pudo crear el engagement local')


def workspace_root(scope: Any) -> Path:
    root = Path(scope.notes) if getattr(scope, 'client', '') == 'local-workspace' else Path.cwd()
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError('El workspace del engagement ya no es un directorio')
    return resolved
