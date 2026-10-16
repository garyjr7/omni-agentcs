"""Stable, tenant-scoped local engagements; no network authorization is inferred."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from nexus_core.scope import EngagementScope, EngagementStore


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
    now = datetime.now(timezone.utc)
    scope = EngagementScope(
        engagement_id=engagement_id, tenant_id=tenant_id, name=root.name or str(root),
        client='local-workspace', owner_id='operator', valid_from=now.isoformat(),
        valid_until=(now + timedelta(days=3650)).isoformat(), cidrs=(), domains=(),
        urls=(), exclusions=(), notes=str(root), created_at=now.isoformat(),
    )
    try:
        return scopes.create(scope)
    except Exception:
        # A simultaneous startup may win the unique primary-key insertion.
        existing = scopes.get(tenant_id, engagement_id)
        if existing is None:
            raise
        return existing


def workspace_root(scope: Any) -> Path:
    root = Path(scope.notes) if getattr(scope, 'client', '') == 'local-workspace' else Path.cwd()
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError('El workspace del engagement ya no es un directorio')
    return resolved
