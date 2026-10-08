"""Carga un EngagementScope desde el control store para una task durable."""

from __future__ import annotations

import os
from typing import Any

from nexus_core.scope import EngagementScope, EngagementStore, ScopeValidator
from .audit import AuditWriter


def load_engagement_scope(
    store: Any,
    tenant_id: str,
    engagement_id: str | None,
) -> EngagementScope | None:
    """
    Devuelve el EngagementScope o None si engagement_id no se especifica.

    Lanza PermissionError si:
      - engagement_id se especifica pero no existe para el tenant.
      - La engagement existe pero no está dentro de la ventana temporal.
      - La firma falta o es inválida en modo governed.
    """
    if not engagement_id:
        return None
    engagement_store = EngagementStore(store)
    scope = engagement_store.get(tenant_id, engagement_id)
    if scope is None:
        raise PermissionError(f"engagement not found: {engagement_id}")
    validate_scope_authentication(scope, store, tenant_id)
    return scope


def scope_signing_secret() -> str | None:
    """Lee NEXUS_SCOPE_SIGNING_SECRET del entorno, o None."""
    value = os.getenv("NEXUS_SCOPE_SIGNING_SECRET", "").strip()
    return value or None


def validate_scope_authentication(scope, store, tenant_id, trace_id=None, actor_id="runtime"):
    """Authenticate before exposing scope to any runtime, even scope-free tools."""
    writer = AuditWriter(store)

    def audit(action, detail):
        writer.append(tenant_id=tenant_id, trace_id=trace_id or scope.engagement_id,
                      actor_id=actor_id, action=action, resource_type="scope",
                      resource_id=scope.engagement_id, payload=detail,
                      decision="deny" if action == "scope.denied" else "allow")

    try:
        if scope.tenant_id != tenant_id:
            raise PermissionError("scope belongs to another tenant")
        validator = ScopeValidator(scope, signing_secret=scope_signing_secret(), audit=audit)
        validator._validate_signature()
        validator._validate_time_window()
    except Exception as exc:
        audit("scope.denied", {"reason": str(exc), "mode": os.getenv("NEXUS_SCOPE_MODE", "governed")})
        raise
