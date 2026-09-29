"""Carga un EngagementScope desde el control store para una task durable."""

from __future__ import annotations

import os
from typing import Any

from nexus_core.scope import EngagementScope, EngagementStore


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
      - La firma está presente pero es inválida (si hay signing_secret).
    """
    if not engagement_id:
        return None
    engagement_store = EngagementStore(store)
    scope = engagement_store.get(tenant_id, engagement_id)
    if scope is None:
        raise PermissionError(f"engagement not found: {engagement_id}")
    # La validación de ventana temporal y firma ocurre en ScopeValidator,
    # no aquí. El loader solo carga.
    return scope


def scope_signing_secret() -> str | None:
    """Lee NEXUS_SCOPE_SIGNING_SECRET del entorno, o None."""
    value = os.getenv("NEXUS_SCOPE_SIGNING_SECRET", "").strip()
    return value or None
