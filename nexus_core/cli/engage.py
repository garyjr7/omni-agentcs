"""Create and manage signed engagement scopes from the CLI.

An engagement is a signed, time-bounded authorization envelope. Creating one
used to require onboarding or an external script; these helpers let the REPL
(``/engage``) and the CLI (``--new-engagement``) do it safely: the scope is
built from concrete domains/CIDRs, signed with the operator's
``scope.signing_secret`` and persisted in the control store.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import getpass
import hashlib
import hmac
import ipaddress
import re
import socket
from typing import Any
from uuid import uuid4

from nexus_core.scope import EngagementScope, EngagementStore

#: Concrete domain names only (no wildcard, no scheme, no path).
_DOMAIN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}")
DEFAULT_VALID_HOURS = 24


def parse_scope_entries(entries: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split ``"10.0.0.0/24, scanme.nmap.org"`` into ``(cidrs, domains)``.

    CIDRs are canonicalized; domains are lowercased and resolved to /32 (or
    /128) CIDRs, exactly like the onboarding wizard. Raises ``ValueError`` for a
    malformed entry or an empty scope.
    """
    cidrs: set[str] = set()
    domains: list[str] = []
    for raw in str(entries or "").split(","):
        entry = raw.strip()
        if not entry:
            continue
        try:
            cidrs.add(str(ipaddress.ip_network(entry, strict=False)))
            continue
        except ValueError:
            pass
        if not _DOMAIN_RE.fullmatch(entry):
            raise ValueError("scope debe contener dominios concretos o CIDRs")
        domains.append(entry.lower())
        try:
            infos = socket.getaddrinfo(entry, None, type=socket.SOCK_STREAM)
        except OSError as exc:  # noqa: PERF203 - one entry failure aborts
            raise ValueError(f"no se pudo resolver el dominio {entry!r}: {exc}") from exc
        for info in infos:
            addr = ipaddress.ip_address(info[4][0])
            cidrs.add(f"{addr}/{addr.max_prefixlen}")
    if not cidrs:
        raise ValueError("scope vacío")
    return tuple(sorted(cidrs)), tuple(domains)


def build_scope(
    name: str,
    entries: str,
    secret: str,
    *,
    tenant_id: str = "system",
    client: str = "operator",
    owner_id: str | None = None,
    hours: int = DEFAULT_VALID_HOURS,
) -> EngagementScope:
    """Build a signed :class:`EngagementScope` (not persisted).

    ``created_at`` is set *before* signing because it is part of the canonical
    form: filling it later would invalidate the stored signature.
    """
    cidrs, domains = parse_scope_entries(entries)
    now = datetime.now(timezone.utc)
    scope = EngagementScope(
        engagement_id="eng-" + uuid4().hex[:12],
        tenant_id=tenant_id,
        name=str(name).strip() or "Engagement",
        client=client,
        owner_id=owner_id or ("operator:" + getpass.getuser()),
        valid_from=now.isoformat(),
        valid_until=(now + timedelta(hours=max(1, int(hours)))).isoformat(),
        cidrs=cidrs,
        domains=domains,
        urls=(),
        exclusions=(),
        created_at=now.isoformat(),
    )
    signature = hmac.new(
        str(secret).encode(), scope.canonical_form().encode(), hashlib.sha256
    ).hexdigest()
    return replace(scope, signature=signature)


def signing_secret() -> str:
    """The engagement signing secret from ``config.toml`` (may be empty)."""
    from nexus_core.config.loader import load_config
    from nexus_core.config.xdg import resolve_xdg_paths

    return str(getattr(load_config(resolve_xdg_paths()).scope, "signing_secret", "") or "")


def create_engagement(
    store: Any,
    name: str,
    entries: str,
    *,
    tenant_id: str = "system",
    hours: int = DEFAULT_VALID_HOURS,
    secret: str | None = None,
) -> EngagementScope:
    """Sign and persist a new engagement; return the created scope."""
    resolved_secret = signing_secret() if secret is None else str(secret)
    if not resolved_secret:
        raise ValueError(
            "config.toml no tiene scope.signing_secret; ejecuta `omni --setup` una vez"
        )
    scope = build_scope(
        name, entries, resolved_secret, tenant_id=tenant_id, hours=hours
    )
    return EngagementStore(store).create(scope)


def list_engagements(store: Any, tenant_id: str = "system") -> list[EngagementScope]:
    """Every engagement of a tenant, oldest first (best effort)."""
    if store is None:
        return []
    try:
        return EngagementStore(store).list_for_tenant(tenant_id)
    except Exception:  # noqa: BLE001 - listing must never break the REPL
        return []


def get_engagement(store: Any, tenant_id: str, engagement_id: str) -> EngagementScope | None:
    """Return one engagement by id, or ``None`` (best effort)."""
    if store is None:
        return None
    try:
        return EngagementStore(store).get(tenant_id, engagement_id)
    except Exception:  # noqa: BLE001 - lookup must never break the REPL
        return None


__all__ = [
    "DEFAULT_VALID_HOURS",
    "build_scope",
    "create_engagement",
    "get_engagement",
    "list_engagements",
    "parse_scope_entries",
    "signing_secret",
]
