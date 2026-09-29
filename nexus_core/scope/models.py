"""Canonical, serializable models for engagement scope gating.

An :class:`EngagementScope` is a signed, time-bounded authorization envelope
for offensive/engagement targets. Targets are validated against it *before*
the policy engine and any tool handler run, so a tool can never receive a
target outside the signed engagement.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ScopeKind(str, Enum):
    """Kind of target accepted by the scope validator."""

    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"


def parse_iso8601(value: str) -> datetime:
    """Parse an ISO 8601 string into a timezone-aware UTC ``datetime``.

    Naive timestamps are interpreted as UTC. ``Z`` suffixes are accepted.
    """
    text = str(value).strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class EngagementScope:
    """Signed, durable authorization envelope for a single engagement."""

    engagement_id: str
    tenant_id: str
    name: str
    client: str
    owner_id: str
    valid_from: str
    valid_until: str
    cidrs: tuple[str, ...]
    domains: tuple[str, ...]
    urls: tuple[str, ...]
    exclusions: tuple[str, ...]
    notes: str = ""
    signature: str = ""
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the scope."""
        return {
            "engagement_id": self.engagement_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "client": self.client,
            "owner_id": self.owner_id,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "cidrs": list(self.cidrs),
            "domains": list(self.domains),
            "urls": list(self.urls),
            "exclusions": list(self.exclusions),
            "notes": self.notes,
            "signature": self.signature,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> EngagementScope:
        """Rebuild a scope from :meth:`to_dict` output or a decoded DB row."""
        return cls(
            engagement_id=str(value["engagement_id"]),
            tenant_id=str(value["tenant_id"]),
            name=str(value["name"]),
            client=str(value["client"]),
            owner_id=str(value["owner_id"]),
            valid_from=str(value["valid_from"]),
            valid_until=str(value["valid_until"]),
            cidrs=tuple(value.get("cidrs") or ()),
            domains=tuple(value.get("domains") or ()),
            urls=tuple(value.get("urls") or ()),
            exclusions=tuple(value.get("exclusions") or ()),
            notes=str(value.get("notes") or ""),
            signature=str(value.get("signature") or ""),
            created_at=str(value.get("created_at") or ""),
        )

    def canonical_form(self) -> str:
        """Return the deterministic byte string signed by HMAC-SHA256.

        The ``signature`` field itself is excluded so a scope can be signed and
        later re-verified without mutating the canonical payload.
        """
        payload = self.to_dict()
        payload.pop("signature", None)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class ResolvedTarget:
    """Result of successfully validating a single target against a scope."""

    original: str
    kind: ScopeKind
    ip: str | None
    domain: str | None
    matched_rule: str
    resolved_ips: tuple[str, ...] = ()


class ScopeViolation(Exception):
    """Raised whenever a target is not authorized by the engagement scope."""

    def __init__(self, target: str, reason: str, engagement_id: str = ""):
        self.target = target
        self.reason = reason
        self.engagement_id = engagement_id
        super().__init__(f"ScopeViolation({target}): {reason}")


class ScopeExpired(ScopeViolation):
    """Raised when the current time falls outside the validity window."""


class ScopeSignatureInvalid(ScopeViolation):
    """Raised when the HMAC signature does not match the canonical form."""


class ScopeUnresolvable(ScopeViolation):
    """Raised when a domain target cannot be resolved to addresses."""


class ScopePrivateIP(ScopeViolation):
    """Raised when a private/loopback/multicast address is not authorized."""
