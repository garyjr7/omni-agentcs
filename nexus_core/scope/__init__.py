"""Scope gating: signed engagements and mandatory target validation."""

from .models import (
    EngagementScope,
    ResolvedTarget,
    ScopeExpired,
    ScopeKind,
    ScopePrivateIP,
    ScopeSignatureInvalid,
    ScopeUnresolvable,
    ScopeViolation,
)
from .resolver import DNSResolver
from .store import EngagementStore
from .validator import ScopeValidator, make_scope_validator

__all__ = [
    "DNSResolver",
    "EngagementScope",
    "EngagementStore",
    "ResolvedTarget",
    "ScopeExpired",
    "ScopeKind",
    "ScopePrivateIP",
    "ScopeSignatureInvalid",
    "ScopeUnresolvable",
    "ScopeValidator",
    "ScopeViolation",
    "make_scope_validator",
]
