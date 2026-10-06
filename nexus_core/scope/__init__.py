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
from .roe import (
    RoEEnforcer,
    RoEKillSwitch,
    RoEViolation,
    RulesOfEngagement,
    TimeWindow,
    load_enforcer,
    load_roe,
    make_roe_validator,
    save_roe,
)
from .store import EngagementStore
from .validator import ScopeValidator, make_scope_validator

__all__ = [
    "DNSResolver",
    "EngagementScope",
    "EngagementStore",
    "ResolvedTarget",
    "RoEEnforcer",
    "RoEKillSwitch",
    "RoEViolation",
    "RulesOfEngagement",
    "ScopeExpired",
    "ScopeKind",
    "ScopePrivateIP",
    "ScopeSignatureInvalid",
    "ScopeUnresolvable",
    "ScopeValidator",
    "ScopeViolation",
    "TimeWindow",
    "load_enforcer",
    "load_roe",
    "make_roe_validator",
    "make_scope_validator",
    "save_roe",
]
