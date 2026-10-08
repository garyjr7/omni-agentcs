"""Scope gating for the new web/recon durable tools.

The kernel derives the scope check from ``scope_target_field``/``scope_required``
on each ToolDefinition. These tests drive ``make_scope_validator`` directly with
the real definitions, so an in-scope target passes and an out-of-scope one is
denied before any process is spawned.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from nexus_core.scope import EngagementScope, ScopeViolation
from nexus_core.scope.validator import make_scope_validator
from nexus_core.tools.handlers.dalfox import dalfox_definition
from nexus_core.tools.handlers.gobuster import gobuster_definition
from nexus_core.tools.handlers.searchsploit import searchsploit_definition
from nexus_core.tools.handlers.sqlmap import sqlmap_definition
from nexus_core.tools.handlers.whatweb import whatweb_definition

IN_SCOPE = "45.33.32.156"
OUT_OF_SCOPE = "8.8.8.8"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-scanme",
        tenant_id="system",
        name="scanme",
        client="NEXUS",
        owner_id="operator",
        valid_from=_iso(-timedelta(days=1)),
        valid_until=_iso(timedelta(days=1)),
        cidrs=(f"{IN_SCOPE}/32",),
        domains=(),
        urls=(),
        exclusions=(),
        created_at=_iso(timedelta(0)),
    )


@dataclass
class _Context:
    scope: EngagementScope


def _validate(definition, target) -> None:
    validator = make_scope_validator()
    field = definition.scope_target_field
    arguments = {field: target}
    validator(_Context(_scope()), definition, arguments)


def test_sqlmap_in_scope_url_passes():
    _validate(sqlmap_definition(), f"http://{IN_SCOPE}/?id=1")


def test_sqlmap_out_of_scope_url_denied():
    with pytest.raises(ScopeViolation):
        _validate(sqlmap_definition(), f"http://{OUT_OF_SCOPE}/?id=1")


def test_gobuster_in_scope_target_passes():
    _validate(gobuster_definition(), f"http://{IN_SCOPE}/")


def test_gobuster_out_of_scope_target_denied():
    with pytest.raises(ScopeViolation):
        _validate(gobuster_definition(), f"http://{OUT_OF_SCOPE}/")


def test_whatweb_in_scope_targets_pass():
    _validate(whatweb_definition(), [f"http://{IN_SCOPE}/"])


def test_whatweb_out_of_scope_target_denied():
    with pytest.raises(ScopeViolation):
        _validate(whatweb_definition(), [f"http://{IN_SCOPE}/", f"http://{OUT_OF_SCOPE}/"])


def test_dalfox_in_scope_target_passes():
    _validate(dalfox_definition(), f"http://{IN_SCOPE}/?q=1")


def test_dalfox_out_of_scope_target_denied():
    with pytest.raises(ScopeViolation):
        _validate(dalfox_definition(), f"http://{OUT_OF_SCOPE}/?q=1")


def test_searchsploit_needs_no_scope():
    definition = searchsploit_definition()
    assert definition.scope_required is False
    assert definition.scope_target_field is None


# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))
