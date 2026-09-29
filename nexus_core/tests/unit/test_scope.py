"""Unit and integration tests for signed engagement scope gating.

All DNS access is mocked; the suite performs no network I/O.
"""

import asyncio
import hashlib
import hmac
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from nexus_core.kernel import Identity, PolicyEngine, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.scope import (
    DNSResolver,
    EngagementScope,
    EngagementStore,
    ScopeExpired,
    ScopeKind,
    ScopePrivateIP,
    ScopeSignatureInvalid,
    ScopeUnresolvable,
    ScopeValidator,
    ScopeViolation,
    make_scope_validator,
)

PUBLIC_DOC_CIDR = "203.0.113.0/24"  # TEST-NET-3
OUT_OF_SCOPE_IP = "8.8.8.8"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def make_scope(**overrides) -> EngagementScope:
    base = {
        "engagement_id": "eng-1",
        "tenant_id": "system",
        "name": "engagement",
        "client": "acme",
        "owner_id": "owner-1",
        "valid_from": _iso(-timedelta(days=1)),
        "valid_until": _iso(timedelta(days=1)),
        "cidrs": (PUBLIC_DOC_CIDR,),
        "domains": (),
        "urls": (),
        "exclusions": (),
        "notes": "",
        "signature": "",
        "created_at": _iso(timedelta(0)),
    }
    base.update(overrides)
    return EngagementScope(**base)


def sign(scope: EngagementScope, secret: str) -> EngagementScope:
    signature = hmac.new(
        secret.encode("utf-8"),
        scope.canonical_form().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return EngagementScope.from_dict({**scope.to_dict(), "signature": signature})


class ScopeValidationTests(unittest.TestCase):
    def test_ip_in_scope_passes(self):
        result = ScopeValidator(make_scope()).validate("203.0.113.10")
        self.assertEqual(result.kind, ScopeKind.IP)
        self.assertEqual(result.ip, "203.0.113.10")
        self.assertEqual(result.matched_rule, PUBLIC_DOC_CIDR)

    def test_ip_out_of_scope_raises(self):
        with self.assertRaises(ScopeViolation):
            ScopeValidator(make_scope()).validate(OUT_OF_SCOPE_IP)

    def test_cidr_fully_contained_passes(self):
        result = ScopeValidator(make_scope()).validate("203.0.113.0/25")
        self.assertEqual(result.kind, ScopeKind.CIDR)
        self.assertEqual(result.matched_rule, PUBLIC_DOC_CIDR)

    def test_cidr_partially_outside_raises(self):
        with self.assertRaises(ScopeViolation):
            ScopeValidator(make_scope()).validate("203.0.112.0/23")

    def test_exclusion_overrides_scope(self):
        scope = make_scope(exclusions=("203.0.113.10",))
        with self.assertRaises(ScopeViolation):
            ScopeValidator(scope).validate("203.0.113.10")

    def test_domain_exact_match(self):
        scope = make_scope(domains=("example.com",))
        with mock.patch.object(DNSResolver, "resolve", return_value=("203.0.113.10",)):
            result = ScopeValidator(scope).validate("example.com")
        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.resolved_ips, ("203.0.113.10",))

    def test_domain_wildcard_matches_subdomain(self):
        scope = make_scope(domains=("*.example.com",))
        with mock.patch.object(DNSResolver, "resolve", return_value=("203.0.113.10",)):
            result = ScopeValidator(scope).validate("api.example.com")
        self.assertEqual(result.matched_rule, "*.example.com")

    def test_domain_wildcard_does_not_match_root(self):
        scope = make_scope(domains=("*.example.com",))
        with self.assertRaises(ScopeViolation):
            ScopeValidator(scope).validate("example.com")

    def test_domain_dot_prefix_matches_root_and_sub(self):
        scope = make_scope(domains=(".example.com",))
        with mock.patch.object(DNSResolver, "resolve", return_value=("203.0.113.10",)):
            validator = ScopeValidator(scope)
            self.assertEqual(validator.validate("example.com").matched_rule, ".example.com")
            self.assertEqual(validator.validate("api.example.com").matched_rule, ".example.com")

    def test_domain_resolves_to_multiple_ips_all_must_be_in_scope(self):
        scope = make_scope(domains=("example.com",))
        resolved = ("203.0.113.10", "203.0.113.11", OUT_OF_SCOPE_IP)
        with mock.patch.object(DNSResolver, "resolve", return_value=resolved):
            with self.assertRaises(ScopeViolation):
                ScopeValidator(scope).validate("example.com")

    def test_domain_resolving_to_private_ip_outside_private_cidr_raises(self):
        scope = make_scope(domains=("internal.example.com",))
        with mock.patch.object(DNSResolver, "resolve", return_value=("10.0.0.5",)):
            with self.assertRaises(ScopePrivateIP):
                ScopeValidator(scope).validate("internal.example.com")

    def test_url_target_extracts_host(self):
        scope = make_scope(domains=("api.example.com",))
        with mock.patch.object(DNSResolver, "resolve", return_value=("203.0.113.10",)):
            result = ScopeValidator(scope).validate("https://api.example.com/admin")
        self.assertEqual(result.kind, ScopeKind.URL)
        self.assertEqual(result.domain, "api.example.com")

    def test_time_window_expired_raises(self):
        scope = make_scope(
            valid_from=_iso(-timedelta(days=2)), valid_until=_iso(-timedelta(days=1))
        )
        with self.assertRaises(ScopeExpired):
            ScopeValidator(scope).validate("203.0.113.10")

    def test_time_window_not_yet_valid_raises(self):
        scope = make_scope(
            valid_from=_iso(timedelta(days=1)), valid_until=_iso(timedelta(days=2))
        )
        with self.assertRaises(ScopeExpired):
            ScopeValidator(scope).validate("203.0.113.10")

    def test_signature_valid_passes(self):
        secret = "top-secret"
        scope = sign(make_scope(), secret)
        result = ScopeValidator(scope, signing_secret=secret).validate("203.0.113.10")
        self.assertEqual(result.ip, "203.0.113.10")

    def test_signature_invalid_raises(self):
        scope = make_scope(signature="0" * 64)
        with self.assertRaises(ScopeSignatureInvalid):
            ScopeValidator(scope, signing_secret="top-secret").validate("203.0.113.10")

    def test_signature_absent_is_allowed(self):
        scope = make_scope(signature="")
        result = ScopeValidator(scope, signing_secret="top-secret").validate("203.0.113.10")
        self.assertEqual(result.ip, "203.0.113.10")

    def test_private_ip_with_private_cidr_is_allowed(self):
        scope = make_scope(cidrs=("10.0.0.0/8",))
        result = ScopeValidator(scope).validate("10.1.2.3")
        self.assertEqual(result.matched_rule, "10.0.0.0/8")

    def test_private_ip_denied_when_disabled(self):
        scope = make_scope(cidrs=("10.0.0.0/8",))
        with self.assertRaises(ScopePrivateIP):
            ScopeValidator(scope, allow_private_ips_in_scope=False).validate("10.1.2.3")

    def test_unrecognized_target_raises(self):
        with self.assertRaises(ScopeViolation):
            ScopeValidator(make_scope()).validate("not-a-target")


class ScopeResolverTests(unittest.TestCase):
    def test_resolver_deduplicates_and_caches(self):
        resolver = DNSResolver(cache_ttl_seconds=300)
        infos = [
            (2, 1, 6, "", ("203.0.113.10", 0)),
            (2, 1, 6, "", ("203.0.113.10", 0)),
            (2, 1, 6, "", ("203.0.113.11", 0)),
        ]
        with mock.patch(
            "nexus_core.scope.resolver.socket.getaddrinfo", return_value=infos
        ) as patched:
            first = resolver.resolve("example.com")
            second = resolver.resolve("example.com")
        self.assertEqual(first, ("203.0.113.10", "203.0.113.11"))
        self.assertEqual(second, first)
        self.assertEqual(patched.call_count, 1)

    def test_resolver_failure_raises_unresolvable(self):
        resolver = DNSResolver()
        with mock.patch(
            "nexus_core.scope.resolver.socket.getaddrinfo", side_effect=OSError("boom")
        ):
            with self.assertRaises(ScopeUnresolvable):
                resolver.resolve("example.com")


class ScopeStoreTests(unittest.TestCase):
    def test_store_roundtrip_and_tenant_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            engagements = EngagementStore(store)
            created = engagements.create(make_scope())
            self.assertTrue(created.created_at)
            loaded = engagements.get("system", "eng-1")
            self.assertEqual(loaded, created)
            self.assertEqual(engagements.get("other", "eng-1"), None)
            self.assertEqual(len(engagements.list_for_tenant("system")), 1)
            engagements.update_signature("system", "eng-1", "sig")
            self.assertEqual(engagements.get("system", "eng-1").signature, "sig")
            self.assertTrue(engagements.delete("system", "eng-1"))
            self.assertFalse(engagements.delete("system", "eng-1"))

    def test_load_active_returns_current_engagement(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            engagements = EngagementStore(store)
            engagements.create(
                make_scope(
                    engagement_id="expired", name="expired",
                    valid_from=_iso(-timedelta(days=5)),
                    valid_until=_iso(-timedelta(days=4)),
                )
            )
            engagements.create(
                make_scope(engagement_id="active", name="active")
            )
            active = engagements.load_active("system")
            self.assertIsNotNone(active)
            self.assertEqual(active.engagement_id, "active")


def make_gateway(store, scope):
    return ToolGateway(
        PolicyEngine(),
        AuditWriter(store),
        scope_validator=make_scope_validator(),
    )


def make_scan_tool():
    return ToolDefinition(
        "scan",
        "system",
        {
            "type": "object",
            "required": ["target"],
            "properties": {"target": {"type": "string"}},
        },
        scope_target_field="target",
        scope_required=True,
    )


class ScopeGatewayIntegrationTests(unittest.TestCase):
    def test_tool_gateway_denies_when_scope_required_and_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            gateway = make_gateway(store, None)
            tool = make_scan_tool()
            gateway.register(tool, lambda arguments, context: ToolResult(verified=True))
            context = RunContext(
                "system", Identity("operator-1", "system", roles=("operator",))
            )
            with self.assertRaises(PermissionError):
                asyncio.run(gateway.invoke(tool.tool_id, {"target": "203.0.113.10"}, context))

    def test_tool_gateway_denies_when_target_out_of_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            gateway = make_gateway(store, make_scope())
            tool = make_scan_tool()
            gateway.register(tool, lambda arguments, context: ToolResult(verified=True))
            context = RunContext(
                "system",
                Identity("operator-1", "system", roles=("operator",)),
                scope=make_scope(),
            )
            with self.assertRaises(ScopeViolation):
                asyncio.run(gateway.invoke(tool.tool_id, {"target": OUT_OF_SCOPE_IP}, context))

    def test_tool_gateway_audits_scope_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            gateway = make_gateway(store, make_scope())
            tool = make_scan_tool()
            gateway.register(tool, lambda arguments, context: ToolResult(verified=True))
            context = RunContext(
                "system",
                Identity("operator-1", "system", roles=("operator",)),
                scope=make_scope(),
            )
            with self.assertRaises(ScopeViolation):
                asyncio.run(gateway.invoke(tool.tool_id, {"target": OUT_OF_SCOPE_IP}, context))
            events = AuditWriter(store).export("system")
            scope_events = [event for event in events if event["action"] == "scope.denied"]
            self.assertEqual(len(scope_events), 1)
            self.assertEqual(scope_events[0]["decision"], "deny")
            self.assertEqual(scope_events[0]["resource_id"], tool.tool_id)
            self.assertIn("target", scope_events[0]["payload"]["target_keys"])
            self.assertEqual(AuditWriter(store).verify_chain(), (True, None))

    def test_tool_gateway_allows_in_scope_target(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlStore(Path(directory) / "control.db")
            store.initialize()
            gateway = make_gateway(store, make_scope())
            tool = make_scan_tool()
            gateway.register(
                tool,
                lambda arguments, context: ToolResult(
                    output={"target": arguments["target"]},
                    verified=True,
                    verification_method="test-observation",
                ),
            )
            context = RunContext(
                "system",
                Identity("operator-1", "system", roles=("operator",)),
                scope=make_scope(),
            )
            result = asyncio.run(
                gateway.invoke(tool.tool_id, {"target": "203.0.113.10"}, context)
            )
            self.assertTrue(result["success"])
            self.assertEqual(result["output"]["target"], "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
