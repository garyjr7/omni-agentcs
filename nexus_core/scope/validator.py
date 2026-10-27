"""Target validation against a signed :class:`EngagementScope`.

The validator is the only component that decides whether a target is inside
an engagement. It performs, in order: signature check, time-window check,
target parsing, exclusion check, then per-kind matching (IP / CIDR / domain /
URL), including a private-address guard.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import logging
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Callable

from .models import (
    EngagementScope,
    ResolvedTarget,
    ScopeExpired,
    ScopeKind,
    ScopePrivateIP,
    ScopeSignatureInvalid,
    ScopeUnresolvable,
    ScopeViolation,
    parse_iso8601,
)
from .resolver import DNSResolver

_IPAddress = "ipaddress.IPv4Address | ipaddress.IPv6Address"
_IPNetwork = "ipaddress.IPv4Network | ipaddress.IPv6Network"

_URL_HOST_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.\-]*://(?:[^@/?#]*@)?(\[[^\]]+\]|[^/:?#]+)"
)


def _try_ip(value: str):
    """Return an ``ipaddress`` address object, or ``None`` if not an IP."""
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


class LabScopeForbidden(ValueError):
    """``NEXUS_SCOPE_MODE=lab`` was requested while ``NEXUS_ENV=production``.

    Lab mode accepts scopes with **no signature** (it only audits
    ``scope.unsigned_accepted``). That is a development convenience, not a
    production guarantee, and an environment variable should not be able to
    switch off the legal boundary of an engagement (audit SEC-06).
    """


class ScopeValidator:
    """Validate individual targets against one signed engagement scope."""

    def __init__(
        self,
        scope: EngagementScope,
        resolver: DNSResolver | None = None,
        signing_secret: str | None = None,
        allow_private_ips_in_scope: bool = True,
        mode: str | None = None,
        audit: Callable | None = None,
    ):
        self.mode = mode if mode is not None else os.getenv("NEXUS_SCOPE_MODE", "governed")
        if self.mode not in {"governed", "lab"}:
            raise ValueError(f"unknown scope mode: {self.mode!r}")
        if self.mode == "lab" and os.getenv("NEXUS_ENV", "development").lower() == "production":
            # SEC-06: lab mode skips the signature check entirely. Letting an
            # environment variable disable it in production would turn the
            # signed scope into decoration.
            raise LabScopeForbidden(
                "NEXUS_SCOPE_MODE=lab is not allowed with NEXUS_ENV=production: "
                "lab mode accepts unsigned scopes. Use governed mode with a "
                "signed engagement, or run with NEXUS_ENV=development."
            )
        self.audit = audit
        self.scope = scope
        self.resolver = resolver if resolver is not None else DNSResolver()
        self.signing_secret = signing_secret
        self.allow_private_ips_in_scope = allow_private_ips_in_scope
        self._cidrs: list[Any] | None = None
        self._exclusions: tuple[list[Any], list[Any], list[str]] | None = None

    # ------------------------------------------------------------------ public
    def validate(self, target: str) -> ResolvedTarget:
        """Validate ``target`` and return how it was authorized.

        Raises a :class:`ScopeViolation` subclass when the target is not
        covered by the engagement scope.
        """
        self._validate_signature()
        self._validate_time_window()
        kind, canonical, domain = self._parse_target(target)
        if kind is ScopeKind.IP:
            return self._validate_ip(target, ipaddress.ip_address(canonical), ScopeKind.IP)
        if kind is ScopeKind.CIDR:
            return self._validate_cidr(target, canonical)
        if kind is ScopeKind.URL:
            address = _try_ip(canonical)
            if address is not None:
                return self._validate_ip(target, address, ScopeKind.URL)
            return self._validate_domain(target, canonical, ScopeKind.URL)
        return self._validate_domain(target, canonical or domain or canonical, ScopeKind.DOMAIN)

    # ------------------------------------------------------------ pre-checks
    def _validate_signature(self) -> None:
        """Verify HMAC-SHA256 over :meth:`EngagementScope.canonical_form`."""
        if not self.scope.signature and self.mode == "lab":
            detail = {"engagement_id": self.scope.engagement_id, "mode": "lab"}
            if self.audit is not None:
                self.audit("scope.unsigned_accepted", detail)
            else:
                logging.getLogger(__name__).warning("scope.unsigned_accepted: %s", detail)
            return
        if not self.scope.signature or not self.signing_secret:
            raise ScopeSignatureInvalid(
                self.scope.engagement_id or self.scope.name,
                "governed scope requires a signature and signing secret",
                self.scope.engagement_id,
            )
        expected = hmac.new(
            self.signing_secret.encode("utf-8"),
            self.scope.canonical_form().encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, self.scope.signature):
            raise ScopeSignatureInvalid(
                self.scope.engagement_id or self.scope.name,
                "scope signature is invalid",
                self.scope.engagement_id,
            )

    def _validate_time_window(self) -> None:
        """Ensure ``valid_from <= now <= valid_until``."""
        now = datetime.now(timezone.utc)
        try:
            start = parse_iso8601(self.scope.valid_from)
            end = parse_iso8601(self.scope.valid_until)
        except ValueError as exc:
            raise ScopeViolation(
                self.scope.engagement_id or self.scope.name,
                f"scope has an invalid validity window: {exc}",
                self.scope.engagement_id,
            ) from exc
        if now < start:
            raise ScopeExpired(
                self.scope.engagement_id or self.scope.name,
                "engagement is not yet valid",
                self.scope.engagement_id,
            )
        if now > end:
            raise ScopeExpired(
                self.scope.engagement_id or self.scope.name,
                "engagement has expired",
                self.scope.engagement_id,
            )

    def _parse_target(self, target: str) -> tuple[ScopeKind, str, str | None]:
        """Return ``(kind, canonical, domain_or_none)`` for a raw target."""
        value = str(target).strip()
        if not value:
            raise self._violation(target, "target is empty")
        if value.lower().startswith(("http://", "https://")):
            match = _URL_HOST_RE.match(value)
            if not match:
                raise self._violation(target, "url has no parsable host")
            host = match.group(1)
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
            host = host.lower().rstrip(".")
            address = _try_ip(host)
            return ScopeKind.URL, host, None if address is not None else host
        address = _try_ip(value)
        if address is not None:
            return ScopeKind.IP, str(address), None
        if "/" in value:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise self._violation(target, f"invalid cidr: {exc}") from exc
            return ScopeKind.CIDR, str(network), None
        if value == "localhost" or "." in value:
            canonical = value.lower().rstrip(".")
            return ScopeKind.DOMAIN, canonical, canonical
        raise self._violation(target, "target is not recognized")

    # --------------------------------------------------------------- matching
    def _resolve_cidrs(self) -> list[Any]:
        """Parse (and cache) the authorized CIDRs of the scope."""
        if self._cidrs is None:
            networks: list[Any] = []
            for entry in self.scope.cidrs:
                try:
                    networks.append(ipaddress.ip_network(entry, strict=False))
                except ValueError as exc:
                    raise self._violation(entry, f"scope has an invalid cidr: {exc}") from exc
            self._cidrs = networks
        return self._cidrs

    def _resolve_exclusions(self) -> tuple[list[Any], list[Any], list[str]]:
        """Classify exclusions into ``(ips, networks, domains)``."""
        if self._exclusions is None:
            ips: list[Any] = []
            networks: list[Any] = []
            domains: list[str] = []
            for entry in self.scope.exclusions:
                text = str(entry).strip()
                if not text:
                    continue
                if "/" in text:
                    try:
                        networks.append(ipaddress.ip_network(text, strict=False))
                        continue
                    except ValueError:
                        pass
                address = _try_ip(text)
                if address is not None:
                    ips.append(address)
                    continue
                domains.append(text.lower().rstrip("."))
            self._exclusions = (ips, networks, domains)
        return self._exclusions

    def _match_domain(self, domain: str) -> str | None:
        """Return the scope domain rule that matches, or ``None``."""
        candidate = str(domain).lower().rstrip(".")
        for rule in self.scope.domains:
            normalized = str(rule).lower().rstrip(".")
            if not normalized:
                continue
            if normalized.startswith("*."):
                base = normalized[2:]
                if base and candidate != base and candidate.endswith("." + base):
                    return rule
            elif normalized.startswith("."):
                base = normalized[1:]
                if base and (candidate == base or candidate.endswith("." + base)):
                    return rule
            elif candidate == normalized:
                return rule
        return None

    # ------------------------------------------------------ kind validation
    def _validate_ip(self, target: str, address, kind: ScopeKind) -> ResolvedTarget:
        if self._is_excluded_ip(address):
            raise self._violation(target, "target is excluded")
        self._check_private(target, address)
        matched = self._match_cidr(address)
        if matched is None:
            raise self._violation(target, "ip is outside the engagement scope")
        return ResolvedTarget(
            original=target,
            kind=kind,
            ip=str(address),
            domain=None,
            matched_rule=str(matched),
            resolved_ips=(str(address),),
        )

    def _validate_cidr(self, target: str, canonical: str) -> ResolvedTarget:
        network = ipaddress.ip_network(canonical, strict=False)
        if self._is_excluded_network(network):
            raise self._violation(target, "target is excluded")
        matched = None
        for scope_network in self._resolve_cidrs():
            if network.version == scope_network.version and network.subnet_of(scope_network):
                matched = scope_network
                break
        if matched is None:
            raise self._violation(target, "cidr is not fully contained in the engagement scope")
        self._check_private(target, network.network_address)
        return ResolvedTarget(
            original=target,
            kind=ScopeKind.CIDR,
            ip=str(network.network_address),
            domain=None,
            matched_rule=str(matched),
            resolved_ips=(str(network.network_address),),
        )

    def _validate_domain(self, target: str, domain: str, kind: ScopeKind) -> ResolvedTarget:
        if self._is_excluded_domain(domain):
            raise self._violation(target, "target is excluded")
        rule = self._match_domain(domain)
        if rule is None:
            raise self._violation(target, "domain is outside the engagement scope")
        try:
            resolved = self.resolver.resolve(domain)
        except ScopeUnresolvable:
            raise
        except Exception as exc:  # noqa: BLE001 - surface any resolver failure as unresolvable
            raise ScopeUnresolvable(
                target, f"domain could not be resolved: {exc}", self.scope.engagement_id
            ) from exc
        if not resolved:
            raise ScopeUnresolvable(target, "domain resolved to no addresses", self.scope.engagement_id)

        normalized: list[str] = []
        for ip_text in resolved:
            address = _try_ip(str(ip_text))
            if address is None:
                raise ScopeUnresolvable(
                    target, f"resolver returned an invalid address: {ip_text}", self.scope.engagement_id
                )
            if self._is_excluded_ip(address):
                raise self._violation(target, f"resolved address is excluded: {address}")
            self._check_private(target, address)
            if self._match_cidr(address) is None:
                raise self._violation(target, f"resolved address is outside the scope: {address}")
            normalized.append(str(address))
        return ResolvedTarget(
            original=target,
            kind=kind,
            ip=None,
            domain=domain,
            matched_rule=str(rule),
            resolved_ips=tuple(normalized),
        )

    # ------------------------------------------------------------- helpers
    def _match_cidr(self, address):
        for network in self._resolve_cidrs():
            if network.version == address.version and address in network:
                return network
        return None

    def _check_private(self, target: str, address) -> None:
        """Reject private/loopback/link-local/multicast addresses unless the
        authorizing CIDR is itself an explicit private range."""
        if not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
        ):
            return
        if not self.allow_private_ips_in_scope:
            raise ScopePrivateIP(
                target, f"private address is not permitted: {address}", self.scope.engagement_id
            )
        authorizing = self._match_cidr(address)
        if authorizing is None or not authorizing.is_private:
            raise ScopePrivateIP(
                target,
                f"private address is not authorized by a private scope range: {address}",
                self.scope.engagement_id,
            )

    def _is_excluded_ip(self, address) -> bool:
        ips, networks, _ = self._resolve_exclusions()
        if any(address == excluded for excluded in ips):
            return True
        return any(
            network.version == address.version and address in network for network in networks
        )

    def _is_excluded_network(self, network) -> bool:
        _, networks, _ = self._resolve_exclusions()
        return any(
            network.version == excluded.version and network.overlaps(excluded)
            for excluded in networks
        )

    def _is_excluded_domain(self, domain: str) -> bool:
        _, _, domains = self._resolve_exclusions()
        candidate = str(domain).lower().rstrip(".")
        for rule in domains:
            if rule.startswith("*."):
                base = rule[2:]
                if base and candidate != base and candidate.endswith("." + base):
                    return True
            elif rule.startswith("."):
                base = rule[1:]
                if base and (candidate == base or candidate.endswith("." + base)):
                    return True
            elif candidate == rule:
                return True
        return False

    def _violation(self, target: str, reason: str) -> ScopeViolation:
        return ScopeViolation(target, reason, self.scope.engagement_id)


def make_scope_validator(
    signing_secret: str | None = None,
) -> Callable[[Any, Any, dict[str, Any]], None]:
    """Build the callable consumed by ``ToolGateway(scope_validator=...)``.

    The returned callable extracts the target from
    ``arguments[definition.scope_target_field]``, validates it against
    ``context.scope`` and raises a :class:`ScopeViolation` on failure.

    The field may hold a single target or a **list** of targets (tools such as
    ``nexus.recon.httpx`` and ``nexus.web.nuclei`` take a batch). A list passes
    only when every element is in scope; the first violation aborts the whole
    call. An empty list is rejected.
    """

    def _validator(context: Any, definition: Any, arguments: dict[str, Any]) -> None:
        if context.scope is None:
            raise PermissionError("scope not set on context")
        field = definition.scope_target_field
        if not field or field not in arguments:
            raise ValueError(f"scope_target_field '{field}' missing in arguments")
        value = arguments[field]
        validator = ScopeValidator(context.scope, signing_secret=signing_secret)
        if isinstance(value, (list, tuple)):
            if not value:
                raise ValueError(f"scope_target_field '{field}' is empty")
            for target in value:
                validator.validate(str(target))
            return
        validator.validate(str(value))

    return _validator
