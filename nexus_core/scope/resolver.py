"""Dependency-free DNS resolver with an in-memory TTL cache.

The resolver never decides whether a target is in scope; it only turns a
domain into a deduplicated tuple of IPv4/IPv6 addresses. The validator makes
the authorization decision.
"""

from __future__ import annotations

import socket
import time

from .models import ScopeUnresolvable


class DNSResolver:
    """Resolve domains to IP addresses using ``socket.getaddrinfo``."""

    def __init__(self, cache_ttl_seconds: int = 300, timeout_seconds: float = 5.0):
        self.cache_ttl_seconds = cache_ttl_seconds
        self.timeout_seconds = timeout_seconds
        self._cache: dict[str, tuple[float, tuple[str, ...]]] = {}

    def resolve(self, domain: str) -> tuple[str, ...]:
        """Resolve ``domain`` to a deduplicated tuple of addresses.

        Results are cached per domain for ``cache_ttl_seconds``. Raises
        :class:`ScopeUnresolvable` when resolution fails or yields no address.
        """
        key = str(domain).strip().lower().rstrip(".")
        if not key:
            raise ScopeUnresolvable(domain, "empty domain cannot be resolved")
        now = time.monotonic()
        cached = self._cache.get(key)
        if cached is not None and now - cached[0] < self.cache_ttl_seconds:
            return cached[1]

        previous_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout_seconds)
        try:
            infos = socket.getaddrinfo(key, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ScopeUnresolvable(domain, f"dns resolution failed: {exc}") from exc
        finally:
            socket.setdefaulttimeout(previous_timeout)

        addresses: list[str] = []
        seen: set[str] = set()
        for info in infos:
            address = str(info[4][0]).split("%", 1)[0]
            if address and address not in seen:
                seen.add(address)
                addresses.append(address)
        if not addresses:
            raise ScopeUnresolvable(domain, "dns resolution returned no addresses")

        result = tuple(addresses)
        self._cache[key] = (now, result)
        return result

    def clear_cache(self) -> None:
        """Drop every cached resolution."""
        self._cache.clear()
