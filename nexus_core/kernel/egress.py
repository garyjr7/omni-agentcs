"""Scope-governed SOCKS5 egress: the missing half of ``oci_network``.

``oci`` runs containers with ``--network none``: strong isolation, and every
network tool (nmap, httpx, hydra) simply cannot reach its target. Enabling the
network without a policy would trade that isolation for nothing, which is why
``oci_network`` used to fail closed with ``SandboxModeNotImplemented``.

This module supplies the policy: a small SOCKS5 proxy that is the container's
only route out (the container joins an ``--internal`` Docker network). Every
``CONNECT`` is authorized against the signed engagement scope before a socket
exists:

* The destination is validated with :class:`nexus_core.scope.validator.ScopeValidator`
  (HMAC signature, validity window, exclusions, private-range guard).
* The socket is opened to the **IP the validator authorized**, never to a name
  the client sent. A DNS answer that changes between check and connect therefore
  cannot redirect the connection (blueprint §8 finding 9: DNS rebinding).
* A denied destination is dropped, counted and handed to the audit hook, so the
  attempt is visible instead of being an unexplained tool timeout.

The proxy refuses to run without an explicit authorizer: a proxy that accepts
everything is worse than no proxy, because it looks like a control.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, Self

logger = logging.getLogger(__name__)

#: SOCKS5 (RFC 1928) wire constants.
SOCKS_VERSION = 0x05
AUTH_NONE = 0x00
AUTH_UNACCEPTABLE = 0xFF
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REPLY_SUCCEEDED = 0x00
REPLY_NOT_ALLOWED = 0x02
REPLY_HOST_UNREACHABLE = 0x04
REPLY_COMMAND_NOT_SUPPORTED = 0x07
REPLY_ADDRESS_NOT_SUPPORTED = 0x08

#: Default bind address. The container reaches the proxy through the
#: ``--internal`` network gateway, so listening on all interfaces of the host
#: is the simplest correct choice; the operator can narrow it.
DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_BIND_PORT = 1080
#: Ceiling on simultaneous client connections (each one holds two sockets).
DEFAULT_MAX_CONNECTIONS = 64
#: Ceiling on one upstream connect attempt.
DEFAULT_CONNECT_TIMEOUT = 15.0
#: Idle ceiling for an established tunnel.
DEFAULT_IDLE_TIMEOUT = 300.0
#: Bytes relayed per ``write`` call while pumping a tunnel.
RELAY_CHUNK = 65_536


@dataclass(frozen=True)
class EgressDecision:
    """Verdict for one destination, with what the proxy must actually dial."""

    allowed: bool
    host: str
    port: int
    #: Address to dial when allowed. Equals the authorized IP, not the name.
    connect_ip: str | None = None
    reason: str = ""
    #: Scope rule that authorized the destination (audit evidence).
    matched_rule: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable form for audit payloads."""
        return {
            "allowed": self.allowed,
            "host": self.host,
            "port": self.port,
            "connect_ip": self.connect_ip,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
        }


class EgressAuthorizer(Protocol):
    """Decides whether one ``host:port`` destination may be dialed."""

    def authorize(self, host: str, port: int) -> EgressDecision: ...


def denied(host: str, port: int, reason: str) -> EgressDecision:
    """Build a denial (kept small so guard implementations stay readable)."""
    return EgressDecision(allowed=False, host=host, port=port, reason=reason)


class ScopeEgressGuard:
    """Authorize egress destinations against one signed engagement scope.

    :class:`ScopeValidator` already answers "is this target inside the
    engagement" for a ``host``, ``host:port``, ``ip`` or URL. The guard reuses it
    instead of re-implementing CIDR/domain matching, and returns the authorized
    IP so the caller can dial it directly.
    """

    def __init__(self, validator: Any):
        if validator is None or not hasattr(validator, "validate"):
            raise TypeError("ScopeEgressGuard requires a ScopeValidator")
        self._validator = validator
        self._cache: dict[tuple[str, int], EgressDecision] = {}

    def authorize(self, host: str, port: int) -> EgressDecision:
        """Validate ``host``/``port``; denials carry the validator's reason.

        Results are cached per destination so a single ``nmap -p-`` does not
        re-resolve and re-sign-check the same host for every connection. The
        cache is per-run, so a new engagement starts clean.
        """
        key = (str(host).strip().lower(), int(port))
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        decision = self._decide(key[0], key[1])
        self._cache[key] = decision
        return decision

    def _decide(self, host: str, port: int) -> EgressDecision:
        try:
            resolved = self._validator.validate(f"{host}:{port}")
        except Exception as error:  # noqa: BLE001 - any refusal is a denial, never a crash
            return denied(host, port, f"{type(error).__name__}: {error}")
        addresses = [str(value) for value in (getattr(resolved, "resolved_ips", None) or ())]
        address = getattr(resolved, "ip", None)
        if address and str(address) not in addresses:
            addresses.insert(0, str(address))
        if not addresses:
            return denied(host, port, "scope authorized the destination but resolved no address")
        return EgressDecision(
            allowed=True,
            host=host,
            port=port,
            connect_ip=addresses[0],
            matched_rule=str(getattr(resolved, "matched_rule", "") or ""),
        )


@dataclass
class EgressStats:
    """Counters a caller can report (doctor output, run summary)."""

    connections: int = 0
    authorized: int = 0
    denied: int = 0
    failed: int = 0
    bytes_relayed: int = 0
    denials: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable snapshot, with a bounded denial list."""
        return {
            "connections": self.connections,
            "authorized": self.authorized,
            "denied": self.denied,
            "failed": self.failed,
            "bytes_relayed": self.bytes_relayed,
            "denials": self.denials[-20:],
        }


def _parse_destination(atyp: int, chunk: bytes) -> tuple[str, int]:
    """Decode a SOCKS5 request address; returns ``(host, port)``."""
    if atyp == ATYP_IPV4:
        host = str(ipaddress.IPv4Address(chunk[:-2]))
    elif atyp == ATYP_IPV6:
        host = str(ipaddress.IPv6Address(chunk[:-2]))
    else:
        host = chunk[1 : -2].decode("idna", errors="strict")
    return host, struct.unpack("!H", chunk[-2:])[0]


def _reply(status: int, address: str = "0.0.0.0", port: int = 0) -> bytes:
    """Build a SOCKS5 reply with an ATYP matching ``address``.

    RFC 1928 §6 fixes the layout as ``VER, REP, RSV, ATYP, BND.ADDR, BND.PORT``.
    The reserved byte is part of the wire format: without it a strict client
    (proxychains-ng) reads ``ATYP`` as ``RSV``, rejects the reply and reports
    ``ECONNREFUSED`` even though the tunnel was established.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        parsed = ipaddress.IPv4Address("0.0.0.0")
    atyp = ATYP_IPV6 if parsed.version == 6 else ATYP_IPV4
    return (
        struct.pack("!BBBB", SOCKS_VERSION, status, 0x00, atyp)
        + parsed.packed
        + struct.pack("!H", port)
    )


async def _pump(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    counter: list[int],
    idle_timeout: float,
) -> None:
    """Copy one direction of a tunnel until EOF, then half-close the peer."""
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(RELAY_CHUNK), timeout=idle_timeout)
            if not chunk:
                break
            counter[0] += len(chunk)
            writer.write(chunk)
            await writer.drain()
    except (TimeoutError, ConnectionError, OSError):
        pass
    finally:
        try:
            writer.write_eof()
        except (OSError, RuntimeError):
            pass


class Socks5EgressProxy:
    """SOCKS5 CONNECT proxy that only relays authorized destinations.

    Only ``CONNECT`` is implemented (``BIND``/``UDP ASSOCIATE`` answer
    ``REPLY_COMMAND_NOT_SUPPORTED``): a UDP hole would bypass the scope check
    that makes this proxy meaningful.
    """

    def __init__(
        self,
        authorizer: EgressAuthorizer,
        *,
        bind_host: str = DEFAULT_BIND_HOST,
        bind_port: int = DEFAULT_BIND_PORT,
        audit: Callable[[str, Mapping[str, Any]], None] | None = None,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
    ):
        if authorizer is None:
            raise TypeError("Socks5EgressProxy requires an authorizer")
        self.authorizer = authorizer
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.audit = audit
        self.max_connections = max(1, int(max_connections))
        self.connect_timeout = float(connect_timeout)
        self.idle_timeout = float(idle_timeout)
        self.stats = EgressStats()
        self._semaphore = asyncio.Semaphore(self.max_connections)
        self._server: asyncio.Server | None = None
        #: Open client transports, closed on :meth:`close`. ``Server.wait_closed``
        #: waits for every live connection since Python 3.12, so shutdown must
        #: close them itself or it blocks on a tunnel that is still relaying.
        self._clients: set[asyncio.StreamWriter] = set()

    @property
    def address(self) -> tuple[str, int]:
        """Bound ``(host, port)``; the real port when ``bind_port`` was ``0``."""
        if self._server is None or not self._server.sockets:
            return (self.bind_host, self.bind_port)
        socket = self._server.sockets[0]
        host, port = socket.getsockname()[:2]
        return (str(host), int(port))

    def proxy_url(self) -> str:
        """``socks5://host:port`` as the container's tools should see it."""
        host, port = self.address
        return f"socks5://{host}:{port}"

    async def start(self) -> Socks5EgressProxy:
        """Bind the listener (idempotent)."""
        if self._server is None:
            self._server = await asyncio.start_server(
                self._handle_client, self.bind_host, self.bind_port
            )
            self._announce(
                "egress.proxy_started",
                {"address": f"{self.address[0]}:{self.address[1]}"},
            )
        return self

    async def close(self) -> None:
        """Stop the listener and every live tunnel (bounded, never hangs)."""
        if self._server is None:
            return
        self._server.close()
        for client in tuple(self._clients):
            try:
                client.close()
            except (OSError, RuntimeError):  # pragma: no cover - already closed
                pass
        try:
            # Since 3.12 this waits for open connections, so the timeout is the
            # difference between a clean shutdown and a hung run.
            await asyncio.wait_for(self._server.wait_closed(), timeout=5)
        except (TimeoutError, AttributeError, RuntimeError):
            pass
        finally:
            self._clients.clear()
            self._server = None

    async def __aenter__(self) -> Self:
        return await self.start()

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    def _announce(self, event: str, payload: Mapping[str, Any]) -> None:
        if self.audit is None:
            return
        try:
            self.audit(event, dict(payload))
        except Exception:
            logger.exception("egress audit hook failed for %s", event)

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        async with self._semaphore:
            self.stats.connections += 1
            self._clients.add(writer)
            try:
                await self._serve(reader, writer)
            except (ConnectionError, OSError, asyncio.IncompleteReadError):
                self.stats.failed += 1
            finally:
                self._clients.discard(writer)
                try:
                    writer.close()
                except (OSError, RuntimeError):  # pragma: no cover - already closed
                    pass

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not await self._handshake(reader, writer):
            return
        destination = await self._read_request(reader, writer)
        if destination is None:
            return
        host, port = destination
        try:
            decision = await asyncio.to_thread(self.authorizer.authorize, host, port)
        except Exception as error:  # noqa: BLE001 - a broken guard is a denial
            decision = denied(host, port, f"authorizer failed: {type(error).__name__}: {error}")
        if not decision.allowed:
            self.stats.denied += 1
            self.stats.denials.append({"host": host, "port": port, "reason": decision.reason})
            self._announce("egress.denied", {"host": host, "port": port, "reason": decision.reason})
            writer.write(_reply(REPLY_NOT_ALLOWED))
            await writer.drain()
            return
        await self._tunnel(reader, writer, decision)

    async def _handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """Negotiate "no authentication" (RFC 1928 §3)."""
        header = await reader.readexactly(2)
        if header[0] != SOCKS_VERSION:
            return False
        methods = await reader.readexactly(header[1])
        if AUTH_NONE not in methods:
            writer.write(bytes([SOCKS_VERSION, AUTH_UNACCEPTABLE]))
            await writer.drain()
            return False
        writer.write(bytes([SOCKS_VERSION, AUTH_NONE]))
        await writer.drain()
        return True

    async def _read_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> tuple[str, int] | None:
        """Read one CONNECT request; answers and returns ``None`` on refusal."""
        header = await reader.readexactly(4)
        if header[0] != SOCKS_VERSION:
            return None
        cmd, atyp = header[1], header[3]
        if cmd != CMD_CONNECT:
            # BIND and UDP ASSOCIATE would escape the per-connection scope check.
            writer.write(_reply(REPLY_COMMAND_NOT_SUPPORTED))
            await writer.drain()
            return None
        if atyp not in (ATYP_IPV4, ATYP_DOMAIN, ATYP_IPV6):
            writer.write(_reply(REPLY_ADDRESS_NOT_SUPPORTED))
            await writer.drain()
            return None
        if atyp == ATYP_DOMAIN:
            size = (await reader.readexactly(1))[0]
            chunk = bytes([size]) + await reader.readexactly(size + 2)
        else:
            size = 4 if atyp == ATYP_IPV4 else 16
            chunk = await reader.readexactly(size + 2)
        try:
            return _parse_destination(atyp, chunk)
        except (UnicodeDecodeError, ValueError, struct.error):
            writer.write(_reply(REPLY_ADDRESS_NOT_SUPPORTED))
            await writer.drain()
            return None

    async def _tunnel(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        decision: EgressDecision,
    ) -> None:
        """Dial the authorized IP and relay both directions."""
        attempt = None
        if decision.connect_ip:
            try:
                attempt = await asyncio.wait_for(
                    asyncio.open_connection(decision.connect_ip, decision.port),
                    timeout=self.connect_timeout,
                )
            except (TimeoutError, OSError):
                attempt = None
        if attempt is None:
            self.stats.failed += 1
            writer.write(_reply(REPLY_HOST_UNREACHABLE))
            await writer.drain()
            return
        upstream_reader, upstream_writer = attempt
        self.stats.authorized += 1
        self._announce(
            "egress.authorized",
            {
                "host": decision.host,
                "port": decision.port,
                "connect_ip": decision.connect_ip,
                "matched_rule": decision.matched_rule,
            },
        )
        writer.write(_reply(REPLY_SUCCEEDED))
        await writer.drain()
        counter = [0]
        pumps = {
            asyncio.create_task(_pump(reader, upstream_writer, counter, self.idle_timeout)),
            asyncio.create_task(_pump(upstream_reader, writer, counter, self.idle_timeout)),
        }
        try:
            # One direction ending ends the tunnel: half-open relays would keep
            # a dead peer's socket alive for the whole idle window.
            _, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        finally:
            for task in pumps:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            self.stats.bytes_relayed += counter[0]
            upstream_writer.close()


def proxy_for_scope(
    scope: Any,
    *,
    signing_secret: str | None = None,
    audit: Callable[[str, Mapping[str, Any]], None] | None = None,
    bind_host: str = DEFAULT_BIND_HOST,
    bind_port: int = DEFAULT_BIND_PORT,
    validator: Any = None,
) -> Socks5EgressProxy:
    """Build a scope-governed proxy for ``scope`` (an ``EngagementScope``).

    ``validator`` exists so a caller that already built a
    :class:`ScopeValidator` (it holds the resolver and signing secret) can reuse
    it instead of resolving the name twice.
    """
    guard_validator = validator
    if guard_validator is None:
        from nexus_core.scope.validator import ScopeValidator

        guard_validator = ScopeValidator(scope, signing_secret=signing_secret)
    return Socks5EgressProxy(
        ScopeEgressGuard(guard_validator),
        bind_host=bind_host,
        bind_port=bind_port,
        audit=audit,
    )


__all__ = [
    "AUTH_NONE",
    "CMD_CONNECT",
    "DEFAULT_BIND_HOST",
    "DEFAULT_BIND_PORT",
    "EgressAuthorizer",
    "EgressDecision",
    "EgressStats",
    "ScopeEgressGuard",
    "Socks5EgressProxy",
    "denied",
    "proxy_for_scope",
]
