"""``nexus.post.verify_route``: prove a route before enumerating behind it.

Measured origin: DeadDrop P11 (2026-10-22, ``run_4d72624a…``). The run held SSH
on ``192.168.11.200``, knew the DC at ``192.168.11.100`` and spent its last
twenty turns alternating between ``ssh -L`` by port and a wrapper script, with
no way to tell whether any tunnel it built actually carried traffic. The plan's
``pivot-lan`` TODO could not close either, because "a route exists" had no
fact behind it.

This tool answers exactly that question and nothing else: *from this process,
does the route I just built carry a TCP connection to ``to_host:to_port``?*
A success is what lets :func:`nexus_core.kernel.route_facts.route_reaches` seed
the pre-scan gate and close a ``route`` TODO; a failure is an observation with
the exact cause (the forwarder is not listening, the proxy refused the CONNECT,
the destination timed out), not a generic ``tool_failure``.

It does not execute a program and does not touch the target's state: it opens
sockets, which is why it runs without a sandbox and without a scope target
(``scope_required=False`` -the addresses it names are the operator's own tunnel
endpoints and the engagement's internal hosts, and the gateway would otherwise
demand a ``target`` field that no scope rule describes).
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.route_facts import ROUTE_METHODS, route_key

#: Tool id, exported so the registry and the tests name it once.
VERIFY_ROUTE_TOOL_ID = "nexus.post.verify_route"

#: A probe is cheap; more than this means the tunnel is not answering.
VERIFY_ROUTE_DEFAULT_TIMEOUT_SECONDS = 8
VERIFY_ROUTE_MAX_TIMEOUT_SECONDS = 30

#: ``host:port`` of a local forward (``127.0.0.1:1080``, ``[::1]:1080``).
_ENDPOINT_RE = re.compile(r"^\[?(?P<host>[^\]\s:/]+|::1)\]?:(?P<port>\d{1,5})$")

#: How each declared method is probed. A method declared in the schema but
#: missing here is answered as ``unavailable`` ("method not implemented") instead
#: of raising or, worse, emitting a route nobody proved: adding ``chisel`` is one
#: entry in this table, and until that entry exists the honest answer is "I
#: cannot verify this yet".
_PROBES: dict[str, str] = {
    "direct": "tcp",
    "ssh_L": "tcp",
    "ligolo": "tcp",
    "ssh_D": "socks5",
    "socks": "socks5",
}
#: Methods that speak SOCKS5: the proxy decides the destination, so the probe is
#: a CONNECT through it and `to_port` is required for that CONNECT.
_SOCKS_METHODS = frozenset(name for name, kind in _PROBES.items() if kind == "socks5")


def verify_route_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.verify_route``."""
    return ToolDefinition(
        tool_id=VERIFY_ROUTE_TOOL_ID,
        idempotent=True,
        name="Verify route",
        tenant_id=tenant_id,
        description=(
            "Verifica que una ruta (SOCKS, -L, ligolo o directa) alcanza "
            "to_host:to_port y emite el hecho route que cierra el TODO de pivote."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "from_host": {"type": "string", "minLength": 1, "maxLength": 255},
                "to_host": {"type": "string", "minLength": 1, "maxLength": 255},
                "to_port": {"type": ["integer", "null"], "minimum": 1, "maximum": 65535},
                "method": {"type": "string", "enum": list(ROUTE_METHODS)},
                "forwarder_ref": {
                    "type": ["string", "null"],
                    "maxLength": 512,
                    "description": (
                        "Extremo local del túnel (host:puerto), p. ej. 127.0.0.1:1080 "
                        "para un ssh -D o 127.0.0.1:18445 para un ssh -L."
                    ),
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": VERIFY_ROUTE_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["from_host", "to_host", "method"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        effect="read_only",
        required_permissions=["execute:tool:nexus.post.verify_route"],
        timeout_seconds=60,
        max_output_bytes=100_000,
        scope_required=False,
        sandbox_required=False,
    )


def _validate_host(value: Any, field: str) -> str:
    """Return a host the probe can dial (IPv4, IPv6 or a DNS name)."""
    text = str(value or "").strip()
    if not text or len(text) > 255:
        raise ValueError(f"{field} is required and must be at most 255 characters")
    if any(char.isspace() for char in text) or "/" in text:
        raise ValueError(f"{field} must be a single host, not a range or a URL")
    try:
        ipaddress.ip_address(text)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", text):
            raise ValueError(f"{field} is not a valid host name") from None
    return text


def _endpoint(value: Any) -> tuple[str, int] | None:
    """Parse ``host:port`` into a tuple, or ``None`` when it is not one."""
    text = str(value or "").strip()
    match = _ENDPOINT_RE.match(text)
    if not match:
        return None
    port = int(match.group("port"))
    if not 0 < port < 65536:
        return None
    return match.group("host"), port


async def _tcp_reaches(host: str, port: int, timeout: float) -> bool:
    """True when ``host:port`` completes a TCP handshake inside ``timeout``."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError, ValueError):
        return False
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:  # noqa: BLE001 - closing a probe is never the decision
        pass
    return True


async def _socks5_reaches(
    proxy: tuple[str, int], to_host: str, to_port: int, timeout: float
) -> tuple[bool, str]:
    """SOCKS5 CONNECT through ``proxy`` to ``to_host:to_port``.

    A listening proxy is not a route: only a ``REP=0x00`` reply proves the proxy
    reached the destination. No authentication is attempted (``ssh -D`` and
    ``ligolo`` expose a no-auth listener); a proxy that demands auth is reported
    as a failure with that cause instead of being mistaken for a dead tunnel.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy[0], proxy[1]), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError, ValueError) as exc:
        return False, f"socks proxy {proxy[0]}:{proxy[1]} did not accept: {exc}"
    try:
        writer.write(b"\x05\x01\x00")  # version 5, one method, no auth
        await writer.drain()
        greeting = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if greeting[1] == 0xFF:
            return False, "socks proxy requires authentication"
        if greeting[1] != 0x00:
            return False, f"socks proxy chose unsupported auth method {greeting[1]}"
        try:
            address = ipaddress.ip_address(to_host)
        except ValueError:
            address = None
        if address is None:
            name = to_host.encode("idna")
            request = b"\x05\x01\x00\x03" + bytes([len(name)]) + name
        elif address.version == 4:
            request = b"\x05\x01\x00\x01" + address.packed
        else:
            request = b"\x05\x01\x00\x04" + address.packed
        writer.write(request + int(to_port).to_bytes(2, "big"))
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if reply[1] != 0x00:
            return False, f"socks CONNECT refused with code {reply[1]}"
        return True, ""
    except asyncio.TimeoutError:
        return False, f"socks CONNECT to {to_host}:{to_port} timed out"
    except (OSError, asyncio.IncompleteReadError) as exc:
        return False, f"socks proxy closed the connection: {exc}"
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - teardown is never the decision
            pass


async def verify_route_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Probe the route and report it as a verifiable observation."""
    del context  # the probe uses no engagement state; the fact is the assertion's
    from_host = _validate_host(arguments.get("from_host"), "from_host")
    to_host = _validate_host(arguments.get("to_host"), "to_host")
    method = str(arguments.get("method") or "direct").strip()
    probe_kind = _PROBES.get(method)

    raw_port = arguments.get("to_port")
    to_port: int | None = None
    if raw_port is not None:
        to_port = int(raw_port)
        if not 0 < to_port < 65536:
            raise ValueError("to_port must be between 1 and 65535")

    forwarder_ref = str(arguments.get("forwarder_ref") or "").strip() or None
    endpoint = _endpoint(forwarder_ref) if forwarder_ref else None
    if forwarder_ref and endpoint is None:
        raise ValueError(
            "forwarder_ref must be the local endpoint of the tunnel as host:port "
            "(e.g. 127.0.0.1:1080); the handle alone cannot be probed"
        )

    requested = arguments.get("timeout_seconds")
    timeout = min(
        VERIFY_ROUTE_MAX_TIMEOUT_SECONDS,
        max(1, int(requested) if requested else VERIFY_ROUTE_DEFAULT_TIMEOUT_SECONDS),
    )

    route = {
        "from_host": from_host,
        "to_host": to_host,
        "to_port": to_port,
        "method": method,
        "forwarder_ref": endpoint and f"{endpoint[0]}:{endpoint[1]}" or None,
    }
    evidence: dict[str, Any] = {
        "route": route,
        "key": route_key(from_host, to_host, to_port),
        "timeout_seconds": timeout,
        "noise_level": "none",
    }

    # Declared in the vocabulary but not yet probed: say so. ``unavailable``
    # means "this was not observed", which is exactly the truth, and it is not a
    # fact either (no route is asserted).
    if probe_kind is None:
        cause = f"method not implemented: {method}"
        return ToolResult(
            output={**evidence, "error": cause},
            verified=False,
            verification_method="route_probe_failed",
            evidence={**evidence, "cause": "method_not_implemented", "detail": cause},
            outcome="unavailable",
        )
    # A socks route without its proxy cannot be verified: dialing to_host:to_port
    # from here would answer a different question (the direct path) and could
    # report a working route the SOCKS proxy does not provide.
    if probe_kind == "socks5" and endpoint is None:
        return ToolResult(
            output={**evidence, "error": "the SOCKS route needs forwarder_ref host:port"},
            verified=False,
            verification_method="route_probe_failed",
            evidence={**evidence, "cause": "missing_forwarder"},
            outcome="unavailable",
        )
    if to_port is None and probe_kind != "socks5" and endpoint is None:
        return ToolResult(
            output={**evidence, "error": "a direct/L route needs to_port"},
            verified=False,
            verification_method="route_probe_failed",
            evidence={**evidence, "cause": "missing_port"},
            outcome="unavailable",
        )
    if to_port is None and probe_kind == "socks5":
        return ToolResult(
            output={**evidence, "error": "a SOCKS CONNECT needs to_port"},
            verified=False,
            verification_method="route_probe_failed",
            evidence={**evidence, "cause": "missing_port"},
            outcome="unavailable",
        )

    started = time.monotonic()
    if probe_kind == "socks5":
        assert endpoint is not None and to_port is not None
        ok, cause = await _socks5_reaches(endpoint, to_host, to_port, timeout)
        probe = "socks5"
        dialled = f"{endpoint[0]}:{endpoint[1]} -> {to_host}:{to_port}"
    else:
        # The local end of an ssh -L forward is the destination: connecting to it
        # *is* the end-to-end test. Without one (direct/ligolo) the destination
        # itself is dialled.
        host, port = endpoint if endpoint else (to_host, int(to_port or 0))
        ok = await _tcp_reaches(host, port, timeout)
        cause = "" if ok else f"no TCP handshake with {host}:{port} in {timeout}s"
        probe = "tcp"
        dialled = f"{host}:{port}"
    elapsed_ms = int((time.monotonic() - started) * 1000)

    evidence.update(
        {"probe": probe, "dialled": dialled, "latency_ms": elapsed_ms, "cause": cause}
    )
    if ok:
        return ToolResult(
            output={**evidence, "reached": True},
            verified=True,
            verification_method="route_probe_ok",
            evidence=evidence,
        )
    return ToolResult(
        output={**evidence, "reached": False, "error": cause},
        verified=False,
        verification_method="route_probe_failed",
        evidence=evidence,
        outcome="unavailable",
    )


__all__ = [
    "VERIFY_ROUTE_DEFAULT_TIMEOUT_SECONDS",
    "VERIFY_ROUTE_MAX_TIMEOUT_SECONDS",
    "VERIFY_ROUTE_TOOL_ID",
    "verify_route_definition",
    "verify_route_handler",
]
