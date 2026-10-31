"""Scope-governed SOCKS5 egress (``oci_network`` policy)."""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass

import pytest

from nexus_core.kernel import egress
from nexus_core.kernel import sandbox_modes as modes
from nexus_core.kernel.sandbox import OCINetworkSandbox, OCISandbox
from nexus_core.scope.models import ResolvedTarget, ScopeKind, ScopeViolation

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------- helpers
@dataclass
class _FakeValidator:
    """Stands in for ``ScopeValidator`` so the proxy test has no DNS."""

    result: ResolvedTarget | None = None
    error: Exception | None = None

    def __post_init__(self) -> None:
        self.calls: list[str] = []

    def validate(self, target: str) -> ResolvedTarget:
        self.calls.append(target)
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


def _allowed(ip: str = "127.0.0.1", rule: str = "10.0.0.0/8") -> ResolvedTarget:
    return ResolvedTarget(
        original="target", kind=ScopeKind.IP, ip=ip, domain=None,
        matched_rule=rule, resolved_ips=(ip,),
    )


def _authorizer(allowed: bool, ip: str = "127.0.0.1", reason: str = "out of scope"):
    """Authorizer stub with a fixed verdict and a call log."""

    class _Fixed:
        def __init__(self) -> None:
            self.calls: list[tuple[str, int]] = []

        def authorize(self, host: str, port: int) -> egress.EgressDecision:
            self.calls.append((host, port))
            if not allowed:
                return egress.denied(host, port, reason)
            return egress.EgressDecision(
                allowed=True, host=host, port=port, connect_ip=ip, matched_rule="10.0.0.0/8"
            )

    return _Fixed()


async def _echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(1024):
            writer.write(chunk.upper())
            await writer.drain()
    finally:
        writer.close()


async def _echo_server() -> tuple[asyncio.base_events.Server, int, list[int]]:
    hits: list[int] = []

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        hits.append(1)
        await _echo(reader, writer)

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    return server, port, hits


async def _connect_request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    *,
    cmd: int = egress.CMD_CONNECT,
) -> tuple[int, int]:
    """Perform greeting + request; return ``(status, atyp)`` of the reply."""
    writer.write(bytes([5, 1, 0]))
    await writer.drain()
    assert await reader.readexactly(2) == bytes([5, 0])
    encoded = host.encode("idna")
    writer.write(
        bytes([5, cmd, 0, egress.ATYP_DOMAIN, len(encoded)]) + encoded + struct.pack("!H", port)
    )
    await writer.drain()
    # Reply is ``ver, status, atyp`` followed by the bound address and port.
    version, status, atyp = await reader.readexactly(3)
    assert version == 5
    size = {egress.ATYP_IPV4: 4, egress.ATYP_IPV6: 16}.get(atyp, 0)
    await reader.readexactly(size + 2)
    return status, atyp


async def _proxy(authorizer, **kwargs) -> egress.Socks5EgressProxy:
    proxy = egress.Socks5EgressProxy(authorizer, bind_host="127.0.0.1", bind_port=0, **kwargs)
    await proxy.start()
    return proxy


# ----------------------------------------------------------------------- proxy
async def test_authorized_destination_is_tunneled():
    echo, echo_port, hits = await _echo_server()
    authorizer = _authorizer(True, "127.0.0.1")
    proxy = await _proxy(authorizer)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(*proxy.address), 5
        )
        status, _ = await asyncio.wait_for(
            _connect_request(reader, writer, "unauthorized.example", echo_port), 5
        )
        assert status == egress.REPLY_SUCCEEDED
        writer.write(b"ping")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(4), 2) == b"PING"
        assert authorizer.calls == [("unauthorized.example", echo_port)]
        assert proxy.stats.authorized == 1
        assert proxy.stats.denied == 0
    finally:
        await proxy.close()
        echo.close()
    assert hits == [1]


async def test_denied_destination_never_reaches_the_target():
    echo, echo_port, hits = await _echo_server()
    events: list[tuple[str, dict]] = []
    proxy = await _proxy(_authorizer(False), audit=lambda event, payload: events.append((event, payload)))
    try:
        reader, writer = await asyncio.open_connection(*proxy.address)
        status, _ = await _connect_request(reader, writer, "10.9.9.9.example", echo_port)
        assert status == egress.REPLY_NOT_ALLOWED
        assert proxy.stats.denied == 1
        assert [event for event, _ in events if event == "egress.denied"]
        # The scope check runs before any socket exists: no connection was made.
        assert hits == []
    finally:
        await proxy.close()
        echo.close()


async def test_bind_and_udp_associate_are_refused():
    """Only CONNECT is relayed; BIND would bypass the per-connection check."""
    proxy = await _proxy(_authorizer(True))
    try:
        reader, writer = await asyncio.open_connection(*proxy.address)
        status, _ = await _connect_request(reader, writer, "example.com", 80, cmd=0x02)
        assert status == egress.REPLY_COMMAND_NOT_SUPPORTED
        assert proxy.stats.connections == 1
        assert proxy.stats.authorized == 0
    finally:
        await proxy.close()


async def test_broken_authorizer_is_a_denial_not_a_crash():
    class _Exploding:
        def authorize(self, host: str, port: int):
            raise RuntimeError("scope store unavailable")

    proxy = await _proxy(_Exploding())
    try:
        reader, writer = await asyncio.open_connection(*proxy.address)
        status, _ = await _connect_request(reader, writer, "example.com", 80)
        assert status == egress.REPLY_NOT_ALLOWED
        assert proxy.stats.denied == 1
    finally:
        await proxy.close()


async def test_unreachable_authorized_target_reports_failure():
    authorizer = _authorizer(True, "127.0.0.1")
    proxy = await _proxy(authorizer, connect_timeout=0.5)
    try:
        reader, writer = await asyncio.open_connection(*proxy.address)
        # Port 9 (discard) is virtually never listening in the test environment.
        status, _ = await _connect_request(reader, writer, "10.0.0.5", 9)
        assert status in {egress.REPLY_HOST_UNREACHABLE, egress.REPLY_SUCCEEDED}
        if status == egress.REPLY_HOST_UNREACHABLE:
            assert proxy.stats.failed == 1
    finally:
        await proxy.close()


def test_proxy_requires_an_authorizer():
    with pytest.raises(TypeError):
        egress.Socks5EgressProxy(None)


def test_proxy_url_reports_the_bound_port():
    proxy = egress.Socks5EgressProxy(_authorizer(True), bind_host="127.0.0.1", bind_port=1080)
    assert proxy.proxy_url() == "socks5://127.0.0.1:1080"


# ----------------------------------------------------------------------- guard
def test_guard_dials_the_authorized_ip_not_the_name():
    """DNS rebinding: the name is validated once and never re-resolved to dial."""
    validator = _FakeValidator(result=_allowed("127.0.0.1"))
    guard = egress.ScopeEgressGuard(validator)
    decision = guard.authorize("evil.example", 443)
    assert decision.allowed is True
    assert decision.connect_ip == "127.0.0.1"
    assert decision.matched_rule == "10.0.0.0/8"
    assert validator.calls == ["evil.example:443"]


def test_guard_denies_with_the_validator_reason():
    validator = _FakeValidator(error=ScopeViolation("evil.example:443", "ip is outside the engagement scope"))
    decision = egress.ScopeEgressGuard(validator).authorize("evil.example", 443)
    assert decision.allowed is False
    assert "outside the engagement scope" in decision.reason
    assert decision.connect_ip is None


def test_guard_caches_per_destination():
    validator = _FakeValidator(result=_allowed("127.0.0.1"))
    guard = egress.ScopeEgressGuard(validator)
    guard.authorize("target.example", 22)
    guard.authorize("target.example", 22)
    assert validator.calls == ["target.example:22"]


def test_guard_denies_when_scope_resolved_nothing_to_dial():
    validator = _FakeValidator(
        result=ResolvedTarget(
            original="target", kind=ScopeKind.DOMAIN, ip=None, domain="target.example",
            matched_rule="target.example", resolved_ips=(),
        )
    )
    decision = egress.ScopeEgressGuard(validator).authorize("target.example", 80)
    assert decision.allowed is False
    assert "resolved no address" in decision.reason


def test_guard_requires_a_validator():
    with pytest.raises(TypeError):
        egress.ScopeEgressGuard(None)


class _Resolver:
    """Deterministic resolver: the guard must never see real DNS in tests."""

    def __init__(self, *addresses: str) -> None:
        self.addresses = addresses or ("127.0.0.1",)

    def resolve(self, domain: str) -> tuple[str, ...]:
        return tuple(self.addresses)


def _scope(*, domains: tuple[str, ...] = ("website.thm",), cidrs: tuple[str, ...] = ("127.0.0.0/8",)):
    from nexus_core.scope.models import EngagementScope

    return EngagementScope(
        engagement_id="eng-1", tenant_id="t1", name="lab", client="lab", owner_id="op",
        valid_from="2020-01-01T00:00:00+00:00", valid_until="2099-01-01T00:00:00+00:00",
        cidrs=cidrs, domains=domains, urls=(), exclusions=(),
    )


def test_guard_uses_the_real_scope_validator():
    """Integration: same authorization the gateway applies, not a copy of it."""
    from nexus_core.scope.validator import ScopeValidator

    validator = ScopeValidator(
        _scope(), resolver=_Resolver("127.0.0.1"), mode="lab"
    )
    guard = egress.ScopeEgressGuard(validator)

    allowed = guard.authorize("website.thm", 80)
    assert allowed.allowed is True
    assert allowed.connect_ip == "127.0.0.1"
    assert allowed.matched_rule == "website.thm"

    outside = guard.authorize("evil.example", 80)
    assert outside.allowed is False
    assert "outside the engagement scope" in outside.reason


def test_guard_denies_a_name_that_resolves_outside_the_scope():
    """A domain rule is not enough: the address it resolves to must be in scope."""
    from nexus_core.scope.validator import ScopeValidator

    validator = ScopeValidator(_scope(), resolver=_Resolver("93.184.216.34"), mode="lab")
    decision = egress.ScopeEgressGuard(validator).authorize("website.thm", 443)
    assert decision.allowed is False
    assert "outside the scope" in decision.reason


def test_proxy_for_scope_wires_a_guard():
    from nexus_core.scope.validator import ScopeValidator

    proxy = egress.proxy_for_scope(_scope(), validator=ScopeValidator(_scope(), resolver=_Resolver(), mode="lab"))
    assert isinstance(proxy.authorizer, egress.ScopeEgressGuard)
    assert proxy.proxy_url().startswith("socks5://")


# -------------------------------------------------------------------- sandbox
def test_oci_network_container_joins_internal_network_with_the_proxy(tmp_path):
    sandbox = OCINetworkSandbox(
        tmp_path,
        ["python:3.12-alpine"],
        proxy="socks5://172.18.0.1:1080",
        network="nexus-egress",
    )
    argv = sandbox.build_argv("python:3.12-alpine", ["nmap", "-sT", "10.0.0.5"])
    assert argv[argv.index("--network") + 1] == "nexus-egress"
    assert "--network" in argv and "none" not in argv
    for key in OCINetworkSandbox.PROXY_ENV_KEYS:
        assert f"{key}=socks5://172.18.0.1:1080" in argv
    assert argv[-1] == "10.0.0.5"


def test_plain_oci_sandbox_keeps_no_network(tmp_path):
    argv = OCISandbox(tmp_path, ["python:3.12-alpine"]).build_argv(
        "python:3.12-alpine", ["nmap", "-sT", "10.0.0.5"]
    )
    assert argv[argv.index("--network") + 1] == "none"
    assert not any(token.startswith("ALL_PROXY=") for token in argv)


@pytest.mark.parametrize("network", ["", "none", "host", "bridge"])
def test_oci_network_refuses_ungoverned_networks(tmp_path, network):
    with pytest.raises(ValueError):
        OCINetworkSandbox(tmp_path, ["python:3.12-alpine"], proxy="socks5://h:1", network=network)


@pytest.mark.parametrize("proxy", ["", "172.18.0.1:1080", "ftp://h:1"])
def test_oci_network_refuses_non_proxy_urls(tmp_path, proxy):
    with pytest.raises(ValueError):
        OCINetworkSandbox(tmp_path, ["python:3.12-alpine"], proxy=proxy, network="nexus-egress")


# ---------------------------------------------------------------------- modes
def test_oci_network_without_configuration_still_fails_closed(tmp_path):
    with pytest.raises(modes.SandboxModeNotImplemented) as excinfo:
        modes.SandboxPolicy.resolve(
            {"NEXUS_ENV": "production", modes.MODE_ENV: "oci_network"},
            workspace_root=tmp_path,
        )
    message = str(excinfo.value)
    assert modes.EGRESS_PROXY_ENV in message and modes.EGRESS_NETWORK_ENV in message


def test_oci_network_resolves_with_proxy_and_internal_network(tmp_path):
    resolved, executor, guarantees = modes.SandboxPolicy.resolve(
        {
            "NEXUS_ENV": "production",
            modes.MODE_ENV: "oci_network",
            modes.EGRESS_PROXY_ENV: "socks5://172.18.0.1:1080",
            modes.EGRESS_NETWORK_ENV: "nexus-egress",
        },
        workspace_root=tmp_path,
    )
    assert resolved is modes.SandboxMode.OCI_NETWORK
    assert isinstance(executor, OCINetworkSandbox)
    assert guarantees["supports_network_tools"] is True
    # Filtered, not absent: the guarantees table must not claim isolation it
    # does not provide, nor deny the capability the mode enables.
    assert guarantees["network_isolation"] is False


def test_oci_network_still_forbidden_with_local_production_guard(tmp_path):
    """Integrating egress must not weaken SEC-03 (local modes in production)."""
    with pytest.raises(modes.SandboxModeForbidden):
        modes.SandboxPolicy.resolve(
            {"NEXUS_ENV": "production", modes.MODE_ENV: "local_strict"},
            workspace_root=tmp_path,
        )
