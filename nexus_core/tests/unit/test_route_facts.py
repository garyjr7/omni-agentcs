"""Verified routes: the fact that turns a tunnel into reachability.

Measured origin: DeadDrop P11 (2026-10-22). The run held SSH on
``192.168.11.200``, knew the DC at ``192.168.11.100`` and closed at iteration 45
with 0 findings. Two defects produced that:

* ``pivot_state`` returned ``None`` as soon as *any* action contained ``-D``,
  so an ``ssh -D`` that never came up disarmed the pre-scan gate for the rest of
  the run (the fail-open this file pins shut);
* "a route exists" had no fact, so the plan's pivot TODO could never close and
  the gate had nothing to read but a command string.

These tests cover the four acceptance criteria of Tanda A: the gate stays armed
without a verified route, a verified route lets the sweep run without probing,
``nexus.post.verify_route`` emits the route only on a completed probe, and the
model's own registration of a route never counts.
"""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.agent.engagement_plan import new_plan, prompt_block, reconcile, todo_from_mapping
from nexus_core.agent.planner import pivot_gate, pivot_hint, pivot_state
from nexus_core.agent.subagents import SUBAGENTS_BY_ID
from nexus_core.kernel.fact_verification import derive_assertions
from nexus_core.kernel.models import ToolResult
from nexus_core.kernel.route_facts import (
    RouteValue,
    route_key,
    route_reaches,
    verified_routes,
)
from nexus_core.tools.handlers.verify_route import (
    VERIFY_ROUTE_TOOL_ID,
    verify_route_definition,
    verify_route_handler,
)

pytestmark = pytest.mark.unit

DMZ = "192.168.11.200"
DC = "192.168.11.100"


def _ssh_access(host: str = DMZ) -> dict:
    return {
        "tool_id": "nexus.post.ssh_exec",
        "arguments": {"target": host, "username": "svc-drop", "command": "id"},
    }


def _attempted_socks_tunnel(host: str = DMZ) -> dict:
    """The exact history P11 produced: a ``-D`` that never came up."""
    return {
        "tool_id": "nexus.shell.exec",
        "arguments": {
            "command": f"ssh -f -N -D 1080 svc-drop@{host}",
            "timeout_seconds": 60,
        },
        "tool_result": {"success": False, "outcome": "timeout"},
    }


def _pivot_history(*extra: dict) -> list[dict]:
    return [
        {"tool_id": "nexus.recon.nmap", "arguments": {"target": DMZ}},
        *extra,
        _ssh_access(),
    ]


def _route_fact(
    *,
    from_host: str = DMZ,
    to_host: str = DC,
    to_port: int | None = None,
    method: str = "ssh_D",
    forwarder_ref: str | None = "127.0.0.1:1080",
    verified: bool = True,
    asserted_by: str = "verifier",
) -> dict:
    return {
        "fact_type": "route",
        "key": route_key(from_host, to_host, to_port),
        "value": {
            "from_host": from_host,
            "to_host": to_host,
            "to_port": to_port,
            "method": method,
            "forwarder_ref": forwarder_ref,
            "verified_by": "inv-route-1",
        },
        "verified": verified,
        "asserted_by": asserted_by,
        "verification_method": "route_probe_ok" if verified else "",
        "invocation_id": "inv-route-1" if verified else "",
    }


# --------------------------------------------------------------- the fail-open
def test_an_attempted_socks_tunnel_is_not_a_route():
    """The bug: ``-D`` in the history used to switch the whole rule off."""
    state = pivot_state(_pivot_history(_attempted_socks_tunnel()))

    assert state is not None
    assert state.access_host == DMZ
    assert state.access_user == "svc-drop"


@pytest.mark.asyncio
async def test_the_gate_stays_armed_after_a_dead_socks_tunnel():
    """Acceptance 1: no verified route -> the sweep against the DC is refused."""
    asked: list[tuple[str, tuple[int, ...]]] = []

    async def unreachable(host: str, ports) -> bool:
        asked.append((host, tuple(ports)))
        return False

    order = await pivot_gate(
        "nexus.recon.nmap",
        {"target": DC},
        _pivot_history(_attempted_socks_tunnel()),
        probe=unreachable,
    )

    assert "PIVOTE NECESARIO" in order and DC in order
    assert asked and asked[0][0] == DC
    # ...and the same history with no tunnel attempt behaves identically: the
    # gate no longer depends on the text of a command at all.
    asked.clear()
    assert await pivot_gate(
        "nexus.recon.nmap", {"target": DC}, _pivot_history(), probe=unreachable
    )
    assert asked and asked[0][0] == DC


@pytest.mark.asyncio
async def test_the_pivot_order_no_longer_depends_on_a_tunnel_attempt():
    """The post-hoc order fires on a dead ``-D`` just like on no tunnel at all."""
    history = [
        *_pivot_history(_attempted_socks_tunnel()),
        {"tool_id": "nexus.recon.nmap", "arguments": {"target": DC}},
    ]

    assert "PIVOTE NECESARIO" in pivot_hint(history)
    # A verified route does silence it, because then there is nothing to order.
    assert pivot_hint(history, facts=[_route_fact()]) == ""


# --------------------------------------------------- a verified route unarms it
@pytest.mark.asyncio
async def test_a_verified_route_lets_the_sweep_run_without_probing():
    """Acceptance 2: the board proves the path, so the probe is never called."""
    asked: list[str] = []

    async def spy(host: str, ports) -> bool:
        asked.append(host)
        return False

    order = await pivot_gate(
        "nexus.recon.nmap",
        {"target": DC},
        _pivot_history(_attempted_socks_tunnel()),
        probe=spy,
        facts=[_route_fact()],
    )

    assert order == ""
    assert asked == []


@pytest.mark.asyncio
async def test_a_route_to_another_host_does_not_unarm_the_gate():
    """Only the route that ends where the call aims counts."""
    order = await pivot_gate(
        "nexus.recon.nmap",
        {"target": "192.168.11.51"},
        _pivot_history(),
        probe=_unreachable_probe,
        facts=[_route_fact()],
    )
    assert "PIVOTE NECESARIO" in order


async def _unreachable_probe(host: str, ports) -> bool:
    return False


def test_a_route_from_another_host_is_not_a_route_from_here():
    """The same destination reached from a different pivot proves nothing."""
    facts = [_route_fact(from_host="192.168.11.51")]
    assert route_reaches(facts, from_host=DMZ, to_host=DC) is None


def test_the_models_own_route_registration_never_counts():
    """Acceptance 4 (first half): a route the model registered is a hypothesis."""
    lead = _route_fact(verified=False, asserted_by="agent")
    unverified = _route_fact(verified=False)

    assert verified_routes([lead, unverified]) == []
    assert route_reaches([lead], from_host=DMZ, to_host=DC) is None
    # Only a verifier's fully-shaped value is a route.
    assert route_reaches([_route_fact()], from_host=DMZ, to_host=DC) is not None


def test_a_malformed_route_value_is_never_trusted():
    broken = _route_fact()
    broken["value"] = {"from_host": DMZ, "to_host": DC, "method": "carrier-pigeon"}
    assert verified_routes([broken]) == []


def test_a_port_agnostic_route_covers_every_port():
    route = RouteValue(
        from_host=DMZ,
        to_host=DC,
        to_port=None,
        method="socks",
        forwarder_ref="127.0.0.1:1080",
        verified_by="inv-1",
    )
    facts = [{"fact_type": "route", "key": "k", "value": route.model_dump(),
              "verified": True, "asserted_by": "verifier"}]
    assert route_reaches(facts, from_host=DMZ, to_host=DC, to_port=445) is not None
    assert route_reaches(facts, from_host=DMZ, to_host=DC, to_port=22) is not None


# ------------------------------------------------------------ the tool contract
def test_verify_route_is_read_only_and_needs_no_scope_target():
    definition = verify_route_definition()

    assert definition.tool_id == VERIFY_ROUTE_TOOL_ID
    assert definition.effect == "read_only"
    assert definition.scope_required is False
    assert definition.sandbox_required is False
    assert set(definition.input_schema["required"]) == {"from_host", "to_host", "method"}


def test_the_sweeping_profiles_can_verify_a_route():
    """A profile that can build a tunnel must be able to prove it."""
    for profiled in ("postexploit", "lateral"):
        assert SUBAGENTS_BY_ID[profiled].allows(VERIFY_ROUTE_TOOL_ID), profiled


@pytest.mark.asyncio
async def test_verify_route_emits_a_route_when_the_forwarder_answers():
    """Acceptance 3 (half): a live forwarder produces ``route_probe_ok``."""
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await verify_route_handler(
            {
                "from_host": DMZ,
                "to_host": DC,
                "to_port": 445,
                "method": "ssh_L",
                "forwarder_ref": f"127.0.0.1:{port}",
            },
            None,
        )
    finally:
        server.close()
        await server.wait_closed()

    assert result.verified is True
    assert result.verification_method == "route_probe_ok"
    assert result.output["route"]["forwarder_ref"] == f"127.0.0.1:{port}"
    assert result.evidence["probe"] == "tcp"


@pytest.mark.asyncio
async def test_verify_route_reports_the_cause_when_the_forwarder_is_dead():
    """Acceptance 3 (half): a dead tunnel is ``unavailable`` with its cause."""
    # Bind then release a port so it is provably closed.
    probe = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = probe.sockets[0].getsockname()[1]
    probe.close()
    await probe.wait_closed()

    result = await verify_route_handler(
        {
            "from_host": DMZ,
            "to_host": DC,
            "to_port": 445,
            "method": "ssh_L",
            "forwarder_ref": f"127.0.0.1:{port}",
            "timeout_seconds": 1,
        },
        None,
    )

    assert result.verified is False
    assert result.outcome == "unavailable"
    assert result.verification_method == "route_probe_failed"
    assert f"127.0.0.1:{port}" in result.evidence["cause"]


@pytest.mark.asyncio
async def test_a_socks_route_without_its_proxy_is_not_verified_directly():
    """A SOCKS route must be tested through the proxy, never around it."""
    result = await verify_route_handler(
        {"from_host": DMZ, "to_host": DC, "to_port": 445, "method": "ssh_D"}, None
    )

    assert result.verified is False
    assert result.outcome == "unavailable"
    assert result.evidence["cause"] == "missing_forwarder"


@pytest.mark.asyncio
async def test_a_socks_proxy_that_cannot_reach_the_destination_refuses_the_route():
    """The proxy listening is not the route: only a ``REP=0`` proves it."""
    async def handler(reader, writer):
        await reader.readexactly(3)  # greeting: ver=5, nmethods=1, no-auth
        writer.write(b"\x05\x00")
        await reader.readexactly(4)  # CONNECT request header
        await reader.readexactly(2)  # port
        writer.write(b"\x05\x05\x00\x01" + b"\x00" * 6)  # REP=5: refused
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await verify_route_handler(
            {
                "from_host": DMZ,
                "to_host": DC,
                "to_port": 445,
                "method": "ssh_D",
                "forwarder_ref": f"127.0.0.1:{port}",
                "timeout_seconds": 2,
            },
            None,
        )
    finally:
        server.close()
        await server.wait_closed()

    assert result.verified is False
    assert "code 5" in result.evidence["cause"]


@pytest.mark.asyncio
async def test_a_socks_connect_that_succeeds_becomes_an_asserted_route():
    """The canonical chain: ``ssh -D`` + a CONNECT that reaches the DC."""
    async def handler(reader, writer):
        await reader.readexactly(3)
        writer.write(b"\x05\x00")
        await reader.readexactly(4)
        await reader.readexactly(2)  # 192.168.11.100:445
        writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    proxy_port = server.sockets[0].getsockname()[1]
    try:
        result = await verify_route_handler(
            {
                "from_host": DMZ,
                "to_host": DC,
                "to_port": 445,
                "method": "ssh_D",
                "forwarder_ref": f"127.0.0.1:{proxy_port}",
                "timeout_seconds": 2,
            },
            None,
        )
    finally:
        server.close()
        await server.wait_closed()

    assert result.verified is True and result.evidence["probe"] == "socks5"

    class _Ctx:
        invocation_id = "inv-verify-1"
        run_id = "run-1"

    assertions = derive_assertions(VERIFY_ROUTE_TOOL_ID, {}, result, _Ctx)
    assert len(assertions) == 1
    fact = assertions[0]
    assert fact["fact_type"] == "route"
    assert fact["value"]["from_host"] == DMZ
    assert fact["value"]["to_host"] == DC
    assert fact["value"]["verified_by"] == "inv-verify-1"

    # ...and that assertion is what unarms the gate.
    board = [{"fact_type": "route", "key": fact["key"], "value": fact["value"],
              "verified": True, "asserted_by": "verifier"}]
    assert route_reaches(board, from_host=DMZ, to_host=DC) is not None


# ------------------------------------------------- the plan closes on the fact
def test_pivot_lan_closes_with_a_route_and_dc_access_is_next():
    """Acceptance: the pivot TODO closes on the fact, not on the model's word."""
    plan = new_plan("Compromete DeadDrop", "eng-deaddrop", [
        todo_from_mapping({
            "id": "pivot-lan",
            "description": "Pivote desde 192.168.11.200 a la LAN interna",
            "fact_types": ["route"],
            "condition": {"route": {"value.to_host": DC}},
        }),
        todo_from_mapping({
            "id": "dc-access",
            "description": "Acceder al DC 192.168.11.100",
            "fact_types": ["access"],
        }),
    ])

    # The DMZ sweep produced a `host` fact for the DC and it closed nothing.
    host_fact = {"fact_type": "host", "key": DC, "value": {"state": "up"},
                 "verified": True, "asserted_by": "verifier"}
    assert reconcile(plan, [host_fact])[1] == []

    # The verified route closes `pivot-lan` and only `pivot-lan`.
    updated, ticks = reconcile(plan, [_route_fact()])

    assert ticks == ["pivot-lan"]
    assert updated.by_id("dc-access").open
    assert "SIGUIENTE TODO: dc-access" in prompt_block(updated)


@pytest.mark.asyncio
async def test_a_failed_probe_asserts_nothing():
    """No route fact from a failure: the absence of a tunnel is not a fact."""
    class _Ctx:
        invocation_id = "inv-verify-2"
        run_id = "run-1"

    failed = ToolResult(
        output={"route": {"from_host": DMZ, "to_host": DC, "to_port": 445,
                          "method": "ssh_L", "forwarder_ref": None}},
        verified=False,
        verification_method="route_probe_failed",
        outcome="unavailable",
    )
    assert derive_assertions(VERIFY_ROUTE_TOOL_ID, {}, failed, _Ctx) == []
