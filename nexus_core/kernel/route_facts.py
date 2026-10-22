"""Verified routes: the fact that separates a tunnel from a hypothesis.

DeadDrop P11 (2026-10-22) is the measured origin. The run held a proven SSH
``access`` on ``192.168.11.200``, knew the DC ``192.168.11.100`` existed and
still never reached it: "a route exists" had no representation, so the plan
could not close its pivot TODO, the pre-scan gate had nothing to read and the
model improvised one-port ``ssh -L`` forwards it could not verify. The gate
guessed from the *history* (``-D`` in a command), which meant a tunnel that was
attempted and died disabled the gate for the rest of the run.

A route is therefore a first-class fact, and it can only be written by a
deterministic verifier (:class:`RouteValue` is validated on read as well as on
write). It carries the two hosts, the method, the optional forwarder handle and
the ``invocation_id`` that proved it, so "the tunnel is up" is an observation
with provenance instead of a claim in a command string.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

#: Fact type of a proven route between two hosts.
ROUTE_FACT_TYPE = "route"

#: Closed set of transports a route can be built on. ``direct`` is the operator
#: reaching the host itself (no tunnel); the rest name how the traffic travels.
ROUTE_METHODS: tuple[str, ...] = ("ssh_L", "ssh_D", "socks", "ligolo", "direct")
RouteMethod = Literal["ssh_L", "ssh_D", "socks", "ligolo", "direct"]


class RouteValue(BaseModel):
    """One proven route: "from ``from_host`` I reach ``to_host:to_port``".

    Strict and frozen, like every other durable value in the project: an
    unknown field is a bug in the producer, not a detail to ignore.
    """

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    from_host: str = Field(min_length=1, max_length=255)
    to_host: str = Field(min_length=1, max_length=255)
    #: ``None`` when the route is port-agnostic (a SOCKS proxy, a ligolo agent).
    to_port: int | None = Field(default=None, ge=1, le=65535)
    method: RouteMethod
    #: Handle of the process/tunnel in the sandbox (``127.0.0.1:1080``, a tmux
    #: session, a ligolo listener); ``None`` for ``direct``.
    forwarder_ref: str | None = Field(default=None, max_length=512)
    #: ``invocation_id`` of the tool that proved it. Never the model's word.
    verified_by: str = Field(min_length=1, max_length=128)


def route_key(from_host: str, to_host: str, to_port: int | None = None) -> str:
    """Canonical key of a route fact (``.200->.100:445`` or ``.200->.100``)."""
    base = f"{str(from_host).strip()}->{str(to_host).strip()}"
    return f"{base}:{int(to_port)}" if to_port else base


def _route_from_fact(fact: Mapping[str, Any]) -> RouteValue | None:
    """Validate one blackboard fact as a route, or return ``None``.

    Only a verifier's assertion counts: a route the model registered is a
    hypothesis and must never seed the gate or close a TODO.
    """
    if not isinstance(fact, Mapping):
        return None
    if str(fact.get("fact_type") or "") != ROUTE_FACT_TYPE:
        return None
    if fact.get("verified") is not True:
        return None
    if str(fact.get("asserted_by") or "") != "verifier":
        return None
    value = fact.get("value")
    if not isinstance(value, Mapping):
        return None
    try:
        return RouteValue.model_validate(dict(value))
    except ValidationError:
        return None


def verified_routes(facts: Iterable[Mapping[str, Any]] | None) -> list[RouteValue]:
    """Every proven route on the board (order preserved, duplicates kept)."""
    routes: list[RouteValue] = []
    for fact in facts or ():
        route = _route_from_fact(fact)
        if route is not None:
            routes.append(route)
    return routes


def route_reaches(
    facts: Iterable[Mapping[str, Any]] | None,
    *,
    from_host: str,
    to_host: str,
    to_port: int | None = None,
) -> RouteValue | None:
    """The proven route ``from_host -> to_host[:to_port]``, or ``None``.

    A route with ``to_port is None`` covers every port on that host (it is how a
    SOCKS proxy or a ligolo agent behaves); a route with a port only covers that
    one. Hosts compare case-insensitively because the model writes them by hand.
    """
    wanted_from = str(from_host or "").strip().lower()
    wanted_to = str(to_host or "").strip().lower()
    if not wanted_from or not wanted_to:
        return None
    for route in verified_routes(facts):
        if route.from_host.strip().lower() != wanted_from:
            continue
        if route.to_host.strip().lower() != wanted_to:
            continue
        if to_port is not None and route.to_port is not None and route.to_port != to_port:
            continue
        return route
    return None


__all__ = [
    "ROUTE_FACT_TYPE",
    "ROUTE_METHODS",
    "RouteMethod",
    "RouteValue",
    "route_key",
    "route_reaches",
    "verified_routes",
]
