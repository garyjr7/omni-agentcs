"""Read the client-facing kill chain from the engagement's asset graph.

The graph already stores *why* a fact exists (``kernel_fact_edges``). The report
used to show the inventory and the findings as separate lists, leaving the
reader to reconstruct the path from a host to root. This module walks the edges
and returns bounded, de-duplicated chains whose labels are the facts' own data:
nothing is inferred from prose and no step is invented to make a nicer story.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from .models import AttackChain, AttackChainStep

#: Types that belong in a client-facing path, in the order they normally occur.
CHAIN_TYPES: tuple[str, ...] = (
    "host",
    "service",
    "endpoint",
    "credential",
    "access",
    "session",
    "privilege",
    "loot",
)
_CHAIN_TYPE_SET = frozenset(CHAIN_TYPES)
_SERVICE_KEY = re.compile(r"^(?P<host>.+):(?P<port>\d+):(?P<proto>tcp|udp)$")


def _uri_parts(uri: str) -> tuple[str, str]:
    """``blackboard/<eng>/<type>/<key>`` → ``(type, key)`` (``("", "")`` else)."""
    parts = str(uri or "").split("/", 3)
    if len(parts) != 4 or parts[0] != "blackboard":
        return "", ""
    return parts[2], parts[3]


def _label(step_type: str, key: str, value: Any) -> str:
    """Human label from the fact itself, never from its position in the graph."""
    data = value if isinstance(value, Mapping) else {}
    if step_type == "service":
        match = _SERVICE_KEY.match(key)
        port = f"{match.group('port')}/{match.group('proto')}" if match else ""
        name = str(data.get("service") or data.get("product") or "").strip()
        return " ".join(part for part in (port, name) if part) or key
    if step_type == "credential":
        username = str(data.get("username") or "").strip()
        service = str(data.get("service") or "").strip()
        if username:
            return f"{username} ({service})" if service else username
        return key
    if step_type == "access":
        username = str(data.get("username") or "").strip()
        transport = str(data.get("transport") or "").strip()
        if username and transport:
            return f"{username} vía {transport}"
        return username or transport or key
    if step_type == "session":
        owner = str(data.get("user") or "").strip()
        return f"sesión {owner}" if owner else "sesión"
    if step_type == "privilege":
        if data.get("uid") == 0 or str(data.get("user") or "").lower() == "root":
            return "root"
        return str(data.get("user") or key)
    if step_type == "loot":
        flag = str(data.get("flag") or data.get("path") or "").strip()
        return f"loot {flag}" if flag else "loot"
    return key


def build_attack_chains(
    facts: Iterable[Mapping[str, Any]] | None,
    edges: Iterable[Mapping[str, Any]] | None,
    *,
    engagement_id: str = "",
    limit: int = 12,
    max_depth: int = 7,
) -> tuple[AttackChain, ...]:
    """Walk verified edges from each host and return bounded kill chains.

    Only chains with at least two steps are useful to a reader; a lone service
    is already in the inventory. Branches are deduplicated by their labels, and
    the ones that reach privilege or loot come first.
    """
    fact_rows = [fact for fact in (facts or ()) if isinstance(fact, Mapping)]
    by_uri: dict[str, Mapping[str, Any]] = {}
    for fact in fact_rows:
        fact_type = str(fact.get("fact_type") or "")
        key = str(fact.get("key") or "")
        if fact_type and key:
            by_uri[
                f"blackboard/{fact.get('engagement_id') or engagement_id}/{fact_type}/{key}"
            ] = fact
    # ``engagement_id`` may be absent from a fact read; index by the same URI
    # suffix the edges use so both sides always meet.
    suffix_index: dict[tuple[str, str], Mapping[str, Any]] = {
        (str(fact.get("fact_type") or ""), str(fact.get("key") or "")): fact
        for fact in fact_rows
    }

    outgoing: dict[str, list[str]] = {}
    for edge in edges or ():
        if not isinstance(edge, Mapping):
            continue
        src = str(edge.get("src_uri") or "")
        dst = str(edge.get("dst_uri") or "")
        if not src or not dst:
            continue
        outgoing.setdefault(src, []).append(dst)

    def fact_for(uri: str) -> Mapping[str, Any]:
        return by_uri.get(uri) or suffix_index.get(_uri_parts(uri), {})

    def walk(uri: str, chain: list[AttackChainStep], seen: set[str]) -> None:
        if len(chain) >= max_depth:
            chains.append(chain)
            return
        children = [child for child in outgoing.get(uri, ()) if child not in seen]
        if not children:
            if len(chain) >= 2:
                chains.append(chain)
            return
        extended = False
        for child in children:
            child_type, child_key = _uri_parts(child)
            if child_type not in _CHAIN_TYPE_SET:
                continue
            child_fact = fact_for(child)
            label = _label(child_type, child_key, child_fact.get("value"))
            walk(
                child,
                [*chain, AttackChainStep(child_type, child_key, label)],
                {*seen, child},
            )
            extended = True
        if not extended and len(chain) >= 2:
            chains.append(chain)

    chains: list[list[AttackChainStep]] = []
    for fact_type, key in suffix_index:
        if fact_type != "host":
            continue
        fact = suffix_index[(fact_type, key)]
        start = (
            f"blackboard/{fact.get('engagement_id') or engagement_id}/{fact_type}/{key}"
        )
        if not outgoing.get(start):
            continue
        label = _label(fact_type, key, fact.get("value"))
        walk(start, [AttackChainStep(fact_type, key, label)], {start})

    unique: list[tuple[AttackChainStep, ...]] = []
    seen_chains: set[tuple[str, ...]] = set()
    for chain in chains:
        signature = tuple(f"{step.fact_type}:{step.key}" for step in chain)
        if len(chain) < 2 or signature in seen_chains:
            continue
        seen_chains.add(signature)
        unique.append(tuple(chain))

    def rank(chain: tuple[AttackChainStep, ...]) -> tuple[int, int]:
        ends = chain[-1].fact_type
        return (0 if ends in {"privilege", "loot"} else 1, -len(chain))

    unique.sort(key=rank)
    return tuple(AttackChain(steps=chain) for chain in unique[: max(1, int(limit))])


__all__ = ["CHAIN_TYPES", "build_attack_chains"]
