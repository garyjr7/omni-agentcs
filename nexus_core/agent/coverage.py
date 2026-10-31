"""Deterministic attack-surface ledger: one verdict per discovered service.

A pentest does not fail because a service is patched. It fails because the agent
keeps attacking the patched service -or the decoy route- while another open port
is still unexplored. Per-room fixes cannot solve that: the next target will have
a different set of ports, a different patched version and a different working
vector. What generalizes is the *discipline*:

1. Every open service found by recon is an item of a ledger.
2. Every item ends with a verdict: owned, probed (still open) or closed (not a
   vector, with the reason written down).
3. A service without verdict is a *pending branch*, never a dead end: the agent
   works one branch at a time and, when the branch is dead, documents it and
   moves to the next pending one instead of insisting.

This module is pure and deterministic: it reads blackboard facts (the same
records the planner trusts) and renders the ledger plus the correction the loop
injects when the run stalls. It never executes anything and never calls a model,
so it is cheap to compute on every turn and cheap to unit-test.

The ledger is intentionally *not* a planner phase rule. Closing ``enumeration``
by "some fact exists" stays as it is (that contract is pinned by the planner
tests); the ledger is the breadth-first map the model reasons over, and the
deterministic pivot below is what stops a run from spending its budget on a
service that is already a documented dead end.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

#: A service is *open work*: no fact says anything about what it exposes yet.
STATUS_PENDING = "pendiente"
#: Something was already learnt from it (an endpoint, a user, a vulnerability),
#: but it is not owned and it is not closed.
STATUS_PROBED = "sondeado"
#: Verified access/credential/session/privilege/loot is tied to this service.
STATUS_OWNED = "comprometido"
#: A ``barrier`` fact documents why this route is not a vector. Never retried.
STATUS_CLOSED = "descartado"

#: Rank used to order the rendered ledger: actionable branches first, history
#: last. ``pending`` is what the model must look at, ``closed`` is what it must
#: not touch again.
_STATUS_RANK = {
    STATUS_PENDING: 0,
    STATUS_PROBED: 1,
    STATUS_OWNED: 2,
    STATUS_CLOSED: 3,
}

#: Fact types whose *verified* presence means the engagement already reached the
#: service (access, a validated credential, an interactive session, a privilege
#: proven through it or loot read through it).
OWNERSHIP_TYPES: tuple[str, ...] = (
    "access",
    "credential",
    "session",
    "privilege",
    "loot",
    "artifact",
)

#: Service names that describe one *family* rather than one independent branch.
#: A Windows host with SMB/RDP/WinRM also exposes a block of dynamic RPC ports
#: (49152-65535 by default); each is the same endpoint mapper, not a new vector.
#: Treating every port as its own campaign spends the budget on near-identical
#: probes, so the ledger groups them and works one representative (see
#: ``SurfaceEntry.family`` and ``Coverage.first_open``). The set is evidence-based
#: (the service name nmap/the parser actually reported), never a room rule.
RPC_FAMILY_SERVICES = frozenset({
    "rpcbind",
    "msrpc",
    "dcerpc",
    "epmap",
    "rpc",
    "ncacn_http",
})
FAMILY_RPC = "rpc"


def service_family(service: Any, product: Any = "") -> str:
    """Family a service belongs to (``""`` when it is its own branch).

    Only families with an engine-level reason to be merged are named here: the
    ports of a dynamic RPC range answer the same endpoint mapper and share the
    same enumeration path. An unknown high port is *not* folded into a family:
    nothing proves it is the same service, and hiding an open port would be the
    opposite of the ledger's purpose.
    """
    name = str(service or "").strip().lower()
    if name in RPC_FAMILY_SERVICES:
        return FAMILY_RPC
    if FAMILY_RPC in str(product or "").lower().split():
        return FAMILY_RPC
    return ""


#: Ports a bare ``http://host/`` (or ``https://host/``) can reach: the scheme's
#: own default. A URL that omits the port is not evidence about 8080/8443 -a
#: measured false positive: one endpoint on :80 marked an unrelated Squid on
#: :8080 as ``sondeado``-, so the scheme rule is limited to the defaults.
_SCHEME_PORTS = frozenset({80, 443})

#: Ledger lines rendered per prompt. The rest is summarized: a /24 scan can put
#: hundreds of services on the board and the prompt is paid on every turn.
MAX_LEDGER_ENTRIES = 24
#: Paths rendered under one service. The rest are summarized: the ledger is read
#: every turn and a target with twenty routes cannot own the prompt.
MAX_VECTOR_LINES = 3

#: Completed turns without a new verified fact before the pivot is injected.
#: Matches the loop's own stuck threshold, so both signals agree.
DEFAULT_PIVOT_TURNS = 5

#: ``host:port[:proto]`` as written by ``nmap`` (``10.10.10.5:21:tcp``) or by an
#: agent-recorded barrier (``10.10.10.5:21``). Non-greedy host so an IPv4
#: address with dots is one group; an IPv6 literal is out of scope here (the
#: recon parser rewrites services to their IPv4/hostname anyway).
_SERVICE_KEY = re.compile(r"^(?P<host>.+?):(?P<port>\d{1,5})(?::(?P<proto>[A-Za-z]+))?$")

#: A host (optionally with a port) written in the operator's objective. The
#: lookbehind/lookahead keep an octet out of a longer number.
_ADDRESS_IN_TEXT = re.compile(
    r"(?<![\d.])(?P<host>(?:\d{1,3}\.){3}\d{1,3})(?::(?P<port>\d{1,5}))?(?![\d.])"
)
#: A document route named in the objective (``/admin/app_themes.aspx``). Only
#: extension-bearing routes: a bare ``/admin`` is a directory the model can
#: still explore, while a file route is the concrete step the operator fixed.
_ROUTE_IN_TEXT = re.compile(
    r"/[A-Za-z0-9_\-./]*[A-Za-z0-9_\-]\."
    r"(?:aspx|ascx|ashx|asmx|axd|php\d?|jspx?|do|action|html?|cgi|pl|py)",
    re.IGNORECASE,
)
#: Phrases with which the operator puts a service out of play. Matched against
#: the accent-stripped, casefolded objective, so ``ÚNICO HOST`` and
#: ``no hagas pivoteo`` are found regardless of how the line is typed.
_NO_PIVOT_PHRASES: tuple[str, ...] = (
    "no hagas pivoteo",
    "no pivoteo",
    "no pivotee",
    "no pivotes",
    "no pivotar",
    "sin pivoteo",
    "no pivot",
    "unico host",
    "un solo host",
    "single host",
    "solo este host",
    "solo este objetivo",
    "no movimiento lateral",
    "no lateral movement",
)
#: Characters of the operator's own sentences quoted back in a hint. The quote
#: exists so the model re-reads the order next to the heuristic that contradicts
#: it; it is capped because it is paid on the turns the pivot fires.
DIRECTIVE_QUOTE_CHARS = 300


@dataclass(frozen=True)
class VectorEntry:
    """One *path* inside a service, with its own verdict.

    A service is not a vector. Measured on a web target with four routes into the
    same ``:80``: the ledger had one item, so a ``barrier`` recorded after the
    first dead end closed the service and the other three paths disappeared from
    the map. ``vectors`` keeps them visible and lets a barrier close the path it
    actually names.

    States are the three the engine can *prove*: ``pendiente`` (no attempt
    recorded), ``sondeado`` (something else on the board mentions this path) and
    ``descartado`` (a conclusive barrier names it). A vector is never marked
    ``comprometido`` on its own: ownership is a property of the service, and
    inventing per-path ownership from a host-wide ``access`` fact would be the
    same lie the ledger exists to prevent.
    """

    ref: str
    label: str
    status: str = STATUS_PENDING
    verdict: str = ""

    def render(self) -> str:
        """One sub-line under its service."""
        if self.status == STATUS_CLOSED:
            reason = self.verdict or "sin vector demostrado"
            return f"    ↳ {self.label} → descartado: {reason}"
        if self.status == STATUS_PROBED:
            return f"    ↳ {self.label} → sondeado"
        return f"    ↳ {self.label} → pendiente"

    def to_dict(self) -> dict[str, Any]:
        return {"ref": self.ref, "label": self.label,
                "status": self.status, "verdict": self.verdict}


@dataclass(frozen=True)
class SurfaceEntry:
    """One open service and the best verdict the board supports for it."""

    host: str
    port: int
    protocol: str
    service: str
    product: str
    version: str
    key: str
    status: str = STATUS_PENDING
    verdict: str = ""
    evidence: int = 0
    #: The paths the board proved inside this service (one per vulnerability
    #: fact), each with its own verdict. A branch with a pending vector is not
    #: "closed for lack of a way in": the loop refuses to write a ``barrier``
    #: over it (see ``ReActCoordinator._close_stalled_branch``), because hiding a
    #: proven vector behind a dead branch is worse than stalling.
    vectors: tuple[VectorEntry, ...] = ()
    #: ``vulnerability`` facts that name this service, whether or not they carry
    #: a path. The loop refuses to write a ``barrier`` over a service with any.
    #: Kept apart from ``vector_count`` on purpose: a fact keyed on the service
    #: ("this port has a vulnerability") is a reason to keep the branch open but
    #: names no path, so it cannot appear in the per-path ledger.
    vulnerabilities: int = 0
    #: Service family (``"rpc"`` for dynamic RPC ports, ``""`` otherwise).
    #: Members of one family are branches of the same campaign: the ledger works
    #: the representative and leaves the siblings deferred, not discarded.
    family: str = ""

    @property
    def family_key(self) -> tuple[str, str]:
        """``(host, family)`` - hashable key of the campaign (empty when none)."""
        return (self.host.strip().lower(), self.family) if self.family else ("", "")

    @property
    def family_ref(self) -> str:
        """``host:rpc`` - key that closes/defers the whole family at once."""
        return f"{self.host}:{self.family}" if self.family else ""

    @property
    def vector_count(self) -> int:
        """Number of known paths (kept for the readers that only need a count)."""
        return len(self.vectors)

    @property
    def ref(self) -> str:
        """Stable, short reference used in the prompt and in ``barrier`` keys."""
        return f"{self.host}:{self.port}"

    @property
    def label(self) -> str:
        """``10.10.10.5:21/tcp ftp (vsftpd 3.0.3)`` — one readable item."""
        detail = " ".join(part for part in (self.service, self.product, self.version) if part)
        base = f"{self.ref}/{self.protocol or 'tcp'}"
        return f"{base} {detail}".strip()

    def render(self) -> str:
        """One ledger line with its verdict, plus its paths when it has any."""
        if self.status == STATUS_CLOSED:
            reason = self.verdict or "sin vector demostrado"
            line = f"- {self.label} → descartado: {reason}"
        elif self.status == STATUS_OWNED:
            line = f"- {self.label} → comprometido"
        elif self.status == STATUS_PROBED:
            suffix = f" ({self.evidence} hecho{'s' if self.evidence != 1 else ''})"
            line = f"- {self.label} → sondeado{suffix}"
        else:
            line = f"- {self.label} → pendiente"
        if not self.vectors:
            return line
        visible = self.vectors[:MAX_VECTOR_LINES]
        lines = [line, *(item.render() for item in visible)]
        hidden = self.vectors[len(visible):]
        if hidden:
            # The summary names the verdicts it hides: a closed path that falls
            # out of the cap must still say "descartado", or the model retries
            # the only route it was told not to retry.
            words = {STATUS_PENDING: "pendiente", STATUS_PROBED: "sondeado",
                     STATUS_CLOSED: "descartado"}
            counts: dict[str, int] = {}
            for item in hidden:
                word = words.get(item.status, item.status)
                counts[word] = counts.get(word, 0) + 1
            detail = ", ".join(
                f"{count} {word}{'s' if count != 1 else ''}"
                for word, count in sorted(counts.items())
            )
            lines.append(f"    ↳ … y {len(hidden)} camino(s) más ({detail})")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "status": self.status,
            "verdict": self.verdict,
            "evidence": self.evidence,
            "vulnerabilities": self.vulnerabilities,
            "vector_count": self.vector_count,
            "vectors": [item.to_dict() for item in self.vectors],
            "family": self.family,
        }


@dataclass(frozen=True)
class Directive:
    """The part of the operator's objective that outranks the ledger.

    The objective is the human's order; this ledger is a breadth-first
    heuristic. When the order names a service or a route, or takes a service out
    of play, the pivot must not contradict it -that inversion is what made
    ``run_e971fff78593498081567bdfc602d23a`` (V15, HackPark 2026-10-21) leave a
    proven BlogEngine route at iteration 12 and spend its remaining budget on
    RDP, a service the same objective had excluded.
    """

    #: ``host:port`` named by the objective, in the order it appears.
    refs: tuple[str, ...] = ()
    #: Hosts named by the objective (with or without a port in the sentence).
    hosts: tuple[str, ...] = ()
    #: Document routes named by the objective (``/admin/app_themes.aspx``).
    paths: tuple[str, ...] = ()
    #: The operator forbade pivoting / limited the engagement to one host.
    no_pivot: bool = False
    #: The operator's own sentences, quoted back in the hint (bounded).
    text: str = ""

    @property
    def active(self) -> bool:
        """Whether the objective constrains the branch set at all."""
        return bool(self.refs or self.paths or self.no_pivot)

    def names(self, entry: SurfaceEntry) -> bool:
        """Whether the objective names this ledger entry."""
        ref = entry.ref.lower()
        if ref in {item.lower() for item in self.refs}:
            return True
        # An explicit ``host:port`` narrows the objective to those services: a
        # mention of ``host:80`` is not a mention of the same host's RDP.
        if self.refs:
            return False
        if entry.host.lower() not in {item.lower() for item in self.hosts}:
            return False
        # A document route (``/admin/app_themes.aspx``) names the *web* service
        # of that host, not every port on it (V15: the objective named the theme
        # endpoint and forbade pivoting; RDP on the same host stayed excluded).
        if self.paths:
            return _is_web(entry)
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "refs": list(self.refs),
            "paths": list(self.paths),
            "no_pivot": self.no_pivot,
        }


@dataclass(frozen=True)
class Coverage:
    """The ledger of one engagement at one point in time."""

    entries: tuple[SurfaceEntry, ...] = ()
    #: ``{status: count}`` for telemetry and events.
    counts: Mapping[str, int] = field(default_factory=dict)

    @property
    def pending(self) -> tuple[SurfaceEntry, ...]:
        return tuple(item for item in self.entries if item.status == STATUS_PENDING)

    @property
    def closed(self) -> tuple[SurfaceEntry, ...]:
        return tuple(item for item in self.entries if item.status == STATUS_CLOSED)

    @property
    def open_work(self) -> tuple[SurfaceEntry, ...]:
        """Entries that still need a verdict (pending or merely probed)."""
        return tuple(
            item
            for item in self.entries
            if item.status in (STATUS_PENDING, STATUS_PROBED)
        )

    @property
    def families(self) -> dict[tuple[str, str], tuple[SurfaceEntry, ...]]:
        """Open services grouped by ``(host, family)`` (only real families).

        The siblings are *not* dropped: every port keeps its own entry and its
        own verdict. Grouping only changes *which* entry the ledger proposes
        next and tells the model the campaign is shared, so a block of dynamic
        RPC ports is probed once instead of once per port.
        """
        grouped: dict[tuple[str, str], list[SurfaceEntry]] = {}
        for item in self.entries:
            key = item.family_key
            if not key[1]:
                continue
            grouped.setdefault(key, []).append(item)
        return {
            key: tuple(sorted(items, key=lambda entry: entry.port))
            for key, items in grouped.items()
            if len(items) > 1
        }

    def _family_representative(self, item: SurfaceEntry, seen: set[tuple[str, str]]) -> bool:
        """Whether ``item`` is the one branch of its family to work right now.

        The lowest-port member of the family that still needs a verdict is the
        representative. Skipping the rest is deliberate: they answer the same
        endpoint mapper, and one campaign over the family is the honest unit.
        """
        key = item.family_key
        if not key[1]:
            return True
        if key in seen:
            return False
        members = self.families.get(key, ())
        if not members:
            return True
        open_members = [entry for entry in members if entry.status in (STATUS_PENDING, STATUS_PROBED)]
        if not open_members:
            return True
        if open_members[0].ref != item.ref:
            return False
        seen.add(key)
        return True

    def first_open(self) -> SurfaceEntry | None:
        """The next branch to work: pending first, then probed, in port order.

        Members of one service family are proposed through a single
        representative (see :meth:`_family_representative`); the other ports
        stay in ``open_work`` as deferred, not discarded.
        """
        open_items = self.open_work
        seen_families: set[tuple[str, str]] = set()
        for item in open_items:
            if item.status == STATUS_PENDING and self._family_representative(item, seen_families):
                return item
        for item in open_items:
            if self._family_representative(item, seen_families):
                return item
        return None

    def family_representative(self, host: str, family: str) -> SurfaceEntry | None:
        """Lowest-port open member of ``(host, family)`` (the one to work)."""
        members = self.families.get((str(host).strip().lower(), str(family)))
        if not members:
            return None
        open_members = [
            item for item in members if item.status in (STATUS_PENDING, STATUS_PROBED)
        ]
        return open_members[0] if open_members else None

    def deferred_family_members(self, entry: SurfaceEntry) -> tuple[SurfaceEntry, ...]:
        """Siblings of ``entry``'s family that wait behind its verdict."""
        members = self.families.get(entry.family_key, ())
        return tuple(
            item
            for item in members
            if item.ref != entry.ref and item.status in (STATUS_PENDING, STATUS_PROBED)
        )

    def find(self, ref: str) -> SurfaceEntry | None:
        """Look one entry up by ``host:port`` (case-insensitive)."""
        wanted = str(ref or "").strip().lower()
        if not wanted:
            return None
        for item in self.entries:
            if item.ref.lower() == wanted:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "counts": dict(self.counts),
            "entries": [item.to_dict() for item in self.entries],
            "families": {
                f"{host}:{family}": [item.ref for item in members]
                for (host, family), members in self.families.items()
            },
        }


# --------------------------------------------------------------------------- #
# Derivation
# --------------------------------------------------------------------------- #
def _parse_service_fact(fact: Mapping[str, Any]) -> SurfaceEntry | None:
    """Coerce a ``service`` fact into an entry (``None`` for a foreign shape)."""
    key = str(fact.get("key") or "").strip()
    match = _SERVICE_KEY.match(key)
    if match is None:
        return None
    port = int(match.group("port"))
    if not 0 < port < 65536:
        return None
    raw_value = fact.get("value")
    value: Mapping[str, Any] = raw_value if isinstance(raw_value, Mapping) else {}
    protocol = str(match.group("proto") or value.get("protocol") or "tcp").lower()
    service = str(value.get("service") or "").strip().lower()
    product = str(value.get("product") or "").strip()
    return SurfaceEntry(
        host=str(match.group("host")),
        port=port,
        protocol=protocol,
        service=service,
        product=product,
        version=str(value.get("version") or "").strip(),
        key=key,
        family=service_family(service, product),
    )


def _fact_blob(fact: Mapping[str, Any]) -> str:
    """Lowercased text of a fact's key and value (the match substrate)."""
    try:
        return json.dumps(
            {"key": fact.get("key"), "value": fact.get("value")},
            default=str,
            sort_keys=True,
        ).lower()
    except (TypeError, ValueError, RecursionError):
        return str(fact).lower()


def _scheme_touches(blob: str, host: str, port: int) -> bool:
    """Whether a ``http(s)://host`` URL *without an explicit port* is this port.

    ``http://host/x`` can only be reached on the scheme's default port; a URL
    that names a port (``http://host:8080/x``) is evidence about that port and
    about no other. Measured false positive: one endpoint on :80 marked an
    unrelated Squid on :8080 as ``sondeado``.
    """
    if port not in _SCHEME_PORTS:
        return False
    match = re.search(rf"https?://{re.escape(host)}(?::(\d+))?", blob)
    if match is None:
        return False
    explicit = match.group(1)
    return explicit is None or int(explicit) == port


def _mentions(blob: str, entry: SurfaceEntry) -> bool:
    """Whether a fact's text refers to this service.

    The host must appear, plus *one* of: the port as a standalone number, the
    service name (``ftp``/``http``/…), or -for a web service- a scheme that can
    only be served by that port family. Requiring the host keeps a global
    keyword ("http") from touching every entry on the board.
    """
    host = entry.host.strip().lower()
    if not host or host not in blob:
        return False
    if re.search(rf"(?<![\d.]){entry.port}(?![\d.])", blob):
        return True
    service = entry.service.strip().lower()
    if len(service) >= 2 and service in blob:
        return True
    return _scheme_touches(blob, host, entry.port)


def _same_ref(fact: Mapping[str, Any], entry: SurfaceEntry) -> bool:
    """Whether a fact's *key* is this service's own key (any spelling)."""
    key = str(fact.get("key") or "").strip().lower()
    if not key:
        return False
    wanted = {entry.key.lower(), entry.ref.lower(), f"{entry.ref.lower()}:{entry.protocol}"}
    if entry.family_ref:
        wanted.add(entry.family_ref.lower())
    return key in wanted


def _recorded_at(fact: Mapping[str, Any]) -> str:
    """When the fact was written (``""`` for a fact that carries no stamp).

    ``Blackboard.record`` always stores ``recorded_at`` as an ISO-8601 UTC
    string, so a plain lexicographic comparison orders two facts correctly.
    """
    return str(fact.get("recorded_at") or "").strip()


def _newest(facts: list[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """The most recent of ``facts``, or ``None`` when recency is unknowable.

    Without a stamp on every candidate there is no way to say which verdict
    came last, so the caller falls back to the historical rule (the barrier
    wins) instead of guessing.
    """
    if not facts:
        return None
    stamps = [_recorded_at(fact) for fact in facts]
    if not all(stamps):
        return None
    return max(zip(stamps, facts), key=lambda pair: pair[0])[1]


#: Outcomes that are *not* a verdict about the target: the tool refused the
#: call (bad argument, schema, policy) or could not reach the backend. None of
#: them tested the vector, so none of them may close a branch (R6).
INCONCLUSIVE_BARRIER_OUTCOMES: frozenset[str] = frozenset(
    {
        "invalid_arguments",
        "invalid_failure_string",
        "invalid_csrf",
        "unavailable",
        "rejected",
        "denied",
        "validation_error",
        "partial",
        "timeout",
    }
)


def barrier_is_conclusive(fact: Mapping[str, Any]) -> bool:
    """Whether a ``barrier`` may close its branch.

    A barrier is the agent's *decision to stop*, not evidence about the target,
    so it needs provenance. Measured in HackPark V12 (2026-10-21, iteration 17):
    after two **argument** rejections the model recorded a barrier saying "el
    bruteforce no ha devuelto sesión" about a sweep that never ran
    (``sweep_attempted: false``); the ledger marked :80 ``descartado`` and the
    pivot sent the run to RDP, which was never a vector.

    Rules, in order:

    * an explicit ``sweep_attempted: false`` means nothing was tried -> the
      branch stays open;
    * an ``outcome`` that is a rejection/infrastructure failure -> stays open;
    * anything else (including a fact recorded before this field existed) keeps
      the historical behaviour and closes the branch.
    """
    raw_value = fact.get("value")
    value: Mapping[str, Any] = raw_value if isinstance(raw_value, Mapping) else {}
    if value.get("sweep_attempted") is False:
        return False
    outcome = str(value.get("outcome") or "").strip().lower()
    if not outcome:
        return True
    if outcome.startswith("invalid_"):
        return False
    return outcome not in INCONCLUSIVE_BARRIER_OUTCOMES


def _barrier_reason(fact: Mapping[str, Any]) -> str:
    """Human-readable reason of a barrier fact (always something usable)."""
    raw_value = fact.get("value")
    value: Mapping[str, Any] = raw_value if isinstance(raw_value, Mapping) else {}
    for name in ("reason", "detail", "why", "cve", "status"):
        text = str(value.get(name) or "").strip()
        if text:
            return " ".join(text.split())[:180]
    return "documentado sin vector por el agente"


def _vector_needles(fact: Mapping[str, Any], entry_ref: str = "") -> tuple[str, ...]:
    """Strings that identify *this path*, never the host it lives on.

    A bare host is excluded on purpose: it is a substring of the service ref
    (``10.0.0.5`` inside ``10.0.0.5:80``), so accepting it would attribute every
    service-level barrier to every path and the ledger would stop closing
    anything. For the same reason a fact keyed on the service itself
    (``10.10.10.5:80``) carries no path needle: it says "this service has a
    vulnerability", not *which route* is vulnerable.
    """
    entry_ref = str(entry_ref or "").strip().lower()
    raw_value = fact.get("value")
    value: Mapping[str, Any] = raw_value if isinstance(raw_value, Mapping) else {}
    needles: set[str] = set()
    key = str(fact.get("key") or "").strip()
    if key and ("/" in key or ":" in key) and len(key) >= 4:
        needles.add(key)
    for name in ("id", "cve", "endpoint"):
        text = str(value.get(name) or "").strip()
        if len(text) >= 4:
            needles.add(text)
    url = str(value.get("url") or "").strip()
    for path in (urlsplit(url).path if url else "", str(value.get("path") or "")):
        if len(path) > 1:
            needles.add(path)
    if entry_ref:
        needles = {item for item in needles if item.lower() != entry_ref}
    return tuple(sorted(needles, key=len, reverse=True))


def _mentions_any(blob: str, needles: Iterable[str]) -> bool:
    """Whether a flattened fact names one of the vector's needles."""
    return any(needle and needle in blob for needle in needles)


def _vector_label(fact: Mapping[str, Any]) -> str:
    """Readable name for a path: ``CVE-2019-6714 (/admin/app_themes.aspx)``."""
    raw_value = fact.get("value")
    value: Mapping[str, Any] = raw_value if isinstance(raw_value, Mapping) else {}
    name = ""
    for candidate in ("id", "cve", "class"):
        text = str(value.get(candidate) or "").strip()
        if text:
            name = text
            break
    url = str(value.get("url") or "").strip()
    path = urlsplit(url).path if url else ""
    if not name:
        name = str(fact.get("key") or "camino")
    if path and len(path) > 1 and path not in name:
        name = f"{name} ({path})"
    return " ".join(name.split())[:140]


def _vector_entries(
    vectors: list[Mapping[str, Any]],
    barriers: list[Mapping[str, Any]],
    related: list[tuple[Mapping[str, Any], str]],
    entry_ref: str = "",
) -> tuple[VectorEntry, ...]:
    """One entry per distinct path, with the verdict its own facts support."""
    by_ref: dict[str, VectorEntry] = {}
    strength = {
        STATUS_PENDING: 1,
        STATUS_PROBED: 2,
        STATUS_CLOSED: 3,
    }
    for fact in vectors:
        needles = _vector_needles(fact, entry_ref)
        if not needles:
            continue
        ref = str(fact.get("key") or "") or _vector_label(fact)
        # Only a barrier recorded *after* the path was found can close it: a
        # newer vulnerability reopens its own path, exactly like the service
        # rule above (measured in run_3d90f7f3…).
        closing = [
            item for item in barriers
            if _mentions_any(_fact_blob(item), needles)
            and _recorded_at(item) >= _recorded_at(fact)
        ]
        probed = any(
            other is not fact
            and str(other.get("fact_type") or "") != "barrier"
            and _mentions_any(blob, needles)
            for other, blob in related
        )
        status = (
            STATUS_CLOSED if closing
            else STATUS_PROBED if probed
            else STATUS_PENDING
        )
        newest = _newest(closing) if closing else None
        candidate = VectorEntry(
            ref=ref[:160],
            label=_vector_label(fact),
            status=status,
            verdict=_barrier_reason(newest) if newest is not None else "",
        )
        current = by_ref.get(ref)
        if current is None or strength.get(status, 0) > strength.get(current.status, 0):
            by_ref[ref] = candidate
    return tuple(
        sorted(by_ref.values(), key=lambda item: (_STATUS_RANK.get(item.status, 9), item.label))
    )


def build_coverage(facts: Iterable[Mapping[str, Any]] | None) -> Coverage:
    """Build the ledger of one engagement from its blackboard facts.

    Only ``service`` facts *create* entries (recon is what discovers a port);
    every other fact can only give an existing entry a status. Ownership
    outranks everything: once the service is reached it is not "closed". A
    barrier closes an unowned service and survives a later scan that
    rediscovers the port -and an older barrier wins over nothing-, but a
    *newer* vulnerability reopens it: the ledger's newest verdict is the one
    that counts, which is exactly what ``pivot_hint`` tells the model.
    """
    records = [fact for fact in (facts or ()) if isinstance(fact, Mapping)]
    entries: list[SurfaceEntry] = []
    seen: set[str] = set()
    for fact in records:
        if str(fact.get("fact_type") or "") != "service":
            continue
        entry = _parse_service_fact(fact)
        if entry is None or entry.ref.lower() in seen:
            continue
        seen.add(entry.ref.lower())
        entries.append(entry)

    if not entries:
        return Coverage()

    related: list[tuple[Mapping[str, Any], str]] = [
        (fact, _fact_blob(fact))
        for fact in records
        if str(fact.get("fact_type") or "") not in ("service", "host")
    ]

    resolved: list[SurfaceEntry] = []
    for entry in entries:
        evidence = 0
        owned = False
        barriers: list[Mapping[str, Any]] = []
        vectors: list[Mapping[str, Any]] = []
        for fact, blob in related:
            fact_type = str(fact.get("fact_type") or "")
            if fact_type == "barrier":
                if not (_same_ref(fact, entry) or _mentions(blob, entry)):
                    continue
                # R6: a barrier that does not prove an attempt is a hypothesis,
                # not a closed branch (V12, HackPark iteration 17).
                if not barrier_is_conclusive(fact):
                    continue
                barriers.append(fact)
            elif not _mentions(blob, entry):
                continue
            elif fact_type in OWNERSHIP_TYPES and fact.get("verified") is True:
                owned = True
            elif fact_type == "vulnerability":
                vectors.append(fact)
            evidence += 1

        known_paths = [
            needles for vector in vectors
            if (needles := _vector_needles(vector, entry.ref))
        ]
        vector_entries = _vector_entries(vectors, barriers, related, entry.ref)
        # A barrier that names a path closes *that path*; one that names only the
        # service keeps the historical meaning (the whole route is dead). Keeping
        # the two apart is what stops the first dead end from hiding the other
        # three routes of the same port.
        named_barriers = [
            item for item in barriers
            if any(_mentions_any(_fact_blob(item), needles) for needles in known_paths)
        ]
        named_ids = {id(item) for item in named_barriers}
        service_barriers = [item for item in barriers if id(item) not in named_ids]

        status = STATUS_PENDING
        verdict = ""
        if owned:
            # Access, a validated credential, a session, a privilege or loot
            # proves the service was reached: a later barrier cannot hide it.
            status = STATUS_OWNED
        elif service_barriers:
            # The *newest* verdict wins. A barrier is the agent's decision to
            # stop on this route, but it is not infallible: a vulnerability
            # found afterwards reopens the branch. Measured in
            # ``run_3d90f7f388144557ae97466b0a19ce55`` (2026-10-20), where the
            # agent proved CVE-2017-8917 error-based on :80 while the ledger
            # kept ordering it to abandon the only working vector because
            # ``pivot_hint`` promises "si aparece un vector nuevo, regístralo
            # como hecho antes de retomarlo" and nothing honoured it.
            chosen = _newest(service_barriers)
            latest_vector = _newest(vectors)
            reopened = (
                chosen is not None
                and latest_vector is not None
                and _recorded_at(latest_vector) > _recorded_at(chosen)
            )
            if reopened:
                status = STATUS_PROBED
            else:
                status = STATUS_CLOSED
                verdict = _barrier_reason(
                    chosen if chosen is not None else service_barriers[0]
                )
        elif named_barriers:
            # The service stays open work while any of its paths has no verdict.
            if any(item.status != STATUS_CLOSED for item in vector_entries):
                status = STATUS_PROBED
            else:
                chosen = _newest(named_barriers)
                status = STATUS_CLOSED
                verdict = _barrier_reason(
                    chosen if chosen is not None else named_barriers[0]
                )
        elif evidence:
            status = STATUS_PROBED
        resolved.append(
            SurfaceEntry(
                host=entry.host,
                port=entry.port,
                protocol=entry.protocol,
                service=entry.service,
                product=entry.product,
                version=entry.version,
                key=entry.key,
                status=status,
                verdict=verdict,
                evidence=evidence,
                vulnerabilities=len(vectors),
                vectors=vector_entries,
                family=service_family(entry.service, entry.product),
            )
        )

    resolved.sort(key=lambda item: (_STATUS_RANK.get(item.status, 9), item.host, item.port))
    counts: dict[str, int] = {}
    for item in resolved:
        counts[item.status] = counts.get(item.status, 0) + 1
    return Coverage(entries=tuple(resolved), counts=counts)


def load_coverage(store: Any, tenant_id: str, engagement_id: str | None) -> Coverage:
    """Read the blackboard and build the ledger (never raises).

    The prompt is rendered every turn, so a memory problem must degrade to an
    empty ledger (no block) instead of aborting a run -the same contract the
    rest of the blackboard view follows.
    """
    if not engagement_id or store is None:
        return Coverage()
    try:
        from nexus_core.kernel.blackboard import Blackboard

        facts = Blackboard(store).list_facts(tenant_id, engagement_id, limit=500)
    except Exception:  # noqa: BLE001 - memory must never kill a run
        return Coverage()
    return build_coverage(facts)


# --------------------------------------------------------------------------- #
# Prompt rendering
# --------------------------------------------------------------------------- #
def parse_directive(objective: Any) -> Directive:
    """Read the operator's objective for the branches it fixes (deterministic).

    Pure and cheap: two regular expressions over the objective plus a phrase
    list. It never guesses intent -it only sees a literal address, a literal
    document route and the literal phrases that forbid pivoting- and an empty
    objective yields an inactive directive, so every existing caller keeps the
    pre-directive behaviour.
    """
    text = " ".join(str(objective or "").split())
    if not text:
        return Directive()
    refs: list[str] = []
    hosts: list[str] = []
    for match in _ADDRESS_IN_TEXT.finditer(text):
        host = match.group("host")
        if host not in hosts:
            hosts.append(host)
        port = match.group("port")
        if port:
            ref = f"{host}:{int(port)}"
            if ref not in refs:
                refs.append(ref)
    paths: list[str] = []
    seen: set[str] = set()
    for match in _ROUTE_IN_TEXT.finditer(text):
        path = match.group(0).rstrip(".,;:)")
        if path.casefold() in seen:
            continue
        seen.add(path.casefold())
        paths.append(path)
    flat = _unaccent(text).casefold()
    no_pivot = any(phrase in flat for phrase in _NO_PIVOT_PHRASES)
    return Directive(
        refs=tuple(refs),
        hosts=tuple(hosts),
        paths=tuple(paths[:6]),
        no_pivot=no_pivot,
        text=_directive_quote(text, refs, paths, no_pivot),
    )


def _unaccent(text: str) -> str:
    """Fold accents so ``ÚNICO HOST`` matches ``unico host``."""
    import unicodedata

    return "".join(
        char
        for char in unicodedata.normalize("NFKD", text)
        if not unicodedata.combining(char)
    )


def _directive_quote(
    text: str, refs: list[str], paths: list[str], no_pivot: bool
) -> str:
    """The operator's own sentences that carry the directive (bounded)."""
    cues = [item.casefold() for item in paths]
    cues.extend(item.casefold() for item in refs)
    sentences = [
        part.strip()
        for part in re.split(r"(?<=[.!?;])\s+|\n+", text)
        if part.strip()
    ]
    # The sentence that fixes the *step* (a route, an address) comes first: it is
    # the one that survives the truncation when the objective is long. The
    # sentence that forbids pivoting follows, because it is the one the ledger
    # would otherwise contradict.
    specific = [
        sentence for sentence in sentences if any(cue in sentence.casefold() for cue in cues)
    ]
    limiting = [
        sentence
        for sentence in sentences
        if sentence not in specific
        and no_pivot
        and any(
            phrase in _unaccent(sentence).casefold() for phrase in _NO_PIVOT_PHRASES
        )
    ]
    # "NO hagas pivoteo" before "único host": the explicit prohibition is the
    # sentence the coverage order contradicts.
    limiting.sort(key=lambda sentence: 0 if "pivot" in _unaccent(sentence).casefold() else 1)
    chosen = (specific[:1] + limiting[:2]) or specific or limiting
    quote = " ".join(chosen) or text
    quote = " ".join(quote.split())
    return quote[:DIRECTIVE_QUOTE_CHARS].strip()


def _is_web(entry: SurfaceEntry) -> bool:
    """Whether the entry is the host's web service (the route's transport)."""
    service = str(entry.service or "").casefold()
    return entry.port in _SCHEME_PORTS or service.startswith(("http", "https", "www"))


def _directive_scope(directive: Directive) -> str:
    """Readable summary of what the objective fixes (for hints and the ledger)."""
    parts: list[str] = []
    if directive.refs:
        parts.append("servicio(s) " + ", ".join(directive.refs))
    elif directive.hosts:
        parts.append("host " + ", ".join(directive.hosts))
    if directive.paths:
        parts.append("ruta(s) " + ", ".join(directive.paths))
    return " · ".join(parts)


def _directive_open(coverage: Coverage, directive: Directive) -> SurfaceEntry | None:
    """The next branch the operator named and that still needs a verdict."""
    for item in coverage.open_work:
        if directive.names(item):
            return item
    return None


def render_coverage(
    coverage: Coverage | None, *, directive: Directive | None = None
) -> str:
    """Render the ledger block for the prompt (``""`` when there is no surface).

    The header states the rule, not just the data: each open service needs a
    verdict, a pending service is the next branch, and a dead route is closed
    with a ``barrier`` fact so it is never attacked again.
    """
    if coverage is None or not coverage.entries:
        return ""
    lines = [
        "COBERTURA DE SERVICIOS (ledger determinista; un veredicto por servicio abierto):"
    ]
    visible = coverage.entries[:MAX_LEDGER_ENTRIES]
    lines.extend(item.render() for item in visible)
    hidden = len(coverage.entries) - len(visible)
    if hidden:
        lines.append(f"- … y {hidden} servicio(s) más (ordenados por estado y puerto)")
    for (host, family), members in sorted(coverage.families.items()):
        opened = [item for item in members if item.status in (STATUS_PENDING, STATUS_PROBED)]
        if not opened:
            continue
        ports = ", ".join(str(item.port) for item in members)
        representative = coverage.family_representative(host, family)
        lead = (
            f" representante {representative.ref}"
            if representative is not None
            else ""
        )
        lines.append(
            f"- familia {family.upper()} en {host}: {len(members)} puertos ({ports})."
            f" Es UNA campaña, no {len(members)} ramas:{lead or ' un solo sondeo de familia'}."
            " Los puertos hermanos quedan APLAZADOS (no descartados) hasta que la "
            "familia tenga veredicto; registra qué quedó sin identificar y por qué "
            "se cierra o se aplaza."
        )
    open_count = len(coverage.open_work)
    total = len(coverage.entries)
    bounds = directive if directive is not None and directive.active else None
    if open_count:
        # The branch the ledger suggests must not be one the operator excluded:
        # the frontier line is read on every turn, before any pivot fires.
        following = (
            (_directive_open(coverage, bounds) if bounds is not None else None)
            or coverage.first_open()
        )
        target = f" Siguiente rama: {following.label}." if following else ""
        lines.append(
            f"FRONTERA: {open_count}/{total} servicios sin veredicto.{target}"
        )
    else:
        lines.append(
            f"FRONTERA: 0/{total} servicios sin veredicto (superficie cerrada)."
        )
    if bounds is not None:
        lines.append(
            "DIRECTIVA DEL OPERADOR (prioridad sobre este ledger): "
            f"{_directive_scope(bounds) or 'alcance fijado en el objetivo'}"
            f"{'; nada de pivoteo' if bounds.no_pivot else ''}. Una rama que el "
            "objetivo nombra no se abandona ni se cierra para desbloquear el "
            "ledger: si el paso falla, el arreglo está en el argumento. Las ramas "
            "que el objetivo no nombra no autorizan un pivote."
        )
    # The *rule* travels with the data on purpose: it costs tokens only on the
    # turns that actually have a surface, and this is when the model can pick a
    # dead branch. Keeping it out of the static prompt leaves the per-turn
    # budget intact (measured: the refresh turn already sits at the 8 000-token
    # contract of ``test_prompt_optimization``).
    lines.append(
        "REGLA DE COBERTURA: trabaja UNA rama a la vez y no más de 3 turnos "
        "seguidos sobre la misma sin un hecho nuevo; si el vector está parcheado "
        "o no existe, ciérralo con nexus.knowledge.record_fact fact_type=\"barrier\" "
        "(key \"<host>:<familia>\", p. ej. \"<host>:rpc\", cierra/aplaza la familia "
        "entera con una sola razón; key "
        "\"<host>:<puerto><ruta>\" o una razón que nombre la ruta cierra solo ese "
        "camino; value con la razón) y pasa al siguiente camino. Un servicio con "
        "caminos pendientes no está cerrado: no repitas el que ya tiene veredicto, "
        "y no repitas trabajo sobre un descartado."
    )
    return "\n".join(lines)


def focus_entry(
    coverage: Coverage | None, arguments: Mapping[str, Any] | None
) -> SurfaceEntry | None:
    """The ledger entry the proposed tool call is aimed at (or ``None``).

    Reads only the arguments of the action about to run: a ``target`` holding
    ``host:port``, a URL with an explicit port, or separate ``host``/``port``
    keys. It never guesses from the tool name.
    """
    if coverage is None or not coverage.entries or not arguments:
        return None
    blob = " ".join(str(value) for value in _flatten(arguments)).lower()
    if not blob:
        return None
    for item in coverage.entries:
        if item.host.lower() not in blob:
            continue
        if re.search(rf"(?<![\d.]){item.port}(?![\d.])", blob):
            return item
        # A bare ``http://host/`` is a call to the host's web service, whose
        # port the URL omits; no other service can answer that scheme.
        if _scheme_touches(blob, item.host.lower(), item.port):
            return item
    return None


def _flatten(value: Any) -> Iterable[str]:
    """Yield every scalar of a nested argument structure (bounded)."""
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _flatten(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _flatten(item)
    elif isinstance(value, (str, int, float)):
        yield str(value)


def _directive_hint(coverage: Coverage, directive: Directive) -> str:
    """The correction when the operator already fixed the branch to work.

    Same wording contract as :func:`pivot_hint` -a concrete order, not "you are
    stuck"- but inverted: the branch is *not* to be abandoned, because the human
    named it. Measured in V15: the pivot ordered RDP while the objective said
    "NO hagas pivoteo ... sube el tema a POST /admin/app_themes.aspx".
    """
    scope = _directive_scope(directive) or "el alcance fijado en el objetivo"
    quote = (
        f" Instrucción literal del operador: «{directive.text}»."
        if directive.text
        else ""
    )
    named = _directive_open(coverage, directive)
    if named is not None:
        return (
            "DIRECTIVA DEL OPERADOR (manda sobre este ledger): el objetivo "
            f"nombra {scope}. Esa rama NO se cierra ni se abandona por una racha "
            "sin hechos nuevos: corrige el argumento del paso que falla (ruta, "
            "campo, credencial, sesión) y reintenta "
            f"{named.label} antes de tocar otra rama. Si el paso falla, el arreglo "
            f"está en el argumento, no en cambiar de servicio.{quote}"
        )
    return (
        "DIRECTIVA DEL OPERADOR (manda sobre este ledger): el objetivo limita el "
        f"trabajo a {scope}. No cambies de servicio ni registres un barrier para "
        "desbloquear el ledger: documenta el punto exacto que falló y pide "
        f"aclaración al operador con request_clarification.{quote}"
    )


def pivot_hint(
    coverage: Coverage | None,
    *,
    no_progress: int = 0,
    threshold: int = DEFAULT_PIVOT_TURNS,
    focus: SurfaceEntry | None = None,
    directive: Directive | None = None,
) -> str:
    """The correction injected when the run is stuck on a dead branch.

    Two independent triggers, both deterministic:

    * The proposed action aims at a service already marked ``descartado``: the
      model is about to re-attack a documented dead end. This fires at once,
      with no need to wait for a barren streak.
    * ``no_progress`` reached the threshold and the ledger still has open work:
      the run is burning turns on one branch while another port is unexplored.

    The operator's objective outranks both: when it names a branch (or forbids
    pivoting) the order changes branch only among the branches it allows. An
    objective that names nothing leaves the historical behaviour untouched.

    Returns ``""`` when none holds. The text is an order with the concrete next
    branch and the exact fact to record, because "you are stuck" alone was
    measured to change nothing (run_abe04509…, 10 barren turns).
    """
    if coverage is None or not coverage.entries:
        return ""
    bounds = directive if directive is not None and directive.active else None
    if focus is not None and focus.status == STATUS_CLOSED:
        if bounds is not None:
            return _directive_hint(coverage, bounds)
        following = coverage.first_open()
        where = (
            f"Pasa a: {following.label}." if following else "No quedan ramas abiertas."
        )
        return (
            f"RAMAL CERRADO: {focus.label} ya está documentado como descartado "
            f"({focus.verdict or 'sin vector'}). No vuelvas a atacarlo ni a "
            f"escanearlo. {where} Si aparece un vector nuevo, regístralo como "
            "hecho antes de retomarlo."
        )
    if int(no_progress or 0) < int(threshold or 0):
        return ""
    # A service kept open by its own paths is not a dead end: ordering a pivot
    # here would abandon the two routes the board already proved.
    if focus is not None and focus.status != STATUS_CLOSED:
        pending = [item for item in focus.vectors if item.status == STATUS_PENDING]
        if pending:
            names = "; ".join(item.label for item in pending[:3])
            return (
                f"CAMINOS PENDIENTES en {focus.label}: {names}. No cierres el "
                "servicio ni cambies de rama: ataca el siguiente camino y, si no "
                "cede, documéntalo con un barrier que nombre esa ruta (no el "
                "servicio) para que los demás sigan abiertos."
            )
    open_items = coverage.open_work
    if not open_items:
        return ""
    if bounds is not None:
        # The directive replaces the branch order entirely: a barren streak is a
        # reason to fix the argument on the branch the human named, not a reason
        # to spend the budget on a service the objective left out of scope.
        return _directive_hint(coverage, bounds)
    names = "; ".join(item.label for item in open_items[:3])
    following = coverage.first_open()
    order = f" Siguiente rama: {following.label}." if following else ""
    return (
        f"FIN DE CALLEJÓN ({int(no_progress)} turnos sin hechos nuevos): no sigas "
        "insistiendo sobre el mismo servicio. Si el vector actual está parcheado, "
        "no expone nada o exige algo que no tienes, documéntalo con "
        "nexus.knowledge.record_fact (fact_type=\"barrier\", key=\"<host>:<puerto>\", "
        "value con la razón) y cambia de rama."
        f"{order} Ramas abiertas: {names}."
    )


__all__ = [
    "Coverage",
    "DEFAULT_PIVOT_TURNS",
    "Directive",
    "MAX_LEDGER_ENTRIES",
    "MAX_VECTOR_LINES",
    "OWNERSHIP_TYPES",
    "STATUS_CLOSED",
    "STATUS_OWNED",
    "STATUS_PENDING",
    "STATUS_PROBED",
    "SurfaceEntry",
    "VectorEntry",
    "build_coverage",
    "focus_entry",
    "load_coverage",
    "parse_directive",
    "pivot_hint",
    "render_coverage",
]
