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

#: Ports a bare ``http://host/`` (or ``https://host/``) can reach: the scheme's
#: own default. A URL that omits the port is not evidence about 8080/8443 -a
#: measured false positive: one endpoint on :80 marked an unrelated Squid on
#: :8080 as ``sondeado``-, so the scheme rule is limited to the defaults.
_SCHEME_PORTS = frozenset({80, 443})

#: Ledger lines rendered per prompt. The rest is summarized: a /24 scan can put
#: hundreds of services on the board and the prompt is paid on every turn.
MAX_LEDGER_ENTRIES = 24

#: Completed turns without a new verified fact before the pivot is injected.
#: Matches the loop's own stuck threshold, so both signals agree.
DEFAULT_PIVOT_TURNS = 5

#: ``host:port[:proto]`` as written by ``nmap`` (``10.10.10.5:21:tcp``) or by an
#: agent-recorded barrier (``10.10.10.5:21``). Non-greedy host so an IPv4
#: address with dots is one group; an IPv6 literal is out of scope here (the
#: recon parser rewrites services to their IPv4/hostname anyway).
_SERVICE_KEY = re.compile(r"^(?P<host>.+?):(?P<port>\d{1,5})(?::(?P<proto>[A-Za-z]+))?$")


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
        """One ledger line with its verdict."""
        if self.status == STATUS_CLOSED:
            reason = self.verdict or "sin vector demostrado"
            return f"- {self.label} → descartado: {reason}"
        if self.status == STATUS_OWNED:
            return f"- {self.label} → comprometido"
        if self.status == STATUS_PROBED:
            suffix = f" ({self.evidence} hecho{'s' if self.evidence != 1 else ''})"
            return f"- {self.label} → sondeado{suffix}"
        return f"- {self.label} → pendiente"

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

    def first_open(self) -> SurfaceEntry | None:
        """The next branch to work: pending first, then probed, in port order."""
        open_items = self.open_work
        for item in open_items:
            if item.status == STATUS_PENDING:
                return item
        return open_items[0] if open_items else None

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
    return SurfaceEntry(
        host=str(match.group("host")),
        port=port,
        protocol=protocol,
        service=str(value.get("service") or "").strip().lower(),
        product=str(value.get("product") or "").strip(),
        version=str(value.get("version") or "").strip(),
        key=key,
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


def _barrier_reason(fact: Mapping[str, Any]) -> str:
    """Human-readable reason of a barrier fact (always something usable)."""
    raw_value = fact.get("value")
    value: Mapping[str, Any] = raw_value if isinstance(raw_value, Mapping) else {}
    for name in ("reason", "detail", "why", "cve", "status"):
        text = str(value.get(name) or "").strip()
        if text:
            return " ".join(text.split())[:180]
    return "documentado sin vector por el agente"


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
                barriers.append(fact)
            elif not _mentions(blob, entry):
                continue
            elif fact_type in OWNERSHIP_TYPES and fact.get("verified") is True:
                owned = True
            elif fact_type == "vulnerability":
                vectors.append(fact)
            evidence += 1

        status = STATUS_PENDING
        verdict = ""
        if owned:
            # Access, a validated credential, a session, a privilege or loot
            # proves the service was reached: a later barrier cannot hide it.
            status = STATUS_OWNED
        elif barriers:
            # The *newest* verdict wins. A barrier is the agent's decision to
            # stop on this route, but it is not infallible: a vulnerability
            # found afterwards reopens the branch. Measured in
            # ``run_3d90f7f388144557ae97466b0a19ce55`` (2026-10-20), where the
            # agent proved CVE-2017-8917 error-based on :80 while the ledger
            # kept ordering it to abandon the only working vector because
            # ``pivot_hint`` promises "si aparece un vector nuevo, regístralo
            # como hecho antes de retomarlo" and nothing honoured it.
            chosen = _newest(barriers)
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
                verdict = _barrier_reason(chosen if chosen is not None else barriers[0])
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
def render_coverage(coverage: Coverage | None) -> str:
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
    open_count = len(coverage.open_work)
    total = len(coverage.entries)
    if open_count:
        following = coverage.first_open()
        target = f" Siguiente rama: {following.label}." if following else ""
        lines.append(
            f"FRONTERA: {open_count}/{total} servicios sin veredicto.{target}"
        )
    else:
        lines.append(
            f"FRONTERA: 0/{total} servicios sin veredicto (superficie cerrada)."
        )
    # The *rule* travels with the data on purpose: it costs tokens only on the
    # turns that actually have a surface, and this is when the model can pick a
    # dead branch. Keeping it out of the static prompt leaves the per-turn
    # budget intact (measured: the refresh turn already sits at the 8 000-token
    # contract of ``test_prompt_optimization``).
    lines.append(
        "REGLA DE COBERTURA: trabaja UNA rama a la vez y no más de 3 turnos "
        "seguidos sobre la misma sin un hecho nuevo; si el vector está parcheado "
        "o no existe, ciérrala con nexus.knowledge.record_fact fact_type=\"barrier\" "
        "(key \"<host>:<puerto>\", value con la razón) y pasa a la siguiente. Un "
        "servicio sin veredicto es una rama pendiente, no un callejón: no repitas "
        "trabajo sobre un descartado."
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


def pivot_hint(
    coverage: Coverage | None,
    *,
    no_progress: int = 0,
    threshold: int = DEFAULT_PIVOT_TURNS,
    focus: SurfaceEntry | None = None,
) -> str:
    """The correction injected when the run is stuck on a dead branch.

    Two independent triggers, both deterministic:

    * The proposed action aims at a service already marked ``descartado``: the
      model is about to re-attack a documented dead end. This fires at once,
      with no need to wait for a barren streak.
    * ``no_progress`` reached the threshold and the ledger still has open work:
      the run is burning turns on one branch while another port is unexplored.

    Returns ``""`` when neither holds. The text is an order with the concrete
    next branch and the exact fact to record, because "you are stuck" alone was
    measured to change nothing (run_abe04509…, 10 barren turns).
    """
    if coverage is None or not coverage.entries:
        return ""
    if focus is not None and focus.status == STATUS_CLOSED:
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
    open_items = coverage.open_work
    if not open_items:
        return ""
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
    "MAX_LEDGER_ENTRIES",
    "OWNERSHIP_TYPES",
    "STATUS_CLOSED",
    "STATUS_OWNED",
    "STATUS_PENDING",
    "STATUS_PROBED",
    "SurfaceEntry",
    "build_coverage",
    "focus_entry",
    "load_coverage",
    "pivot_hint",
    "render_coverage",
]
