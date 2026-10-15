"""Deterministic, blackboard-driven multi-phase engagement planner.

The planner never calls the LLM. Given the blackboard fact counts it decides
which phase of the kill chain the engagement sits in, what the next objective
is, and how far the plan has progressed. The ReAct loop embeds this in every
system prompt so the model plans *inside* a stable frame instead of re-deriving
the methodology each iteration; the CLI/TUI surface the very same plan to the
human operator.

Keeping it deterministic (no model in the loop) makes it auditable and cheap to
unit-test, exactly like the tool parsers.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Mapping

#: Statuses of one phase inside a plan.
STATUS_DONE = "done"
STATUS_CURRENT = "current"
STATUS_PENDING = "pending"

#: Rendering markers, shared by the prompt and the TUI.
MARKERS = {STATUS_DONE: "[x]", STATUS_CURRENT: "[>]", STATUS_PENDING: "[ ]"}


@dataclass(frozen=True)
class Phase:
    """One step of the kill chain.

    ``evidence`` lists the blackboard fact types that mark the phase complete:
    it is done when any of them reaches ``min_count``. ``optional`` phases
    render in the pipeline but never become the *current* phase, so they cannot
    block the endgame (reporting).
    """

    id: str
    label: str
    focus: str
    hint: str
    evidence: tuple[str, ...] = ()
    min_count: int = 1
    optional: bool = False


#: The kill chain, in order. Reporting is never auto-completed: only the model's
#: ``task_complete`` closes it.
PHASES: tuple[Phase, ...] = (
    Phase(
        "recon",
        "Reconocimiento",
        "descubrir hosts, puertos y servicios",
        "Escanea TODOS los puertos TCP (profile full_tcp) y luego versiones/scripts.",
        ("host", "service"),
    ),
    Phase(
        "enumeration",
        "Enumeración",
        "enumerar cada servicio: usuarios, endpoints, pistas",
        "Enumera los servicios hallados y registra usuarios/endpoints/pistas.",
        ("endpoint", "user", "email", "credential", "vulnerability"),
    ),
    Phase(
        "exploitation",
        "Acceso inicial",
        "convertir un hallazgo en acceso (validar credenciales o explotar)",
        "Usa las credenciales o vulnerabilidades registradas para obtener acceso.",
        ("access", "session"),
    ),
    Phase(
        "privilege_escalation",
        "Escalada de privilegios",
        "enumerar sudo/SUID/capabilities y demostrar uid=0",
        "Enumera la escalada local (sudo -l, SUID, capabilities) y propone el vector.",
        ("privilege",),
    ),
    Phase(
        "post_exploitation",
        "Post-explotación",
        "recolectar loot/artefactos y registrar evidencia",
        "Recolecta loot y registra artefactos con su procedencia.",
        ("loot", "artifact"),
    ),
    Phase(
        "lateral_movement",
        "Movimiento lateral",
        "reutilizar el acceso para comprometer más hosts",
        "Reutiliza credenciales/accesos para alcanzar nuevos hosts.",
        ("session", "access"),
        min_count=2,
        optional=True,
    ),
    Phase(
        "reporting",
        "Reporte",
        "consolidar hallazgos verificados y cerrar el engagement",
        "Consolida los hallazgos verificados y genera el reporte del engagement.",
    ),
)

PHASE_IDS: tuple[str, ...] = tuple(phase.id for phase in PHASES)
_BY_ID = {phase.id: phase for phase in PHASES}


@dataclass(frozen=True)
class PhaseStatus:
    """A phase plus its resolved status inside one plan."""

    id: str
    label: str
    status: str
    optional: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "status": self.status,
            "optional": self.optional,
        }


@dataclass(frozen=True)
class Plan:
    """Resolved engagement plan for one iteration."""

    objective: str
    engagement_id: str | None
    facts_total: int
    counts: Mapping[str, int]
    phases: tuple[PhaseStatus, ...]
    current: str
    next_hint: str
    #: Counts of *unverified* facts (agent-recorded leads). They never change
    #: ``current`` or a phase status - only verified evidence does - but they do
    #: steer which capability profile is useful next (see
    #: :func:`nexus_core.agent.subagents.select_for_plan`).
    leads: Mapping[str, int] = field(default_factory=dict)

    # ------------------------------------------------------------- derived
    @property
    def phase(self) -> Phase:
        return _BY_ID[self.current]

    @property
    def done_required(self) -> int:
        return sum(
            1 for item in self.phases if not item.optional and item.status == STATUS_DONE
        )

    @property
    def required_total(self) -> int:
        return sum(1 for item in self.phases if not item.optional)

    @property
    def progress(self) -> tuple[int, int]:
        return self.done_required, self.required_total

    def pipeline(self) -> str:
        """One compact line, e.g. ``recon ✓ ▸ enumeración ▶ ▸ …``."""
        glyphs = {STATUS_DONE: "✓", STATUS_CURRENT: "▶", STATUS_PENDING: "·"}
        parts = [
            f"{item.label}{' (opcional)' if item.optional else ''} {glyphs.get(item.status, '·')}"
            for item in self.phases
        ]
        return " ▸ ".join(parts)

    def render(self) -> str:
        """Multi-line, prompt-ready plan block."""
        done, total = self.progress
        lines = [
            f"PLAN DE ENGAGEMENT (fase actual: {self.phase.label} · {done}/{total} fases)",
        ]
        for item in self.phases:
            marker = MARKERS.get(item.status, "[ ]")
            if item.status == STATUS_CURRENT:
                lines.append(f"  {marker} {item.label} — foco: {_BY_ID[item.id].focus}")
            else:
                suffix = " (opcional)" if item.optional else ""
                lines.append(f"  {marker} {item.label}{suffix}")
        lines.append(f"SIGUIENTE PASO DEL PLAN: {self.next_hint}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        done, total = self.progress
        return {
            "objective": self.objective,
            "engagement_id": self.engagement_id,
            "facts_total": self.facts_total,
            "current": self.current,
            "current_label": self.phase.label,
            "next_hint": self.next_hint,
            "pipeline": self.pipeline(),
            "done": done,
            "total": total,
            "counts": dict(self.counts),
            "phases": [item.to_dict() for item in self.phases],
        }


def normalize_counts(
    *,
    counts: Mapping[str, int] | None = None,
    facts: Iterable[Any] | None = None,
) -> dict[str, int]:
    """Coerce either fact records or a raw count mapping into counts."""
    normalized: dict[str, int] = {}
    if counts:
        for key, value in counts.items():
            try:
                amount = int(value)
            except (TypeError, ValueError):
                continue
            if amount > 0:
                normalized[str(key)] = amount
    from nexus_core.kernel.blackboard import is_verified_fact

    for fact in facts or ():
        if not is_verified_fact(fact):
            continue
        fact_type = None
        if isinstance(fact, Mapping):
            fact_type = fact.get("fact_type") or fact.get("type")
        else:
            fact_type = getattr(fact, "fact_type", None)
        if not fact_type:
            continue
        normalized[str(fact_type)] = normalized.get(str(fact_type), 0) + 1
    return normalized


def count_leads(facts: Iterable[Any] | None = None) -> dict[str, int]:
    """Count the *unverified* facts per type: leads, not evidence.

    A lead must never advance a phase (``test_unverified_fact_does_not_advance_plan``
    pins that): only a deterministic parser's fact does. It only informs the
    profile choice, so an agent-recorded ``user``/``credential`` moves the loop to
    the credential profile instead of leaving it enumerating forever.
    """
    from nexus_core.kernel.blackboard import is_verified_fact

    leads: dict[str, int] = {}
    for fact in facts or ():
        if is_verified_fact(fact):
            continue
        if isinstance(fact, Mapping):
            fact_type = fact.get("fact_type") or fact.get("type")
        else:
            fact_type = getattr(fact, "fact_type", None)
        if not fact_type:
            continue
        leads[str(fact_type)] = leads.get(str(fact_type), 0) + 1
    return leads


def _is_done(phase: Phase, counts: Mapping[str, int]) -> bool:
    if not phase.evidence:
        return False
    return any(counts.get(fact_type, 0) >= phase.min_count for fact_type in phase.evidence)


def active_phase(counts: Mapping[str, int] | None = None) -> str:
    """Return the id of the phase the engagement is currently in."""
    counts = counts or {}
    for phase in PHASES:
        if phase.optional:
            continue
        if not _is_done(phase, counts):
            return phase.id
    return PHASES[-1].id


def build_plan(
    objective: str | None = None,
    *,
    counts: Mapping[str, int] | None = None,
    facts: Iterable[Any] | None = None,
    engagement_id: str | None = None,
    facts_total: int | None = None,
    leads: Mapping[str, int] | None = None,
) -> Plan:
    """Build the plan from blackboard evidence (never raises on bad input)."""
    normalized = normalize_counts(counts=counts, facts=facts)
    lead_counts = normalize_counts(counts=leads) if leads is not None else count_leads(facts)
    current = active_phase(normalized)
    statuses: list[PhaseStatus] = []
    for phase in PHASES:
        if _is_done(phase, normalized):
            status = STATUS_DONE
        elif phase.id == current:
            status = STATUS_CURRENT
        else:
            status = STATUS_PENDING
        statuses.append(PhaseStatus(phase.id, phase.label, status, phase.optional))
    total = facts_total if facts_total is not None else sum(normalized.values())
    return Plan(
        objective=str(objective or ""),
        engagement_id=engagement_id,
        facts_total=int(total),
        counts=normalized,
        phases=tuple(statuses),
        current=current,
        next_hint=_BY_ID[current].hint,
        leads=lead_counts,
    )


#: Fact types that describe what can be reached or tried on the target.
SURFACE_TYPES: tuple[str, ...] = (
    "host",
    "service",
    "web_app",
    "endpoint",
    "vulnerability",
    "user",
    "email",
    "credential",
)

#: Fact types that describe access the engagement already obtained.
ACCESS_TYPES: tuple[str, ...] = ("access", "privilege", "session", "loot", "artifact")

#: Maximum entries listed per surface bucket before the rest is summarized.
SURFACE_PREVIEW = 12


@dataclass(frozen=True)
class AttackSurface:
    """Deterministic map of the verified attack surface of an engagement.

    Built only from *verified* facts, so the tactic the operator sees is the
    same evidence the planner and the gateway trust. Unverified facts are
    counted but never listed: they are leads, not surface.
    """

    hosts: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    web: tuple[str, ...] = ()
    endpoints: tuple[str, ...] = ()
    vulnerabilities: tuple[str, ...] = ()
    identities: tuple[str, ...] = ()
    credentials: int = 0
    access: int = 0
    verified_facts: int = 0
    unverified_facts: int = 0

    @property
    def total(self) -> int:
        return self.verified_facts + self.unverified_facts

    def to_dict(self) -> dict[str, Any]:
        return {
            "hosts": list(self.hosts),
            "services": list(self.services),
            "web": list(self.web),
            "endpoints": list(self.endpoints),
            "vulnerabilities": list(self.vulnerabilities),
            "identities": list(self.identities),
            "credentials": self.credentials,
            "access": self.access,
            "verified_facts": self.verified_facts,
            "unverified_facts": self.unverified_facts,
        }

    @staticmethod
    def _line(label: str, values: tuple[str, ...]) -> str | None:
        if not values:
            return None
        shown = ", ".join(values[:SURFACE_PREVIEW])
        if len(values) > SURFACE_PREVIEW:
            shown += f" (+{len(values) - SURFACE_PREVIEW} más)"
        return f"  {label}: {shown}"

    def render(self) -> str:
        """Multi-line, operator-ready surface map."""
        lines = ["SUPERFICIE DE ATAQUE (hechos verificados)"]
        for label, values in (
            ("hosts", self.hosts),
            ("servicios", self.services),
            ("web", self.web),
            ("endpoints", self.endpoints),
            ("vulnerabilidades", self.vulnerabilities),
            ("identidades", self.identities),
        ):
            line = self._line(label, values)
            if line is not None:
                lines.append(line)
        lines.append(
            f"  credenciales: {self.credentials} · accesos/privilegios: {self.access}"
        )
        if not self.verified_facts:
            lines.append("  (sin hechos verificados todavía)")
        if self.unverified_facts:
            lines.append(
                f"  ({self.unverified_facts} hecho(s) sin verificar, no cuentan como superficie)"
            )
        return "\n".join(lines)


def _unique_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value}))


def attack_surface(facts: Iterable[Any]) -> AttackSurface:
    """Build the verified attack surface from blackboard facts (never raises)."""
    from nexus_core.kernel.blackboard import is_verified_fact

    buckets: dict[str, list[str]] = {fact_type: [] for fact_type in SURFACE_TYPES}
    credentials = 0
    access = 0
    verified = 0
    unverified = 0
    for fact in facts or ():
        if not isinstance(fact, Mapping):
            continue
        if not is_verified_fact(fact):
            unverified += 1
            continue
        verified += 1
        fact_type = str(fact.get("fact_type") or "")
        key = str(fact.get("key") or "")
        if fact_type == "credential":
            credentials += 1
        if fact_type in ACCESS_TYPES:
            access += 1
        if fact_type in buckets and key:
            buckets[fact_type].append(key)
    return AttackSurface(
        hosts=_unique_sorted(buckets["host"]),
        services=_unique_sorted(buckets["service"]),
        web=_unique_sorted(buckets["web_app"]),
        endpoints=_unique_sorted(buckets["endpoint"]),
        vulnerabilities=_unique_sorted(buckets["vulnerability"]),
        identities=_unique_sorted([*buckets["user"], *buckets["email"]]),
        credentials=credentials,
        access=access,
        verified_facts=verified,
        unverified_facts=unverified,
    )


#: Reason recorded when an exhausted enumeration is handed over to initial
#: access (Fase 3 fixes). Measured in run_abe04509c5064c6e8e475f46ba8f8c60: the
#: ``services`` profile spent its whole budget enumerating SMB/AD -SMBv1=true,
#: signing=false, null_auth=denied on the board- with no credential and no
#: access, and never changed profile. This is the *first deterministic step* of
#: V0-12 (the full kill-chain planner stays open): one rule, one case, no LLM.
ENUMERATION_EXHAUSTED_REASON = "enumeration_exhausted_to_exploit"
#: No-progress turns that make enumeration count as exhausted. Stricter than the
#: global stuck signal (5) because this rule also changes the profile.
ENUMERATION_EXHAUSTED_NO_PROGRESS = 3
#: Profiles the rule applies to (the enumeration and credential profiles).
ENUMERATION_EXHAUSTED_SUBAGENTS: frozenset[str] = frozenset({"services", "cred"})
#: Markers that identify an SMB/AD surface inside a ``service`` fact key.
SMB_SERVICE_MARKERS: tuple[str, ...] = (
    "smb",
    "microsoft-ds",
    "netbios",
    ":445",
    "445/tcp",
    ":139",
    "139/tcp",
)


@dataclass(frozen=True)
class EnumerationEscalation:
    """Deterministic proposal: leave ``enumeration`` for initial access."""

    phase: str
    subagent: str
    reason: str


def smb_surface(services: Iterable[str] | None) -> bool:
    """True when any verified ``service`` key looks like SMB/AD (no inference)."""
    for service in services or ():
        text = str(service or "").lower()
        if any(marker in text for marker in SMB_SERVICE_MARKERS):
            return True
    return False


def enumeration_escalation(
    plan: Plan,
    *,
    subagent_id: str | None,
    no_progress: int,
    services: Iterable[str] | None = None,
) -> EnumerationEscalation | None:
    """Rule ``si X entonces Y`` (no inference): an SMB/AD surface plus no
    credential and no access plus the enumeration profile stuck for N turns
    hands the engagement over to ``exploit``/``exploitation``.

    Anything outside that shape returns ``None``: the rest of the kill-chain
    planning (web-only, AD-only, other profiles) is V0-12 and stays open.
    """
    if str(getattr(plan, "current", "")) != "enumeration":
        return None
    if int(no_progress or 0) < ENUMERATION_EXHAUSTED_NO_PROGRESS:
        return None
    if str(subagent_id or "") not in ENUMERATION_EXHAUSTED_SUBAGENTS:
        return None
    counts = normalize_counts(counts=getattr(plan, "counts", None))
    if any(counts.get(kind, 0) > 0 for kind in ("credential", *ACCESS_TYPES)):
        return None
    if counts.get("host", 0) < 1:
        return None
    if not services or not smb_surface(services):
        return None
    return EnumerationEscalation(
        phase="exploitation", subagent="exploit", reason=ENUMERATION_EXHAUSTED_REASON
    )


def hand_over_phase(plan: Plan, *, phase: str) -> Plan:
    """Return *plan* focused on *phase*, closing the phase it leaves (Fase 3c).

    Every *deliberate* hand-off goes through here, so the statuses stay coherent
    with the completion gate: the phase the plan leaves is marked ``done`` (the
    hand-off **is** the deterministic decision that it yielded all it will
    yield), the target phase becomes ``current``, and whatever evidence already
    closed behind it stays ``done``. A hand-off that does not move forward in the
    kill chain changes nothing but the focus -it never invents a close.

    Measured in rerun #3 (commit `8de386b`): ``enumeration`` stayed ``pending``
    while ``exploitation`` was ``current`` and ``progress`` showed ``[1, 6]``, a
    state the gate can never leave, because a plan with a mandatory pending phase
    never reaches ``reporting``.
    """
    previous = str(getattr(plan, "current", "") or "")
    target = str(phase or "")
    if target not in _BY_ID:
        raise ValueError(f"unknown phase {phase!r}")
    counts = normalize_counts(counts=getattr(plan, "counts", None))
    forward = (
        PHASE_IDS.index(target) > PHASE_IDS.index(previous) if previous in _BY_ID else True
    )
    statuses: list[PhaseStatus] = []
    for item in plan.phases:
        if item.id == target:
            status = STATUS_CURRENT
        elif (item.id == previous and forward) or _is_done(_BY_ID[item.id], counts):
            status = STATUS_DONE
        else:
            status = STATUS_PENDING
        statuses.append(PhaseStatus(item.id, item.label, status, item.optional))
    return replace(
        plan,
        phases=tuple(statuses),
        current=target,
        next_hint=_BY_ID[target].hint,
    )


def escalate_enumeration(plan: Plan, escalation: EnumerationEscalation) -> Plan:
    """Return *plan* with *escalation* applied (pure; statuses stay coherent).

    The exhausted phase closes as ``done``: the rule *is* the decision that
    enumeration has yielded all it will yield. Before Fase 3c it stayed
    ``pending`` and left the plan in a state the completion gate cannot close
    (V1-18).
    """
    return hand_over_phase(plan, phase=escalation.phase)


#: Reason recorded when an established session hands the engagement over to
#: post-exploitation (V1-25). Measured in rerun 6: the MSF session was verified
#: and registered while the plan stayed on ``exploitation`` (``progress [2, 6]``)
#: until the ``exploit`` profile ran out of tokens, because nothing connected the
#: session to the profile that can use one.
SESSION_ESTABLISHED_REASON = "session_established_to_post"
#: Profiles whose turn may trigger the hand-over: the one that owns initial
#: access. A session opened by any other profile is not this rule's case.
SESSION_HANDOVER_SUBAGENTS: frozenset[str] = frozenset({"exploit"})
#: Phases the hand-over may leave. ``privilege_escalation`` belongs here because
#: the plan is rebuilt from the blackboard on every turn and ``session`` is itself
#: the evidence that closes ``exploitation`` for the table above: the iteration
#: right after the session lands is *already* on ``privilege_escalation``, so a
#: rule that only accepted ``exploitation`` could never fire on the measured case
#: -and the phase would snap back, every turn, to a profile that cannot use the
#: session. The rule still keys on a provenanced MSF session alone: web, AD or a
#: bare credential never reach it.
SESSION_HANDOVER_PHASES: frozenset[str] = frozenset(
    {"exploitation", "privilege_escalation"}
)


@dataclass(frozen=True)
class SessionHandover:
    """Deterministic proposal: leave initial access for post-exploitation."""

    phase: str
    subagent: str
    reason: str


def established_msf_session(facts: Iterable[Any] | None = None) -> bool:
    """True when the board carries a *verified* MSF session fact (never raises).

    The flag the rule below keys on is computed from the facts themselves, not
    from counts: a session the model recorded by hand is a lead (``source=agent``,
    ``verified=False``), and a lead must never move a phase. Measured in rerun 6:
    the agent tried exactly that and the fact stayed a lead.
    """
    from nexus_core.kernel.blackboard import is_verified_fact
    from nexus_core.kernel.fact_verification import MSF_SESSION_METHOD

    for fact in facts or ():
        if not isinstance(fact, Mapping) or not is_verified_fact(fact):
            continue
        if str(fact.get("fact_type") or "") != "session":
            continue
        if str(fact.get("verification_method") or "") == MSF_SESSION_METHOD:
            return True
    return False


def session_handover(
    plan: Plan,
    *,
    subagent_id: str | None,
    session_established: bool,
) -> SessionHandover | None:
    """Rule ``si X entonces Y`` (no inference): an engagement that holds a session
    the verifier proved has finished initial access, so its next phase is
    post-exploitation -where the ``session.*`` / ``post.*`` tools live- instead of
    more turns of the profile that opened it.

    Anything outside that shape returns ``None``: this is not a general
    "access→post" rule (V1-25 is scoped to the measured MSF case; web, AD and
    credential-derived access keep their own phases).
    """
    if not session_established:
        return None
    if str(getattr(plan, "current", "")) not in SESSION_HANDOVER_PHASES:
        return None
    if str(subagent_id or "") not in SESSION_HANDOVER_SUBAGENTS:
        return None
    return SessionHandover(
        phase="post_exploitation",
        subagent="postexploit",
        reason=SESSION_ESTABLISHED_REASON,
    )


def escalate_session(plan: Plan, handover: SessionHandover) -> Plan:
    """Return *plan* with the session hand-over applied (pure).

    Same contract as :func:`escalate_enumeration`: the phase the plan leaves is
    closed by the hand-off itself, so the completion gate can reach ``reporting``
    instead of waiting for a phase nobody is going to work on again.
    """
    return hand_over_phase(plan, phase=handover.phase)


def plan_from_summary(
    summary: Mapping[str, Any] | None,
    *,
    objective: str | None = None,
    engagement_id: str | None = None,
) -> Plan:
    """Build a plan from a blackboard ``summary()`` payload."""
    summary = summary or {}
    return build_plan(
        objective,
        counts=summary.get("counts") if isinstance(summary, Mapping) else None,
        engagement_id=engagement_id or (summary.get("engagement_id") if isinstance(summary, Mapping) else None),
        facts_total=int(summary.get("total") or 0) if isinstance(summary, Mapping) else 0,
        leads=summary.get("leads") if isinstance(summary, Mapping) else None,
    )


__all__ = [
    "ACCESS_TYPES",
    "ENUMERATION_EXHAUSTED_NO_PROGRESS",
    "ENUMERATION_EXHAUSTED_REASON",
    "ENUMERATION_EXHAUSTED_SUBAGENTS",
    "MARKERS",
    "PHASES",
    "SESSION_ESTABLISHED_REASON",
    "SESSION_HANDOVER_PHASES",
    "SESSION_HANDOVER_SUBAGENTS",
    "SMB_SERVICE_MARKERS",
    "EnumerationEscalation",
    "SessionHandover",
    "enumeration_escalation",
    "escalate_enumeration",
    "escalate_session",
    "established_msf_session",
    "session_handover",
    "smb_surface",
    "PHASE_IDS",
    "STATUS_CURRENT",
    "STATUS_DONE",
    "STATUS_PENDING",
    "SURFACE_PREVIEW",
    "SURFACE_TYPES",
    "AttackSurface",
    "Phase",
    "PhaseStatus",
    "Plan",
    "active_phase",
    "attack_surface",
    "build_plan",
    "count_leads",
    "normalize_counts",
    "plan_from_summary",
]
