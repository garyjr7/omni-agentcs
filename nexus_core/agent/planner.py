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

import re
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

    ``requires`` is the *sustainer* of a phase whose own evidence is only a
    signal: when it is non-empty the phase is done only if one of its
    ``evidence`` types fired **and** one of ``requires`` is on the board. It is
    what keeps ``post_exploitation`` from closing on a bare ``loot`` (V1-39): a
    captured file -the *user* flag included- says there is something to collect,
    not that the engagement reached the tail of the chain. Escalated privilege or
    an interactive session is what says that.

    ``min_turns`` is the other half of the same idea and only applies when the
    caller supplies the loop's turn history (see :func:`build_plan`): a phase
    closes by its own evidence only once it has been *current* for that many
    completed turns of the run. It exists for the phase whose work is to
    **consume** what the previous one produced: measured in rerun 13 (V1-46),
    ``privilege`` landed in the same turn that closed ``privilege_escalation``
    while a ``loot`` from earlier already satisfied ``post_exploitation``, so the
    phase closed one turn after it opened, the profile that reads ``root.txt``
    never ran, and the run had no turn left to spend the privilege it had just
    won.

    The rule is about a phase that *opens during the run*, which is the measured
    trigger ("it may not close in the same turn the previous phase closed"). A
    board that arrives already complete -a resumed run, a second objective of the
    same work session- is not held: its opening turn, if it ever had one, belongs
    to an earlier run, and the history of *this* one is empty.
    """

    id: str
    label: str
    focus: str
    hint: str
    evidence: tuple[str, ...] = ()
    min_count: int = 1
    optional: bool = False
    requires: tuple[str, ...] = ()
    min_turns: int = 0


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
        # V1-39: loot/artifact is the signal, the escalation is the closure.
        # Measured in rerun 11 (`run_30bfde08…`): `cat /home/lin/Desktop/user.txt`
        # produced a verified `loot` fact, that alone closed this phase, and the
        # chain jumped past the escalation it had not performed.
        requires=("privilege", "session"),
        # V1-46: this is the phase that *consumes* the privilege, so it may not
        # close in the same turn it opened. Measured in rerun 13
        # (`run_c1b80861…`): iteration 12 derived `privilege {uid:0}` while the
        # `loot` from iteration 9 was already on the board, so the phase closed
        # instantly, the plan jumped to `reporting` and the `postexploit` profile
        # -the only one with ssh_exec and the ability to read root.txt as root-
        # never got a turn: iteration 13 was denied (reporter is read_only) and the
        # run died with the privilege unspent.
        min_turns=1,
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
    #: True when the objective is already completed on the board (verified top
    #: privilege plus verified loot). It never changes ``current`` by itself: the
    #: phases are closed by their own evidence. It adds ``objective_hint`` to the
    #: prompt and lets the loop exempt the active profile's token ceiling so the
    #: model can close with ``task_complete`` (V1-35, V1-38).
    objective_complete: bool = False
    objective_hint: str = ""
    #: Completed turns the loop has already spent with each phase as ``current``
    #: (``{phase_id: turns}``), carried by the plan so every transformation keeps
    #: it. ``None`` means *untracked*: a plan built outside the loop (CLI, report,
    #: tests) has no turn history, so ``min_turns`` is not enforced there and the
    #: statuses are the ones the evidence alone produces (V1-46).
    phase_turns: Mapping[str, int] | None = None

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
        if self.objective_complete and self.objective_hint:
            lines.append(f"OBJETIVO CUMPLIDO: {self.objective_hint}")
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
            "objective_complete": self.objective_complete,
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


def _turns_in(phase_turns: Mapping[str, int] | None, phase_id: str) -> int:
    """Completed turns a phase has been *current* for (0 when untracked/unknown)."""
    if not phase_turns:
        return 0
    try:
        return max(0, int(phase_turns.get(phase_id, 0)))
    except (TypeError, ValueError):
        return 0


def _is_done(
    phase: Phase,
    counts: Mapping[str, int],
    phase_turns: Mapping[str, int] | None = None,
) -> bool:
    """Whether *phase* is closed by the evidence on the board.

    Its own evidence type must reach ``min_count``; when the phase declares a
    ``requires`` sustainer, one of those types must be on the board too (V1-39);
    and when it declares ``min_turns`` **and** the caller tracks the loop's turns,
    it must already have been current for that many completed turns of the run
    (V1-46). The turn rule needs a run to have run: an empty/absent history means
    either a caller that does not track turns at all (CLI, report, tests) or a
    loop that has not finished its first turn yet -and in the second case the phase
    it would hold was already closed by evidence before that turn, so there is no
    "same turn it opened" to protect. From the second turn on, the counter decides.
    """
    if not phase.evidence:
        return False
    if not any(counts.get(fact_type, 0) >= phase.min_count for fact_type in phase.evidence):
        return False
    if phase.requires and not any(counts.get(fact_type, 0) >= 1 for fact_type in phase.requires):
        return False
    if phase.min_turns and phase_turns:
        return _turns_in(phase_turns, phase.id) >= phase.min_turns
    return True


def _last_closed_index(
    counts: Mapping[str, int],
    phase_turns: Mapping[str, int] | None = None,
) -> int:
    """Index of the furthest phase the evidence has closed (``-1`` when none)."""
    last = -1
    for index, phase in enumerate(PHASES):
        if _is_done(phase, counts, phase_turns):
            last = index
    return last


def active_phase(
    counts: Mapping[str, int] | None = None,
    phase_turns: Mapping[str, int] | None = None,
) -> str:
    """Return the id of the phase the engagement is currently in.

    A phase cannot be *current* while a later one is already closed by evidence:
    the chain advanced past it, so it is treated as behind the engagement (a
    plan that reports an earlier phase as current while a later one is ``done``
    has a mandatory-phase inversion the completion gate can never close).
    Measured in rerun 10 (``run_179cef8b7b424b339caba3d2093eed9d``): ``access``
    was verified against SSH while the board carried no
    ``endpoint``/``credential``/``user`` fact -the flag closes ``exploitation``
    but is not enumeration evidence-, so ``enumeration`` came back as the current
    phase with ``exploitation`` already ``done`` and the profile selector sent
    the run back to enumerating with access in hand.

    A phase held open by ``min_turns`` (V1-46) is *not* closed, so it is returned
    here as the current one: that is precisely the turn it demanded.
    """
    counts = counts or {}
    closed = _last_closed_index(counts, phase_turns)
    for index, phase in enumerate(PHASES):
        if phase.optional or index <= closed:
            continue
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
    phase_turns: Mapping[str, int] | None = None,
) -> Plan:
    """Build the plan from blackboard evidence (never raises on bad input).

    ``phase_turns`` is the ReAct loop's own history (``{phase_id: completed
    turns}``); passing it is what makes ``min_turns`` effective (V1-46). Callers
    that do not track turns -the CLI, a report, a test- leave it out and get the
    plan the evidence alone describes.
    """
    normalized = normalize_counts(counts=counts, facts=facts)
    lead_counts = normalize_counts(counts=leads) if leads is not None else count_leads(facts)
    current = active_phase(normalized, phase_turns)
    statuses: list[PhaseStatus] = []
    for phase in PHASES:
        if _is_done(phase, normalized, phase_turns):
            # Closed by its own evidence, and only by its own evidence: a status
            # of ``done`` is a claim about what the engagement proved, so it can
            # never be derived from the *position* of another phase (V1-40).
            # Measured in rerun 11 (`run_30bfde08…`): the ``loot`` fact advanced
            # ``current`` to ``reporting`` and this loop marked
            # ``privilege_escalation`` done with no ``privilege`` fact on the
            # board, so the plan claimed a root the run never got. A deliberate
            # hand-off still closes the phase it leaves: that is
            # :func:`hand_over_phase`, where the rule itself is the decision.
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
        phase_turns=dict(phase_turns) if phase_turns is not None else None,
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


#: Endpoints the engagement has *mapped* before enumeration is closed by
#: decision instead of by waiting for the model. Measured in the Simple CTF run
#: of 2026-10-18 02:35 UTC (``run_c034eeeb…``): gobuster put 17 endpoints on the
#: board, the model kept analysing irrelevant routes and the run spent >150k
#: tokens before it reached ``/simple/``. Verified endpoints already close the
#: phase at one (``Phase.evidence`` below), so this rule is the deterministic
#: *ceiling* for a plan that still reports ``enumeration`` -the case where the
#: endpoints exist as agent-recorded leads (a manual gobuster through
#: ``shell.exec``) or the phase is pinned by an earlier hand-over- and the one
#: that keeps the close explicit and auditable instead of model-dependent.
ENUMERATION_ENDPOINT_CEILING = 5
#: Reason recorded when the endpoint ceiling forces the hand-over.
ENUMERATION_ENDPOINT_REASON = "endpoint_ceiling_to_exploit"

#: Smart-budget rule (Simple CTF 2026-10-18 02:35 UTC). From this turn on, a run
#: that already mapped a wide surface but still has no access is told to stop
#: enumerating and pick one endpoint. ``> 10`` is the product contract.
SMART_BUDGET_MIN_ITERATION = 10
#: Services on the board before the hint is worth spending tokens on.
SMART_BUDGET_MIN_SERVICES = 3
#: Endpoints on the board (verified or a lead) before the hint fires.
SMART_BUDGET_MIN_ENDPOINTS = 1
#: The exact correction injected into the system prompt. It names the waste, the
#: decision and the next action, so it is an order and not another status line.
SMART_BUDGET_PROMPT = (
    "PRESUPUESTO DE ENUMERACIÓN: llevas {iteration} turnos y el tablero ya "
    "tiene {services} servicios y {endpoints} endpoints. Estás gastando "
    "demasiado presupuesto en enumeración. Elige UN endpoint prometedor y pasa "
    "a explotación; no enumeres más rutas."
)

#: Turns spent pushing *build/pack work* through a one-command-per-request
#: channel before the loop names the exit. Measured in Vulnversity (2026-10-19):
#: the agent already had a working ``shell.phtml`` RCE and burned **35 turns**
#: compiling ``pwnkit`` locally and shipping it in base64 chunks through
#: ``curl`` -no TTY, no stdin, no state- instead of opening a reverse shell.
WEBSHELL_STALL_TURNS = 10
#: Tools that execute a command on the target through a shell channel. The
#: webshell itself is reached with ``curl`` inside ``nexus.shell.exec``; both
#: share this tool id, so the command text is what classifies the turn.
WEBSHELL_SHELL_TOOLS: frozenset[str] = frozenset({"nexus.shell.exec"})
#: Command markers of work a webshell cannot carry well: compiling a binary or
#: packing/decoding one to move it. Plain ``curl`` recon is **not** here: a hint
#: that says "webshell" must be about a build/transfer loop.
WEBSHELL_BUILD_MARKERS: tuple[str, ...] = (
    "gcc",
    "g++",
    "clang",
    "musl-gcc",
    "cc -",
    "make ",
    "base64 -d",
    "base64 -w0",
    "base64 -w 0",
    "tar ",
    "chmod +x",
)
#: The exact correction injected into the system prompt. It names the stall, the
#: two governed ways out and the payloads, so it is an order and not a status.
WEBSHELL_STALL_PROMPT = (
    "Estás atascado en un webshell: llevas {turns} turnos compilando o moviendo "
    "archivos pesados por `shell.exec`/`curl` sin avanzar. Usa "
    "`nexus.session.pty` o `nexus.post.listener` para estabilizar una shell "
    "interactiva y ejecuta una reverse shell (bash, nc, python). No compiles "
    "nada a través del webshell."
)

#: Files whose body is an *index of routes nobody linked*: reading one is not the
#: same as following it. Measured in ``/tmp/bruteit-run-v2.ndjson`` (Brute It,
#: 2026-10-20): the model did GET ``/robots.txt`` at iteration 22 and, on the
#: next turn, closed the branch with a ``barrier`` -the paths it listed were
#: never requested- so the run ended in ``request_clarification`` with the
#: cheapest route of the room still unvisited.
ROBOTS_INDEX_FILES: tuple[str, ...] = ("robots.txt", "sitemap.xml")
#: Routes named in one hint. The line is an order, not a fuzzing run: past this
#: many the prompt starts replacing the tool.
ROBOTS_HINT_MAX_PATHS = 10
#: ``Disallow: /admin`` / ``Allow: /pub`` rules (an empty value means "no rule").
#: Matched per *stripped* line and deliberately without a trailing anchor: a
#: real ``robots.txt`` (TryHackMe rooms, 2026-10-20) writes ``Disallow:/admin``
#: without the space, indents the rule, ends lines in ``\r\n`` and appends an
#: inline ``# comment``. The old ``(\S+)\s*$`` shape rejected all of those.
ROBOTS_RULE_RE = re.compile(r"^(?:Disallow|Allow)\s*:\s*(\S+)", re.IGNORECASE)
#: ``<loc>https://host/path</loc>`` entries of a sitemap.
ROBOTS_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
#: The order itself: name the file, name the routes, and require the two
#: follow-ups the web checklist already asks for (download+read, record).
ROBOTS_HINT_PROMPT = (
    "ÍNDICE SIN SEGUIR: {source} nombra {count} ruta(s) que todavía no has "
    "visitado: {paths}. Haz un GET a CADA una ahora con `nexus.web.request` "
    "ANTES de cerrar la rama o cambiar de servicio; si alguna es un backup, una "
    "clave o un fichero de configuración, descárgala con `save_path` y léela "
    "con `nexus.workspace.read`. Registra lo que encuentres con "
    "`nexus.knowledge.record_fact`."
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
    # V1-46: the turn history rides with the plan, so a transformation cannot
    # silently drop the hold a phase is under.
    phase_turns = getattr(plan, "phase_turns", None)
    forward = (
        PHASE_IDS.index(target) > PHASE_IDS.index(previous) if previous in _BY_ID else True
    )
    statuses: list[PhaseStatus] = []
    for item in plan.phases:
        if item.id == target:
            status = STATUS_CURRENT
        elif (item.id == previous and forward) or _is_done(_BY_ID[item.id], counts, phase_turns):
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


def endpoint_ceiling(
    plan: Plan, *, min_endpoints: int = ENUMERATION_ENDPOINT_CEILING
) -> Plan | None:
    """Close ``enumeration`` deterministically once enough endpoints are mapped.

    The request is the decision: a plan that is still on ``enumeration`` with
    ``min_endpoints`` endpoints already mapped has enough surface to attack, and
    more gobuster/ffuf runs only spend tokens. The hand-over closes the phase it
    leaves (``hand_over_phase``) so the completion gate stays coherent and the
    change is audited with :data:`ENUMERATION_ENDPOINT_REASON`.

    Endpoints count whether the verifier proved them or the agent recorded them
    as leads: this is an explicit hand-off, not a claim about evidence (which is
    why the status changes only through ``hand_over_phase``). Verified endpoints
    already close the phase by themselves at one, so in a normal run this rule
    is a ceiling/guard rather than the usual path.
    """
    if str(getattr(plan, "current", "") or "") != "enumeration":
        return None
    counts = normalize_counts(counts=getattr(plan, "counts", None))
    leads = normalize_counts(counts=getattr(plan, "leads", None))
    mapped = max(counts.get("endpoint", 0), leads.get("endpoint", 0))
    if mapped < int(min_endpoints):
        return None
    return hand_over_phase(plan, phase="exploitation")


def enumeration_budget_hint(
    plan: Plan,
    *,
    iteration: int,
    min_iteration: int = SMART_BUDGET_MIN_ITERATION,
) -> str:
    """The smart-budget correction for a run that keeps enumerating (or "").

    Fires when the loop has already spent more than ``min_iteration`` turns, the
    board carries a wide-but-unexploited surface (:data:`SMART_BUDGET_MIN_SERVICES`
    services and at least :data:`SMART_BUDGET_MIN_ENDPOINTS` endpoints) and there
    is still **no access, session, privilege, loot or credential** to act on.

    The phase test accepts ``exploitation`` as well as ``enumeration`` on
    purpose: in the measured run the plan had already advanced to exploitation
    at iteration 5 (verified endpoints close enumeration at one) while the model
    went on enumerating routes. Gating on the literal label would have made the
    rule unreachable in exactly the run it was written for; the real signal is
    "pre-access and still mapping".
    """
    if int(iteration or 0) <= int(min_iteration):
        return ""
    if str(getattr(plan, "current", "") or "") not in {"enumeration", "exploitation"}:
        return ""
    counts = normalize_counts(counts=getattr(plan, "counts", None))
    leads = normalize_counts(counts=getattr(plan, "leads", None))
    endpoints = max(counts.get("endpoint", 0), leads.get("endpoint", 0))
    if counts.get("service", 0) < SMART_BUDGET_MIN_SERVICES:
        return ""
    if endpoints < SMART_BUDGET_MIN_ENDPOINTS:
        return ""
    # Anything the engagement can already *use* ends the enumeration problem:
    # the next action is validating that credential / using that access.
    if any(counts.get(kind, 0) for kind in (*ACCESS_TYPES, "credential")):
        return ""
    return SMART_BUDGET_PROMPT.format(
        iteration=int(iteration), services=counts.get("service", 0), endpoints=endpoints
    )


def _webshell_build_turn(action: Any) -> bool:
    """Whether one action is build/pack work pushed through a shell channel."""
    if not isinstance(action, Mapping):
        return False
    if str(action.get("tool_id") or "") not in WEBSHELL_SHELL_TOOLS:
        return False
    arguments = action.get("arguments")
    if isinstance(arguments, Mapping):
        command = str(arguments.get("command") or arguments.get("cmd") or "")
    else:
        command = str(arguments or "")
    text = command.casefold()
    return any(marker in text for marker in WEBSHELL_BUILD_MARKERS)


def webshell_stall_hint(
    actions: Iterable[Any] | None = None,
    *,
    no_progress: int,
    threshold: int = WEBSHELL_STALL_TURNS,
) -> str:
    """The correction for a run stuck building through a webshell (or "").

    Fires only when both halves of the measured stall hold: ``no_progress``
    consecutive turns without a new verified fact (the loop already tracks the
    counter) **and** at least ``threshold`` recent turns of compile/pack work
    sent through a shell channel. The latest action must still be one of them,
    so a run that already pivoted is not told to pivot.

    The hint never stops the run, changes the plan or authorizes a tool: it is
    the cheapest correction before the budget decides, and the deterministic
    rule lives here so it is unit-testable without an LLM.
    """
    limit = int(threshold or 0)
    if limit <= 0 or int(no_progress or 0) < limit:
        return ""
    history = [action for action in actions or () if isinstance(action, Mapping)]
    recent = history[-limit * 2:]
    heavy = [action for action in recent if _webshell_build_turn(action)]
    if len(heavy) < limit:
        return ""
    # The stall interleaves builds with cheap inspection (``cat wc -c``, ``ls``).
    # Requiring the very last action to be a build missed the measured run: it
    # ended on ``cat /tmp/pwnkit/pwnkit.c`` after 35 barren turns, so the hint
    # never fired. One inspection turn is part of the loop; two clean turns in a
    # row mean the run already pivoted and the hint would be stale.
    if not recent or not any(_webshell_build_turn(action) for action in recent[-2:]):
        return ""
    return WEBSHELL_STALL_PROMPT.format(turns=len(heavy))


def _action_url(action: Mapping[str, Any]) -> str:
    """The ``url`` an action aimed at ("" for any other tool)."""
    arguments = action.get("arguments")
    if isinstance(arguments, Mapping):
        return str(arguments.get("url") or "").strip()
    return ""


def _url_path(url: str) -> str:
    """Path of an absolute ``http(s)`` URL ("" when it is not one)."""
    text = str(url or "").strip()
    if "://" not in text:
        return ""
    rest = text.split("://", 1)[1]
    slash = rest.find("/")
    return rest[slash:] if slash >= 0 else "/"


def _path_key(path: str) -> str:
    """Comparison key of a route: ``/admin/`` and ``/admin`` are the same one."""
    key = str(path or "").split("?", 1)[0].split("#", 1)[0].rstrip("/")
    return (key or "/").casefold()


def _action_body_preview(action: Mapping[str, Any]) -> str:
    """Body preview the tool returned for this action ("" when there is none)."""
    result = action.get("tool_result")
    if not isinstance(result, Mapping):
        return ""
    output = result.get("output")
    if not isinstance(output, Mapping):
        return ""
    preview = output.get("body_preview")
    return preview if isinstance(preview, str) else ""


def _index_routes(body: str, name: str, base: str) -> list[str]:
    """Routes an index file names, as URLs (empty list when it names none)."""
    routes: list[str] = []
    if name == "sitemap.xml":
        for match in ROBOTS_LOC_RE.finditer(body or ""):
            candidate = match.group(1).strip()
            if candidate and _path_key(_url_path(candidate)) != "/":
                routes.append(candidate)
        return routes
    for raw_line in (body or "").splitlines():
        # ``strip`` already eats the ``\r`` of a CRLF file, the indentation of a
        # nested rule and the surrounding blanks; a full-line comment is not a
        # rule at all.
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Inline comment (``Disallow: /admin # legacy``): the route ends at the
        # first ``#`` that follows whitespace, so a path is never truncated.
        comment = line.find(" #")
        if comment > 0:
            line = line[:comment].rstrip()
        rule = ROBOTS_RULE_RE.match(line)
        if not rule:
            continue
        route = rule.group(1)
        # Wildcards and regex suffixes are a fuzzing pattern, not a route.
        if not route.startswith("/") or any(char in route for char in "*$"):
            continue
        routes.append(f"{base}{route}" if base else route)
    return routes


LOGIN_PROBE_PROMPT = (
    'FORMULARIO DE LOGIN SIN SONDEAR: {url} sirve un formulario con campo de '
    'contraseña y el run todavía no ha probado nada sobre él. Antes de '
    'cualquier wordlist, haz estas TRES peticiones, una por llamada, con '
    'nexus.web.request(url="{url}", method="POST", data=...):\n'
    '  1. username=nosuchuser&password=x — ¿el error distingue al usuario?\n'
    '  2. username=admin\'-- -&password=x — bypass por comentario SQL\n'
    '  3. username[$ne]=x&password[$ne]=x — operador NoSQL\n'
    'La prueba de éxito es un 302 a un panel con Set-Cookie: guarda ese '
    'set_cookie y mándalo como cabecera Cookie en cada petición siguiente. '
    'Un 200 con el formulario otra vez es un fallo, no un login. Solo si las '
    'tres fallan pasa a nexus.cred.bruteforce; si una devuelve error del '
    'servidor o traza, escálala a nexus.web.sqlmap con el data exacto.'
)

#: Respuestas que delatan un campo de contraseña en el HTML.
_PASSWORD_INPUT_RE = re.compile(r"type\s*=\s*[\"']?password", re.IGNORECASE)
#: Datos de un POST que ya es una sonda de inyección (no una credencial).
_INJECTION_PROBE_RE = re.compile(r"['\"]|\[\$ne\]|--", re.IGNORECASE)


def login_probe_hint(actions: Iterable[Any] | None = None) -> str:
    """Order the three login probes on a form the run read but never tested.

    Fires while the history holds a response whose ``body_preview`` has a
    password input and no POST has yet carried an injection probe. DeadDrop
    (2026-10-22): the login accepted ``admin'-- -`` with any password and the
    runs P1/P3 spent five and thirty minutes on directory wordlists before
    touching it, because enumerating first is the documented order and nothing
    said the form was still untested.

    A POST with a plain credential (``admin/admin``) does **not** silence the
    hint: that is the guessing the rule exists to replace. Only a probe with a
    quote, a comment marker or a NoSQL operator counts. The rule never stops the
    run, never changes the plan and never authorizes a tool.
    """
    history = [action for action in actions or () if isinstance(action, Mapping)]
    if not history:
        return ""
    form_url = ""
    probed = False
    for action in history:
        arguments = action.get("arguments")
        arguments = arguments if isinstance(arguments, Mapping) else {}
        body = _action_body_preview(action)
        if (
            not form_url
            and body
            and "<form" in body.casefold()
            and _PASSWORD_INPUT_RE.search(body)
        ):
            form_url = _action_url(action)
        if str(arguments.get("method") or "").upper() == "POST":
            data = str(arguments.get("data") or "")
            if data and _INJECTION_PROBE_RE.search(data):
                probed = True
    if not form_url or probed:
        return ""
    return LOGIN_PROBE_PROMPT.format(url=form_url)


def robots_paths_hint(actions: Iterable[Any] | None = None) -> str:
    """Order visiting the routes a read ``robots.txt``/``sitemap.xml`` lists.

    Fires while an index file read by this run still names a path that no
    ``http`` action has requested. The rule is deliberately *body-driven* and
    deterministic: the loop already keeps every action's ``tool_result`` (which
    carries the ``body_preview`` of the response), so no model call is needed to
    know what the file said. A path is considered visited once any action in the
    history requested it, in any order, which makes the rule idempotent and
    keeps it from ordering the same GET twice.

    It never stops the run, changes the plan nor authorizes a tool: it injects
    one order naming the concrete URLs, exactly like the budget and webshell
    corrections.
    """
    history = [action for action in actions or () if isinstance(action, Mapping)]
    if not history:
        return ""
    visited: set[str] = set()
    indexes: list[tuple[str, str, str]] = []  # (source, base, body)
    for action in history:
        url = _action_url(action)
        path = _url_path(url)
        if path:
            visited.add(_path_key(path))
        body = _action_body_preview(action)
        if not body or not path:
            continue
        name = path.rstrip("/").rsplit("/", 1)[-1].casefold()
        if name in ROBOTS_INDEX_FILES:
            indexes.append((name, url[: len(url) - len(path)], body))
    if not indexes:
        return ""
    pending: list[str] = []
    for name, base, body in indexes:
        for route in _index_routes(body, name, base):
            if _path_key(_url_path(route)) in visited or route in pending:
                continue
            pending.append(route)
    if not pending:
        return ""
    sources = {name for name, _, _ in indexes}
    source = sources.pop() if len(sources) == 1 else "/".join(sorted(sources))
    return ROBOTS_HINT_PROMPT.format(
        source=source,
        count=len(pending),
        paths=", ".join(pending[:ROBOTS_HINT_MAX_PATHS]),
    )


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


#: Reason recorded when a validated credential hands enumeration over to initial
#: access (V1-34). Measured in rerun 9 (``run_8f23f9…``): ``cred.bruteforce``
#: validated ``lin``'s SSH password, the verifier recorded the ``credential``
#: fact, and the selector routed enumeration to the ``cred`` profile -whose
#: toolset has no access tool (no ``ssh_exec``, no ``winrm_exec``, no
#: ``session.*``)- with 6 iterations and a completion gate that demands the next
#: phase. The profile re-listed and re-downloaded the FTP, re-ran hydra, had two
#: ``task_complete`` refused and died on ``subagent_budget_exceeded``. The rule
#: below is the deterministic exit: ``cred`` finds, ``exploit`` uses.
CREDENTIAL_FOUND_REASON = "credential_found_to_exploit"
#: Profiles whose turn may trigger the hand-over: the one that owns
#: credential-testing. Anything else that holds a credential is not this rule's
#: case.
CREDENTIAL_HANDOVER_SUBAGENTS: frozenset[str] = frozenset({"cred"})


@dataclass(frozen=True)
class CredentialHandover:
    """Deterministic proposal: leave enumeration for initial access."""

    phase: str
    subagent: str
    reason: str


def verified_credential(facts: Iterable[Any] | None = None) -> bool:
    """True when the board carries a *verified* credential fact (never raises).

    Read from the facts, not from counts, exactly like
    :func:`established_msf_session`: a credential the model recorded by hand is a
    lead (``source=agent``, ``verified=False``) and must never move a phase.
    """
    from nexus_core.kernel.blackboard import is_verified_fact

    for fact in facts or ():
        if not isinstance(fact, Mapping) or not is_verified_fact(fact):
            continue
        if str(fact.get("fact_type") or "") == "credential":
            return True
    return False


def credential_handover(
    plan: Plan,
    *,
    subagent_id: str | None,
    credential_found: bool,
) -> CredentialHandover | None:
    """Rule ``si X entonces Y`` (no inference): an engagement whose board holds a
    credential the verifier proved is past enumeration, so the profile that owns
    credential-testing hands the turn to the profile that can *use* one instead
    of looping with no tool that reaches access.

    Anything outside that shape returns ``None``: this is not a general
    "enumeration→exploitation" rule (web, AD and lead-only credentials keep their
    own phases).
    """
    if not credential_found:
        return None
    if str(getattr(plan, "current", "")) != "enumeration":
        return None
    if str(subagent_id or "") not in CREDENTIAL_HANDOVER_SUBAGENTS:
        return None
    return CredentialHandover(
        phase="exploitation",
        subagent="exploit",
        reason=CREDENTIAL_FOUND_REASON,
    )


def escalate_credential(plan: Plan, handover: CredentialHandover) -> Plan:
    """Return *plan* with the credential hand-over applied (pure).

    Same contract as :func:`escalate_enumeration` and :func:`escalate_session`:
    the phase the plan leaves is closed by the hand-off itself, so the completion
    gate can reach ``reporting`` instead of waiting for a phase nobody is going to
    work on again.
    """
    return hand_over_phase(plan, phase=handover.phase)


#: Reason/hint the planner adds once the objective is complete (V1-35). It is a
#: *suggestion*: the model decides whether to close (the completion gate keeps its
#: own rules). Measured in rerun 10 (``run_179cef8b7b424b339caba3d2093eed9d``): with
#: ``uid=0`` proven and ``root.txt`` already promoted as a verified ``loot`` fact,
#: the agent kept hunting a ``user.txt`` that does not exist on the instance until
#: ``privesc`` exhausted its 60 000-token budget, and the run closed with
#: ``findings: 0`` and no ``task_complete``.
OBJECTIVE_COMPLETE_HINT = (
    "Objetivo cumplido: privilegio máximo alcanzado + loot verificado capturado. "
    "Puedes cerrar con task_complete."
)
#: Profiles whose turn may see the objective completed. They are the profiles that
#: own the last phases of the kill chain; the iteration right after the loot lands
#: is still running the profile that captured it, because the plan is rebuilt from
#: the board on the *next* turn.
#:
#: ``reporter`` belongs here for the same reason and with the same material
#: condition (V1-47): it is the profile that **closes** the run, and the plan
#: reaches ``reporting`` precisely when the tail phases are closed by their own
#: evidence. Leaving it out made the verdict depend on *who* was holding the turn
#: instead of on the board: measured in rerun 13 (`run_c1b80861…`), iteration 13
#: was already running ``reporter`` with ``privilege {uid:0}`` and ``loot`` both
#: verified, ``objective_complete`` came back ``false``, the ``react.budget_exempt``
#: path never applied, and the profile died at 31 669/30 000 tokens just before it
#: could close (`premature_completion` on the way).
OBJECTIVE_COMPLETE_SUBAGENTS: frozenset[str] = frozenset(
    {"privesc", "postexploit", "lateral", "reporter"}
)
#: Accounts whose privilege is "top" for the closure rule. ``root`` is Unix and
#: ``SYSTEM``/``Administrator`` are Windows; the comparison is case-insensitive and
#: a ``uid == 0`` value counts on its own (the ssh/ret2libc branches assert it).
TOP_PRIVILEGE_ACCOUNTS: frozenset[str] = frozenset(
    {"root", "system", "nt authority\\system", "administrator", "admin"}
)
#: ``verification_method`` of a verified SSH channel (V1-31).
SSH_ACCESS_METHOD = "ssh_exec_completed"


@dataclass(frozen=True)
class ObjectiveCompletion:
    """Verdict of the objective-completion rule plus the refs that prove it."""

    complete: bool = False
    privilege_ref: str = ""
    loot_refs: tuple[str, ...] = ()
    hint: str = ""

    def to_payload(self) -> dict[str, Any]:
        """Payload of the ``orchestrator.objective_complete`` event."""
        return {"privilege_ref": self.privilege_ref, "loot_refs": list(self.loot_refs)}


_FLAG_SHAPED = re.compile(r"(?:THM|HTB|FLAG|flag|CTF|ctf)\{[^}\s]{4,200}\}")
#: A content digest (MD5/SHA) held by a loot value: Vulnversity's ``user.txt`` is
#: an MD5, so an all-digit shape is a legitimate capture even without letters.
_HASH_SHAPED = re.compile(r"^[0-9a-fA-F]{32,128}$")
#: Depth ceiling of :func:`flag_tokens`: a tool output is arbitrary JSON, and a
#: cyclic/hostile value must not turn the closure check into a crash.
FLAG_MAX_DEPTH = 12
#: Flag files a CTF objective names. One named file is one expected flag, so an
#: objective that asks for ``user.txt`` *and* ``root.txt`` closes only after both
#: were captured -never after the user flag alone, which would abandon the
#: escalation that the room still expects.
FLAG_FILE_TARGETS: tuple[str, ...] = ("user.txt", "root.txt", "local.txt", "proof.txt")
#: Objective words that say the engagement is a flag hunt. Checked casefolded.
FLAG_OBJECTIVE_TOKENS: tuple[str, ...] = ("flag", "flags", "bandera", "banderas", "ctf")


def flag_tokens(value: Any) -> tuple[str, ...]:
    """Every flag-shaped token inside *value* (deduplicated, input order).

    The value is scanned recursively because a captured flag is not always under
    a key called ``flag``: the RootMe run recorded ``rootme_flags`` with
    ``user_txt``/``root_txt`` as the leaves, and a rule that only looked at
    ``flag``/``content``/``excerpt`` would have seen nothing. Keys are scanned
    too: a ``loot`` fact whose *key* is the flag is the shape the ssh/ret2libc
    branches record. Never raises: anything that is not a mapping, sequence or
    string carries no flag.
    """
    found: list[str] = []

    def walk(node: Any, depth: int) -> None:
        if depth > FLAG_MAX_DEPTH:
            return
        if isinstance(node, Mapping):
            for key, item in node.items():
                walk(key, depth + 1)
                walk(item, depth + 1)
        elif isinstance(node, (list, tuple, set, frozenset)):
            for item in node:
                walk(item, depth + 1)
        elif isinstance(node, str):
            for token in _FLAG_SHAPED.findall(node):
                if token not in found:
                    found.append(token)

    walk(value, 0)
    return tuple(found)


def flag_file_capture(fact: Any) -> str:
    """Text of a verified ``loot`` fact whose *key* names a flag file.

    The format is never guessed: a ``user.txt``/``root.txt``/``local.txt``/
    ``proof.txt`` capture may be an ``MD5``, a sentence or anything else short
    enough to be a flag (Vulnversity's ``user.txt`` is
    ``8bd7992fbe8a6ad22a63361004cfcedb``). The key is the path the engine proved
    it read, so the fact is the capture whatever the value looks like.
    """
    if not isinstance(fact, Mapping):
        return ""
    key = str(fact.get("key") or "")
    if not any(name in key.casefold() for name in FLAG_FILE_TARGETS):
        return ""
    value = _fact_value(fact)
    for name in ("content", "flag", "value", "excerpt", "sha256"):
        text = str(value.get(name) or "").strip()
        if text:
            return text
    return key


def objective_asks_for_flags(objective: Any) -> bool:
    """Whether the engagement objective is a flag hunt (deterministic, no LLM)."""
    text = str(objective or "").casefold()
    return any(token in text for token in FLAG_OBJECTIVE_TOKENS) or any(
        name in text for name in FLAG_FILE_TARGETS
    )


def expected_flag_count(objective: Any) -> int:
    """How many distinct flags the objective names, at least one.

    Only the flag *files* are counted (``user.txt`` + ``root.txt`` = 2). An
    objective that just says "captura la flag" counts one; a plural it does not
    enumerate stays at one, because forcing a higher number would keep the run
    alive forever on a single-flag room.
    """
    text = str(objective or "").casefold()
    named = sum(1 for name in FLAG_FILE_TARGETS if name in text)
    return max(1, named)


@dataclass(frozen=True)
class TargetReached:
    """Verdict of the target-reached rule plus the evidence behind each flag."""

    reached: bool = False
    flags: tuple[str, ...] = ()
    sources: tuple[dict[str, Any], ...] = ()
    verified: bool = False
    expected: int = 1

    def to_payload(self) -> dict[str, Any]:
        """Payload of the ``react.target_reached`` / forced events."""
        return {
            "flags": list(self.flags),
            "verified": self.verified,
            "expected": self.expected,
            "sources": [dict(source) for source in self.sources],
        }


def _fact_target(fact: Mapping[str, Any]) -> str:
    """Best target of a loot fact: its value fields, else its key (never raises)."""
    value = _fact_value(fact)
    for name in ("target", "url", "host", "address"):
        text = str(value.get(name) or "").strip()
        if text:
            return text
    return str(fact.get("key") or "")


def target_reached(
    facts: Iterable[Any] | None = None,
    *,
    objective: str = "",
    observed_flags: Mapping[str, Mapping[str, Any]] | None = None,
) -> TargetReached:
    """Rule ``si X entonces Y``: the flags the objective asked for were captured.

    A flag counts when it comes from one of two deterministic sources:

    * a **verified** ``loot`` fact on the board (the verifier attested it). The
      value counts when it is flag-shaped, **or** when the fact's key names a
      conventional flag file (:func:`flag_file_capture`): Vulnversity's
      ``user.txt`` holds an MD5, not ``flag{fake_flag}``, and the read is the evidence;
    * a flag-shaped token in the output of a successful tool call of this run
      (``observed_flags``), which is how a webshell/curl branch reports it: the
      RootMe run captured both flags through command output and never derived a
      verifier assertion for them.

    The objective must ask for flags (or name ``user.txt``/``root.txt``), and as
    many distinct flags as the objective names must be present. Anything else
    returns ``TargetReached(reached=False)``; nothing is closed by this function.
    """
    from nexus_core.kernel.blackboard import is_verified_fact

    if not objective_asks_for_flags(objective):
        return TargetReached(expected=expected_flag_count(objective))
    sources: list[dict[str, Any]] = []
    seen: set[str] = set()
    for fact in facts or ():
        if not isinstance(fact, Mapping) or not is_verified_fact(fact):
            continue
        if str(fact.get("fact_type") or "") != "loot":
            continue
        key = str(fact.get("key") or "")
        tokens = flag_tokens(_fact_value(fact)) or flag_tokens(key)
        if not tokens:
            captured = flag_file_capture(fact)
            tokens = (captured,) if captured else ()
        for token in tokens:
            if token in seen:
                continue
            seen.add(token)
            sources.append(
                {
                    "flag": token,
                    "ref": key,
                    "fact_type": "loot",
                    "invocation_id": str(fact.get("invocation_id") or ""),
                    "verification_method": str(fact.get("verification_method") or ""),
                    "target": _fact_target(fact),
                    "source": "blackboard",
                    "verified": True,
                }
            )
    for token, source in (observed_flags or {}).items():
        flag = str(token or "").strip()
        if not flag or flag in seen:
            continue
        seen.add(flag)
        detail: dict[str, Any] = dict(source) if isinstance(source, Mapping) else {}
        detail.update(
            {
                "flag": flag,
                "ref": str(detail.get("ref") or ""),
                "fact_type": "loot",
                "source": "observation",
                "verified": True,
            }
        )
        sources.append(detail)
    expected = expected_flag_count(objective)
    flags = tuple(source["flag"] for source in sources)
    reached = len(flags) >= expected
    return TargetReached(
        reached=reached,
        flags=flags,
        sources=tuple(sources),
        # Both sources are evidence of this engagement: a verifier assertion or the
        # literal output of a successful tool call. Nothing here is a model claim.
        verified=bool(sources),
        expected=expected,
    )


def _fact_value(fact: Any) -> Mapping[str, Any]:
    """``value`` of a fact record, as a mapping (never raises)."""
    if not isinstance(fact, Mapping):
        return {}
    value = fact.get("value")
    return value if isinstance(value, Mapping) else {}


def loot_is_evidence(value: Mapping[str, Any] | None) -> bool:
    """Whether a ``loot`` value is a *captured artifact* rather than a note.

    Two shapes count: a content digest (``sha256``/MD5, what ``sliver_loot`` and
    a flag-file read record) or a flag-shaped token (``flag{fake_flag}``, what every
    command-execution branch records). A loot fact whose value carries neither
    is a note, not loot.
    """
    value = value or {}
    if str(value.get("sha256") or "").strip():
        return True
    for name in ("flag", "value", "content", "excerpt"):
        text = str(value.get(name) or "").strip()
        if _FLAG_SHAPED.search(text) or _HASH_SHAPED.match(text):
            return True
    key_flag = str(value.get("flag") or "").strip()
    return bool(key_flag and key_flag.upper() != key_flag.lower())


def top_privilege(value: Mapping[str, Any] | None) -> bool:
    """Whether a ``privilege`` value states the maximum privilege level.

    Only two shapes count: ``uid == 0`` (Unix) or an account name in
    :data:`TOP_PRIVILEGE_ACCOUNTS` (Windows). A ``privilege`` fact naming some
    other account is real evidence, just not the top of the chain.
    """
    value = value or {}
    uid = value.get("uid")
    if uid in (0, "0"):
        return True
    for name in ("user", "username", "account"):
        account = str(value.get(name) or "").strip().lower()
        if account and account in TOP_PRIVILEGE_ACCOUNTS:
            return True
    return False


def objective_completion(
    facts: Iterable[Any] | None = None,
    *,
    subagent_id: str | None = None,
    legacy: bool | None = None,
) -> ObjectiveCompletion:
    """Rule ``si X entonces Y`` (no inference): the board holds a verified top
    privilege **and** verified loot, so the objective is met.

    WP2: the verdict reads the **board only**. It used to also require the turn
    to be run by a profile that owns the tail of the chain, which is what let a
    planner hand-off turn a root+loot board into ``complete=False`` and kill the
    run (rerun 13). ``subagent_id`` is kept for the legacy path:
    ``NEXUS_LEGACY_PROFILES=1`` (or an explicit ``legacy=True``) restores the
    profile gate so the old regression suite keeps its meaning.

    A lead never counts (``is_verified_fact``): an agent-declared ``privilege`` or
    ``loot`` is a hypothesis. Anything outside the shape returns
    ``ObjectiveCompletion()`` with ``complete=False``.
    """
    from nexus_core.kernel.blackboard import is_verified_fact

    if legacy is None:
        from .subagents import legacy_profiles

        legacy = legacy_profiles()
    if legacy and str(subagent_id or "") not in OBJECTIVE_COMPLETE_SUBAGENTS:
        return ObjectiveCompletion()
    privilege_ref = ""
    loot_refs: list[str] = []
    for fact in facts or ():
        if not isinstance(fact, Mapping) or not is_verified_fact(fact):
            continue
        fact_type = str(fact.get("fact_type") or "")
        key = str(fact.get("key") or "")
        if fact_type == "privilege" and not privilege_ref and top_privilege(_fact_value(fact)):
            privilege_ref = key
        elif fact_type == "loot" and loot_is_evidence(_fact_value(fact)):
            loot_refs.append(key)
    if not privilege_ref or not loot_refs:
        return ObjectiveCompletion()
    return ObjectiveCompletion(
        complete=True,
        privilege_ref=privilege_ref,
        loot_refs=tuple(loot_refs),
        hint=OBJECTIVE_COMPLETE_HINT,
    )


def apply_objective_completion(plan: Plan, completion: ObjectiveCompletion) -> Plan:
    """Return *plan* carrying the closure hint, or *plan* unchanged.

    The hint is **not** an order and closes nothing: it only tells the model the
    objective is met (the phases were closed by their own evidence).
    """
    if not completion.complete:
        return plan
    return replace(
        plan,
        objective_complete=True,
        objective_hint=completion.hint or OBJECTIVE_COMPLETE_HINT,
    )


def enumeration_still_open(plan: Plan) -> bool:
    """Whether the *board's own counts* still describe ``enumeration``.

    Used to bound the one-way enumeration hand-over: while the counts still say
    ``enumeration`` the forced ``exploitation`` must stick (there is no evidence
    to replace it with), but as soon as the evidence closes the phase the latch
    has to let go, or the plan can never reach ``privilege_escalation`` /
    ``post_exploitation`` again (V1-36: measured in rerun 10, where the profile
    selection could be monopolised by the phase the hand-over forced).

    ``normalize_counts`` drops the two counts that describe *reaching the goal of
    the hand-over itself* (``access``/``session``): those close ``exploitation``,
    which is what the forced phase was for, so they end the latch too.
    """
    counts = normalize_counts(counts=getattr(plan, "counts", None))
    if any(counts.get(kind, 0) for kind in ("access", "session")):
        return False
    return active_phase(counts) == "enumeration"


def plan_from_summary(
    summary: Mapping[str, Any] | None,
    *,
    objective: str | None = None,
    engagement_id: str | None = None,
    phase_turns: Mapping[str, int] | None = None,
) -> Plan:
    """Build a plan from a blackboard ``summary()`` payload."""
    summary = summary or {}
    return build_plan(
        objective,
        counts=summary.get("counts") if isinstance(summary, Mapping) else None,
        engagement_id=engagement_id or (summary.get("engagement_id") if isinstance(summary, Mapping) else None),
        facts_total=int(summary.get("total") or 0) if isinstance(summary, Mapping) else 0,
        leads=summary.get("leads") if isinstance(summary, Mapping) else None,
        phase_turns=phase_turns,
    )


__all__ = [
    "ACCESS_TYPES",
    "CREDENTIAL_FOUND_REASON",
    "OBJECTIVE_COMPLETE_HINT",
    "OBJECTIVE_COMPLETE_SUBAGENTS",
    "SSH_ACCESS_METHOD",
    "TOP_PRIVILEGE_ACCOUNTS",
    "CREDENTIAL_HANDOVER_SUBAGENTS",
    "ENUMERATION_ENDPOINT_CEILING",
    "ENUMERATION_ENDPOINT_REASON",
    "ENUMERATION_EXHAUSTED_NO_PROGRESS",
    "ENUMERATION_EXHAUSTED_REASON",
    "ENUMERATION_EXHAUSTED_SUBAGENTS",
    "SMART_BUDGET_MIN_ENDPOINTS",
    "SMART_BUDGET_MIN_ITERATION",
    "SMART_BUDGET_MIN_SERVICES",
    "SMART_BUDGET_PROMPT",
    "WEBSHELL_BUILD_MARKERS",
    "WEBSHELL_SHELL_TOOLS",
    "WEBSHELL_STALL_PROMPT",
    "WEBSHELL_STALL_TURNS",
    "MARKERS",
    "PHASES",
    "SESSION_ESTABLISHED_REASON",
    "SESSION_HANDOVER_PHASES",
    "SESSION_HANDOVER_SUBAGENTS",
    "SMB_SERVICE_MARKERS",
    "CredentialHandover",
    "EnumerationEscalation",
    "ObjectiveCompletion",
    "SessionHandover",
    "apply_objective_completion",
    "credential_handover",
    "endpoint_ceiling",
    "enumeration_budget_hint",
    "enumeration_escalation",
    "enumeration_still_open",
    "loot_is_evidence",
    "objective_completion",
    "flag_tokens",
    "objective_asks_for_flags",
    "expected_flag_count",
    "TargetReached",
    "target_reached",
    "top_privilege",
    "escalate_credential",
    "escalate_enumeration",
    "escalate_session",
    "established_msf_session",
    "session_handover",
    "webshell_stall_hint",
    "verified_credential",
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
