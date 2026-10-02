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

from dataclasses import dataclass
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
    for fact in facts or ():
        fact_type = None
        if isinstance(fact, Mapping):
            fact_type = fact.get("fact_type") or fact.get("type")
        else:
            fact_type = getattr(fact, "fact_type", None)
        if not fact_type:
            continue
        normalized[str(fact_type)] = normalized.get(str(fact_type), 0) + 1
    return normalized


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
) -> Plan:
    """Build the plan from blackboard evidence (never raises on bad input)."""
    normalized = normalize_counts(counts=counts, facts=facts)
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
    )


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
    )


__all__ = [
    "MARKERS",
    "PHASES",
    "PHASE_IDS",
    "STATUS_CURRENT",
    "STATUS_DONE",
    "STATUS_PENDING",
    "Phase",
    "PhaseStatus",
    "Plan",
    "active_phase",
    "build_plan",
    "normalize_counts",
    "plan_from_summary",
]
