"""``/interview``: guided engagement intake (scope, RoE, targets, objectives).

The interview is the operator-facing front door of an engagement. It walks the
operator through a fixed question set and records the answers into the
**durable session context** instead of leaving them as prose in the chat:

* The business objective, client and restrictions are stored as one durable
  blackboard ``hint`` fact (``engagement-brief``), so the ReAct loop, the
  planner and the prompt frame see them in every later iteration.
* Rules of Engagement limits (time window, rate, concurrency, emergency
  contact) are persisted as the same signed RoE artifact ``/roe`` and
  :func:`nexus_core.scope.roe.load_enforcer` consume at execution time.
* Authorized targets are validated against the **signed scope**. A target the
  scope does not cover is reported and never recorded: the interview can
  document an engagement, but it can never widen an authorization.

Nothing here executes a tool; it only records intent. The handler never raises
on bad input and always leaves the REPL in a usable state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.scope_loader import scope_signing_secret
from nexus_core.scope import RulesOfEngagement, ScopeViolation, TimeWindow, save_roe
from nexus_core.scope.models import EngagementScope
from nexus_core.scope.resolver import DNSResolver
from nexus_core.scope.validator import ScopeValidator

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .session import OmniSession

#: Fact type/key of the durable engagement brief. ``hint`` is a context-only
#: fact: it never counts as phase evidence, so it cannot advance the plan.
BRIEF_FACT_TYPE = "hint"
BRIEF_FACT_KEY = "engagement-brief"
BRIEF_SOURCE = "nexus.cli.interview"

_YES = {"y", "yes", "s", "si", "sí", "true", "1"}


@dataclass(frozen=True)
class InterviewResult:
    """Outcome of one guided interview (empty when the operator cancelled)."""

    objectives: str = ""
    client: str = ""
    authorized_targets: tuple[str, ...] = ()
    rejected_targets: tuple[str, ...] = ()
    restrictions: str = ""
    roe_saved: bool = False
    roe_path: str = ""
    brief_recorded: bool = False
    cancelled: bool = False

    def to_brief(self) -> dict[str, Any]:
        """JSON-serializable engagement brief persisted on the blackboard."""
        return {
            "objectives": self.objectives,
            "client": self.client,
            "authorized_targets": list(self.authorized_targets),
            "rejected_targets": list(self.rejected_targets),
            "restrictions": self.restrictions,
            "roe_saved": self.roe_saved,
        }


def _default_reader(session: "OmniSession") -> Callable[[str], str]:
    """Same line reader the other interactive commands use (TUI-aware)."""
    if session.input_reader is not None:
        return session.input_reader
    if session._tui.use_tui:
        return session._tui.prompt
    return input


def _ask(reader: Callable[[str], str], prompt: str) -> str:
    """Read one answer, turning Ctrl+C/Ctrl+D into an empty (cancel) answer."""
    try:
        return str(reader(prompt) or "").strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def _parse_targets(text: str) -> tuple[str, ...]:
    """Split a comma/space separated target list, dropping blanks."""
    raw = str(text).replace(",", " ").replace(";", " ")
    seen: set[str] = set()
    targets: list[str] = []
    for item in raw.split():
        value = item.strip()
        if value and value not in seen:
            seen.add(value)
            targets.append(value)
    return tuple(targets)


def _parse_positive_int(text: str) -> int:
    """Parse a non-negative integer; anything else is ``0`` (unlimited)."""
    try:
        return max(0, int(str(text).strip()))
    except (TypeError, ValueError):
        return 0


def _parse_window(text: str) -> tuple[str, str] | None:
    """Parse ``HH:MM-HH:MM`` into ``(start, end)``, or ``None`` when absent."""
    value = str(text).strip().replace("–", "-")
    if not value:
        return None
    parts = [item.strip() for item in value.split("-")]
    if len(parts) != 2:
        return None
    try:
        TimeWindow(start=parts[0], end=parts[1])
    except ValueError:
        return None
    return parts[0], parts[1]


def _validate_targets(
    scope: EngagementScope, targets: tuple[str, ...], resolver: DNSResolver | None
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split targets into ``(in_scope, rejected)`` using the signed scope.

    Validation is the exact same component the gateway runs before execution,
    so the interview and the tool path cannot disagree. A DNS failure is a
    rejection too: an unresolvable target cannot be proven in scope.
    """
    validator = ScopeValidator(
        scope, resolver=resolver, signing_secret=scope_signing_secret()
    )
    accepted: list[str] = []
    rejected: list[str] = []
    for target in targets:
        try:
            validator.validate(target)
        except ScopeViolation:
            rejected.append(target)
            continue
        except Exception:  # noqa: BLE001 - never let a probe abort the intake
            rejected.append(target)
            continue
        accepted.append(target)
    return tuple(accepted), tuple(rejected)


def _build_roe(
    session: "OmniSession",
    *,
    name: str,
    window: tuple[str, str] | None,
    max_actions_per_minute: int,
    max_concurrent_actions: int,
    emergency_contact: str,
    restrictions: str,
) -> RulesOfEngagement:
    windows = (TimeWindow(start=window[0], end=window[1]),) if window else ()
    return RulesOfEngagement(
        engagement_id=str(session.engagement_id),
        tenant_id=session.tenant_id,
        name=name,
        windows=windows,
        max_actions_per_minute=max_actions_per_minute,
        max_concurrent_actions=max_concurrent_actions,
        emergency_contact=emergency_contact,
        notes=restrictions,
    ).sign(scope_signing_secret() or "")


def run_interview(
    session: "OmniSession",
    *,
    reader: Callable[[str], str] | None = None,
    resolver: DNSResolver | None = None,
) -> InterviewResult:
    """Run the guided intake and persist what it collected.

    Returns an :class:`InterviewResult`; ``cancelled`` is set when the operator
    answered nothing to the very first question (they still keep their session).
    """
    scope = session.engagement
    if scope is None:
        return InterviewResult(cancelled=True)
    ask = reader if reader is not None else _default_reader(session)

    objectives = _ask(ask, "Objetivo de negocio del engagement: ")
    client = _ask(ask, f"Cliente / propietario [{scope.client or 'opcional'}]: ")
    scope_targets = ", ".join([*scope.cidrs, *scope.domains, *scope.urls]) or "ninguno"
    raw_targets = _ask(
        ask, f"Targets autorizados (coma) [scope firmado: {scope_targets}]: "
    )
    restrictions = _ask(ask, "Restricciones / notas (opcional): ")
    window = _parse_window(
        _ask(ask, "RoE ventana horaria HH:MM-HH:MM (opcional): ")
    )
    max_actions = _parse_positive_int(
        _ask(ask, "RoE máx. acciones por minuto (0 = sin límite): ")
    )
    max_concurrent = _parse_positive_int(
        _ask(ask, "RoE máx. acciones concurrentes (0 = sin límite): ")
    )
    contact = _ask(ask, "RoE contacto de emergencia (opcional): ")

    if not objectives and not raw_targets:
        return InterviewResult(cancelled=True)

    requested = _parse_targets(raw_targets) if raw_targets else (*scope.cidrs, *scope.domains, *scope.urls)
    accepted, rejected = _validate_targets(scope, requested, resolver)

    roe_applicable = bool(
        window or max_actions or max_concurrent or contact or restrictions
    )
    roe_path_text = ""
    roe_saved = False
    if roe_applicable:
        roe = _build_roe(
            session,
            name=client or scope.name,
            window=window,
            max_actions_per_minute=max_actions,
            max_concurrent_actions=max_concurrent,
            emergency_contact=contact,
            restrictions=restrictions,
        )
        if roe.signature_valid(scope_signing_secret()):
            roe_path_text = str(save_roe(roe))
            roe_saved = True

    result = InterviewResult(
        objectives=objectives,
        client=client or scope.client,
        authorized_targets=accepted,
        rejected_targets=rejected,
        restrictions=restrictions,
        roe_saved=roe_saved,
        roe_path=roe_path_text,
    )

    brief_recorded = False
    try:
        Blackboard(session.store).record(
            tenant_id=session.tenant_id,
            engagement_id=str(session.engagement_id),
            fact_type=BRIEF_FACT_TYPE,
            key=BRIEF_FACT_KEY,
            value=result.to_brief(),
            source=BRIEF_SOURCE,
            created_by=session.operator_id or session.agent_subject_id,
        )
        brief_recorded = True
    except Exception:  # noqa: BLE001 - the intake must survive an unwritable board
        brief_recorded = False

    stored = InterviewResult(
        objectives=result.objectives,
        client=result.client,
        authorized_targets=result.authorized_targets,
        rejected_targets=result.rejected_targets,
        restrictions=result.restrictions,
        roe_saved=result.roe_saved,
        roe_path=result.roe_path,
        brief_recorded=brief_recorded,
    )
    session.engagement_brief = stored.to_brief()
    return stored


__all__ = [
    "BRIEF_FACT_KEY",
    "BRIEF_FACT_TYPE",
    "InterviewResult",
    "run_interview",
]
