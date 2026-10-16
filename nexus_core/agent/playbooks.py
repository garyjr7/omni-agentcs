"""Deterministic operator playbooks: codified attack chains over the blackboard.

A playbook is a named, ordered sequence of tool steps whose applicability is a
pure function of the engagement blackboard. It never executes anything: it tells
the agent (or the human) what the *next* gated step is, and the gateway still
scopes, approves and audits every call. This encodes "how a senior pentester
would chain it" without letting a model invent a step.

The three chains below are hand-written Python. Since the declarative packages
landed (``nexus_core/playbooks/*.yaml``), this module is also the *registry*:
:func:`registered_playbooks` merges them with every phase of every package, and
:func:`gate_for` resolves the applicability of either kind. A packaged phase and
a hand-written chain are indistinguishable to the loop and the prompt.

Nothing here calls the LLM, so the guidance is reproducible and testable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from .playbook_proofs import ExecutionProof, target_key
from nexus_core.kernel.blackboard import is_verified_fact
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from nexus_core.playbooks.loader import LoadedPackage


@dataclass(frozen=True)
class PlaybookStep:
    """One gated tool step; ``produces`` marks the fact that completes it."""

    step_id: str
    title: str
    tool_id: str
    produces: str | None = None
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "title": self.title,
            "tool_id": self.tool_id,
            "produces": self.produces,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class Playbook:
    playbook_id: str
    title: str
    phase: str
    requires: str
    steps: tuple[PlaybookStep, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "title": self.title,
            "phase": self.phase,
            "requires": self.requires,
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass(frozen=True)
class PlaybookMatch:
    playbook: Playbook
    completed: tuple[str, ...]
    next_step: PlaybookStep | None
    facts_used: tuple[str, ...] = field(default=())

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook.playbook_id,
            "title": self.playbook.title,
            "phase": self.playbook.phase,
            "completed": list(self.completed),
            "next_step": self.next_step.to_dict() if self.next_step else None,
        }


#: Fact types that gate each playbook (``requires`` is the human-readable form).
FTP_ANON_TO_CRED = Playbook(
    playbook_id="ftp_anon_to_cred",
    title="FTP anónimo → credenciales",
    phase="exploitation",
    requires="un servicio FTP con login anónimo",
    steps=(
        PlaybookStep(
            "ftp_list",
            "Listar el FTP anónimo",
            "nexus.recon.ftp",
            produces="endpoint",
            rationale="un FTP anónimo suele exponer pistas de usuario/password",
        ),
        PlaybookStep(
            "ftp_download",
            "Descargar los ficheros hallados",
            "nexus.recon.ftp",
            produces="artifact",
            rationale="locks.txt/task.txt contienen usuarios y patrones de password",
        ),
        PlaybookStep(
            "bruteforce",
            "Probar la wordlist contra SSH",
            "nexus.cred.bruteforce",
            produces="credential",
            rationale="fuerza bruta dirigida y limitada, nunca infinita",
        ),
    ),
)

LINUX_PRIVESC = Playbook(
    playbook_id="linux_privesc",
    title="Post-explotación Linux → root",
    phase="privilege_escalation",
    requires="acceso a un host Linux",
    steps=(
        PlaybookStep(
            "enum_system",
            "Enumerar el sistema",
            "nexus.post.enum_system",
            produces=None,
            rationale="sudo -l, SUID y capabilities revelan el vector",
        ),
        PlaybookStep(
            "privesc_hints",
            "Correlacionar vectores GTFOBins",
            "nexus.post.privesc_hints",
            produces=None,
            rationale="sugiere el exploit exacto; nunca lo ejecuta",
        ),
        PlaybookStep(
            "escalate",
            "Ejecutar el comando sugerido",
            "nexus.post.ssh_exec",
            produces="privilege",
            rationale="un solo comando aprobado convierte el hint en acceso root",
        ),
    ),
)

LATERAL_MOVEMENT = Playbook(
    playbook_id="lateral_movement",
    title="Movimiento lateral con C2",
    phase="lateral_movement",
    requires="acceso a un host y al menos otro servicio descubierto",
    steps=(
        PlaybookStep(
            "generate",
            "Generar el implante",
            "nexus.c2.sliver_generate",
            produces=None,
            rationale="construye un implante acorde al host destino",
        ),
        PlaybookStep(
            "deploy",
            "Desplegarlo por la sesión actual",
            "nexus.c2.sliver_deploy",
            produces=None,
            rationale="sube y ejecuta el implante en el host nuevo (DESTRUCTIVA)",
        ),
        PlaybookStep(
            "register",
            "Registrar la nueva sesión",
            "nexus.c2.sliver_sessions",
            produces="session",
            rationale="la sesión nueva queda ligada al engagement como evidencia",
        ),
    ),
)

#: Applicability gate of one playbook, evaluated against the blackboard facts.
GateFn = Callable[[list[dict[str, Any]]], bool]

PLAYBOOKS: tuple[Playbook, ...] = (FTP_ANON_TO_CRED, LINUX_PRIVESC, LATERAL_MOVEMENT)


def _has_type(facts: list[dict[str, Any]], fact_type: str) -> bool:
    return any(fact.get("fact_type") == fact_type for fact in facts)


def _service_blob(facts: list[dict[str, Any]]) -> str:
    return " ".join(
        json.dumps(fact, sort_keys=True, default=str).lower()
        for fact in facts
        if fact.get("fact_type") == "service"
    )


def precondition_ftp(facts: list[dict[str, Any]]) -> bool:
    blob = _service_blob(facts)
    return any(needle in blob for needle in ("ftp", "21/tcp", "\"port\": 21"))


def precondition_privesc(facts: list[dict[str, Any]]) -> bool:
    return _has_type(facts, "access")


def precondition_lateral(facts: list[dict[str, Any]]) -> bool:
    return _has_type(facts, "access") and _has_type(facts, "service")


#: Applicability gate per hand-written playbook (deterministic, no LLM).
PRECONDITIONS: dict[str, GateFn] = {
    FTP_ANON_TO_CRED.playbook_id: precondition_ftp,
    LINUX_PRIVESC.playbook_id: precondition_privesc,
    LATERAL_MOVEMENT.playbook_id: precondition_lateral,
}


def packaged_packages() -> tuple[LoadedPackage, ...]:
    """Validated declarative packages, or ``()`` when none can be loaded.

    Fail-soft on purpose: the loader raises on a malformed document, and a run
    must degrade to "no packaged guidance" instead of dying because a YAML file
    was edited in a hurry. Tests and ``doctor`` call the loader directly for the
    strict answer (``strict=True``).
    """
    try:
        from nexus_core.playbooks.loader import load_packages

        return tuple(load_packages())
    except Exception:  # noqa: BLE001 - guidance must never abort a run
        return ()


def packaged_playbooks() -> tuple[Playbook, ...]:
    """Every phase of every declarative package, in package/declared order."""
    return tuple(
        playbook for package in packaged_packages() for playbook in package.playbooks
    )


def registered_playbooks() -> tuple[Playbook, ...]:
    """Every playbook the engine knows: hand-written first, then packaged."""
    return PLAYBOOKS + packaged_playbooks()


def playbook_by_id(playbook_id: str) -> Playbook | None:
    """Look one playbook up across both sources (``None`` when unknown)."""
    return next(
        (item for item in registered_playbooks() if item.playbook_id == str(playbook_id)),
        None,
    )


def gate_for(playbook_id: str) -> GateFn | None:
    """Resolve the applicability gate of a playbook, hand-written or packaged."""
    key = str(playbook_id)
    gate = PRECONDITIONS.get(key)
    if gate is not None:
        return gate
    for package in packaged_packages():
        packaged: GateFn | None = package.gates().get(key)
        if packaged is not None:
            return packaged
    return None


def is_applicable(playbook_id: str, facts: list[dict[str, Any]]) -> bool:
    """Whether a playbook's gate holds for these facts (unknown ids: never)."""
    gate = gate_for(playbook_id)
    return bool(gate and gate([fact for fact in facts or [] if is_verified_fact(fact)]))


def _completion(playbook: Playbook, proofs: tuple[ExecutionProof, ...],
                target: str | None = None) -> list[bool]:
    """Consume distinct, ordered executions; global facts never complete steps."""
    done = [False] * len(playbook.steps)
    cursor = 0
    seen: set[str] = set()
    bound_target = target_key(target or "")
    for index, step in enumerate(playbook.steps):
        for position in range(cursor, len(proofs)):
            proof = proofs[position]
            if proof.invocation_id in seen or proof.tool_id != step.tool_id:
                continue
            if bound_target and proof.target and proof.target != bound_target:
                continue
            if step.produces is not None and step.produces not in proof.fact_types:
                continue
            seen.add(proof.invocation_id)
            if proof.target and not bound_target:
                bound_target = proof.target
            done[index] = True
            cursor = position + 1
            break
        if not done[index]:
            break
    return done


def match_playbook(playbook: Playbook, facts: list[dict[str, Any]], *,
                   proofs: tuple[ExecutionProof, ...] = (), target: str | None = None) -> PlaybookMatch:
    """Evaluate one playbook against the facts (no execution)."""
    done = _completion(playbook, proofs, target)
    completed = tuple(
        step.step_id for step, is_done in zip(playbook.steps, done) if is_done
    )
    next_step = next(
        (step for step, is_done in zip(playbook.steps, done) if not is_done), None
    )
    return PlaybookMatch(
        playbook=playbook,
        completed=completed,
        next_step=next_step,
    )


def select_playbooks(
    facts: list[dict[str, Any]], *, only_ready: bool = True,
    proofs: tuple[ExecutionProof, ...] = (), target: str | None = None,
) -> tuple[PlaybookMatch, ...]:
    """Return matches for every playbook whose precondition holds.

    With ``only_ready=False`` the not-yet-applicable playbooks are included too
    (useful for ``list``), each with no next step.
    """
    facts = [fact for fact in facts or [] if is_verified_fact(fact)]
    matches: list[PlaybookMatch] = []
    for playbook in registered_playbooks():
        gate = gate_for(playbook.playbook_id)
        applicable = bool(gate and gate(facts))
        if applicable:
            matches.append(match_playbook(playbook, facts, proofs=proofs, target=target))
        elif not only_ready:
            matches.append(PlaybookMatch(playbook, (), None))
    return tuple(matches)


def render_playbook_matches(matches: tuple[PlaybookMatch, ...]) -> str:
    """Render the applicable playbooks and their next step for the prompt.

    This is the piece that was missing: the deterministic chains existed and the
    ``nexus.orchestrator.playbook`` tool exposed them, but the model had to
    *choose* to call that tool. Putting the next step of every applicable chain
    directly in the system prompt is what makes the agent prioritise the
    service it can actually enter (E2E #5 walked into HTTP instead of FTP).
    """
    if not matches:
        return "(ningún playbook aplica todavía)"
    lines: list[str] = []
    for match in matches:
        head = (
            f"- [{match.playbook.playbook_id}] {match.playbook.title} "
            f"(fase {match.playbook.phase})"
        )
        step = match.next_step
        if step is None:
            lines.append(f"{head}: COMPLETADO")
            continue
        detail = f" → SIGUIENTE PASO: {step.title} [{step.tool_id}]"
        if step.rationale:
            detail += f" ({step.rationale})"
        lines.append(f"{head}{detail}")
    return "\n".join(lines)


__all__ = [
    "PLAYBOOKS",
    "PRECONDITIONS",
    "FTP_ANON_TO_CRED",
    "GateFn",
    "LATERAL_MOVEMENT",
    "LINUX_PRIVESC",
    "Playbook",
    "PlaybookMatch",
    "PlaybookStep",
    "gate_for",
    "is_applicable",
    "match_playbook",
    "packaged_packages",
    "packaged_playbooks",
    "playbook_by_id",
    "precondition_ftp",
    "precondition_lateral",
    "precondition_privesc",
    "registered_playbooks",
    "render_playbook_matches",
    "select_playbooks",
]
