"""Deterministic operator playbooks: codified attack chains over the blackboard.

A playbook is a named, ordered sequence of tool steps whose applicability is a
pure function of the engagement blackboard. It never executes anything: it tells
the agent (or the human) what the *next* gated step is, and the gateway still
scopes, approves and audits every call. This encodes "how a senior pentester
would chain it" without letting a model invent a step.

Nothing here calls the LLM, so the guidance is reproducible and testable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class PlaybookStep:
    """One gated tool step; ``produces`` marks the fact that completes it."""

    step_id: str
    title: str
    tool_id: str
    produces: str | None = None
    rationale: str = ""

    def to_dict(self) -> dict:
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

    def to_dict(self) -> dict:
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

    def to_dict(self) -> dict:
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

PLAYBOOKS: tuple[Playbook, ...] = (FTP_ANON_TO_CRED, LINUX_PRIVESC, LATERAL_MOVEMENT)


def _has_type(facts: list[dict], fact_type: str) -> bool:
    return any(fact.get("fact_type") == fact_type for fact in facts)


def _service_blob(facts: list[dict]) -> str:
    return " ".join(
        json.dumps(fact, sort_keys=True, default=str).lower()
        for fact in facts
        if fact.get("fact_type") == "service"
    )


def precondition_ftp(facts: list[dict]) -> bool:
    blob = _service_blob(facts)
    return any(needle in blob for needle in ("ftp", "21/tcp", "\"port\": 21"))


def precondition_privesc(facts: list[dict]) -> bool:
    return _has_type(facts, "access")


def precondition_lateral(facts: list[dict]) -> bool:
    return _has_type(facts, "access") and _has_type(facts, "service")


#: Applicability gate per playbook (deterministic, no LLM).
PRECONDITIONS: dict[str, Callable[[list[dict]], bool]] = {
    FTP_ANON_TO_CRED.playbook_id: precondition_ftp,
    LINUX_PRIVESC.playbook_id: precondition_privesc,
    LATERAL_MOVEMENT.playbook_id: precondition_lateral,
}


def _completion(playbook: Playbook, facts: list[dict]) -> list[bool]:
    """Sequential completion: a step is done if it produced its fact, or a
    later step is done and it only primes it (``produces is None``)."""
    types = {fact.get("fact_type") for fact in facts}
    done = [False] * len(playbook.steps)
    for index in range(len(playbook.steps) - 1, -1, -1):
        produces = playbook.steps[index].produces
        if produces is None:
            done[index] = any(done[index + 1:])
        else:
            done[index] = produces in types
    return done


def match_playbook(playbook: Playbook, facts: list[dict]) -> PlaybookMatch:
    """Evaluate one playbook against the facts (no execution)."""
    done = _completion(playbook, facts)
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
    facts: list[dict], *, only_ready: bool = True
) -> tuple[PlaybookMatch, ...]:
    """Return matches for every playbook whose precondition holds.

    With ``only_ready=False`` the not-yet-applicable playbooks are included too
    (useful for ``list``), each with no next step.
    """
    facts = list(facts or [])
    matches: list[PlaybookMatch] = []
    for playbook in PLAYBOOKS:
        applicable = PRECONDITIONS[playbook.playbook_id](facts)
        if applicable:
            matches.append(match_playbook(playbook, facts))
        elif not only_ready:
            matches.append(PlaybookMatch(playbook, (), None))
    return tuple(matches)


__all__ = [
    "PLAYBOOKS",
    "PRECONDITIONS",
    "Playbook",
    "PlaybookMatch",
    "PlaybookStep",
    "FTP_ANON_TO_CRED",
    "LINUX_PRIVESC",
    "LATERAL_MOVEMENT",
    "match_playbook",
    "precondition_ftp",
    "precondition_lateral",
    "precondition_privesc",
    "select_playbooks",
]
