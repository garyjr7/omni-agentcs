"""Per-vector engagement states and the closure gate (V0-12).

The coverage ledger already derives one verdict per discovered service. This
module turns that ledger into the durable attack-vector queue the run resumes
and closes against:

``discovered -> tested -> exploited`` or ``discarded``.

A successful vector is terminal: a later scan cannot make an owned service
"pending" again. A discarded vector can reopen only when newer evidence (a
vulnerability found after the barrier) says so, which is exactly what
``coverage`` already does. The queue is deterministic and always picks a
discovered branch before a merely tested one, so the agent cannot stop at the
first success while another route is untouched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .coverage import (
    STATUS_CLOSED,
    STATUS_OWNED,
    STATUS_PENDING,
    STATUS_PROBED,
    Coverage,
    SurfaceEntry,
)

VECTOR_DISCOVERED = "discovered"
VECTOR_TESTED = "tested"
VECTOR_EXPLOITED = "exploited"
VECTOR_DISCARDED = "discarded"

#: The four states of the kill-chain queue, in the order a closure gate reads
#: them: open work first, terminal history last.
VECTOR_STATES = (VECTOR_DISCOVERED, VECTOR_TESTED, VECTOR_EXPLOITED, VECTOR_DISCARDED)
_TERMINAL = frozenset({VECTOR_EXPLOITED, VECTOR_DISCARDED})
_OPEN = frozenset({VECTOR_DISCOVERED, VECTOR_TESTED})
_STATUS_MAP = {
    STATUS_PENDING: VECTOR_DISCOVERED,
    STATUS_PROBED: VECTOR_TESTED,
    STATUS_OWNED: VECTOR_EXPLOITED,
    STATUS_CLOSED: VECTOR_DISCARDED,
}
_RANK = {
    VECTOR_DISCOVERED: 0,
    VECTOR_TESTED: 1,
    VECTOR_EXPLOITED: 2,
    VECTOR_DISCARDED: 3,
}


def vector_status(entry: SurfaceEntry | None) -> str:
    """Map one coverage verdict to the four kill-chain states."""
    if entry is None:
        return VECTOR_DISCOVERED
    return _STATUS_MAP.get(str(getattr(entry, "status", "")), VECTOR_DISCOVERED)


@dataclass(frozen=True)
class AttackVector:
    """One discovered service as an item of the attack-vector queue."""

    ref: str
    label: str
    status: str
    host: str = ""
    port: int = 0
    service: str = ""
    verdict: str = ""
    evidence: int = 0

    @property
    def open(self) -> bool:
        return self.status in _OPEN

    def to_dict(self) -> dict[str, Any]:
        return {
            "ref": self.ref,
            "label": self.label,
            "status": self.status,
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "verdict": self.verdict,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "AttackVector | None":
        ref = str(raw.get("ref") or "").strip()
        status = str(raw.get("status") or "").strip().lower()
        if not ref or status not in VECTOR_STATES:
            return None
        try:
            port = int(raw.get("port") or 0)
            evidence = int(raw.get("evidence") or 0)
        except (TypeError, ValueError):
            port = 0
            evidence = 0
        return cls(
            ref=ref,
            label=str(raw.get("label") or ref),
            status=status,
            host=str(raw.get("host") or ""),
            port=port,
            service=str(raw.get("service") or ""),
            verdict=str(raw.get("verdict") or ""),
            evidence=max(0, evidence),
        )


@dataclass(frozen=True)
class VectorPlan:
    """The durable attack-vector queue of one run."""

    vectors: tuple[AttackVector, ...] = field(default_factory=tuple)

    @property
    def open_vectors(self) -> tuple[AttackVector, ...]:
        return tuple(
            sorted(
                (item for item in self.vectors if item.open),
                key=lambda item: (_RANK[item.status], item.host, item.port, item.ref),
            )
        )

    @property
    def next_vector(self) -> AttackVector | None:
        opened = self.open_vectors
        return opened[0] if opened else None

    def to_state(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.vectors]

    def refs(self, *, open_only: bool = False) -> tuple[str, ...]:
        items = self.open_vectors if open_only else self.vectors
        return tuple(item.ref for item in items)

    @classmethod
    def from_coverage(cls, coverage: Coverage | None) -> "VectorPlan":
        if coverage is None:
            return cls()
        return cls(tuple(_vector_from_entry(entry) for entry in coverage.entries))

    @classmethod
    def from_state(cls, raw: Any) -> "VectorPlan":
        items: list[AttackVector] = []
        for item in raw if isinstance(raw, (list, tuple)) else ():
            if not isinstance(item, Mapping):
                continue
            vector = AttackVector.from_dict(item)
            if vector is not None:
                items.append(vector)
        return cls(tuple(_sorted(items)))

    @classmethod
    def merge(cls, previous: "VectorPlan", coverage: Coverage | None) -> "VectorPlan":
        """Merge the board's current verdict with what this run already knew.

        The board wins for every service it still knows, except that an
        ``exploited`` service never regresses: the fact that a session was
        opened is not undone by a later enumeration. A previous service that the
        current board no longer carries stays in the queue as history, so a
        resumed run does not silently forget an open branch.
        """
        if coverage is None or not coverage.entries:
            return previous
        current = {item.ref: item for item in cls.from_coverage(coverage).vectors}
        old = {item.ref: item for item in previous.vectors}
        merged: list[AttackVector] = []
        for ref in sorted(set(current) | set(old)):
            new_vector = current.get(ref)
            old_vector = old.get(ref)
            if new_vector is None:
                assert old_vector is not None  # ref came from ``old``
                merged.append(old_vector)
                continue
            if old_vector is not None and old_vector.status == VECTOR_EXPLOITED:
                merged.append(old_vector)
                continue
            merged.append(new_vector)
        return cls(tuple(_sorted(merged)))


def _vector_from_entry(entry: SurfaceEntry) -> AttackVector:
    return AttackVector(
        ref=str(entry.ref),
        label=str(entry.label),
        status=vector_status(entry),
        host=str(entry.host),
        port=int(entry.port),
        service=str(entry.service),
        verdict=str(entry.verdict or ""),
        evidence=int(entry.evidence or 0),
    )


def _sorted(items: Iterable[AttackVector]) -> list[AttackVector]:
    return sorted(
        items,
        key=lambda item: (_RANK.get(item.status, 9), item.host, item.port, item.ref),
    )


def open_vector_objection(plan: VectorPlan | Coverage | None) -> str | None:
    """Why ``task_complete`` cannot close while an attack vector is open.

    Only services the board discovered count: a run with no recon has no
    surface to reconcile. The message names the next queue item so the refusal
    is actionable, never a dead end.
    """
    if plan is None:
        return None
    if isinstance(plan, Coverage):
        plan = VectorPlan.from_coverage(plan)
    opened = plan.open_vectors
    if not opened:
        return None
    shown = ", ".join(item.label for item in opened[:5])
    if len(opened) > 5:
        shown += f" y {len(opened) - 5} más"
    following = plan.next_vector
    target = f"Siguiente de la cola: {following.label}. " if following else ""
    return (
        f"quedan {len(opened)} vector(es) de ataque sin veredicto: {shown}. "
        f"{target}No declares task_complete hasta probarlos y cerrarlos con "
        "evidencia: un acceso/credencial verificado (exploited) o un barrier "
        "conclusivo (discarded)."
    )


__all__ = [
    "AttackVector",
    "VECTOR_DISCARDED",
    "VECTOR_DISCOVERED",
    "VECTOR_EXPLOITED",
    "VECTOR_STATES",
    "VECTOR_TESTED",
    "VectorPlan",
    "open_vector_objection",
    "vector_status",
]
