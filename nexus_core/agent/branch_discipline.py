"""A closed branch that stays closed, and a barrier that proves it was tried.

Measured origin: DeadDrop P12 (2026-10-22, ``run_45103fbc0e6d4a9caf76496932777d55``).
The harness did what it was told and the run still died on its own reasoning:

* the model uploaded a Node module whose command ran through the **async**
  ``exec('id > /tmp/...')`` with no ``module.exports``, read ``{}`` back from
  ``/preview/...`` and concluded -wrongly- that the preview "serves the file as
  plain text". It recorded a ``barrier`` for the only web branch at iteration 21
  after that one payload;
* the loop closed the branch itself at iteration 44 (``react.branch_closed``)
  and the model kept calling ``web.*`` against the same ``host:port`` for
  fifteen more turns, because the event was descriptive and nothing refused the
  next call;
* the credentials it found were the web app's own (``admin``/``svc-backup``),
  it tried them over SSH, and -correctly refused- it never moved to the
  operating system's own corpus (``/etc/shadow``).

Those are three different gaps and each has a deterministic answer, so they live
here instead of in the prompt alone:

* :func:`barrier_refusal` refuses a ``barrier`` that has not tried anything, or
  that follows an *executed* ``/preview`` module (the exact false verdict of the
  measured run);
* :func:`closed_branch_refusal` refuses the tools that attack a branch the loop
  already closed, for :data:`CLOSED_BRANCH_BLOCK_TURNS` turns, and lets coverage
  reopen it (a newer ``vulnerability`` fact) without a special "reopen" verb;
* :data:`PREVIEW_MODULE_NOTE` is what the HTTP handler says when a ``/preview``
  body is exactly ``{}``, so the model reads "the module ran and exported
  nothing" instead of inventing an explanation.

Everything here is pure: it reads the loop's action history and the coverage
ledger and returns text. No tool runs, no fact is written, no network.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from nexus_core.agent.coverage import (
    STATUS_CLOSED,
    Coverage,
    SurfaceEntry,
    focus_entry,
)

#: A ``barrier`` may close a branch only after this many **distinct** tools tried
#: it inside the same window. Two is the smallest number that is not "one guess":
#: the measured run closed the web branch after a single ``web.upload`` +
#: ``/preview`` pair with no ``execSync``/``fs`` alternative.
BARRIER_MIN_DISTINCT_TOOLS = 2

#: Turns inspected for both the attempt count and the executed-preview check.
#: Three is one round of "try, read, decide", which is how a human notices the
#: bad payload; thirty is how long the measured model took.
BARRIER_ATTEMPT_WINDOW = 3

#: Turns a branch the loop closed stays refused for the tools that attack it.
#: Long enough to be a real stop, short enough not to deadlock a run whose only
#: open branch is that one.
CLOSED_BRANCH_BLOCK_TURNS = 5

#: The tools a closed web branch refuses. ``ssh``/``smb``/``winrm`` are other
#: branches and are never touched by this gate.
BRANCH_ATTACK_PREFIX = "nexus.web."
BRANCH_ATTACK_TOOLS: frozenset[str] = frozenset(
    {"nexus.recon.gobuster", "nexus.recon.ffuf"}
)

#: Tools whose calls are bookkeeping, not an attempt against a branch. Without
#: this a model could satisfy the two-attempt rule with ``query_facts``.
_NON_ATTEMPT_PREFIXES: tuple[str, ...] = (
    "nexus.knowledge.",
    "nexus.workspace.",
    "nexus.orchestrator.",
    "nexus.skill.",
    "nexus.system.",
)

RECORD_FACT_TOOL = "nexus.knowledge.record_fact"

#: A fact that *opens* a branch again. Registering one in the same window is the
#: documented way out of both gates: a new vector is evidence, and a barrier on
#: top of a fresh vulnerability would hide the vector.
_OPENING_FACT_TYPES: frozenset[str] = frozenset({"hint", "vulnerability"})

PREVIEW_MARKER = "/preview/"
PREVIEW_EMPTY_BODY = "{}"

#: Appended to the observation of an executed Node module that exported nothing.
#: The measured run read ``{}`` and decided the preview "does not execute JS";
#: the body is exactly what an empty ``module.exports`` serializes to.
PREVIEW_MODULE_NOTE = (
    "El módulo Node.js de /preview SE EJECUTÓ y su `module.exports` estaba "
    "vacío: `{}` es la respuesta correcta, NO significa que el fichero se "
    "sirva como texto plano. `require('child_process').exec(...)` es "
    "asíncrono y no devuelve salida; para capturarla reescribe el .js con "
    "`module.exports = require('child_process').execSync('id').toString()` "
    "(o `require('fs').readFileSync('/etc/shadow').toString()`), vuelve a "
    "subirlo y repite la petición. No registres un barrier por este `{}`."
)

BARRIER_PREVIEW_REFUSAL = (
    "barrier RECHAZADO sobre {ref}: en los últimos {window} turnos un "
    "`/preview/*.js` devolvió `{{}}`, y eso significa que el módulo SE EJECUTÓ "
    "con `module.exports` vacío, no que el preview no ejecute código. "
    "Reescribe el payload con `execSync` + `module.exports` (o "
    "`fs.readFileSync`) y repite la petición ANTES de cerrar la rama {ref}."
)

BARRIER_TOO_EARLY = (
    "barrier RECHAZADO sobre {ref}: solo hay {count} intento(s) distinto(s) en "
    "los últimos {window} turnos ({tools}) y se exigen al menos {minimum}. "
    "Cerrar una rama con una sola prueba es una hipótesis, no un veredicto: "
    "prueba otro payload o herramienta sobre {ref}, o registra primero el "
    "vector (`vulnerability`/`hint`) que justifique el cierre."
)

CLOSED_BRANCH_REFUSAL = (
    "RAMA CERRADA: {ref} está documentada como descartada desde la iteración "
    "{closed_at} y no se vuelve a atacar con {tools_used} durante {remaining} "
    "turno(s) más. Ramas abiertas: {open_branches}. Siguiente rama sugerida: "
    "{next_branch}. Si aparece un vector nuevo sobre {ref}, regístralo con "
    "nexus.knowledge.record_fact (fact_type=\"vulnerability\") y el ledger la "
    "reabre."
)


def attacks_a_branch(tool_id: Any) -> bool:
    """Whether ``tool_id`` is a call that attacks a service branch."""
    name = str(tool_id or "").strip()
    return name.startswith(BRANCH_ATTACK_PREFIX) or name in BRANCH_ATTACK_TOOLS


def _tool_turns(actions: Iterable[Any], window: int) -> list[Mapping[str, Any]]:
    """The last ``window`` turns that really invoked a tool.

    Parse errors, clarifications and ``task_complete`` carry no ``tool_id`` and
    no result; they are turns, but they are not attempts and must not dilute the
    window that decides whether a branch was tried.
    """
    turns: list[Mapping[str, Any]] = []
    for entry in actions or ():
        if not isinstance(entry, Mapping):
            continue
        if not entry.get("tool_id") or not isinstance(entry.get("tool_result"), Mapping):
            continue
        turns.append(entry)
    return turns[-max(1, int(window)):] if turns else []


def _entry_for_arguments(
    coverage: Coverage | None, entry: Mapping[str, Any]
) -> SurfaceEntry | None:
    """The ledger entry one action was aimed at (or ``None``)."""
    arguments = entry.get("arguments")
    return focus_entry(coverage, arguments if isinstance(arguments, Mapping) else None)


def _entry_for_key(coverage: Coverage | None, key: str) -> SurfaceEntry | None:
    """The ledger entry a fact key names (``host:port``, any spelling)."""
    if coverage is None:
        return None
    direct = coverage.find(key)
    if direct is not None:
        return direct
    return focus_entry(coverage, {"target": key})


def _attempt_tool(entry: Mapping[str, Any]) -> str:
    tool_id = str(entry.get("tool_id") or "")
    if tool_id.startswith(_NON_ATTEMPT_PREFIXES):
        return ""
    return tool_id


def distinct_attempts(
    actions: Iterable[Any],
    coverage: Coverage | None,
    ref: str,
    *,
    window: int = BARRIER_ATTEMPT_WINDOW,
) -> list[str]:
    """Distinct attacking tools used against ``ref`` in the recent window."""
    found: list[str] = []
    for entry in _tool_turns(actions, window):
        focus = _entry_for_arguments(coverage, entry)
        if focus is None or focus.ref.lower() != str(ref).strip().lower():
            continue
        tool_id = _attempt_tool(entry)
        if tool_id and tool_id not in found:
            found.append(tool_id)
    return found


def preview_executed_recently(
    actions: Iterable[Any],
    coverage: Coverage | None,
    ref: str,
    *,
    window: int = BARRIER_ATTEMPT_WINDOW,
) -> bool:
    """Whether an executed ``/preview`` module answered on ``ref`` recently."""
    for entry in _tool_turns(actions, window):
        focus = _entry_for_arguments(coverage, entry)
        if focus is None or focus.ref.lower() != str(ref).strip().lower():
            continue
        result = entry.get("tool_result")
        output = result.get("output") if isinstance(result, Mapping) else None
        if isinstance(output, Mapping) and output.get("preview_executed") is True:
            return True
    return False


def opening_fact_recorded(
    actions: Iterable[Any],
    coverage: Coverage | None,
    ref: str,
    *,
    window: int = BARRIER_ATTEMPT_WINDOW,
) -> bool:
    """Whether a ``hint``/``vulnerability`` for ``ref`` was registered recently."""
    for entry in _tool_turns(actions, window):
        if str(entry.get("tool_id") or "") != RECORD_FACT_TOOL:
            continue
        arguments = entry.get("arguments")
        if not isinstance(arguments, Mapping):
            continue
        if str(arguments.get("fact_type") or "").strip().lower() not in _OPENING_FACT_TYPES:
            continue
        key = str(arguments.get("key") or "").strip()
        if not key:
            continue
        focus = _entry_for_key(coverage, key)
        if focus is not None and focus.ref.lower() == str(ref).strip().lower():
            return True
    return False


def barrier_refusal(
    actions: Iterable[Any],
    coverage: Coverage | None,
    arguments: Mapping[str, Any] | None,
    *,
    window: int = BARRIER_ATTEMPT_WINDOW,
    minimum: int = BARRIER_MIN_DISTINCT_TOOLS,
) -> str | None:
    """Why a ``barrier`` may not close its branch yet, or ``None`` to allow it.

    Two refusals, in order: an executed preview is proof the vector *works*, so a
    barrier that says it does not is the measured false verdict; and fewer than
    ``minimum`` distinct attempts is one guess, not a verdict. A freshly
    registered ``vulnerability``/``hint`` on the same branch always wins: that is
    evidence, and the barrier is what would hide it.
    """
    if coverage is None or not isinstance(arguments, Mapping):
        return None
    if str(arguments.get("fact_type") or "").strip().lower() != "barrier":
        return None
    key = str(arguments.get("key") or "").strip()
    if not key:
        return None
    entry = _entry_for_key(coverage, key)
    if entry is None:
        return None
    if preview_executed_recently(actions, coverage, entry.ref, window=window):
        return BARRIER_PREVIEW_REFUSAL.format(ref=entry.ref, window=int(window))
    if opening_fact_recorded(actions, coverage, entry.ref, window=window):
        return None
    attempts = distinct_attempts(actions, coverage, entry.ref, window=window)
    if len(attempts) >= int(minimum):
        return None
    tools = ", ".join(f"`{tool_id}`" for tool_id in attempts) or "ninguno"
    return BARRIER_TOO_EARLY.format(
        ref=entry.ref,
        count=len(attempts),
        window=int(window),
        tools=tools,
        minimum=int(minimum),
    )


def closed_branch_refusal(
    *,
    tool_id: Any,
    arguments: Mapping[str, Any] | None,
    coverage: Coverage | None,
    closed_at: Mapping[str, int],
    iteration: int,
    window: int = CLOSED_BRANCH_BLOCK_TURNS,
) -> str | None:
    """Why a call against a closed branch is refused now, or ``None``.

    The window is counted from the iteration the loop closed the branch; a
    branch coverage has reopened (a newer ``vulnerability``) or one the model
    never closed is allowed, so the gate cannot outlive its own verdict.
    """
    if not attacks_a_branch(tool_id) or coverage is None:
        return None
    focus = focus_entry(coverage, arguments if isinstance(arguments, Mapping) else None)
    if focus is None:
        return None
    closed_iteration = closed_at.get(focus.ref)
    if closed_iteration is None:
        return None
    # Coverage owns reopening. The snapshot may predate the loop's own barrier
    # (it is gathered at the start of the turn), so a stale ``pendiente`` is not
    # evidence of reopening: only a registered vector is, and coverage counts it.
    if focus.status != STATUS_CLOSED and focus.vectors > 0:
        return None
    remaining = int(closed_iteration) + int(window) - int(iteration) + 1
    if remaining <= 0:
        return None
    open_branches = "; ".join(item.label for item in coverage.open_work[:3]) or "ninguna"
    following = coverage.first_open()
    return CLOSED_BRANCH_REFUSAL.format(
        ref=focus.ref,
        closed_at=int(closed_iteration),
        tools_used=str(tool_id),
        remaining=int(remaining),
        open_branches=open_branches,
        next_branch=following.label if following is not None else "ninguna",
    )


__all__ = [
    "BARRIER_ATTEMPT_WINDOW",
    "BARRIER_MIN_DISTINCT_TOOLS",
    "CLOSED_BRANCH_BLOCK_TURNS",
    "PREVIEW_EMPTY_BODY",
    "PREVIEW_MARKER",
    "PREVIEW_MODULE_NOTE",
    "attacks_a_branch",
    "barrier_refusal",
    "closed_branch_refusal",
    "distinct_attempts",
    "opening_fact_recorded",
    "preview_executed_recently",
]
