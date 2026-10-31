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

#: How many times the same unsatisfiable ``barrier`` may be refused before it is
#: accepted anyway and stamped unsubstantiated (``invalid_*``, which
#: ``coverage.barrier_is_conclusive`` reads as "does not close the branch").
#: Measured in hijack_v7 (2026-10-30): the pivot hint tells the model to
#: document a dead end with ``record_fact(fact_type="barrier")`` and this gate
#: refused that call nine times, so the same instruction could never be
#: satisfied and seventeen turns produced no fact.
BARRIER_INSISTENCE_LIMIT = 2

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
SKILL_LOAD_TOOL = "nexus.skill.load"
SKILL_LIST_TOOL = "nexus.skill.list"

#: Failed loads of one skill name tolerated before the loop answers the call
#: itself. The handler already answers the first miss with the real catalogue, so
#: a second request for the same name cannot learn anything new: it is the
#: measured loop of the Bounty Hacker run (2026-10-30), where ``web-recon-master``
#: was refused because the catalogue was read from the wrong directory and the
#: name came back turn after turn. A name the catalogue now holds is never
#: refused (a skill created mid-run is legitimate).
UNKNOWN_SKILL_RETRY_LIMIT = 1

UNKNOWN_SKILL_REFUSAL = (
    "SKILL INEXISTENTE: `{name}` ya se intentó cargar {count} vez/veces en este "
    "run y no está en el catálogo ({catalogue}). No la vuelvas a pedir. "
    "Catálogo real: {known}. Sigue con las tools que ya tienes o carga una de "
    "las listadas con `{tool}`."
)

UNKNOWN_SKILL_EMPTY_CATALOGUE = (
    "SKILL INEXISTENTE: `{name}` no está en el catálogo y el catálogo está vacío "
    "({catalogue}): no hay ninguna receta que cargar en este host, así que NO "
    "reintentes `{tool}`. Continúa el engagement con las tools del catálogo de "
    "herramientas y documenta el atasco si no hay vector."
)

#: Fact types the deterministic verifier owns: it derives them from a tool's
#: parsed output (nmap XML, httpx JSONL), so a model that writes them back adds
#: nothing. Only these are refused; every other type stays the model's to record.
VERIFIER_OWNED_FACT_TYPES: frozenset[str] = frozenset({"host", "service"})

REDUNDANT_FACT_GUIDANCE = (
    "`{fact_type}:{key}` YA está en la pizarra, verificado por el verifier al "
    "ejecutar la tool que lo observó: registrarlo otra vez no añade ningún hecho "
    "y gasta un turno. Deja de registrar hechos del verifier y ataca la "
    "superficie que ya conoces.{next_branch} Si necesitas releerla, usa "
    "nexus.knowledge.query_facts (una sola vez), no record_fact."
)

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


#: Outcomes a tool can answer with that *are* a verdict about the branch: the
#: service refused, answered "nothing here", or the command it ran failed. One
#: such answer is already more than a guess, so it justifies the barrier the
#: pivot hint asks for.
CONCULSIVE_ATTEMPT_OUTCOMES: frozenset[str] = frozenset(
    {"negative", "denied", "unsupported", "command_failed"}
)


def conclusive_attempt(
    actions: Iterable[Any],
    coverage: Coverage | None,
    ref: str,
    *,
    window: int = BARRIER_ATTEMPT_WINDOW,
) -> bool:
    """Whether a tool that attacked ``ref`` recently got a determinate answer.

    Measured in hijack_v7 (2026-10-30): ``nexus.recon.ftp`` answered
    ``530 Login incorrect`` on ``:21`` -a real verdict from the server- and the
    barrier that documented it was refused for having only *one* distinct tool.
    A refusal that proves the vector does not work is not the "one guess" this
    gate exists to stop.
    """
    for entry in _tool_turns(actions, window):
        focus = _entry_for_arguments(coverage, entry)
        if focus is None or focus.ref.lower() != str(ref).strip().lower():
            continue
        if not _attempt_tool(entry):
            continue
        result = entry.get("tool_result")
        outcome = str(result.get("outcome") or "").strip().lower() if isinstance(
            result, Mapping
        ) else ""
        if outcome in CONCULSIVE_ATTEMPT_OUTCOMES:
            return True
    return False


def barrier_refusal(
    actions: Iterable[Any],
    coverage: Coverage | None,
    arguments: Mapping[str, Any] | None,
    *,
    window: int = BARRIER_ATTEMPT_WINDOW,
    minimum: int = BARRIER_MIN_DISTINCT_TOOLS,
    no_progress: int = 0,
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
    # The loop already declared this branch stalled (``no_progress`` barren
    # turns): its own verdict and the model's barrier agree, so refusing the
    # bookkeeping only burns another turn. The fact is still stamped
    # ``sweep_attempted: false`` by the handler, so it cannot close the branch.
    if int(no_progress or 0) >= int(window):
        return None
    if conclusive_attempt(actions, coverage, entry.ref, window=window):
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


def redundant_fact_refusal(
    facts: Iterable[Any],
    arguments: Mapping[str, Any] | None,
    *,
    next_branch: str = "",
) -> str | None:
    """Why a ``record_fact`` adds nothing, or ``None`` when it does.

    Measured in hijack_v7 (2026-10-30, iterations 3-11): the ``nmap`` turn
    derived all ten facts (host + nine services) from the XML, and the model then
    spent nine turns writing each one back with ``record_fact``. Every call
    succeeded, every turn added zero facts, and the loop read the sequence as a
    dead end until it closed the only web branch.

    Only ``host``/``service`` are considered, and only when the board already
    holds a **verified** fact with every key/value the model sent: a different
    value is the model adding something (a product, a version, a note) and is
    allowed through to the handler.
    """
    if not isinstance(arguments, Mapping):
        return None
    fact_type = str(arguments.get("fact_type") or "").strip().lower()
    key = str(arguments.get("key") or "").strip()
    if fact_type not in VERIFIER_OWNED_FACT_TYPES or not key:
        return None
    raw_value = arguments.get("value")
    value: Mapping[str, Any] = raw_value if isinstance(raw_value, Mapping) else {}
    for fact in facts or ():
        if not isinstance(fact, Mapping) or not fact.get("verified"):
            continue
        if str(fact.get("fact_type") or "").strip().lower() != fact_type:
            continue
        if str(fact.get("key") or "").strip() != key:
            continue
        held = fact.get("value")
        if not isinstance(held, Mapping):
            held = {}
        if any(held.get(name) != item for name, item in value.items()):
            continue
        return REDUNDANT_FACT_GUIDANCE.format(
            fact_type=fact_type,
            key=key,
            next_branch=f" Siguiente rama abierta: {next_branch}." if next_branch else "",
        )
    return None


def unknown_skill_refusal(
    actions: Iterable[Any],
    arguments: Mapping[str, Any] | None,
    *,
    known: Iterable[str] = (),
    catalogue: str = "",
    limit: int = UNKNOWN_SKILL_RETRY_LIMIT,
) -> str | None:
    """Why a ``nexus.skill.load`` of a name that already failed is refused now.

    A missing skill is an argument error, and the handler already answers the
    first one with the real catalogue. What the loop adds is the bound: the same
    name is not requested over and over, because each turn costs a model call and
    the measured run spent them on a name that could never resolve.

    Only *failed* loads of the **same** name count; a successful load, another
    name, or a name the catalogue now holds is untouched, and the refusal never
    stops the run -it is a correction the model reads and moves on from.
    """
    if not isinstance(arguments, Mapping):
        return None
    name = str(arguments.get("name") or "").strip()
    if not name:
        return None
    if name in {str(item) for item in known}:
        # The catalogue gained it (created mid-run): the load is legitimate.
        return None
    failed = 0
    for entry in actions or ():
        if not isinstance(entry, Mapping):
            continue
        if str(entry.get("tool_id") or "") != SKILL_LOAD_TOOL:
            continue
        past = entry.get("arguments")
        if not isinstance(past, Mapping):
            continue
        if str(past.get("name") or "").strip() != name:
            continue
        result = entry.get("tool_result")
        if isinstance(result, Mapping) and not result.get("success"):
            failed += 1
    if failed < int(limit):
        return None
    if not list(known):
        return UNKNOWN_SKILL_EMPTY_CATALOGUE.format(
            name=name, catalogue=catalogue or "?", tool=SKILL_LOAD_TOOL
        )
    return UNKNOWN_SKILL_REFUSAL.format(
        name=name,
        count=failed,
        catalogue=catalogue or "?",
        known=", ".join(sorted(str(item) for item in known)),
        tool=SKILL_LOAD_TOOL,
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
    if focus.status != STATUS_CLOSED and focus.vulnerabilities > 0:
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
    "BARRIER_INSISTENCE_LIMIT",
    "BARRIER_MIN_DISTINCT_TOOLS",
    "CLOSED_BRANCH_BLOCK_TURNS",
    "CONCULSIVE_ATTEMPT_OUTCOMES",
    "REDUNDANT_FACT_GUIDANCE",
    "SKILL_LIST_TOOL",
    "SKILL_LOAD_TOOL",
    "UNKNOWN_SKILL_REFUSAL",
    "UNKNOWN_SKILL_RETRY_LIMIT",
    "VERIFIER_OWNED_FACT_TYPES",
    "conclusive_attempt",
    "redundant_fact_refusal",
    "PREVIEW_EMPTY_BODY",
    "PREVIEW_MARKER",
    "PREVIEW_MODULE_NOTE",
    "attacks_a_branch",
    "barrier_refusal",
    "closed_branch_refusal",
    "distinct_attempts",
    "opening_fact_recorded",
    "preview_executed_recently",
    "unknown_skill_refusal",
]
