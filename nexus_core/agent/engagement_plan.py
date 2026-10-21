"""``loot/ENGAGEMENT_PLAN.md``: the engagement's TODO list, shared on disk.

The planner (:mod:`nexus_core.agent.planner`) answers *where the kill chain is*
from the blackboard. That is a frame, not a contract: it never says what this
engagement promised to do, so a run can close the moment one flag lands (run v8,
``run_a00cddfa69da488d8946188daddee3e3``). This module is the missing contract.

The plan is a Markdown file inside the engagement workspace, on purpose:

* the human can ``cat loot/ENGAGEMENT_PLAN.md`` and read the same checkboxes the
  agent sees;
* every subagent of the run reads it through the system prompt, and an isolated
  child (``supervisor``) reads the same file because the workspace is shared;
* it survives a ``--resume``: the file *is* the state, so a new process does not
  have to reconstruct it from a transcript.

Only the model closes a TODO, and only two ways: a verifier assertion whose
``fact_type`` the TODO declares (``fact_types``) ticks it automatically, or the
model marks it ``failed`` with a reason through ``nexus.orchestrator.update_plan``
(``pending`` never blocks forever silently: an exhausted TODO needs a stated
reason). The engine never marks a TODO ``done`` from prose.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

#: Where the plan lives, relative to the engagement workspace root.
PLAN_RELATIVE_PATH = os.path.join("loot", "ENGAGEMENT_PLAN.md")

#: Statuses of one TODO. ``in_progress`` exists because the model has to be able
#: to say "this is the branch I am on" without claiming it is finished.
TODO_PENDING = "pending"
TODO_IN_PROGRESS = "in_progress"
TODO_DONE = "done"
TODO_FAILED = "failed"
TODO_STATUSES: tuple[str, ...] = (TODO_PENDING, TODO_IN_PROGRESS, TODO_DONE, TODO_FAILED)

#: Markdown checkbox per status (``- [ ]``/``- [~]``/``- [x]``/``- [!]``).
TODO_MARKERS = {
    TODO_PENDING: "[ ]",
    TODO_IN_PROGRESS: "[~]",
    TODO_DONE: "[x]",
    TODO_FAILED: "[!]",
}
_MARKER_TO_STATUS = {marker[1]: status for status, marker in TODO_MARKERS.items()}

#: Pseudo fact types a TODO may declare besides the blackboard's own vocabulary.
#: ``flag`` is the one the closure gate cares about: a verified ``loot`` fact that
#: carries the flag token. ``report`` is never produced by a verifier, so a TODO
#: declaring it can only be closed by the model (which is the point: the report
#: is the model's artifact).
EXTRA_FACT_TYPES = ("flag", "report")

#: ``service``/``host``/... come from the blackboard; keep the list here so the
#: handler can validate without importing the kernel.
FACT_TYPES = (
    "host",
    "service",
    "web_app",
    "endpoint",
    "user",
    "email",
    "credential",
    "access",
    "privilege",
    "vulnerability",
    "barrier",
    "session",
    "artifact",
    "loot",
    "hint",
)

ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_TODO_LINE_RE = re.compile(r"^- \[(?P<mark>[ x~!])\] `(?P<id>[^`]+)`(?P<rest>.*)$")
_META_MARK = "(tipos: "


@dataclass(frozen=True)
class Todo:
    """One verifiable step of the engagement."""

    id: str
    description: str
    evidence: str = ""
    #: Fact types that close this TODO when a verifier asserts one. Empty means
    #: the model owns the closure (a report, a decision).
    fact_types: tuple[str, ...] = ()
    status: str = TODO_PENDING
    #: Set when the engine ticked the TODO: the fact type and key that proved it.
    verified_by: str = ""
    #: Why the TODO failed (required for ``failed``).
    reason: str = ""

    @property
    def done(self) -> bool:
        return self.status == TODO_DONE

    @property
    def open(self) -> bool:
        return self.status in (TODO_PENDING, TODO_IN_PROGRESS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "evidence": self.evidence,
            "fact_types": list(self.fact_types),
            "status": self.status,
            "verified_by": self.verified_by,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class EngagementPlan:
    """The plan of one engagement, as written in ``ENGAGEMENT_PLAN.md``."""

    objective: str = ""
    engagement_id: str = ""
    created_at: str = ""
    updated_at: str = ""
    #: ``model`` when the model drafted it, ``seed`` when the deterministic
    #: fallback had to (the LLM call failed). Both are binding once on disk.
    source: str = "model"
    todos: tuple[Todo, ...] = field(default_factory=tuple)

    # ------------------------------------------------------------- derived
    def by_id(self, todo_id: str) -> Todo | None:
        wanted = str(todo_id or "").strip()
        return next((todo for todo in self.todos if todo.id == wanted), None)

    @property
    def pending(self) -> tuple[Todo, ...]:
        return tuple(todo for todo in self.todos if todo.open)

    @property
    def failed(self) -> tuple[Todo, ...]:
        return tuple(todo for todo in self.todos if todo.status == TODO_FAILED)

    @property
    def flags_pending(self) -> tuple[Todo, ...]:
        """TODOs that promise a flag and are still open (the closure gate)."""
        return tuple(
            todo for todo in self.pending if "flag" in todo.fact_types
        )

    @property
    def complete(self) -> bool:
        return not self.pending

    def counts(self) -> dict[str, int]:
        counts = {status: 0 for status in TODO_STATUSES}
        for todo in self.todos:
            counts[todo.status] = counts.get(todo.status, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """The plan as the run result and the TUI carry it."""
        return {
            "engagement_id": self.engagement_id,
            "objective": self.objective,
            "source": self.source,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "counts": self.counts(),
            "pending": [todo.id for todo in self.pending],
            "failed": [todo.id for todo in self.failed],
            "flags_pending": [todo.id for todo in self.flags_pending],
            "complete": self.complete,
            "todos": [todo.to_dict() for todo in self.todos],
        }


# --------------------------------------------------------------------- helpers
def now_stamp() -> str:
    """UTC timestamp of the plan, second precision (``2026-10-20T10:00:00Z``)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


_now = now_stamp


def _one_line(value: Any, limit: int = 500) -> str:
    text = " ".join(str(value or "").split())
    return text[:limit].strip()


# ----------------------------------------------------------------- IO on disk
def plan_path(root: str | None = None) -> str:
    """Absolute path of the plan inside ``root`` (the workspace by default)."""
    base = root
    if base is None:
        from nexus_core.tools.handlers.workspace import workspace_root

        base = workspace_root()
    return os.path.join(os.path.abspath(str(base)), PLAN_RELATIVE_PATH)


def load_plan(root: str | None = None) -> EngagementPlan | None:
    """Read the plan from disk; ``None`` when the engagement has none yet."""
    path = plan_path(root)
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read(1_000_000)
    except (OSError, ValueError):
        return None
    return parse_markdown(text)


def load_plan_for(
    engagement_id: str | None, root: str | None = None
) -> EngagementPlan | None:
    """The plan of *this* engagement, or ``None``.

    A workspace can outlive one engagement, and a plan from another engagement
    must never bind this run: its TODOs are somebody else's promise. Comparing
    the header line is what keeps a stale file from refusing a closure it has
    nothing to do with.
    """
    plan = load_plan(root)
    if plan is None:
        return None
    if str(plan.engagement_id or "") != str(engagement_id or ""):
        return None
    return plan


def save_plan(plan: EngagementPlan, root: str | None = None) -> str:
    """Write ``plan`` atomically and return its path.

    Atomic because the TUI and a resumed run may read it while the loop writes:
    a reader never sees half a checkbox list (``os.replace`` is atomic on the
    same filesystem).
    """
    path = plan_path(root)
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    payload = render_markdown(plan)
    temporary = f"{path}.{os.getpid()}.tmp"
    try:
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            try:
                os.unlink(temporary)
            except OSError:  # pragma: no cover - defensive
                pass
    return path


# --------------------------------------------------------------- construction
def todo_from_mapping(raw: Mapping[str, Any]) -> Todo:
    """Validate one TODO as the model wrote it, or raise ``ValueError``."""
    if not isinstance(raw, Mapping):
        raise ValueError("every todo must be an object")
    todo_id = str(raw.get("id") or "").strip()
    if not ID_RE.fullmatch(todo_id):
        raise ValueError(
            f"invalid todo id {todo_id!r}: use letters, digits and _ . : - (max 64)"
        )
    description = _one_line(raw.get("description"))
    if not description:
        raise ValueError(f"todo '{todo_id}' needs a description")
    evidence = _one_line(raw.get("evidence"), 300)
    declared = raw.get("fact_types") or ()
    if isinstance(declared, str):
        declared = [item.strip() for item in declared.split(",") if item.strip()]
    if not isinstance(declared, (list, tuple)):
        raise ValueError(f"todo '{todo_id}': fact_types must be a list of names")
    allowed = set(FACT_TYPES) | set(EXTRA_FACT_TYPES)
    fact_types: list[str] = []
    for item in declared:
        name = str(item or "").strip().lower()
        if name not in allowed:
            raise ValueError(
                f"todo '{todo_id}': unknown fact type {name!r} "
                f"(allowed: {', '.join(sorted(allowed))})"
            )
        if name not in fact_types:
            fact_types.append(name)
    status = str(raw.get("status") or TODO_PENDING).strip().lower()
    if status not in TODO_STATUSES:
        raise ValueError(
            f"todo '{todo_id}': invalid status {status!r} "
            f"(allowed: {', '.join(TODO_STATUSES)})"
        )
    return Todo(
        id=todo_id,
        description=description,
        evidence=evidence,
        fact_types=tuple(fact_types),
        status=status,
        reason=_one_line(raw.get("reason"), 300),
    )


def new_plan(
    objective: str,
    engagement_id: str | None,
    todos: Sequence[Todo | Mapping[str, Any]],
    *,
    source: str = "model",
    created_at: str | None = None,
) -> EngagementPlan:
    """Build a plan from validated TODOs (``updated_at`` starts at creation)."""
    stamp = created_at or _now()
    seen: set[str] = set()
    unique: list[Todo] = []
    for todo in todos:
        if not isinstance(todo, Todo):
            todo = todo_from_mapping(todo)
        if todo.id in seen:
            raise ValueError(f"duplicate todo id: {todo.id!r}")
        seen.add(todo.id)
        unique.append(todo)
    if not unique:
        raise ValueError("the plan needs at least one todo")
    return EngagementPlan(
        objective=_one_line(objective, 2000),
        engagement_id=str(engagement_id or ""),
        created_at=stamp,
        updated_at=stamp,
        source=str(source or "model"),
        todos=tuple(unique),
    )


# ------------------------------------------------------------------ rendering
def render_markdown(plan: EngagementPlan) -> str:
    """Render the plan as the human/subagent-facing Markdown file."""
    marks = plan.counts()
    lines = [
        "# ENGAGEMENT PLAN",
        "",
        # The header is parsed back: keep the raw value (an empty engagement is
        # an empty field, never a placeholder that would read as another id).
        f"- engagement: {_one_line(plan.engagement_id)}",
        f"- objective: {_one_line(plan.objective)}",
        f"- created_at: {plan.created_at or _now()}",
        f"- updated_at: {plan.updated_at or plan.created_at or _now()}",
        f"- source: {plan.source or 'model'}",
        (
            "- progress: "
            f"{marks.get(TODO_DONE, 0)}/{len(plan.todos)} done"
            f" · {marks.get(TODO_PENDING, 0)} pending"
            f" · {marks.get(TODO_IN_PROGRESS, 0)} in progress"
            f" · {marks.get(TODO_FAILED, 0)} failed"
        ),
        "",
        "## TODOs",
        "",
    ]
    for todo in plan.todos:
        marker = TODO_MARKERS.get(todo.status, "[ ]")
        line = f"- {marker} `{todo.id}` — {todo.description}"
        if todo.fact_types or todo.evidence:
            meta: list[str] = []
            if todo.fact_types:
                meta.append("tipos: " + ", ".join(todo.fact_types))
            if todo.evidence:
                meta.append("evidencia: " + todo.evidence)
            line += " (" + "; ".join(meta) + ")"
        lines.append(line)
        if todo.verified_by:
            lines.append(f"      verificado: {todo.verified_by}")
        if todo.status == TODO_FAILED:
            lines.append(f"      motivo: {todo.reason or '(sin motivo)'}")
    return "\n".join(lines) + "\n"


def parse_markdown(text: str) -> EngagementPlan | None:
    """Parse ``ENGAGEMENT_PLAN.md`` back into a plan (``None`` when unreadable).

    Deliberately tolerant: the file is also edited by humans, so an unknown line
    is ignored and a TODO without the metadata block keeps its description.
    """
    if not isinstance(text, str) or "## TODOs" not in text:
        return None
    header = {
        "engagement": "",
        "objective": "",
        "created_at": "",
        "updated_at": "",
        "source": "model",
    }
    todos: list[Todo] = []
    current: Todo | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        for key in header:
            prefix = f"- {key}: "
            if stripped.startswith(prefix):
                header[key] = stripped[len(prefix):].strip()
        match = _TODO_LINE_RE.match(stripped)
        if match:
            body = match.group("rest").strip()
            # ``— description (tipos: …; evidencia: …)``; a TODO without the
            # metadata block is still valid (the model may write a short line).
            if body.startswith("—"):
                body = body[1:].strip()
            evidence, fact_types = _parse_meta(body)
            if fact_types or evidence:
                body = body[: body.rfind(_META_MARK)].strip()
            description = body
            status = _MARKER_TO_STATUS.get(match.group("mark"), TODO_PENDING)
            current = Todo(
                id=match.group("id").strip(),
                description=_one_line(description),
                evidence=evidence,
                fact_types=tuple(fact_types),
                status=status,
            )
            todos.append(current)
            continue
        if current is None:
            continue
        if stripped.startswith("verificado:"):
            current = replace(current, verified_by=stripped.split(":", 1)[1].strip())
            todos[-1] = current
        elif stripped.startswith("motivo:"):
            current = replace(current, reason=stripped.split(":", 1)[1].strip())
            todos[-1] = current
    if not todos:
        return None
    return EngagementPlan(
        objective=header["objective"],
        engagement_id=header["engagement"],
        created_at=header["created_at"],
        updated_at=header["updated_at"],
        source=header["source"] or "model",
        todos=tuple(todos),
    )


def _parse_meta(text: str) -> tuple[str, list[str]]:
    """Split our own ``(tipos: a, b; evidencia: …)`` suffix from a TODO line."""
    body = text.strip()
    start = body.rfind(_META_MARK)
    if start < 0:
        return "", []
    meta = body[start + len(_META_MARK):]
    if not meta.endswith(")"):
        return "", []
    meta = meta[:-1]
    types_text, _sep, evidence = meta.partition("; evidencia: ")
    fact_types = [item.strip().lower() for item in types_text.split(",") if item.strip()]
    return _one_line(evidence, 300), fact_types


# ------------------------------------------------------------ reconciliation
def _fact_has_flag(fact: Mapping[str, Any]) -> bool:
    value = fact.get("value")
    if not isinstance(value, Mapping):
        return False
    return bool(value.get("flag"))


#: Flag files a TODO may name (``Capturar root.txt``). When it does, the fact
#: has to be *that* file: the first flag captured must not tick the TODO that
#: promises root (run v8 closed on exactly that confusion).
_FLAG_FILE_RE = re.compile(r"[\w./-]*\.txt|proof\.txt|local\.txt")


def _flag_file_hint(todo: "Todo") -> str:
    """The flag file a TODO names, or ``""`` when it names none."""
    text = f"{todo.id} {todo.description} {todo.evidence}".lower()
    match = _FLAG_FILE_RE.search(text)
    return match.group(0).rsplit("/", 1)[-1] if match else ""


def _fact_for_type(
    kind: str,
    facts: Sequence[Mapping[str, Any]],
    *,
    todo: "Todo | None" = None,
) -> Mapping[str, Any] | None:
    """The first fact that proves ``kind`` for this TODO, or ``None``.

    ``flag`` is not a blackboard type: it is a verified ``loot`` fact that
    carries the token, which is exactly what the flag verifier writes. A TODO
    that names a flag file (``root.txt``) only accepts that file, so the first
    flag of the engagement cannot tick the TODO of the last one.
    """
    wanted = _flag_file_hint(todo) if todo is not None else ""
    for fact in facts:
        fact_type = str(fact.get("fact_type") or "")
        if kind == "flag":
            if fact_type != "loot" or not _fact_has_flag(fact):
                continue
            if wanted:
                key = str(fact.get("key") or "").lower()
                raw_value = fact.get("value")
                value: Mapping[str, Any] = (
                    raw_value if isinstance(raw_value, Mapping) else {}
                )
                path = str(value.get("path") or value.get("file") or "").lower()
                if wanted not in key and wanted not in path:
                    continue
            return fact
        elif fact_type == kind:
            return fact
    return None


def reconcile(
    plan: EngagementPlan | None,
    verified_facts: Iterable[Mapping[str, Any]],
    *,
    engagement_id: str | None = None,
) -> tuple[EngagementPlan | None, list[str]]:
    """Tick every open TODO whose declared fact type is on the board.

    Returns ``(plan, newly_done_ids)``; the plan is returned unchanged (same
    object) when nothing moved, so callers can skip the disk write. Facts from a
    *different* engagement never tick anything: a plan outlives one run but not
    one engagement.
    """
    if plan is None:
        return None, []
    if engagement_id and plan.engagement_id and str(engagement_id) != plan.engagement_id:
        return plan, []
    facts = [
        fact
        for fact in verified_facts
        if isinstance(fact, Mapping) and fact.get("verified") is True
    ]
    if not facts:
        return plan, []
    ticks: list[str] = []
    updated: list[Todo] = []
    for todo in plan.todos:
        if not todo.open or not todo.fact_types:
            updated.append(todo)
            continue
        matched = None
        for kind in todo.fact_types:
            matched = _fact_for_type(kind, facts, todo=todo)
            if matched is not None:
                break
        if matched is None:
            updated.append(todo)
            continue
        kind = str(matched.get("fact_type") or "")
        key = _one_line(matched.get("key"), 120)
        updated.append(
            replace(
                todo,
                status=TODO_DONE,
                verified_by=_one_line(f"{kind}:{key}" if key else kind, 200),
            )
        )
        ticks.append(todo.id)
    if not ticks:
        return plan, []
    return (
        replace(plan, todos=tuple(updated), updated_at=_now()),
        ticks,
    )


# --------------------------------------------------------------- prompt / TUI
def prompt_block(plan: EngagementPlan | None, *, max_todos: int = 40) -> str:
    """The block the loop injects into every system prompt (empty without plan)."""
    if plan is None or not plan.todos:
        return ""
    marks = plan.counts()
    done, total = marks.get(TODO_DONE, 0), len(plan.todos)
    lines = [
        "PLAN DEL ENGAGEMENT (`loot/ENGAGEMENT_PLAN.md`, compartido con todos los "
        f"subagentes): {done}/{total} TODOs hechos · "
        f"{marks.get(TODO_PENDING, 0)} pendientes · "
        f"{marks.get(TODO_IN_PROGRESS, 0)} en curso · "
        f"{marks.get(TODO_FAILED, 0)} fallidos",
    ]
    shown = plan.todos[:max_todos]
    for todo in shown:
        evidence = f" (prueba: {todo.verified_by})" if todo.verified_by else ""
        reason = f" [motivo: {todo.reason}]" if todo.status == TODO_FAILED else ""
        lines.append(
            f"  {TODO_MARKERS.get(todo.status, '[ ]')} {todo.id} — "
            f"{todo.description}{evidence}{reason}"
        )
    if len(plan.todos) > max_todos:
        lines.append(f"  … {len(plan.todos) - max_todos} TODOs más en el fichero")
    nxt = plan.pending[0] if plan.pending else None
    if nxt is not None:
        lines.append(
            f"SIGUIENTE TODO: {nxt.id} — {nxt.description}"
            + (f" (evidencia: {nxt.evidence})" if nxt.evidence else "")
        )
    else:
        lines.append("TODOS COMPLETADOS: puedes cerrar la tarea (task_complete).")
    return "\n".join(lines)


def status_payload(plan: EngagementPlan | None, path: str | None = None) -> dict[str, Any]:
    """JSON view of the plan for ``get_plan_status`` and the TUI panel."""
    if plan is None:
        return {
            "plan": None,
            "exists": False,
            "path": path or PLAN_RELATIVE_PATH,
            "counts": {status: 0 for status in TODO_STATUSES},
            "pending": [],
            "todos": [],
            "complete": False,
        }
    return {
        "plan": PLAN_RELATIVE_PATH,
        "exists": True,
        "path": PLAN_RELATIVE_PATH,
        "engagement_id": plan.engagement_id,
        "objective": plan.objective,
        "source": plan.source,
        "created_at": plan.created_at,
        "updated_at": plan.updated_at,
        "counts": plan.counts(),
        "pending": [todo.id for todo in plan.pending],
        "failed": [todo.id for todo in plan.failed],
        "flags_pending": [todo.id for todo in plan.flags_pending],
        "complete": plan.complete,
        "todos": [todo.to_dict() for todo in plan.todos],
        "markdown": render_markdown(plan),
    }


def panel_todos(plan: EngagementPlan | None, *, limit: int = 40) -> list[dict[str, Any]]:
    """Compact TODO rows for the TUI side panel."""
    if plan is None:
        return []
    return [
        {
            "id": todo.id,
            "description": todo.description,
            "status": todo.status,
            "verified_by": todo.verified_by,
        }
        for todo in plan.todos[:limit]
    ]


# -------------------------------------------------------- objective shape
#: Objectives that only need reasoning: no plan, no tools. The plan is a
#: property of an *engagement* ("compromete el sistema, escala a root"), never of
#: a question, which is why this classifier exists instead of planning always.
_QUESTION_MARKERS = (
    "qué es",
    "que es",
    "explica",
    "explícame",
    "explicame",
    "cómo funciona",
    "como funciona",
    "por qué",
    "por que",
    "resume",
    "resúmeme",
    "resumeme",
    "describe ",
    "diferencia entre",
    "recomienda",
    "qué opinas",
    "que opinas",
)

#: Imperative verbs: the objective *asks for work on a target*. These decide the
#: classification even when the sentence is written as a question
#: ("¿puedes escanear 10.10.10.5?").
_ACTION_MARKERS = (
    "penetration",
    "prueba de penetración",
    "prueba de penetracion",
    "audita",
    "auditoría",
    "auditoria",
    "compromete",
    "comprometer",
    "explota",
    "explotar",
    "escala a",
    "escalar",
    "captura",
    "capturar",
    "reconocimiento",
    "enumera",
    "enumerar",
    "escanea",
    "escanear",
    "ataca",
    "atacar",
    "hackea",
)

#: Topic nouns: they only make an objective an engagement when the sentence is
#: not a question. "¿Qué es un pivot en un pentest?" names the topic and asks for
#: an explanation; it must not trigger a plan.
_TOPIC_MARKERS = (
    "pentest",
    "flag",
    "root",
    "vulnerabilidad",
    "vulnerabilidades",
    "intrusión",
    "intrusion",
    "credencial",
    "credenciales",
    "ctf",
    "shell",
)

_TARGET_RE = re.compile(
    r"(\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b)|(\bhttps?://[^\s]+)|"
    r"(\b[a-z0-9-]+\.(?:com|net|org|local|htb|thm|io|dev|es)\b)"
)


def is_engagement_objective(objective: str) -> bool:
    """Whether ``objective`` asks for work against a target (so it needs a plan).

    A question ("¿qué es un pivot?") gets reasoning, not a TODO list. This is the
    switch the operator asked for: the ENGAGEMENT PLAN applies to engagement
    instructions, never to a chat turn. ``/ask`` bypasses the loop entirely, so
    this only decides whether a *loop* objective needs the planning phase.
    """
    text = " ".join(str(objective or "").lower().split())
    if not text:
        return False
    asks = any(marker in text for marker in _QUESTION_MARKERS)
    acts = any(marker in text for marker in _ACTION_MARKERS)
    if asks and not acts:
        return False
    if acts or _TARGET_RE.search(text):
        return True
    return any(marker in text for marker in _TOPIC_MARKERS)


def seed_todos(objective: str) -> list[Todo]:
    """Deterministic fallback plan, used when the planning call cannot answer.

    It is the kill chain of :mod:`nexus_core.agent.planner` expressed as TODOs, so
    a run always starts with a contract even if the provider is down. The model
    replaces it with its own via ``create_plan`` on the first turn.
    """
    return [
        Todo(
            "recon",
            "Descubrir todos los puertos y servicios del objetivo",
            evidence="nmap full_tcp + service",
            fact_types=("host", "service"),
        ),
        Todo(
            "enumeration",
            "Enumerar cada servicio (web, FTP, SMB, SSH…) y sus pistas",
            evidence="endpoint/user/vulnerability facts",
            fact_types=("endpoint", "user", "vulnerability"),
        ),
        Todo(
            "access",
            "Obtener acceso inicial: validar credenciales o explotar el vector",
            evidence="credential/session/access fact verified",
            fact_types=("credential", "session", "access"),
        ),
        Todo(
            "privesc",
            "Escalar privilegios y demostrar uid=0 / Administrador",
            evidence="privilege fact verified",
            fact_types=("privilege",),
        ),
        Todo(
            "loot_user",
            "Capturar el primer loot (user.txt o equivalente)",
            evidence="loot fact verified",
            fact_types=("loot",),
        ),
        Todo(
            "flag_root",
            "Capturar la flag de root del objetivo",
            evidence="flag fact verified",
            fact_types=("flag",),
        ),
        Todo(
            "report",
            "Consolidar el informe final con la cadena de ataque",
            evidence="nexus.report.generate",
        ),
    ]


__all__ = [
    "EXTRA_FACT_TYPES",
    "EngagementPlan",
    "FACT_TYPES",
    "PLAN_RELATIVE_PATH",
    "TODO_DONE",
    "TODO_FAILED",
    "TODO_IN_PROGRESS",
    "TODO_MARKERS",
    "TODO_PENDING",
    "TODO_STATUSES",
    "Todo",
    "is_engagement_objective",
    "load_plan",
    "load_plan_for",
    "now_stamp",
    "new_plan",
    "panel_todos",
    "parse_markdown",
    "plan_path",
    "prompt_block",
    "reconcile",
    "render_markdown",
    "save_plan",
    "seed_todos",
    "status_payload",
    "todo_from_mapping",
]
