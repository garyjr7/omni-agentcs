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
from fnmatch import fnmatchcase
from datetime import datetime, timezone
from typing import Any, Collection, Iterable, Mapping, Sequence

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
    #: ``route`` mirrors :data:`nexus_core.kernel.blackboard.FACT_TYPES`: a TODO
    #: that promises to reach a host is closed by the verifier that proved the
    #: path (`nexus.post.verify_route`), never by a tunnel the model says it
    #: opened.
    "route",
    #: ``task`` mirrors the blackboard's background-task outcome type; a TODO can
    #: declare it when the deliverable is "the scan already ran".
    "task",
)

ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_TODO_LINE_RE = re.compile(r"^- \[(?P<mark>[ x~!])\] `(?P<id>[^`]+)`(?P<rest>.*)$")
_META_MARK = "(tipos: "
_CONDITION_MARK = "; condición: "

#: Clauses a TODO condition can ask of a fact. ``source``/``key`` compare exactly
#: unless they contain a wildcard; ``key_matches`` is always a glob; any
#: ``value.<field>`` reads that field of the fact's value. Nothing else is
#: accepted: a condition that cannot be evaluated would silently never match (or
#: worse, always match), so an unknown clause is a validation error.
_CONDITION_CLAUSES = ("source", "key", "key_matches")
_CONDITION_VALUE_PREFIX = "value."
_GLOB_CHARS = frozenset("*?[")


@dataclass(frozen=True)
class Todo:
    """One verifiable step of the engagement."""

    id: str
    description: str
    evidence: str = ""
    #: Fact types that close this TODO when a verifier asserts one. Empty means
    #: the model owns the closure (a report, a decision).
    fact_types: tuple[str, ...] = ()
    #: Per-fact-type condition the proving fact must satisfy (``{"credential":
    #: {"source": "apk_decompile", "key_matches": "synthetic-user*"}}``). Required when
    #: the type alone would accept the wrong fact: ``apk-creds`` was ticked by the
    #: shadow hash on DeadDrop (2026-10-22) because both TODOs declared
    #: ``credential`` and nothing distinguished them.
    condition: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
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
            "condition": {
                kind: dict(clauses) for kind, clauses in self.condition.items()
            },
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
    condition = _condition_from_mapping(
        raw.get("condition"), todo_id=todo_id, fact_types=fact_types
    )
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
        condition=condition,
        status=status,
        reason=_one_line(raw.get("reason"), 300),
    )


def _condition_from_mapping(
    raw: Any, *, todo_id: str, fact_types: Sequence[str]
) -> dict[str, dict[str, str]]:
    """Validate the optional ``condition`` a TODO declares, or raise ``ValueError``.

    Shape: ``{fact_type: {clause: expected}}``. The fact type has to be one the
    TODO already declares (a condition on a type it does not accept could never
    run) and every clause has to be one this engine knows how to evaluate.
    """
    if raw in (None, ""):
        return {}
    if not isinstance(raw, Mapping):
        raise ValueError(
            f"todo '{todo_id}': condition must be an object "
            "({fact_type: {clause: value}})"
        )
    parsed: dict[str, dict[str, str]] = {}
    for kind, clauses in raw.items():
        name = str(kind or "").strip().lower()
        if name not in fact_types:
            raise ValueError(
                f"todo '{todo_id}': condition names {name!r}, which the TODO does "
                f"not declare in fact_types ({', '.join(fact_types) or 'none'})"
            )
        if not isinstance(clauses, Mapping) or not clauses:
            raise ValueError(
                f"todo '{todo_id}': condition[{name!r}] must be a non-empty object"
            )
        wanted: dict[str, str] = {}
        for clause, expected in clauses.items():
            key = str(clause or "").strip()
            if key not in _CONDITION_CLAUSES and not key.startswith(_CONDITION_VALUE_PREFIX):
                raise ValueError(
                    f"todo '{todo_id}': unknown condition clause {key!r} "
                    f"(allowed: {', '.join(_CONDITION_CLAUSES)}, value.<field>)"
                )
            if key.startswith(_CONDITION_VALUE_PREFIX) and len(key) == len(
                _CONDITION_VALUE_PREFIX
            ):
                raise ValueError(
                    f"todo '{todo_id}': condition clause {key!r} names no field"
                )
            text = str(expected if expected is not None else "").strip()
            if not text:
                raise ValueError(
                    f"todo '{todo_id}': condition[{name!r}][{key!r}] needs a value"
                )
            wanted[key] = text
        parsed[name] = wanted
    return parsed


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
            if todo.condition:
                meta.append("condición: " + _condition_text(todo.condition))
            if todo.evidence:
                meta.append("evidencia: " + todo.evidence)
            line += " (" + "; ".join(meta) + ")"
        lines.append(line)
        if todo.verified_by:
            lines.append(f"      verificado: {todo.verified_by}")
        if todo.status == TODO_FAILED:
            lines.append(f"      motivo: {todo.reason or '(sin motivo)'}")
    return "\n".join(lines) + "\n"


def _condition_text(condition: Mapping[str, Mapping[str, str]]) -> str:
    """Render a condition as ``credential.source=x, credential.key_matches=y*``."""
    return ", ".join(
        f"{kind}.{clause}={expected}"
        for kind, clauses in condition.items()
        for clause, expected in clauses.items()
    )


def _parse_condition_text(text: str) -> dict[str, dict[str, str]]:
    """Read back :func:`_condition_text` (tolerant: unknown pieces are dropped)."""
    parsed: dict[str, dict[str, str]] = {}
    for item in text.split(","):
        piece = item.strip()
        head, sep, expected = piece.partition("=")
        kind, dot, clause = head.partition(".")
        if not sep or not dot or not kind.strip() or not clause.strip():
            continue
        parsed.setdefault(kind.strip(), {})[clause.strip()] = expected.strip()
    return parsed


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
            evidence, fact_types, condition = _parse_meta(body)
            if fact_types or evidence:
                body = body[: body.rfind(_META_MARK)].strip()
            description = body
            status = _MARKER_TO_STATUS.get(match.group("mark"), TODO_PENDING)
            current = Todo(
                id=match.group("id").strip(),
                description=_one_line(description),
                evidence=evidence,
                fact_types=tuple(fact_types),
                condition=condition,
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


def _parse_meta(
    text: str,
) -> tuple[str, list[str], dict[str, dict[str, str]]]:
    """Split our own ``(tipos: …; condición: …; evidencia: …)`` suffix."""
    body = text.strip()
    start = body.rfind(_META_MARK)
    if start < 0:
        return "", [], {}
    meta = body[start + len(_META_MARK):]
    if not meta.endswith(")"):
        return "", [], {}
    meta = meta[:-1]
    types_text, has_condition, rest = meta.partition(_CONDITION_MARK)
    if has_condition:
        condition_text, _sep, evidence = rest.partition("; evidencia: ")
    else:
        condition_text = ""
        types_text, _sep, evidence = meta.partition("; evidencia: ")
    fact_types = [item.strip().lower() for item in types_text.split(",") if item.strip()]
    return _one_line(evidence, 300), fact_types, _parse_condition_text(condition_text)


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


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _todo_hosts(todo: "Todo") -> set[str]:
    """The IPv4 addresses a TODO names, or an empty set when it names none."""
    return set(_IPV4_RE.findall(f"{todo.id} {todo.description} {todo.evidence}"))


def _fact_hosts(fact: Mapping[str, Any]) -> set[str]:
    """The IPv4 addresses a fact is attributed to (``key``/``target``)."""
    return set(
        _IPV4_RE.findall(
            " ".join(str(fact.get(field) or "") for field in ("key", "target"))
        )
    )


def _value_matches(expected: str, actual: Any) -> bool:
    """Exact match, or a simple glob when ``expected`` carries a wildcard."""
    text = "" if actual is None else str(actual)
    if any(char in expected for char in _GLOB_CHARS):
        return fnmatchcase(text.lower(), expected.lower())
    return text.lower() == expected.lower()


def _condition_matches(
    condition: Mapping[str, str], fact: Mapping[str, Any]
) -> bool:
    """Whether ``fact`` satisfies every clause of a TODO condition.

    ``source``/``key`` read the fact's provenance and key (exact, or glob when
    the expected value carries a wildcard); ``key_matches`` is always a glob;
    ``value.<field>`` reads that field of the fact's value. A clause that names
    a field the fact does not carry never matches -that is the point of the
    condition-.
    """
    raw_value = fact.get("value")
    value = raw_value if isinstance(raw_value, Mapping) else {}
    for clause, expected in condition.items():
        if clause.startswith(_CONDITION_VALUE_PREFIX):
            field = clause[len(_CONDITION_VALUE_PREFIX):]
            if not _value_matches(expected, value.get(field)):
                return False
        elif clause in ("key", "key_matches"):
            if not _value_matches(expected, fact.get("key")):
                return False
        elif not _value_matches(expected, fact.get("source")):
            return False
    return True


def _fact_for_type(
    kind: str,
    facts: Sequence[Mapping[str, Any]],
    *,
    todo: "Todo | None" = None,
    proven_hosts: Collection[str] = (),
    condition: Mapping[str, str] | None = None,
) -> Mapping[str, Any] | None:
    """The first fact that proves ``kind`` for this TODO, or ``None``.

    ``flag`` is not a blackboard type: it is a verified ``loot`` fact that
    carries the token, which is exactly what the flag verifier writes. A TODO
    that names a flag file (``root.txt``) only accepts that file, so the first
    flag of the engagement cannot tick the TODO of the last one.

    A TODO that names hosts only accepts facts attributed to one of them: on
    DeadDrop (2026-10-22) the DMZ sweep of ``192.168.11.200`` ticked the
    ``pivot`` and ``enum-lan`` TODOs, which named ``192.168.11.51`` and
    ``192.168.11.100``, so the plan claimed the internal network was reached
    before it was touched. A fact that carries no address of its own (a
    hostname-only finding) cannot be attributed either way and still counts.

    ``proven_hosts`` are the hosts an earlier TODO already proved. A TODO that
    names a host already proved **and** a new one is a step from the first to
    the second ("pivot from 192.168.11.200 to 192.168.11.51"): only the new
    host can close it, which is what stops the source host's own sweep from
    proving the pivot. When every host it names is already proved the TODO is a
    re-verification of a known host and keeps the old rule.
    """
    wanted = _flag_file_hint(todo) if todo is not None else ""
    wanted_hosts = _todo_hosts(todo) if todo is not None else set()
    accept_hosts = wanted_hosts - set(proven_hosts)
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
            if condition and not _condition_matches(condition, fact):
                continue
            return fact
        elif fact_type == kind:
            if accept_hosts:
                seen = _fact_hosts(fact)
                if seen and not seen & accept_hosts:
                    continue
            elif wanted_hosts:
                seen = _fact_hosts(fact)
                if seen and not seen & wanted_hosts:
                    continue
            if condition and not _condition_matches(condition, fact):
                continue
            return fact
    return None


def _condition_expectation(todo: Todo) -> str:
    """The clauses a done TODO claims to satisfy, as one readable line."""
    clauses = [
        f"{key}={value}"
        for condition in (todo.condition or {}).values()
        for key, value in condition.items()
    ]
    return ", ".join(clauses)


def _fact_observation(todo: Todo, fact: Mapping[str, Any] | None) -> str:
    """What the board actually offers for the clauses the condition names.

    Read exactly like :func:`_condition_matches` does: a bare clause reads the
    fact's provenance (``source``/``key``), ``value.<field>`` reads its value.
    """
    if fact is None:
        return "no matching fact"
    raw_value = fact.get("value")
    value = raw_value if isinstance(raw_value, Mapping) else {}
    parts: list[str] = []
    for condition in (todo.condition or {}).values():
        for clause in sorted(condition):
            if clause.startswith(_CONDITION_VALUE_PREFIX):
                field = clause[len(_CONDITION_VALUE_PREFIX):]
                parts.append(f"{clause}={value.get(field)}")
            else:
                parts.append(f"{clause}={fact.get(clause)}")
    if not parts:
        return f"{fact.get('fact_type')}:{fact.get('key')}"
    return ", ".join(parts)


def _evidence_still_holds(
    todo: Todo,
    facts: Sequence[Mapping[str, Any]],
    proven_hosts: Collection[str],
) -> Mapping[str, Any] | None:
    """The fact that still proves a done TODO, or ``None`` (Tanda C, 5b)."""
    for kind in todo.fact_types:
        matched = _fact_for_type(
            kind,
            facts,
            todo=todo,
            proven_hosts=proven_hosts,
            condition=todo.condition.get(kind),
        )
        if matched is not None:
            return matched
    return None


def reconcile(
    plan: EngagementPlan | None,
    verified_facts: Iterable[Mapping[str, Any]],
    *,
    engagement_id: str | None = None,
    revalidate: bool = False,
) -> tuple[EngagementPlan | None, list[str]]:
    """Tick every open TODO whose declared fact type is on the board.

    Returns ``(plan, newly_done_ids)``; the plan is returned unchanged (same
    object) when nothing moved, so callers can skip the disk write. Facts from a
    *different* engagement never tick anything: a plan outlives one run but not
    one engagement.

    ``revalidate=True`` (Tanda C, 5b) also walks the TODOs the engine already
    ticked and demotes to ``pending`` the ones whose claimed evidence no longer
    satisfies their own condition. That is the only way back from the plan that
    congratulated itself on DeadDrop (2026-10-22): ``apk-creds`` was closed by a
    ``credential`` fact whose ``source`` was ``shadow_crack``, not the
    ``apk_decompile`` the TODO asked for, so a resumed run kept 7/12 and treated
    the decompilation step as done. A TODO the *model* closed (no
    ``verified_by``, e.g. a ``report``) is never demoted: the engine did not
    prove it, so the engine does not get to unprove it. Default ``False`` keeps
    ``update_plan``'s behaviour byte-for-byte; only resume turns it on.
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
        # An empty board is "nothing loaded", not "nothing happened": demoting
        # every tick on it would erase a plan for a missing query.
        return plan, []
    todos = list(plan.todos)
    demoted: list[str] = []
    if revalidate:
        claims = {
            todo.id: set(_IPV4_RE.findall(todo.verified_by))
            for todo in todos
            if todo.done and todo.verified_by
        }
        for index, todo in enumerate(todos):
            if not todo.done or not todo.verified_by or not todo.fact_types:
                continue
            claimed_hosts = set().union(*claims.values()) if claims else set()
            claimed_hosts -= claims.get(todo.id, set())
            if _evidence_still_holds(todo, facts, claimed_hosts) is not None:
                continue
            closest = None
            for kind in todo.fact_types:
                closest = _fact_for_type(kind, facts, todo=todo, proven_hosts=claimed_hosts)
                if closest is not None:
                    break
            expected = _condition_expectation(todo) or ", ".join(todo.fact_types)
            observed = _fact_observation(todo, closest)
            reason = (
                f"condition not met: expected {expected}, got {observed}"
                if todo.condition
                else f"evidence not on the board: expected {expected}, got {observed}"
            )
            todos[index] = replace(
                todo,
                status=TODO_PENDING,
                verified_by="",
                reason=_one_line(reason, 300),
            )
            claims.pop(todo.id, None)
            demoted.append(todo.id)
    ticks: list[str] = []
    updated: list[Todo] = []
    # Hosts already proved by the TODOs the plan carries plus the ones this pass
    # closes: a step that goes from a proved host to a new one is proved only by
    # the new one.
    proven_hosts: set[str] = set()
    for todo in todos:
        if todo.done and todo.verified_by:
            proven_hosts |= set(_IPV4_RE.findall(todo.verified_by))
    for todo in todos:
        if not todo.open or not todo.fact_types:
            updated.append(todo)
            continue
        matched = None
        for kind in todo.fact_types:
            matched = _fact_for_type(
                kind,
                facts,
                todo=todo,
                proven_hosts=proven_hosts,
                condition=todo.condition.get(kind),
            )
            if matched is not None:
                break
        if matched is None:
            updated.append(todo)
            continue
        proven_hosts |= _fact_hosts(matched)
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
    if not ticks and not demoted:
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
            + (
                f" (se cierra con un hecho verificado que cumpla: "
                f"{_condition_text(nxt.condition)})"
                if nxt.condition
                else ""
            )
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


#: A limiter plus explicit narrow parameters is the strongest signal that the
#: user asked for one bounded action ("solo escanea puertos", "only scan the top
#: 100 ports").
_BOUNDED_LIMITER_RE = re.compile(
    r"\b(sol[oa]mente|s[oó]lo|[uú]nicamente|only|just)\b", re.IGNORECASE
)

#: Explicit narrow parameters: a port list ("puertos 80 y 443", "2 puertos"),
#: a single URL, or ``-p``. A bare target is not enough: "escanea 10.10.10.5 y
#: enumera los servicios" is a small engagement, not one bounded action.
_BOUNDED_PARAM_RE = re.compile(
    r"\b(?:puertos?|ports?)\b[^.;\n]{0,30}\d"
    r"|\b\d{1,5}\b[^.;\n]{0,12}\b(?:puertos?|ports?)\b"
    r"|(?<![\w-])-p\s*[\d,]"
    r"|https?://\S+",
    re.IGNORECASE,
)

#: One concrete operation, not a campaign. Deliberately short: a verb that does
#: not appear here falls back to the engagement reading (a plan), never the
#: other way around.
_SINGLE_OPERATION_RE = re.compile(
    r"\b(?:escanea|escanear|escaneo|scan|consulta|consultar|petici[oó]n|"
    r"request|verifica|verificar|comprueba|check|resuelve|resolver|descarga|"
    r"download)\b",
    re.IGNORECASE,
)

#: Campaign words: they keep the objective in engagement territory even when it
#: names a port list ("escanea los puertos y luego captura las flags").
_CAMPAIGN_RE = re.compile(
    r"\b(?:compromete|comprometer|explot\w*|escala\w*|privesc|root|"
    r"flags?|banderas?|salas?|rooms?|complet[oa]s?|aut[oó]nom\w*|"
    r"engagement|pentest|auditor[ií]a|todas?|cadena)\b",
    re.IGNORECASE,
)


def is_bounded_order(objective: Any) -> bool:
    """Whether ``objective`` is one concrete action, not an engagement.

    Measured bug (2026-11-10, ``run_5b1c20c60df74a48b6359c0500498fdb``): the
    objective "Escanea los puertos 80 y 443 de scanme.nmap.org usando nmap" was
    planned as a full engagement before the first action (planner call + 5
    TODOs). The scan succeeded, the ``report-results`` TODO stayed open and
    ``task_complete`` was refused until the run burned ~100k tokens, scanned
    the whole host twice and fell back to ``shell.exec``.

    A campaign word always wins, so a room that happens to name ports still gets
    its plan. Without a campaign word, the signal is a single-operation verb
    plus an explicit narrow parameter (port list, URL, ``-p``). Questions are
    handled later by :func:`is_engagement_objective`, not here.
    """
    text = " ".join(str(objective or "").lower().split())
    if not text:
        return False
    if _CAMPAIGN_RE.search(text):
        return False
    if _BOUNDED_LIMITER_RE.search(text):
        return True
    return bool(_SINGLE_OPERATION_RE.search(text) and _BOUNDED_PARAM_RE.search(text))


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
    if is_bounded_order(text):
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
    "is_bounded_order",
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
