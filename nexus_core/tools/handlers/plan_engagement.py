"""Durable ``nexus.orchestrator.*`` tools: the engagement plan as a contract.

The plan is the file :mod:`nexus_core.agent.engagement_plan` owns
(``loot/ENGAGEMENT_PLAN.md``). These tools are the model's only writer:

* ``create_plan`` drafts it (PLAN MODE, iteration 0);
* ``update_plan`` adds a newly discovered vector or marks a TODO done/failed;
* ``get_plan_status`` reads it back with the live reconciliation against the
  blackboard, so the model always answers "what is left" from evidence.

None of them touches the target: ``scope_required=False`` and the effect is
``state_write`` (they mutate the engagement's own workspace, not the objective),
which is why the plan-first gate lets them run before any attack tool.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult

from nexus_core.kernel.errors import PlanConflict

from nexus_core.agent.engagement_plan import (
    PLAN_RELATIVE_PATH,
    TODO_DONE,
    TODO_FAILED,
    TODO_STATUSES,
    EngagementPlan,
    Todo,
    load_plan_for,
    new_plan,
    now_stamp,
    plan_path,
    reconcile,
    save_plan,
    status_payload,
    todo_from_mapping,
)

CREATE_PLAN_TOOL = "nexus.orchestrator.create_plan"
UPDATE_PLAN_TOOL = "nexus.orchestrator.update_plan"
GET_PLAN_STATUS_TOOL = "nexus.orchestrator.get_plan_status"

_TODO_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[A-Za-z0-9_.:-]+$",
        },
        "description": {"type": "string", "minLength": 1, "maxLength": 300},
        "evidence": {"type": "string", "maxLength": 300},
        "fact_types": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 6,
        },
        # Tanda A: a TODO can say *which* fact closes it, not only its type.
        # ``apk-creds`` was ticked by the shadow hash on DeadDrop because both
        # TODOs declared ``credential`` and nothing distinguished them.
        "condition": {
            "type": "object",
            "description": (
                "Por tipo de hecho: cláusulas que el hecho debe cumplir. Claves: "
                "source, key, key_matches (glob) o value.<campo>. Sin condición, "
                "cualquier hecho del tipo cierra el TODO."
            ),
            "additionalProperties": {
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
        },
        "status": {"type": "string", "enum": ["pending", "in_progress"]},
    },
    "required": ["id", "description"],
    "additionalProperties": False,
}


def create_plan_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.orchestrator.create_plan``."""
    return ToolDefinition(
        tool_id=CREATE_PLAN_TOOL,
        effect="state_write",
        name="Create engagement plan",
        tenant_id=tenant_id,
        description=(
            "Fija el PLAN DEL ENGAGEMENT como lista de TODOs verificables en "
            "loot/ENGAGEMENT_PLAN.md (compartido con todos los subagentes). "
            "Obligatorio antes de la primera tool de ataque. Cada TODO declara "
            "`fact_types`: los hechos verificados que lo cierran."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "todos": {
                    "type": "array",
                    "items": _TODO_SCHEMA,
                    "minItems": 1,
                    "maxItems": 40,
                },
                "objective": {"type": "string", "maxLength": 2000},
                "replace": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "true para reemplazar un plan que ya tiene progreso. Sin "
                        "él, un plan con TODOs hechos se edita con update_plan."
                    ),
                },
            },
            "required": ["todos"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        required_permissions=[f"execute:tool:{CREATE_PLAN_TOOL}"],
        scope_required=False,
        timeout_seconds=30,
        max_output_bytes=200_000,
    )


def update_plan_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.orchestrator.update_plan``."""
    return ToolDefinition(
        tool_id=UPDATE_PLAN_TOOL,
        effect="state_write",
        name="Update engagement plan",
        tenant_id=tenant_id,
        description=(
            "Añade TODOs nuevos (un vector descubierto) o marca el estado de uno "
            "existente. `done` solo se acepta en TODOs sin `fact_types` (p. ej. "
            "el informe); los demás los palomea la evidencia. `failed` exige "
            "`reason` y equivale a justificar por qué ese TODO no se alcanza."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "add": {
                    "type": "array",
                    "items": _TODO_SCHEMA,
                    "maxItems": 20,
                },
                "status": {
                    "type": "array",
                    "maxItems": 20,
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "minLength": 1, "maxLength": 64},
                            "status": {"type": "string", "enum": list(TODO_STATUSES)},
                            "reason": {"type": "string", "maxLength": 300},
                        },
                        "required": ["id", "status"],
                        "additionalProperties": False,
                    },
                },
            },
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        required_permissions=[f"execute:tool:{UPDATE_PLAN_TOOL}"],
        scope_required=False,
        timeout_seconds=30,
        max_output_bytes=200_000,
    )


def get_plan_status_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.orchestrator.get_plan_status``."""
    return ToolDefinition(
        tool_id=GET_PLAN_STATUS_TOOL,
        effect="read_only",
        name="Engagement plan status",
        tenant_id=tenant_id,
        description=(
            "Devuelve el plan vigente con su estado real: reconcilia cada TODO "
            "con los hechos verificados del tablero y dice qué queda pendiente. "
            "Consúltalo antes de cerrar y cuando el plan haya cambiado "
            "(update_plan, un TODO nuevo); si nada cambió desde la última "
            "consulta devolvería lo mismo que ya está en el prompt."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        required_permissions=[f"execute:tool:{GET_PLAN_STATUS_TOOL}"],
        scope_required=False,
        timeout_seconds=30,
        max_output_bytes=200_000,
    )


def _verified_facts(context: RunContext) -> list[dict[str, Any]]:
    """Verified facts of the engagement (empty when there is no board)."""
    engagement_id = context.engagement_id
    if not engagement_id or context.store is None:
        return []
    try:
        from nexus_core.kernel.blackboard import Blackboard, is_verified_fact

        return [
            fact
            for fact in Blackboard(context.store).list_facts(
                context.tenant_id, engagement_id, limit=500
            )
            if is_verified_fact(fact)
        ]
    except Exception:  # noqa: BLE001 - the plan tools must survive a board error
        return []


def _root(context: RunContext) -> str | None:
    """The engagement workspace of this call (the operator's, never a cwd guess)."""
    return str(getattr(context, "project_root", "") or "") or None


def _load(context: RunContext) -> EngagementPlan | None:
    """The engagement's plan: the database when there is a store, else the file."""
    return load_plan_for(
        context.engagement_id,
        _root(context),
        store=getattr(context, "store", None),
        tenant_id=str(getattr(context, "tenant_id", "system") or "system"),
    )


def _save(plan: EngagementPlan, context: RunContext) -> str:
    """Commit the plan (database first) and project it to the Markdown file."""
    return save_plan(
        plan,
        _root(context),
        store=getattr(context, "store", None),
        tenant_id=str(getattr(context, "tenant_id", "system") or "system"),
    )


def _reconciled(context: RunContext, plan: EngagementPlan | None) -> EngagementPlan | None:
    """Tick what the board already proves, persisting only when it moved.

    A lost optimistic write is not an error the model must see: another writer
    committed a newer plan, and the next turn re-reconciles against it. Nothing
    is overwritten here.
    """
    from nexus_core.kernel.errors import PlanConflict

    updated, ticks = reconcile(
        plan, _verified_facts(context), engagement_id=context.engagement_id
    )
    if ticks and updated is not None:
        try:
            _save(updated, context)
        except PlanConflict:
            return plan
    return updated


def _plan_conflict_result(exc: Exception) -> ToolResult:
    """Deterministic answer for a plan write that lost the version race."""
    summary = (
        f"el plan cambió mientras lo editabas ({exc}). Recarga el estado con "
        f"{GET_PLAN_STATUS_TOOL} y repite el cambio sobre la versión vigente."
    )
    return ToolResult(
        output={
            "error": summary,
            "plan_conflict": True,
            "guidance": "No se aplicó nada: otro escritor ganó la versión. Relee el plan.",
        },
        verified=False,
        outcome="plan_conflict",
        verification_method="plan_conflict",
        stdout=summary,
    )


def _invalid_fact_types(
    todos: Any,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Unknown ``fact_types`` per TODO, plus the closed list the plan accepts.

    ``todo_from_mapping`` already refuses an unknown type, but it raises: the
    model reads a schema-ish failure and re-guesses the name. The handler answers
    a first-class observation instead, with the closed list on it, so the next
    call can be right. The allowed names are the board's own ``FACT_TYPES`` (the
    ones every reader understands) plus the plan's ``EXTRA_FACT_TYPES``.
    """
    from collections.abc import Mapping

    from nexus_core.agent.engagement_plan import EXTRA_FACT_TYPES
    from nexus_core.kernel.blackboard import FACT_TYPES

    allowed = sorted(set(FACT_TYPES) | set(EXTRA_FACT_TYPES))
    issues: list[dict[str, Any]] = []
    for raw in todos or ():
        if not isinstance(raw, Mapping):
            continue
        declared = raw.get("fact_types") or ()
        if isinstance(declared, str):
            declared = [part.strip() for part in declared.split(",") if part.strip()]
        if not isinstance(declared, (list, tuple)):
            continue
        unknown = sorted(
            {
                str(item or "").strip().lower()
                for item in declared
                if str(item or "").strip().lower() not in allowed
            }
        )
        if unknown:
            issues.append({"todo": str(raw.get("id") or ""), "unknown": unknown})
    return issues, allowed


def _fact_type_refusal(
    issues: list[dict[str, Any]], allowed: list[str]
) -> ToolResult:
    """Deterministic answer for a plan TODO that names an unknown fact type."""
    names = sorted({name for issue in issues for name in issue["unknown"]})
    todos = ", ".join(str(issue["todo"] or "?") for issue in issues[:6])
    summary = (
        f"fact_type no válido en {todos}: {', '.join(names)}. "
        f"Tipos permitidos: {', '.join(allowed)}. Corrige el TODO y vuelve a llamar."
    )
    return ToolResult(
        output={
            "error": summary,
            "invalid": issues,
            "allowed_fact_types": allowed,
            "guidance": (
                "`fact_types` solo acepta tipos de la lista; no inventes nombres "
                "nuevos (los asserts del tablero no los entenderían)."
            ),
        },
        verified=False,
        # A vocabulary correction, not a broken tool: a determinate answer the
        # model can act on. ``error`` made the gateway raise a post-condition
        # failure and the loop retire ``create_plan`` after three typos.
        outcome="invalid_fact_type",
        verification_method="invalid_fact_type",
        evidence={"invalid": names, "todos": len(issues)},
        stdout=summary,
    )


def _payload(plan: EngagementPlan | None, context: RunContext) -> dict[str, Any]:
    payload = status_payload(plan)
    payload["path"] = PLAN_RELATIVE_PATH
    payload["plan_file"] = plan_path(_root(context))
    return payload


async def create_plan_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Write ``loot/ENGAGEMENT_PLAN.md`` from the model's TODOs."""
    from nexus_core.kernel.schema_validation import validate

    validate(arguments, create_plan_definition().input_schema)
    issues, allowed = _invalid_fact_types(arguments.get("todos"))
    if issues:
        return _fact_type_refusal(issues, allowed)
    existing = _reconciled(context, _load(context))
    replace_plan = bool(arguments.get("replace"))
    if (
        existing is not None
        and not replace_plan
        and (existing.complete or any(todo.done for todo in existing.todos) or existing.failed)
    ):
        raise ValueError(
            "the plan already has progress: use nexus.orchestrator.update_plan to "
            "add or close TODOs, or pass replace=true to discard it deliberately"
        )
    todos = [todo_from_mapping(raw) for raw in arguments["todos"]]
    objective = str(arguments.get("objective") or "") or getattr(context, "objective", "")
    plan = new_plan(objective, context.engagement_id, todos, source="model")
    if existing is not None:
        # A deliberate replacement still writes over the version it just read,
        # instead of trying to create a second plan.
        plan = replace(plan, version=existing.version)
    try:
        path = _save(plan, context)
    except PlanConflict as exc:
        return _plan_conflict_result(exc)
    # A TODO the board already proves is ticked on creation: the planning phase
    # may run on a resumed engagement, and re-doing proven work is not the job.
    plan = _reconciled(context, plan) or plan
    return ToolResult(
        output={
            "plan": "created",
            "path": PLAN_RELATIVE_PATH,
            "plan_file": path,
            "counts": plan.counts(),
            "pending": [todo.id for todo in plan.pending],
            "todos": [todo.to_dict() for todo in plan.todos],
            "markdown": status_payload(plan)["markdown"],
        },
        verified=True,
        verification_method="engagement_plan_written",
        evidence={
            "path": PLAN_RELATIVE_PATH,
            "todos": len(plan.todos),
            "source": plan.source,
        },
    )


async def update_plan_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Add TODOs or move the status of existing ones, persisting the file."""
    from nexus_core.kernel.schema_validation import validate

    validate(arguments, update_plan_definition().input_schema)
    issues, allowed = _invalid_fact_types(arguments.get("add"))
    if issues:
        return _fact_type_refusal(issues, allowed)
    plan = _reconciled(context, _load(context))
    if plan is None:
        raise ValueError(
            "there is no engagement plan yet: call "
            f"{CREATE_PLAN_TOOL} before updating it"
        )
    added = list(arguments.get("add") or ())
    changes = list(arguments.get("status") or ())
    if not added and not changes:
        raise ValueError("update_plan needs `add` and/or `status`")
    todos: list[Todo] = list(plan.todos)
    for raw in added:
        todo = todo_from_mapping(raw)
        if any(existing.id == todo.id for existing in todos):
            raise ValueError(f"todo {todo.id!r} already exists in the plan")
        todos.append(todo)
    for change in changes:
        todo_id = str(change.get("id") or "")
        status = str(change.get("status") or "").strip().lower()
        reason = " ".join(str(change.get("reason") or "").split())
        index = next((i for i, todo in enumerate(todos) if todo.id == todo_id), None)
        if index is None:
            raise ValueError(f"todo {todo_id!r} is not in the plan")
        todo = todos[index]
        if status == TODO_DONE and todo.fact_types:
            raise ValueError(
                f"todo {todo_id!r} closes with evidence, not with a declaration: "
                f"its fact_types are {', '.join(todo.fact_types)}. Produce the "
                "evidence and it will be ticked automatically."
            )
        if status == TODO_FAILED and not reason:
            raise ValueError(f"todo {todo_id!r} cannot fail without a reason")
        todos[index] = Todo(
            id=todo.id,
            description=todo.description,
            evidence=todo.evidence,
            fact_types=todo.fact_types,
            status=status,
            verified_by=todo.verified_by,
            reason=reason if status == TODO_FAILED else "",
        )
    updated = replace(plan, todos=tuple(todos), updated_at=now_stamp())
    try:
        path = _save(updated, context)
    except PlanConflict as exc:
        return _plan_conflict_result(exc)
    return ToolResult(
        output={
            "plan": "updated",
            "path": PLAN_RELATIVE_PATH,
            "plan_file": path,
            "counts": updated.counts(),
            "pending": [todo.id for todo in updated.pending],
            "todos": [todo.to_dict() for todo in updated.todos],
        },
        verified=True,
        verification_method="engagement_plan_written",
        evidence={
            "path": PLAN_RELATIVE_PATH,
            "added": [todo.id for todo in updated.todos if todo.id not in
                      {existing.id for existing in plan.todos}],
            "changed": [str(change.get("id")) for change in changes],
        },
    )


async def get_plan_status_handler(
    arguments: dict[str, Any], context: RunContext
) -> ToolResult:
    """Return the plan with every TODO reconciled against the blackboard."""
    from nexus_core.kernel.schema_validation import validate

    validate(arguments, get_plan_status_definition().input_schema)
    plan = _reconciled(context, _load(context))
    payload = _payload(plan, context)
    if plan is None:
        payload["message"] = (
            f"no engagement plan yet: call {CREATE_PLAN_TOOL} with the TODOs of "
            "this objective before the first attack tool"
        )
    return ToolResult(
        output=payload,
        verified=plan is not None,
        verification_method="engagement_plan_status",
        evidence={"path": PLAN_RELATIVE_PATH, "exists": plan is not None},
    )


__all__ = [
    "CREATE_PLAN_TOOL",
    "GET_PLAN_STATUS_TOOL",
    "UPDATE_PLAN_TOOL",
    "create_plan_definition",
    "create_plan_handler",
    "get_plan_status_definition",
    "get_plan_status_handler",
    "update_plan_definition",
    "update_plan_handler",
]
