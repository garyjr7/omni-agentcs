"""``nexus.orchestrator.playbook``: suggest the next gated step (READ_ONLY).

Reads the engagement blackboard and returns which deterministic playbooks apply
and what their next step is. It never executes the step: the gateway still
scopes, approves and audits every tool call, and the model only chooses whether
to propose it.
"""

from __future__ import annotations

from nexus_core.agent.playbooks import PLAYBOOKS, PRECONDITIONS, match_playbook, select_playbooks
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate

TOOL_ID = "nexus.orchestrator.playbook"
ACTIONS = ("list", "next", "show")


def playbook_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id=TOOL_ID,
        name="Suggest the next playbook step",
        tenant_id=tenant_id,
        description=(
            "Dado el blackboard del engagement, indica qué playbooks deterministas "
            "aplican y cuál es su siguiente paso (tool_id exacto). No ejecuta nada: "
            "cada paso sigue pasando por scope, aprobación y auditoría."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": list(ACTIONS), "default": "next"},
                "playbook_id": {"type": "string", "maxLength": 64},
            },
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        effect="read_only",
        required_permissions=[f"execute:tool:{TOOL_ID}"],
        timeout_seconds=30,
        max_output_bytes=200_000,
        scope_target_field=None,
        scope_required=False,
    )


def _facts(context: RunContext) -> tuple[list[dict], str | None]:
    store = getattr(context, "store", None)
    engagement_id = getattr(getattr(context, "scope", None), "engagement_id", None)
    if store is None or not engagement_id:
        return [], engagement_id
    from nexus_core.kernel.blackboard import Blackboard

    return Blackboard(store).list_facts(context.tenant_id, engagement_id), engagement_id


async def playbook_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, playbook_definition().input_schema)
    action = str(arguments.get("action") or "next").lower()
    if action not in ACTIONS:
        raise ValueError("action must be one of list, next, show")
    facts, engagement_id = _facts(context)

    if action == "show":
        playbook_id = str(arguments.get("playbook_id") or "")
        playbook = next((item for item in PLAYBOOKS if item.playbook_id == playbook_id), None)
        if playbook is None:
            raise ValueError("unknown playbook_id")
        match = match_playbook(playbook, facts) if PRECONDITIONS[playbook_id](facts) else None
        return ToolResult(
            output={
                "engagement_id": engagement_id,
                "playbook": playbook.to_dict(),
                "applicable": match is not None,
                "match": match.to_dict() if match else None,
            },
            verified=True,
            verification_method="playbook_shown",
            evidence={"playbook_id": playbook_id},
        )

    matches = select_playbooks(facts, only_ready=(action == "next"))
    return ToolResult(
        output={
            "engagement_id": engagement_id,
            "facts_total": len(facts),
            "playbooks": [match.to_dict() for match in matches],
            "count": len(matches),
        },
        verified=True,
        verification_method=f"playbook_{action}",
        evidence={"count": len(matches), "facts_total": len(facts)},
    )
