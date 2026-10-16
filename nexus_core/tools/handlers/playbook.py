"""``nexus.orchestrator.playbook``: suggest the next gated step (READ_ONLY).

Reads the engagement blackboard and returns which deterministic playbooks apply
and what their next step is. It never executes the step: the gateway still
scopes, approves and audits every tool call, and the model only chooses whether
to propose it.
"""

from __future__ import annotations

from typing import Any
from nexus_core.agent.playbook_proofs import execution_proofs

from nexus_core.agent.playbooks import (
    is_applicable,
    match_playbook,
    packaged_packages,
    playbook_by_id,
    registered_playbooks,
    select_playbooks,
)
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


def _facts(context: RunContext) -> tuple[list[dict[str, Any]], str | None]:
    store = getattr(context, "store", None)
    engagement_id = getattr(getattr(context, "scope", None), "engagement_id", None)
    if store is None or not engagement_id:
        return [], engagement_id
    from nexus_core.kernel.blackboard import Blackboard

    return Blackboard(store).list_facts(context.tenant_id, engagement_id), engagement_id


async def playbook_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    validate(arguments, playbook_definition().input_schema)
    action = str(arguments.get("action") or "next").lower()
    if action not in ACTIONS:
        raise ValueError("action must be one of list, next, show")
    facts, engagement_id = _facts(context)
    proofs = execution_proofs(context.store, context.tenant_id, context.run_id, engagement_id or "")

    if action == "show":
        playbook_id = str(arguments.get("playbook_id") or "")
        playbook = playbook_by_id(playbook_id)
        if playbook is None:
            known = sorted(item.playbook_id for item in registered_playbooks())
            raise ValueError(f"unknown playbook_id (known: {', '.join(known)})")
        applicable = is_applicable(playbook_id, facts)
        match = match_playbook(playbook, facts, proofs=proofs) if applicable else None
        output: dict[str, Any] = {
            "engagement_id": engagement_id,
            "playbook": playbook.to_dict(),
            "applicable": match is not None,
            "match": match.to_dict() if match else None,
        }
        # A declarative phase carries its own metadata (kill-chain phase, the
        # capability profile that must be able to run it, its objective).
        declared = next(
            (
                phase
                for package in packaged_packages()
                for phase in package.phases
                if phase.playbook.playbook_id == playbook_id
            ),
            None,
        )
        if declared is not None:
            output["declarative"] = {
                "phase_id": declared.phase_id,
                "planner_phase": declared.planner_phase,
                "subagent": declared.subagent,
                "objective": declared.objective,
            }
        return ToolResult(
            output=output,
            verified=True,
            verification_method="playbook_shown",
            evidence={"playbook_id": playbook_id},
        )

    matches = select_playbooks(facts, only_ready=(action == "next"), proofs=proofs)
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
