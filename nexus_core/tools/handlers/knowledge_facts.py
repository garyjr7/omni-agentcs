"""Durable blackboard tools: record and query engagement facts.

``nexus.knowledge.record_fact`` writes one typed fact (with provenance) to the
engagement blackboard; ``nexus.knowledge.query_facts`` reads it back. Neither
touches a target, so both are scope-free: they only persist/read what other
tools discovered. This is the memory the planner chains on.
"""

from __future__ import annotations

from nexus_core.kernel.blackboard import FACT_TYPES, Blackboard
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult


def record_fact_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.knowledge.record_fact``."""
    return ToolDefinition(
        tool_id="nexus.knowledge.record_fact",
        name="Record engagement fact",
        tenant_id=tenant_id,
        description=(
            "Registra un hecho tipado del engagement (servicio, usuario, "
            "credencial, acceso, privilegio...) con su procedencia. Memoria "
            "durable que el agente reutiliza en pasos y runs siguientes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "fact_type": {"type": "string", "enum": list(FACT_TYPES)},
                "key": {"type": "string", "minLength": 1, "maxLength": 512},
                "value": {"type": "object"},
                "source": {"type": "string", "maxLength": 128},
                "verified": {"type": "boolean"},
            },
            "required": ["fact_type", "key"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        required_permissions=["execute:tool:nexus.knowledge.record_fact"],
        timeout_seconds=30,
        max_output_bytes=100_000,
        scope_required=False,
    )


def query_facts_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.knowledge.query_facts``."""
    return ToolDefinition(
        tool_id="nexus.knowledge.query_facts",
        name="Query engagement facts",
        tenant_id=tenant_id,
        description=(
            "Devuelve los hechos registrados del engagement activo, "
            "opcionalmente filtrados por tipo. Para decidir el siguiente paso "
            "sin repetir trabajo."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "fact_type": {"type": "string", "enum": list(FACT_TYPES)},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            },
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        required_permissions=["execute:tool:nexus.knowledge.query_facts"],
        timeout_seconds=30,
        max_output_bytes=1_000_000,
        scope_required=False,
    )


def _engagement_id(context: RunContext) -> str | None:
    scope = getattr(context, "scope", None)
    return getattr(scope, "engagement_id", None) if scope is not None else None


async def record_fact_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Persist one typed fact for the active engagement."""
    store = getattr(context, "store", None)
    if store is None:
        return ToolResult(verification_method="blackboard_store_missing")
    engagement_id = _engagement_id(context)
    if not engagement_id:
        return ToolResult(verification_method="blackboard_no_engagement")
    fact_type = str(arguments.get("fact_type") or "").strip()
    key = str(arguments.get("key") or "").strip()
    value = arguments.get("value") if isinstance(arguments.get("value"), dict) else {}
    source = str(arguments.get("source") or "agent").strip()
    verified = bool(arguments.get("verified", True))
    created_by = getattr(getattr(context, "identity", None), "subject_id", "agent")

    record = Blackboard(store).record(
        tenant_id=context.tenant_id,
        engagement_id=engagement_id,
        fact_type=fact_type,
        key=key,
        value=value,
        source=source,
        created_by=created_by,
        verified=verified,
    )
    return ToolResult(
        output={"recorded": record},
        verified=True,
        verification_method="blackboard_fact_recorded",
        evidence={"fact_type": fact_type, "key": key, "source": source},
    )


async def query_facts_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Return recorded facts for the active engagement."""
    store = getattr(context, "store", None)
    if store is None:
        return ToolResult(verification_method="blackboard_store_missing")
    engagement_id = _engagement_id(context)
    if not engagement_id:
        return ToolResult(verification_method="blackboard_no_engagement")
    fact_type = arguments.get("fact_type")
    limit = int(arguments.get("limit") or 100)
    board = Blackboard(store)
    facts = board.list_facts(
        context.tenant_id, engagement_id, fact_type=fact_type, limit=limit
    )
    return ToolResult(
        output={
            "engagement_id": engagement_id,
            "count": len(facts),
            "facts": facts,
            "summary": board.summary(context.tenant_id, engagement_id),
        },
        verified=True,
        verification_method="blackboard_facts_queried",
        evidence={"fact_type": fact_type, "count": len(facts)},
    )
