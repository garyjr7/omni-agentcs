"""Durable blackboard tools: record and query engagement facts.

``nexus.knowledge.record_fact`` writes one typed fact (with provenance) to the
engagement blackboard; ``nexus.knowledge.query_facts`` reads it back. Neither
touches a target, so both are scope-free: they only persist/read what other
tools discovered. This is the memory the planner chains on.
"""

from __future__ import annotations

from typing import Any

from nexus_core.kernel.blackboard import FACT_TYPES, Blackboard
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult


def record_fact_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.knowledge.record_fact``."""
    return ToolDefinition(
        tool_id="nexus.knowledge.record_fact",
        effect="state_write",
        name="Record engagement fact",
        tenant_id=tenant_id,
        description=(
            "Registra un hecho tipado del engagement (credencial, acceso, "
            "privilegio, pista, barrier...) con su procedencia. NO repitas "
            "`host`/`service`: el verifier ya los escribe desde nmap/httpx y el "
            "motor rechaza el duplicado."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "fact_type": {"type": "string", "enum": list(FACT_TYPES)},
                "key": {"type": "string", "minLength": 1, "maxLength": 512},
                # A model that sends prose as ``value`` used to be rejected by
                # the schema before the handler could normalize it, costing a
                # whole iteration (rerun of 2026-11-07: ``is not of type
                # 'object'``). The handler wraps a string as ``{"detail": ...}``.
                "value": {"type": ["object", "string"]},
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
        effect="read_only",
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
    """Persist one typed fact for the active engagement.

    A registration over a key the verifier already attested is still accepted
    (the agent is never blocked), but it cannot override the verified fact: the
    blackboard's merge keeps the verified value and this result tells the model
    so explicitly (V1-33, measured in rerun 9).
    """
    store = getattr(context, "store", None)
    if store is None:
        return ToolResult(verification_method="blackboard_store_missing")
    engagement_id = _engagement_id(context)
    if not engagement_id:
        return ToolResult(verification_method="blackboard_no_engagement")
    fact_type = str(arguments.get("fact_type") or "").strip()
    key = str(arguments.get("key") or "").strip()
    raw_value = arguments.get("value")
    # Bind once: calling ``get`` twice in a conditional defeats static narrowing.
    # A bare string is still a fact: wrap it instead of dropping it (the schema
    # accepts it since 2026-11-07) so a model that writes prose does not lose
    # the turn to ``is not of type 'object'``.
    if isinstance(raw_value, str):
        value: dict[str, Any] = {"detail": raw_value.strip()} if raw_value.strip() else {}
    elif isinstance(raw_value, dict):
        value = raw_value
    else:
        value = {}
    if fact_type == "barrier":
        # R6: a barrier closes a branch only if the run actually tried the
        # vector. The model writes this fact *after* a failure, so by default it
        # cannot prove an attempt -measured in HackPark V12 (2026-10-21): the
        # iteration-17 barrier claimed the brute force had returned no session
        # when the sweep had been refused before testing one password
        # (``sweep_attempted: false``), and the ledger closed the only working
        # branch. The tools that do run the attempt (``cred.bruteforce`` after a
        # finished wordlist, the loop's own ``_close_stalled_branch``) stamp the
        # field themselves.
        value = {**value}
        value.setdefault("sweep_attempted", False)
        value.setdefault("provenance", "model_claim")
    # Neither ``source`` nor ``verified`` is the model's to grant: both are
    # provenance the engine owns, and a model that could write
    # ``source="deterministic-verifier"`` would be promoting its own guess. The
    # value it sent is not used, but it is answered explicitly below instead of
    # being dropped in silence.
    requested_source = str(arguments.get("source") or "agent").strip()[:128]
    source = "agent"
    requested_verified = bool(arguments.get("verified"))
    verified = False
    created_by = getattr(getattr(context, "identity", None), "subject_id", "agent")

    board = Blackboard(store)
    existing_verified = board.verified_fact(
        context.tenant_id, engagement_id, fact_type=fact_type, key=key
    )
    record = board.record(
        tenant_id=context.tenant_id,
        engagement_id=engagement_id,
        fact_type=fact_type,
        key=key,
        value=value,
        source=source,
        created_by=created_by,
        verified=verified,
    )
    output: dict[str, Any] = {"recorded": record, "verified": False}
    if requested_verified or requested_source not in ("", "agent"):
        # The fact is stored either way; the model has to know it is a lead, not
        # evidence, so it does not stop looking for a deterministic proof.
        output["warning"] = (
            "la procedencia y la verificación las otorga el motor, no el agente: "
            "el hecho queda registrado como pista (source=agent, verified=false) "
            "y no cuenta como evidencia de fase"
        )
    if existing_verified is not None:
        # The registration is persisted but the verified fact stays intact; say
        # so instead of letting the model believe it just replaced it.
        output["existing_verified"] = existing_verified
        output["warning"] = (
            f"el hecho {fact_type}:{key} ya está verificado por el verifier; "
            "tu registro no modifica el hecho verificado"
        )
    return ToolResult(
        output=output,
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
