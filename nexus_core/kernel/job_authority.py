"""Engine-owned delegation envelopes and durable background job allowances.

These values travel in task metadata, never in model-controlled tool arguments.
Reservations intentionally survive crashes: lost enqueue acknowledgements must
not refund an allowance that another worker could already be using.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .budget_ledger import BudgetLedger
from .models import Resource, RunContext, ToolDefinition
from .policy import PolicyEngine


class JobAuthority(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    run_id: str = Field(min_length=1)
    engagement_id: str = ""
    profile_id: str | None = None
    tools: tuple[str, ...]
    token_budget: int = Field(ge=0)
    run_token_budget: int = Field(ge=0)
    job_limit: int = Field(ge=0)
    reservation_id: str | None = None


def parse_authority(value: Any) -> JobAuthority:
    # JSON persistence turns tuples into arrays; validate through JSON mode.
    import json

    return JobAuthority.model_validate_json(json.dumps(value))


def check_authority(authority: JobAuthority, context: RunContext,
                    definition: ToolDefinition) -> None:
    if (authority.run_id != context.run_id or authority.engagement_id != context.engagement_id
            or definition.tool_id not in authority.tools):
        raise PermissionError("job exceeds its originating capability envelope")
    if authority.profile_id is not None:
        from nexus_core.agent.subagents import SUBAGENTS_BY_ID, permits

        profile = SUBAGENTS_BY_ID.get(authority.profile_id)
        if profile is None or not permits(profile, definition.tool_id, definition):
            raise PermissionError("originating subagent no longer permits this tool")
        ceiling = min(authority.token_budget, profile.token_budget)
        spent = float(context.store.usage_total(context.tenant_id, context.run_id,
                      "model_route", "react:" + profile.id, "tokens"))
        if ceiling <= 0 or spent >= ceiling:
            raise PermissionError("originating subagent token budget exhausted")
    if authority.run_token_budget:
        spent = float(context.store.usage_total(context.tenant_id, context.run_id,
                      "model_route", "react", "tokens"))
        if spent >= authority.run_token_budget:
            raise PermissionError("originating run token budget exhausted")
    decision = PolicyEngine(context.store).decide(
        context.identity, "execute:tool", Resource(definition.tool_id, definition.tenant_id, "tool"),
        context.authorized_permissions, definition,
    )
    if not decision.allowed:
        raise PermissionError(decision.reason)


def reserve_job(authority: JobAuthority, context: RunContext) -> JobAuthority:
    # This is an invocation allowance, separate from (and never credited to)
    # token usage. SQLite/Postgres use the same atomic ledger primitive.
    root = f"job-allowance:{context.run_id}:{authority.profile_id or 'operator'}"
    reservation = BudgetLedger(context.store).reserve(
        context.tenant_id, root_id=root, run_id=context.run_id,
        parent_id=context.invocation_id, tokens=1, global_budget=authority.job_limit,
    )
    return authority.model_copy(update={"reservation_id": reservation})


def verify_job_reservation(authority: JobAuthority, context: RunContext) -> None:
    if not authority.reservation_id:
        raise PermissionError("background job has no durable allowance")
    item = BudgetLedger(context.store).get(authority.reservation_id, context.tenant_id)
    root = f"job-allowance:{context.run_id}:{authority.profile_id or 'operator'}"
    if (not item or item["run_id"] != context.run_id or item["root_id"] != root
            or item["state"] != "reserved" or item["tokens_reserved"] != 1):
        raise PermissionError("invalid background job allowance")
    # Claim once under the ledger lock. Duplicate delivery cannot reuse a slot.
    BudgetLedger(context.store).settle(authority.reservation_id, 1)
