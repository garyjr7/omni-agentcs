"""Policy-aware provider routing with token budgets and deterministic fallback."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List

from nexus_core.llm.abstraction import (
    BaseLLMClient,
    LLMMessage,
    LLMResponse,
    NexusLLMError,
)
from nexus_core.llm.limits import llm_request_timeout_seconds

from .control_store import ControlStore
from .models import RunContext
from .telemetry import metrics, telemetry


@dataclass(frozen=True)
class RoutePolicy:
    name: str
    providers: tuple[str, ...]
    classifications: tuple[str, ...] = ("public", "internal")
    allow_cloud: bool = True
    #: Outer guard around one ``client.complete`` call. Must exceed the provider
    #: client's own read budget (``NEXUS_LLM_REQUEST_TIMEOUT``), otherwise the
    #: router cancels a request the client would still have completed.
    timeout_seconds: float = field(default_factory=llm_request_timeout_seconds)
    retries_per_provider: int = 1
    circuit_failures: int = 3
    circuit_cooldown_seconds: float = 30


class ModelRouter:
    def __init__(self, clients: Dict[str, BaseLLMClient], policies: Iterable[RoutePolicy],
                 store: ControlStore | None = None) -> None:
        self.clients = clients
        self.policies = {policy.name: policy for policy in policies}
        self._usage: Dict[str, int] = {}
        self.store = store
        self._circuits: Dict[str, tuple[int, float]] = {}

    async def complete(
        self,
        route: str,
        messages: List[LLMMessage],
        context: RunContext,
        *,
        classification: str = "internal",
        **kwargs: Any,
    ) -> LLMResponse:
        policy = self.policies.get(route)
        if not policy:
            raise KeyError(f"unknown model route: {route}")
        if classification not in policy.classifications:
            raise PermissionError("classification is not allowed by this model route")
        used = int(self.store.usage_total(
            context.tenant_id, context.run_id, "model_route", route, "tokens"
        )) if self.store else self._usage.get(context.run_id, 0)
        if context.budget_tokens and used >= context.budget_tokens:
            raise PermissionError("run token budget exhausted")

        errors = []
        for provider_name in policy.providers:
            client = self.clients.get(provider_name)
            if not client:
                continue
            if not policy.allow_cloud and provider_name not in {"fake", "ollama", "vllm"}:
                continue
            failures, opened_at = self._circuits.get(provider_name, (0, 0.0))
            if failures >= policy.circuit_failures and time.monotonic() - opened_at < policy.circuit_cooldown_seconds:
                errors.append(f"{provider_name}: circuit open")
                continue
            for attempt in range(policy.retries_per_provider + 1):
                try:
                    with telemetry.span("gen_ai.chat", {
                        "nexus.tenant.id": context.tenant_id,
                        "nexus.run.id": context.run_id,
                        "nexus.trace.id": context.trace_id,
                        "gen_ai.provider.name": provider_name,
                        "gen_ai.request.model": client.config.model,
                    }):
                        response = await asyncio.wait_for(
                            client.complete(messages, **kwargs), timeout=policy.timeout_seconds
                        )
                    new_usage = used + response.total_tokens
                    if context.budget_tokens and new_usage > context.budget_tokens:
                        raise PermissionError("model response exceeded run token budget")
                    if self.store:
                        self.store.record_usage(
                            context.tenant_id, context.run_id, "model_route", route,
                            "tokens", response.total_tokens,
                            {"provider": provider_name, "model": client.config.model,
                             "trace_id": context.trace_id},
                        )
                    self._usage[context.run_id] = new_usage
                    self._circuits[provider_name] = (0, 0.0)
                    metrics.increment(
                        "nexus_model_requests_total", provider=provider_name,
                        route=route, status="success", tenant_id=context.tenant_id,
                    )
                    metrics.increment(
                        "nexus_model_tokens_total", response.total_tokens,
                        provider=provider_name, route=route, tenant_id=context.tenant_id,
                    )
                    return response
                except PermissionError:
                    raise
                except Exception as exc:
                    metrics.increment(
                        "nexus_model_requests_total", provider=provider_name,
                        route=route, status="error", tenant_id=context.tenant_id,
                    )
                    failures += 1
                    self._circuits[provider_name] = (failures, time.monotonic())
                    errors.append(f"{provider_name}[{attempt + 1}]: {exc}")
                    if attempt < policy.retries_per_provider:
                        await asyncio.sleep(min(1.0, 0.1 * (2 ** attempt)))
        raise NexusLLMError("No model provider completed the request: " + "; ".join(errors))

    def usage(self, run_id: str) -> int:
        return self._usage.get(run_id, 0)
