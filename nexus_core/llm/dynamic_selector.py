"""Per-task model routing: ``[model_routing]`` in, the right client out.

``nexus_core.kernel.model_router.ModelRouter`` already routes *by durable route
name* among clients registered under a name, with token budgets and a circuit
breaker. That answers "which of the providers this deployment registered serves
route X?". It does not answer the question this module exists for: **given what
the agent is about to do** (plan, execute a tool, summarise, report), which
provider/model is the right one, and what happens when that model fails?

The pieces:

* :class:`ModelTarget` / :class:`RoutingDecision` - the value objects. A decision
  is a pure function of the config plus the providers with a usable key, so the
  same one feeds the run and ``omni --doctor``.
* :func:`resolve_route` - config + task + available providers -> decision. No
  network, no client construction.
* :class:`DynamicModelSelector` - turns a decision into a client. Reuses the
  client already built for a provider when the model matches and clones it (same
  key, same base URL) when ``[model_routing]`` names a different model.
* :class:`RoutedLLM` - a drop-in ``llm_client`` for one task: the pinned model
  first, then the backups, **preferring another provider**. Journals every
  transition (``model.fallback``) so a run never silently changes model.

Everything is inert until the operator pins a profile: with the default
``[model_routing]`` the selector is not even built and every caller keeps the
exact client it had (see :func:`build_model_selector`).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence, Tuple

from nexus_core.config.schema import (
    ROUTING_TASKS,
    ModelRoutingConfig,
    RouteTarget,
)

from .abstraction import (
    LLMConfig,
    LLMProvider,
    NexusLLMError,
)

LOGGER = logging.getLogger("nexus.llm.routing")

TASK_PLANNER = "planner"
TASK_EXECUTOR = "executor"
TASK_REFLECTION = "reflection"
TASK_REPORTING = "reporting"
TASKS = ROUTING_TASKS

#: Event the journal receives when the router moves to a backup model.
FALLBACK_EVENT_TYPE = "model.fallback"
#: Event the journal receives when a task's model is chosen (one per turn).
ROUTE_EVENT_TYPE = "model.route"

EventSink = Callable[[str, Dict[str, Any]], None]


def _provider_name(value: Any) -> str:
    """``LLMProvider.OPENAI``/``"openai"`` -> ``"openai"``; ``None`` -> ``""``."""
    return str(getattr(value, "value", value) or "")


@dataclass(frozen=True)
class ModelTarget:
    """One ``provider/model`` pair the router may use."""

    provider: str
    model: str = ""

    @property
    def label(self) -> str:
        return f"{self.provider}/{self.model}" if self.model else self.provider

    def as_dict(self) -> Dict[str, str]:
        return {"provider": self.provider, "model": self.model}


@dataclass(frozen=True)
class RoutingDecision:
    """Why a task runs on a given model, and what backs it up."""

    task: str
    target: ModelTarget
    fallbacks: Tuple[ModelTarget, ...] = ()
    #: ``config`` when ``[model_routing.<task>]`` pinned it, ``inherit`` when the
    #: task follows ``[llm]``, ``default`` when a pin was unusable (no key).
    source: str = "inherit"
    #: Operator-facing one-liner: never includes a secret, only names.
    reason: str = ""

    def as_payload(self) -> Dict[str, Any]:
        return {
            "task": self.task,
            "provider": self.target.provider,
            "model": self.target.model,
            "source": self.source,
            "reason": self.reason,
            "fallbacks": [item.label for item in self.fallbacks],
        }


def _parse_fallback(item: str, models: Mapping[str, str]) -> ModelTarget | None:
    """``"deepseek/deepseek-flash"`` or ``"deepseek"`` -> a usable target."""
    name, _, model = str(item).partition("/")
    name = name.strip()
    model = model.strip() or str(models.get(name) or "")
    if not name or name == "fake":
        return None
    return ModelTarget(name, model)


def resolve_route(
    routing: ModelRoutingConfig,
    task: str,
    *,
    default: ModelTarget,
    available: Mapping[str, str] | None = None,
    implicit_fallbacks: bool = True,
    strict: bool = True,
) -> RoutingDecision:
    """The decision for ``task``: pinned model if usable, else the default.

    ``available`` maps provider -> the model that provider is configured with; a
    provider with no usable key is absent, and a pin naming it is ignored (with
    a reason that says so) instead of failing the run. When the profile lists no
    backups, every other available provider becomes one - that is the sensible
    default, and it is why an unconfigured ``[model_routing]`` needs no fallback
    list of its own.

    ``strict=False`` answers "what did the operator ask for?" rather than "what
    will the run use?": a pin without a key is still the target. ``--doctor``
    needs both views, the loop only the strict one.
    """
    if task not in TASKS:
        raise ValueError(f"unknown model routing task: {task}")
    models = dict(available or {})
    spec: RouteTarget = getattr(routing, task)
    target = default
    source = "inherit"
    reason = f"{task}: sin perfil, hereda {default.label}"
    if spec.provider or spec.model:
        source = "config"
        provider = spec.provider or default.provider
        if provider in models or provider == default.provider:
            model = spec.model or str(models.get(provider) or default.model)
            target = ModelTarget(provider, model)
            reason = (
                f"{task}: [model_routing.{task}] fija {target.label}"
                if target != default
                else f"{task}: [model_routing.{task}] fija el modelo por defecto"
            )
        elif not strict:
            target = ModelTarget(provider, spec.model or str(models.get(provider) or ""))
            reason = (
                f"{task}: [model_routing.{task}] fija {target.label}; "
                f"sin clave utilizable, el run usará {default.label}"
            )
        else:
            reason = (
                f"{task}: [model_routing.{task}] pide {provider}"
                f"{'/' + spec.model if spec.model else ''}, sin clave utilizable; "
                f"se usa {default.label}"
            )
    fallbacks: List[ModelTarget] = []
    for item in spec.fallbacks:
        candidate = _parse_fallback(item, models)
        if candidate is not None:
            fallbacks.append(candidate)
    if not fallbacks and implicit_fallbacks:
        fallbacks = [
            ModelTarget(name, str(model))
            for name, model in models.items()
            if name not in {"fake", target.provider}
        ]
    # A backup on another provider is the point of the exercise: it survives a
    # dead endpoint, a revoked key or a provider-wide outage. Same-provider
    # backups stay, but after the cross-provider ones.
    ordered = [entry for entry in fallbacks if entry.provider != target.provider]
    ordered += [entry for entry in fallbacks if entry.provider == target.provider]
    deduped: List[ModelTarget] = []
    for entry in ordered:
        if entry != target and entry not in deduped:
            deduped.append(entry)
    return RoutingDecision(task, target, tuple(deduped), source, reason)


def _client_model(client: Any) -> str:
    return str(getattr(getattr(client, "config", None), "model", "") or "")


def _client_provider(client: Any) -> str:
    return _provider_name(getattr(getattr(client, "config", None), "provider", None))


class _ClientFactory:
    """Builds one client per (provider, model), reusing the operator's config.

    A provider that already has a client lends its key, base URL and sampling
    settings to the new model, so ``[model_routing]`` never asks the operator to
    type the same key twice. A provider with no client at all is out of reach:
    without a key the provider is reported unavailable rather than built broken.
    """

    def __init__(self, clients: Mapping[str, Any], builder: Callable[..., Any] | None = None):
        self.clients = dict(clients)
        self.builder = builder
        self._cache: Dict[Tuple[str, str], Any] = {}

    def available(self) -> Dict[str, str]:
        return {name: _client_model(client) for name, client in self.clients.items()}

    def build(self, target: ModelTarget) -> Any | None:
        key = (target.provider, target.model)
        if key in self._cache:
            return self._cache[key]
        existing = self.clients.get(target.provider)
        client: Any | None = None
        if existing is not None and (not target.model or _client_model(existing) == target.model):
            client = existing
        elif self.builder is not None:
            try:
                client = self.builder(target.provider, target.model)
            except Exception as error:  # noqa: BLE001 - a backup that cannot be built is skipped
                LOGGER.warning("cannot build %s: %s", target.label, error)
                client = None
        elif existing is not None:
            client = self._clone(existing, target)
        self._cache[key] = client
        return client

    @staticmethod
    def _clone(existing: Any, target: ModelTarget) -> Any | None:
        """Same provider, different model: clone its config and rebuild the client."""
        from .abstraction import LLMFactory

        base: LLMConfig | None = getattr(existing, "config", None)
        if base is None:
            return None
        try:
            provider = LLMProvider(target.provider)
        except ValueError:
            return None
        try:
            return LLMFactory.create(
                LLMConfig(
                    provider=provider,
                    model=target.model,
                    api_key=base.api_key,
                    base_url=base.base_url,
                    temperature=base.temperature,
                    max_tokens=base.max_tokens,
                    timeout=base.timeout,
                    system_prompt=base.system_prompt,
                )
            )
        except Exception as error:  # noqa: BLE001 - never fail a turn on construction
            LOGGER.warning("cannot clone %s for %s: %s", target.provider, target.label, error)
            return None


class RoutedLLM:
    """One task's client: pinned model first, backups after, journals the change.

    A drop-in for ``BaseLLMClient`` as the ReAct loop uses it (``complete``,
    ``stream``, ``supports_streaming``, ``supports_action_json``, ``config``,
    ``primary``). ``PermissionError`` -the run token budget- is re-raised
    untouched: a budget refusal is a decision, not a provider failure, and
    retrying it on another provider would spend the tokens the budget denied.
    """

    def __init__(
        self,
        decision: RoutingDecision,
        chain: Sequence[Tuple[ModelTarget, Any]],
        *,
        event_sink: EventSink | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.decision = decision
        self._chain = [(target, client) for target, client in chain if client is not None]
        self._event_sink = event_sink
        self._logger = logger or LOGGER

    @property
    def primary(self) -> Any:
        return self._chain[0][1] if self._chain else None

    @property
    def config(self) -> Any:
        return getattr(self.primary, "config", None)

    @property
    def supports_streaming(self) -> bool:
        return bool(getattr(self.primary, "supports_streaming", False))

    @property
    def supports_action_json(self) -> bool:
        return bool(getattr(self.primary, "supports_action_json", False))

    @property
    def last_stream_response(self) -> Any:
        return getattr(self.primary, "last_stream_response", None)

    @property
    def models(self) -> Tuple[str, ...]:
        return tuple(target.label for target, _ in self._chain)

    def attach_event_sink(self, sink: EventSink | None) -> None:
        """Replace the sink; the inner clients keep their own (chain) sink."""
        self._event_sink = sink

    def _emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        if self._event_sink is None:
            return
        try:
            self._event_sink(event_type, payload)
        except Exception as error:  # noqa: BLE001 - telemetry never breaks a turn
            self._logger.warning("routing telemetry failed for %s: %s", event_type, error)

    async def complete(self, messages: List[Any], **kwargs: Any) -> Any:
        causes: List[str] = []
        for index, (target, client) in enumerate(self._chain):
            try:
                return await client.complete(messages, **kwargs)
            except (PermissionError, asyncio.CancelledError):
                raise
            except Exception as error:  # noqa: BLE001 - classified by the cause text
                causes.append(f"{target.label}: {error}")
                if index + 1 < len(self._chain):
                    self._emit(
                        FALLBACK_EVENT_TYPE,
                        {
                            "task": self.decision.task,
                            "from": target.label,
                            "to": self._chain[index + 1][0].label,
                            "reason": _failure_kind(error),
                            "attempt": index + 1,
                        },
                    )
        if not causes:
            raise NexusLLMError(f"no model is available for the {self.decision.task} turn")
        raise NexusLLMError(
            f"no model completed the {self.decision.task} turn: " + "; ".join(causes)
        )

    async def stream(self, messages: List[Any], **kwargs: Any) -> Any:
        """Stream from the pinned model only.

        A mid-stream restart would duplicate the visible answer; when streaming
        fails the loop replays the turn through :meth:`complete`, which is where
        the backups take over.
        """
        if self.primary is None:
            raise NexusLLMError("no model is available for this task")
        async for chunk in self.primary.stream(messages, **kwargs):
            yield chunk


def _failure_kind(error: BaseException) -> str:
    """A short cause class, without any provider text that could carry a key."""
    name = type(error).__name__
    text = str(error).lower()
    for marker, kind in (
        ("rate", "rate_limit"),
        ("429", "rate_limit"),
        ("timeout", "timeout"),
        ("timed out", "timeout"),
        ("401", "auth"),
        ("403", "auth"),
        ("api key", "auth"),
    ):
        if marker in text:
            return kind
    return name


class DynamicModelSelector:
    """Given a task type, the client that should run it."""

    def __init__(
        self,
        clients: Mapping[str, Any],
        routing: ModelRoutingConfig | None = None,
        *,
        wrap: Callable[[Any], Any] | None = None,
        builder: Callable[[str, str], Any] | None = None,
        default: ModelTarget | None = None,
        event_sink: EventSink | None = None,
    ) -> None:
        self.routing = routing or ModelRoutingConfig()
        self._factory = _ClientFactory(
            {_client_provider(client): client for client in clients.values() if client is not None},
            builder,
        )
        self._wrap = wrap
        self._default = default or self._infer_default()
        self.event_sink = event_sink

    def _infer_default(self) -> ModelTarget:
        for name, model in self._factory.available().items():
            if name != "fake":
                return ModelTarget(name, model)
        available = self._factory.available()
        name = next(iter(available), "")
        return ModelTarget(name, available.get(name, ""))

    @property
    def default_target(self) -> ModelTarget:
        return self._default

    def decide(self, task: str) -> RoutingDecision:
        return resolve_route(
            self.routing,
            task,
            default=self._default,
            available=self._factory.available(),
        )

    def client_for(self, target: ModelTarget) -> Any | None:
        client = self._factory.build(target)
        if client is not None and self._wrap is not None:
            client = self._wrap(client)
        return client

    def routed(self, task: str, *, event_sink: EventSink | None = None) -> RoutedLLM:
        """The client for one task, with its backups already resolved."""
        decision = self.decide(task)
        chain: List[Tuple[ModelTarget, Any]] = []
        for target in (decision.target, *decision.fallbacks):
            client = self.client_for(target)
            if client is not None:
                chain.append((target, client))
        if not chain:
            # The default provider is the floor: a selector that produced no
            # client at all must not turn a working run into a dead one.
            client = self.client_for(self._default)
            if client is not None:
                chain.append((self._default, client))
        return RoutedLLM(
            decision,
            chain,
            event_sink=event_sink if event_sink is not None else self.event_sink,
        )

    def policy_summary(self) -> Dict[str, Any]:
        return describe_routing(
            self.routing,
            default=self._default,
            available=self._factory.available(),
        )


def describe_routing(
    routing: ModelRoutingConfig,
    *,
    default: ModelTarget,
    available: Mapping[str, str] | None = None,
) -> Dict[str, Any]:
    """The active policy, for ``omni --doctor``. Pure: no clients are built.

    Each task carries the **configured** model (what the operator pinned, or the
    default it inherits) and ``effective``, the model the next run will really
    use. They differ only when a profile names a provider without a key, which
    is exactly the case an operator opens ``--doctor`` to find.
    """
    models = dict(available or {})
    tasks: Dict[str, Any] = {}
    for task in TASKS:
        configured = resolve_route(
            routing, task, default=default, available=models, strict=False
        )
        effective = resolve_route(routing, task, default=default, available=models)
        payload = configured.as_payload()
        payload["effective"] = effective.target.label
        tasks[task] = payload
    return {
        "enabled": bool(routing.enabled),
        "active": bool(routing.enabled) and not routing.is_default(),
        "default": default.label,
        "tasks": tasks,
    }


def _chain_of(base: Any) -> Dict[str, Any]:
    """The clients behind ``base``, keyed by provider (a ``NexusLLM`` has a chain)."""
    chain: Iterable[Any] = list(getattr(base, "chain", None) or [])
    if not chain:
        chain = [base]
    return {
        _client_provider(client): client
        for client in chain
        if _client_provider(client)
    }


def build_model_selector(
    base: Any,
    *,
    routing: ModelRoutingConfig | None = None,
    wrap: Callable[[Any], Any] | None = None,
    event_sink: EventSink | None = None,
) -> DynamicModelSelector | None:
    """The selector for this run, or ``None`` when routing is a no-op.

    ``None`` is the documented fast path: the operator never pinned a profile,
    or turned routing off, so the caller keeps the client it built and nothing
    downstream changes. When something *is* pinned, the clients of the chain are
    reused and every other provider with a usable key is added, so a pin can
    name a provider that is not today's default.
    """
    if routing is None:
        try:
            from nexus_core.config.loader import load_config

            routing = load_config().model_routing
        except Exception as error:  # noqa: BLE001 - config trouble must not fail a run
            LOGGER.warning("cannot read [model_routing]: %s", error)
            return None
    if not routing.enabled or routing.is_default():
        return None
    clients = _chain_of(base)
    if not clients:
        return None
    try:
        from .abstraction import LLMFactory

        for name, client in LLMFactory.create_from_env().items():
            clients.setdefault(name, client)
    except Exception as error:  # noqa: BLE001 - no extra key is a normal situation
        LOGGER.warning("cannot build the provider pool for model routing: %s", error)
    try:
        default = ModelTarget(*_default_pair(base))
    except Exception:  # noqa: BLE001 - fall back to the selector's own inference
        default = None
    return DynamicModelSelector(
        clients, routing, wrap=wrap, default=default, event_sink=event_sink
    )


def _default_pair(base: Any) -> Tuple[str, str]:
    """``(provider, model)`` of the client the run would have used."""
    chain = list(getattr(base, "chain", None) or [])
    primary = chain[0] if chain else base
    return _client_provider(primary), _client_model(primary)


def routed_for_task(
    task: str,
    *,
    base: Any,
    wrap: Callable[[Any], Any] | None = None,
    routing: ModelRoutingConfig | None = None,
    event_sink: EventSink | None = None,
) -> Any:
    """``base`` routed for ``task``; ``base`` itself when routing is inert.

    Used by the calls that happen outside the ReAct loop -the planning turn and
    the report scorer- so they obey the same policy without the coordinator
    having to reach into them.
    """
    if task not in TASKS:
        raise ValueError(f"unknown model routing task: {task}")
    selector = build_model_selector(
        base, routing=routing, wrap=wrap, event_sink=event_sink
    )
    if selector is None:
        return base
    return selector.routed(task, event_sink=event_sink)


def select_llm_for_task(
    task: str,
    *,
    base: Any | None = None,
    wrap: Callable[[Any], Any] | None = None,
    routing: ModelRoutingConfig | None = None,
) -> Any:
    """Convenience for CLI/tool call sites: resolve the base client, then route."""
    if base is None:
        from nexus_core.kernel.runtime import select_llm_client

        base = select_llm_client()
    return routed_for_task(task, base=base, wrap=wrap, routing=routing)


__all__ = [
    "DynamicModelSelector",
    "FALLBACK_EVENT_TYPE",
    "LOGGER",
    "ModelTarget",
    "ROUTE_EVENT_TYPE",
    "RoutedLLM",
    "RoutingDecision",
    "TASKS",
    "TASK_EXECUTOR",
    "TASK_PLANNER",
    "TASK_REFLECTION",
    "TASK_REPORTING",
    "build_model_selector",
    "describe_routing",
    "resolve_route",
    "routed_for_task",
    "select_llm_for_task",
]
