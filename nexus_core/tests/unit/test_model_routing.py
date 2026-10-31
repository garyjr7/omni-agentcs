"""``[model_routing]``: per-task model selection, fallback and journaling."""

from __future__ import annotations

import asyncio
import json

import pytest

from nexus_core.agent.react import ReActConfig, run_react_loop
from nexus_core.config.schema import ModelRoutingConfig, OmniConfig, RouteTarget
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import (
    LLMConfig,
    LLMProvider,
    LLMResponse,
    NexusLLM,
    NexusLLMError,
)
from nexus_core.llm.dynamic_selector import (
    FALLBACK_EVENT_TYPE,
    ROUTE_EVENT_TYPE,
    DynamicModelSelector,
    ModelTarget,
    build_model_selector,
    describe_routing,
    resolve_route,
    routed_for_task,
)
from nexus_core.tests.unit.test_hooks_lifecycle import context


class StubClient:
    """A provider that answers (or fails) without touching the network."""

    supports_streaming = False
    supports_action_json = True

    def __init__(self, provider: LLMProvider, model: str, *, answer: str = "ok") -> None:
        # A key and a base URL, like every client the factory really builds: the
        # selector clones them when a profile names another model.
        self.config = LLMConfig(
            provider=provider, model=model, api_key="fixture-key", base_url="https://example.invalid"
        )
        self.answer = answer
        self.calls = 0
        self.error: BaseException | None = None

    async def complete(self, messages, **kwargs):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return LLMResponse(
            content=self.answer, model=self.config.model, provider=self.config.provider
        )


GROQ_MODEL = "qwen/qwen3.8-27b"
DEEPSEEK_MODEL = "deepseek-flash"
ANTHROPIC_MODEL = "claude-sonnet-4-20250514"


def _clients():
    return {
        "groq": StubClient(LLMProvider.GROQ, GROQ_MODEL),
        "deepseek": StubClient(LLMProvider.DEEPSEEK, DEEPSEEK_MODEL),
        "anthropic": StubClient(LLMProvider.ANTHROPIC, ANTHROPIC_MODEL),
    }


# --------------------------------------------------------------------- config
def test_nested_profiles_parse_from_toml():
    config = OmniConfig.from_toml(
        """
schema_version = 1

[model_routing]

[model_routing.planner]
provider = "openai"
model = "o3"
fallbacks = ["anthropic/claude-sonnet-4-20250514", "deepseek"]

[model_routing.executor]
provider = "deepseek"
model = "deepseek-flash"
"""
    )
    assert config.model_routing.planner == RouteTarget(
        "openai", "o3", ["anthropic/claude-sonnet-4-20250514", "deepseek"]
    )
    assert config.model_routing.executor.provider == "deepseek"
    # A profile the operator never wrote is "inherit", not a guess.
    assert config.model_routing.reflection == RouteTarget()


def test_the_writer_emits_sub_tables_only_for_pinned_profiles():
    config = OmniConfig()
    config.model_routing.planner = RouteTarget("anthropic", ANTHROPIC_MODEL)
    text = config.to_toml()
    assert "[model_routing.planner]" in text
    assert "[model_routing.executor]" not in text
    assert OmniConfig.from_toml(text).model_routing == config.model_routing


def test_routing_round_trips_through_toml():
    config = OmniConfig()
    config.model_routing = ModelRoutingConfig(
        planner=RouteTarget("anthropic", ANTHROPIC_MODEL, ["deepseek/deepseek-flash"]),
        executor=RouteTarget("deepseek", DEEPSEEK_MODEL),
    )
    assert OmniConfig.from_toml(config.to_toml()) == config


def test_an_unconfigured_routing_section_is_the_default():
    assert ModelRoutingConfig().is_default()
    assert not ModelRoutingConfig(executor=RouteTarget("deepseek", "x")).is_default()


@pytest.mark.parametrize(
    "text",
    [
        # unknown provider
        '[model_routing.executor]\nprovider = "nope"\n',
        # the fake would answer every failure with a canned completion
        '[model_routing.executor]\nfallbacks = ["fake"]\n',
        # a typo in the profile name is not a silent no-op
        "[model_routing.executr]\nprovider = \"deepseek\"\n",
        # a repeated backup is a typo, not a plan
        '[model_routing.executor]\nfallbacks = ["deepseek", "deepseek"]\n',
        # fallbacks must be a list of strings
        '[model_routing.executor]\nfallbacks = "deepseek"\n',
        # enabled is a switch, not a string
        'enabled = "yes"\n',
    ],
)
def test_invalid_routing_is_rejected(text):
    with pytest.raises(ValueError):
        OmniConfig.from_toml("schema_version = 1\n\n[model_routing]\n" + text)


# ------------------------------------------------------------------- selector
def test_each_task_gets_its_pinned_model():
    routing = ModelRoutingConfig(
        planner=RouteTarget("anthropic", ANTHROPIC_MODEL),
        executor=RouteTarget("deepseek", DEEPSEEK_MODEL),
    )
    selector = DynamicModelSelector(_clients(), routing)

    assert selector.decide("planner").target == ModelTarget("anthropic", ANTHROPIC_MODEL)
    assert selector.decide("executor").target == ModelTarget("deepseek", DEEPSEEK_MODEL)
    assert selector.decide("planner").source == "config"


def test_an_empty_profile_inherits_the_default_provider():
    routing = ModelRoutingConfig(planner=RouteTarget("deepseek", DEEPSEEK_MODEL))
    selector = DynamicModelSelector(_clients(), routing)

    decision = selector.decide("reflection")

    assert decision.target == ModelTarget("groq", GROQ_MODEL)
    assert decision.source == "inherit"
    # Other providers with a key are the implicit backups, the fake never is.
    assert [item.label for item in decision.fallbacks] == [
        f"deepseek/{DEEPSEEK_MODEL}",
        f"anthropic/{ANTHROPIC_MODEL}",
    ]


def test_a_pin_without_a_key_falls_back_to_the_default_and_says_why():
    routing = ModelRoutingConfig(planner=RouteTarget("openai", "o3"))
    selector = DynamicModelSelector(_clients(), routing)

    decision = selector.decide("planner")

    assert decision.target == ModelTarget("groq", GROQ_MODEL)
    assert "sin clave utilizable" in decision.reason


def test_explicit_fallbacks_keep_their_order_and_put_other_providers_first():
    routing = ModelRoutingConfig(
        executor=RouteTarget(
            "deepseek", DEEPSEEK_MODEL, ["deepseek/deepseek-reasoner", "groq"]
        )
    )
    selector = DynamicModelSelector(_clients(), routing)

    assert [item.label for item in selector.decide("executor").fallbacks] == [
        f"groq/{GROQ_MODEL}",
        "deepseek/deepseek-reasoner",
    ]


def test_a_different_model_on_the_same_provider_is_cloned():
    routing = ModelRoutingConfig(executor=RouteTarget("deepseek", "deepseek-reasoner"))
    selector = DynamicModelSelector(_clients(), routing)

    client = selector.client_for(ModelTarget("deepseek", "deepseek-reasoner"))

    assert client is not None
    assert client.config.model == "deepseek-reasoner"
    # The operator's key and endpoint travel with the clone.
    assert client.config.provider is LLMProvider.DEEPSEEK


def test_build_selector_is_inert_without_a_pinned_profile():
    base = _clients()["groq"]

    assert build_model_selector(base, routing=ModelRoutingConfig()) is None
    assert build_model_selector(
        base, routing=ModelRoutingConfig(enabled=False)
    ) is None
    # ``routed_for_task`` then hands back the very same client.
    assert routed_for_task("planner", base=base, routing=ModelRoutingConfig()) is base


# ------------------------------------------------------------------- fallback
def test_a_failing_model_retries_on_another_provider_and_journals_it():
    clients = _clients()
    clients["deepseek"].error = RuntimeError("429 rate limit exceeded")
    routing = ModelRoutingConfig(executor=RouteTarget("deepseek", DEEPSEEK_MODEL))
    events: list[tuple[str, dict]] = []
    routed = DynamicModelSelector(clients, routing).routed(
        "executor", event_sink=lambda kind, payload: events.append((kind, payload))
    )

    response = asyncio.run(routed.complete([]))

    assert response.provider is LLMProvider.GROQ
    assert clients["deepseek"].calls == 1
    assert clients["groq"].calls == 1
    kind, payload = events[0]
    assert kind == FALLBACK_EVENT_TYPE
    assert payload["task"] == "executor"
    assert payload["from"] == f"deepseek/{DEEPSEEK_MODEL}"
    assert payload["to"] == f"groq/{GROQ_MODEL}"
    assert payload["reason"] == "rate_limit"


def test_when_every_model_fails_the_error_names_them_all():
    clients = _clients()
    for client in clients.values():
        client.error = NexusLLMError("provider down")
    routing = ModelRoutingConfig(executor=RouteTarget("deepseek", DEEPSEEK_MODEL))
    routed = DynamicModelSelector(clients, routing).routed("executor")

    with pytest.raises(NexusLLMError) as error:
        asyncio.run(routed.complete([]))

    message = str(error.value)
    assert f"deepseek/{DEEPSEEK_MODEL}" in message
    assert f"groq/{GROQ_MODEL}" in message


def test_a_budget_refusal_is_never_retried_on_another_provider():
    """Spending the fallback would spend the tokens the budget just denied."""
    clients = _clients()
    clients["deepseek"].error = PermissionError("model response exceeded run token budget")
    routing = ModelRoutingConfig(executor=RouteTarget("deepseek", DEEPSEEK_MODEL))
    routed = DynamicModelSelector(clients, routing).routed("executor")

    with pytest.raises(PermissionError):
        asyncio.run(routed.complete([]))
    assert clients["groq"].calls == 0


# ---------------------------------------------------------------- ReAct wiring
def _loop_context(tmp_path, monkeypatch) -> ExecutionContext:
    ctx = context(tmp_path, monkeypatch)
    run = ctx.store.create_run("system", {})
    payload = {"objective": "recon", "identity": {"subject_id": "op", "roles": ["operator"]}}
    task = {
        "id": "t",
        "tenant_id": "system",
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": payload,
    }
    return ExecutionContext(ctx.store, task, "worker-test")


_CLARIFY = json.dumps(
    {"thought": "Pido contexto.", "action": "request_clarification", "question": "¿Sigo?"}
)


def test_the_loop_runs_the_turn_on_the_executor_profile_and_journals_why(
    tmp_path, monkeypatch
):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    clients = _clients()
    clients["deepseek"].answer = _CLARIFY
    routing = ModelRoutingConfig(
        planner=RouteTarget("anthropic", ANTHROPIC_MODEL),
        executor=RouteTarget("deepseek", DEEPSEEK_MODEL),
    )
    selector = DynamicModelSelector(clients, routing)

    result = asyncio.run(
        run_react_loop(
            context=exec_ctx,
            objective="recon",
            engagement_id=None,
            llm_client=clients["groq"],
            model_selector=selector,
            config=ReActConfig(max_iterations=2, enforce_completion_gates=False),
        )
    )

    assert result.status == "clarification"
    assert clients["deepseek"].calls == 1
    assert clients["groq"].calls == 0, "the inherited default never served the turn"
    events = [
        event
        for event in exec_ctx.store.list_run_events("system", exec_ctx.run_id)
        if event["event_type"] == ROUTE_EVENT_TYPE
    ]
    assert len(events) == 1
    payload = events[0]["payload"]
    assert payload["task"] == "executor"
    assert payload["provider"] == "deepseek"
    assert payload["model"] == DEEPSEEK_MODEL
    assert payload["source"] == "config"
    assert payload["iteration"] == 1


def test_the_loop_rewraps_a_plain_nonsense_selector_without_failing(tmp_path, monkeypatch):
    """A selector that raises must not end a run that has a working client."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    groq = StubClient(LLMProvider.GROQ, GROQ_MODEL, answer=_CLARIFY)

    class Broken:
        def routed(self, *args, **kwargs):
            raise RuntimeError("boom")

    result = asyncio.run(
        run_react_loop(
            context=exec_ctx,
            objective="recon",
            engagement_id=None,
            llm_client=groq,
            model_selector=Broken(),
            config=ReActConfig(max_iterations=2, enforce_completion_gates=False),
        )
    )

    assert result.status == "clarification"
    assert groq.calls == 1


# --------------------------------------------------------------------- doctor
def test_describe_routing_shows_every_task_and_its_backups():
    routing = ModelRoutingConfig(
        planner=RouteTarget("anthropic", ANTHROPIC_MODEL, ["deepseek/deepseek-flash"]),
    )
    summary = describe_routing(
        routing,
        default=ModelTarget("groq", GROQ_MODEL),
        available={
            "groq": GROQ_MODEL,
            "deepseek": DEEPSEEK_MODEL,
            "anthropic": ANTHROPIC_MODEL,
        },
    )

    assert summary["enabled"] is True and summary["active"] is True
    assert summary["default"] == f"groq/{GROQ_MODEL}"
    assert set(summary["tasks"]) == {"planner", "executor", "reflection", "reporting"}
    assert summary["tasks"]["planner"]["provider"] == "anthropic"
    assert summary["tasks"]["planner"]["fallbacks"] == [f"deepseek/{DEEPSEEK_MODEL}"]
    assert summary["tasks"]["executor"]["source"] == "inherit"


def test_doctor_reports_the_active_policy(onboarding_env, capsys, no_stored_keys):
    from nexus_core.cli import doctor as doctor_module

    config = OmniConfig()
    config.model_routing = ModelRoutingConfig(
        executor=RouteTarget("deepseek", DEEPSEEK_MODEL, ["groq/qwen/qwen3.8-27b"])
    )
    assert doctor_module.run_doctor(onboarding_env.paths, config, as_json=True) == 0
    report = json.loads(capsys.readouterr().out)

    routing = report["model_routing"]
    assert routing["active"] is True
    # The policy the operator wrote is what the section shows...
    assert routing["tasks"]["executor"]["provider"] == "deepseek"
    assert routing["tasks"]["executor"]["model"] == DEEPSEEK_MODEL
    # ...and ``effective`` says the key is missing, so the next run inherits.
    assert routing["tasks"]["executor"]["effective"] == f"groq/{GROQ_MODEL}"

    doctor_module.run_doctor(onboarding_env.paths, config)
    output = capsys.readouterr().out
    assert "Enrutamiento de modelos" in output
    assert f"deepseek/{DEEPSEEK_MODEL}" in output
    assert f"efectivo: groq/{GROQ_MODEL}" in output


def test_resolve_route_rejects_an_unknown_task():
    with pytest.raises(ValueError):
        resolve_route(
            ModelRoutingConfig(), "nonsense", default=ModelTarget("groq", GROQ_MODEL)
        )


def test_the_real_wrapper_is_a_valid_base():
    """``NexusLLM`` advertises its chain, so the selector can reuse its clients."""
    primary = StubClient(LLMProvider.GROQ, GROQ_MODEL)
    wrapper = NexusLLM(primary=primary)
    routing = ModelRoutingConfig(executor=RouteTarget("groq", GROQ_MODEL))

    selector = build_model_selector(wrapper, routing=routing)

    assert selector is not None
    assert selector.default_target == ModelTarget("groq", GROQ_MODEL)
    assert selector.client_for(ModelTarget("groq", GROQ_MODEL)) is primary
