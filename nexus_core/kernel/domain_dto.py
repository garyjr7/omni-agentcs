"""Strict, immutable boundary DTOs; persistence adapters retain legacy shapes."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter, field_validator


class DomainDTO(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, allow_inf_nan=False)


class AgentAction(DomainDTO):
    thought: str = ""
    raw_response: str = Field(default="", exclude=True)
    warnings: tuple[str, ...] = Field(default=(), exclude=True)

    def to_dict(self) -> dict[str, Any]:
        """The historical action-log shape, including absent variant fields."""
        value = self.model_dump(exclude={"raw_response", "warnings"})
        for name in ("tool_id", "arguments", "expected_outcome", "summary", "question"):
            value.setdefault(name, None)
        value.setdefault("findings", [])
        value["warnings"] = list(self.warnings)
        return value

    @field_validator("thought")
    @classmethod
    def strip_thought(cls, value: str) -> str:
        return value.strip()


#: Ceiling on one parallel batch. It is a contract, not a tuning knob: a model
#: that names ten independent tools in one answer is dictating a scan, not
#: orchestrating a turn, and the consolidated observation would not fit the
#: context anyway. Execution is additionally capped by
#: :data:`nexus_core.agent.parallel.PARALLEL_MAX_CONCURRENCY`.
MAX_PARALLEL_TOOL_CALLS = 4


class ToolCallSpec(DomainDTO):
    """One independent invocation inside a parallel batch."""

    tool_id: str = Field(min_length=1)
    arguments: dict[str, JsonValue]
    expected_outcome: str | None = None

    @field_validator("tool_id")
    @classmethod
    def nonempty_tool(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("tool_id must be nonempty")
        return value.strip()


class ToolCall(AgentAction):
    action: Literal["tool_call"] = "tool_call"
    tool_id: str = Field(min_length=1)
    arguments: dict[str, JsonValue]
    expected_outcome: str | None = None

    @field_validator("tool_id")
    @classmethod
    def nonempty_tool(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("tool_id must be nonempty")
        return value.strip()

    @property
    def summary(self) -> None:
        return None

    @property
    def findings(self) -> list[dict[str, Any]]:
        return []

    @property
    def question(self) -> None:
        return None


class ToolCallBatch(AgentAction):
    """Several independent tools the model asked to run at once.

    Every call is validated, approved and audited on its own -a batch is a
    scheduling hint, never a way around the gateway- and the loop answers with a
    single consolidated observation (``parallel.results``). Two calls are the
    minimum: a batch of one is normalised back to a plain ``tool_call`` by the
    parser, so the old single-tool paths never see this shape for one call.
    """

    action: Literal["tool_calls"] = "tool_calls"
    calls: list[ToolCallSpec] = Field(min_length=2, max_length=MAX_PARALLEL_TOOL_CALLS)

    @property
    def tool_id(self) -> str:
        return self.calls[0].tool_id

    @property
    def arguments(self) -> dict[str, JsonValue]:
        return self.calls[0].arguments

    @property
    def expected_outcome(self) -> str | None:
        return self.calls[0].expected_outcome

    @property
    def summary(self) -> None:
        return None

    @property
    def findings(self) -> list[dict[str, Any]]:
        return []

    @property
    def question(self) -> None:
        return None

    @property
    def tool_ids(self) -> tuple[str, ...]:
        return tuple(call.tool_id for call in self.calls)


class SpawnSubAgent(AgentAction):
    """A long call the model wants to run in the background.

    The payload is a normal tool call (catalog membership, subagent subset,
    policy, approval and the gateway all still apply); the only difference is
    *when* the loop awaits it. ``label`` is prompt-visible, so it is short and
    descriptive (``"nmap full TCP"``), never a command line.
    """

    action: Literal["spawn_subagent"] = "spawn_subagent"
    tool_id: str = Field(min_length=1)
    arguments: dict[str, JsonValue]
    label: str | None = Field(default=None, max_length=80)
    expected_outcome: str | None = None

    @field_validator("tool_id")
    @classmethod
    def nonempty_subagent_tool(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("tool_id must be nonempty")
        return value.strip()

    @property
    def summary(self) -> None:
        return None

    @property
    def findings(self) -> list[dict[str, Any]]:
        return []

    @property
    def question(self) -> None:
        return None


class TaskComplete(AgentAction):
    action: Literal["task_complete"] = "task_complete"
    summary: str = Field(min_length=1)
    findings: list[dict[str, JsonValue]] = Field(default_factory=list)

    @field_validator("summary")
    @classmethod
    def nonempty_summary(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("summary must be nonempty")
        return value.strip()

    @property
    def tool_id(self) -> None:
        return None

    @property
    def arguments(self) -> None:
        return None

    @property
    def expected_outcome(self) -> None:
        return None

    @property
    def question(self) -> None:
        return None


class RequestClarification(AgentAction):
    action: Literal["request_clarification"] = "request_clarification"
    question: str = Field(min_length=1)

    @field_validator("question")
    @classmethod
    def nonempty_question(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("question must be nonempty")
        return value.strip()

    @property
    def tool_id(self) -> None:
        return None

    @property
    def arguments(self) -> None:
        return None

    @property
    def expected_outcome(self) -> None:
        return None

    @property
    def summary(self) -> None:
        return None

    @property
    def findings(self) -> list[dict[str, Any]]:
        return []


Action = Annotated[
    ToolCall | ToolCallBatch | SpawnSubAgent | TaskComplete | RequestClarification,
    Field(discriminator="action"),
]
ACTION_ADAPTER: TypeAdapter[Action] = TypeAdapter(Action)


class ApprovalDecisionDTO(DomainDTO):
    approved: bool
    approval_id: str | None = None
    edited_arguments: dict[str, JsonValue] | None = None
    reason: str = ""


class PolicyDecisionDTO(DomainDTO):
    allowed: bool
    reason: str
    policy_id: str
    policy_version: str = "1.0.0"
    requires_approval: bool = False
    obligations: tuple[str, ...] = ()


class ToolResultDTO(DomainDTO):
    """Boundary shape of a tool result.

    ``outcome`` must accept *every* value of
    :data:`nexus_core.kernel.models.OUTCOME_TAXONOMY` (plus ``success``). It used
    to be a hand-written subset, so a handler could emit a value the taxonomy
    allowed and the DTO rejected: measured in Brute It v7 (iterations 9-12),
    where ``invalid_failure_string`` -added to the taxonomy days earlier- raised a
    ``ValidationError`` and the run lost the verdict twice. The parity is
    enforced by ``test_phase3n_fixes.py::test_the_result_dto_accepts_every_taxonomy_outcome``.
    """

    success: bool
    outcome: Literal[
        "success", "negative", "denied", "unsupported", "unavailable", "timeout",
        "command_failed", "scope_denied", "invalid_failure_string", "partial",
        "in_flight", "invalid_fact_type",
        "error",
    ]
    output: dict[str, JsonValue]
    verified: bool
    verification_method: str
    evidence: dict[str, JsonValue]
    exit_code: int | None
    accepted_exit_codes: list[int]
    stdout: str
    stderr: str
    timed_out: bool
    tool_id: str = ""
    contract_version: str = ""
    parser_version: str = ""
    invocation_id: str = ""
    run_id: str = ""
    engagement_id: str = ""
    assertions: list[dict[str, JsonValue]] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_unset=True)


class DomainEvent(DomainDTO):
    """Open event names, closed envelope: existing plugin events remain valid."""

    tenant_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    payload: dict[str, JsonValue] = Field(default_factory=dict)


def legacy_json_containers(value: Any) -> Any:
    """Adapt historical tuple containers to JSON arrays, without scalar coercion.

    Used only by legacy Python facades; new DTO input remains strictly JSON.
    """
    from .serialization import validate_json

    validate_json(value)

    def normalize(item: Any) -> Any:
        if isinstance(item, (tuple, list)):
            return [normalize(child) for child in item]
        if isinstance(item, dict):
            return {key: normalize(child) for key, child in item.items()}
        return item

    return normalize(value)
