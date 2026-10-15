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


Action = Annotated[ToolCall | TaskComplete | RequestClarification, Field(discriminator="action")]
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
    success: bool
    outcome: Literal[
        "success", "negative", "denied", "unsupported", "unavailable", "timeout", "error"
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
