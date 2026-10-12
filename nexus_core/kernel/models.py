"""Canonical, serializable models shared by every NEXUS gateway."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from uuid import uuid4

if TYPE_CHECKING:
    from nexus_core.scope.models import EngagementScope


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RiskLevel(str, Enum):
    READ_ONLY = "read_only"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DESTRUCTIVE = "destructive"


#: Closed vocabulary for ``ToolDefinition.effect`` (V1-3).
#:
#: The gate is binary —anything other than ``read_only`` counts as an *active*
#: operation and is denied in plan mode and requires approval in exec mode— so a
#: free-form string let a tool that executes commands or writes to the target
#: declare itself ``read_only``. ``read_only`` means precisely: does not modify
#: the target and does not mutate the engagement state. Recon and DAST scanners
#: that only read a target's surface stay ``read_only``.
EFFECT_TAXONOMY = frozenset({
    "read_only",
    #: Active operation whose class is unknown. Used by the MCP bridge: an
    #: external capability that is not purely ``read`` must fail closed as
    #: active instead of inventing a value the gate cannot classify.
    "active",
    "recon",
    "network_scan",
    "target_write",
    "state_write",
    "exploit",
    "execution",
    "post_exploitation",
    "credential_access",
    "credential_dump",
    "lateral_movement",
    "pivoting",
    "c2_implant_build",
    "system_install",
    "report",
})


@dataclass(frozen=True)
class Identity:
    subject_id: str
    tenant_id: str
    kind: str = "user"
    roles: tuple[str, ...] = ()
    departments: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    attributes: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Resource:
    resource_id: str
    tenant_id: str
    kind: str
    owner_id: Optional[str] = None
    classification: str = "internal"
    environment: str = "development"
    attributes: Dict[str, str] = field(default_factory=dict)


@dataclass
class AgentDefinition:
    name: str
    tenant_id: str
    version: str = "1.0.0"
    agent_id: str = field(default_factory=lambda: f"agent_{uuid4().hex}")
    description: str = ""
    capabilities: List[str] = field(default_factory=list)
    tool_ids: List[str] = field(default_factory=list)
    model_route: str = "default"
    department_id: Optional[str] = None
    enabled: bool = True
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolDefinition:
    name: str
    tenant_id: str
    input_schema: Dict[str, Any]
    version: str = "1.0.0"
    tool_id: str = field(default_factory=lambda: f"tool_{uuid4().hex}")
    description: str = ""
    risk: RiskLevel = RiskLevel.READ_ONLY
    required_permissions: List[str] = field(default_factory=list)
    timeout_seconds: int = 30
    max_output_bytes: int = 1_000_000
    effect: str = "read_only"
    scopes: List[str] = field(default_factory=list)
    enabled: bool = True
    created_at: str = field(default_factory=utc_now)
    scope_target_field: str | None = None
    scope_required: bool = False
    effects: tuple[str, ...] = ()
    sandbox_required: bool = False
    idempotent: bool = False

    def __post_init__(self) -> None:
        # Fail closed on an invented effect: the gate compares against
        # ``read_only``, so a typo would silently declare an active tool passive.
        if self.effect not in EFFECT_TAXONOMY:
            raise ValueError(
                f"unknown effect {self.effect!r} for tool {self.tool_id!r}; "
                f"declare one of {sorted(EFFECT_TAXONOMY)}"
            )
        # A malformed contract declares limits nobody can enforce (V1-10), so it
        # is rejected where the tool is registered instead of on the first
        # invocation. Imported lazily to keep this module free of a hard import
        # from the validation layer.
        from .schema_validation import check_schema

        check_schema(self.input_schema)

    @property
    def active(self) -> bool:
        """Whether this tool performs an active (non read-only) operation."""
        return self.effect != "read_only"

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["risk"] = self.risk.value
        return value


#: Closed vocabulary for ``ToolResult.outcome`` (V0-22).
#:
#: ``execution_completed`` and ``matched`` are two different questions: a
#: listing that returns no entries, a share that answers ACCESS_DENIED or a
#: protocol the target does not speak are *determinate observations about the
#: target*, not failures of the body. They used to reach the caller as a
#: ``RuntimeError``, which erased the distinction between "we looked and there
#: was nothing" and "we could not look". ``success`` is not part of this
#: vocabulary: a positive result is expressed by ``verified``, never declared.
OUTCOME_TAXONOMY = frozenset({
    #: The operation ran to completion; the target legitimately shows nothing.
    "negative",
    #: The target refused the operation (authentication/authorisation).
    "denied",
    #: The target answered that it does not support the operation.
    "unsupported",
    #: The binary/service is missing; the target was never contacted.
    "unavailable",
    #: The operation ran out of time.
    "timeout",
    #: Anything else, including an unparsed or corrupt answer.
    "error",
})

#: Outcomes that mean the invocation reached a determinate conclusion *against
#: the target*. They complete the invocation (audited and journaled) instead of
#: raising, and derive no positive assertion.
COMPLETED_OUTCOMES = frozenset({"negative", "denied", "unsupported"})


@dataclass(frozen=True)
class ToolResult:
    """Canonical, evidence-backed result returned by every governed tool.

    ``verified`` is a deterministic observation of the requested
    post-condition, not an LLM assertion or the mere absence of an exception.
    """
    output: Dict[str, Any] = field(default_factory=dict)
    verified: bool = False
    verification_method: str = "unspecified"
    evidence: Dict[str, Any] = field(default_factory=dict)
    exit_code: Optional[int] = None
    accepted_exit_codes: tuple[int, ...] = (0,)
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    # Which catalog entry produced this result. The gateway stamps them, so a
    # replay can be compared against the assertions registered with that exact
    # contract/parser version instead of "whatever is installed today" (V1-8).
    tool_id: str = ""
    contract_version: str = ""
    parser_version: str = ""
    #: Explicit classification of what the invocation produced (V0-22). Empty
    #: means the handler declared none and ``outcome_class`` derives one.
    outcome: str = ""

    def __post_init__(self) -> None:
        if self.outcome and self.outcome not in OUTCOME_TAXONOMY:
            raise ValueError(
                f"unknown tool outcome {self.outcome!r}; "
                f"declare one of {sorted(OUTCOME_TAXONOMY)}"
            )

    @property
    def success(self) -> bool:
        return self.verified and not self.timed_out and (
            self.exit_code is None or self.exit_code in self.accepted_exit_codes
        )

    @property
    def outcome_class(self) -> str:
        """Determinate classification of the invocation.

        A declared ``outcome`` wins. Otherwise the legacy signals are mapped so
        callers that never declare one keep their previous meaning: a timeout,
        an absent binary or an unparsed answer stay failures.
        """
        if self.outcome:
            return self.outcome
        if self.success:
            return "success"
        if self.timed_out:
            return "timeout"
        if self.verification_method.endswith(("_unavailable", "_timeout")):
            return "unavailable"
        return "error"

    @property
    def completed(self) -> bool:
        """The invocation reached a determinate conclusion (V0-22)."""
        return self.success or self.outcome in COMPLETED_OUTCOMES

    def to_dict(self) -> Dict[str, Any]:
        value = {
            "success": self.success,
            "outcome": self.outcome_class,
            "output": self.output,
            "verified": self.verified,
            "verification_method": self.verification_method,
            "evidence": self.evidence,
            "exit_code": self.exit_code,
            "accepted_exit_codes": list(self.accepted_exit_codes),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
        }
        if self.tool_id:
            value["tool_id"] = self.tool_id
            value["contract_version"] = self.contract_version
            value["parser_version"] = self.parser_version
        return value

    def stamp_versions(self, tool_id: str, contract_version: str, parser_version: str) -> "ToolResult":
        """Return this result tagged with the contract/parser that produced it.

        ``ToolResult`` is frozen on purpose (evidence must not be mutated in
        place), so the gateway stamps by replacement.
        """
        from dataclasses import replace

        return replace(
            self,
            tool_id=tool_id,
            contract_version=contract_version,
            parser_version=parser_version,
        )


@dataclass(frozen=True)
class RunContext:
    tenant_id: str
    identity: Identity
    run_id: str = field(default_factory=lambda: f"run_{uuid4().hex}")
    trace_id: str = field(default_factory=lambda: uuid4().hex)
    environment: str = "development"
    budget_tokens: int = 0
    budget_usd: float = 0.0
    scope: "EngagementScope | None" = None
    # Execution dependencies used by durable tool handlers. Kept out of the
    # dataclass comparison/repr because they hold live resources.
    store: Any = field(default=None, repr=False, compare=False)
    worker_id: str = ""
    # Only ToolGateway populates this after exact-plan durable approval.
    approved_install_plan: Any = field(default=None, repr=False, compare=False)
    invocation_id: str = ""
    session_id: str = ""
    # Operator-supplied workspace; never taken from tool arguments.
    project_root: str = ""
    # Kill-chain phase and objective of the calling step. Set by the engine (not
    # the model) so the gateway can derive a durable ``step_key`` for the
    # invocation journal.
    phase: str = ""
    objective: str = ""

    @property
    def engagement_id(self) -> str:
        """Engagement of the signed scope, if any.

        Derived from the scope so a tool's lifecycle hooks report the same
        engagement as the run that authorized the call (P2-A2).
        """
        return str(getattr(self.scope, "engagement_id", "") or "")


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    policy_id: str
    policy_version: str = "1.0.0"
    requires_approval: bool = False
    obligations: tuple[str, ...] = ()


@dataclass
class Artifact:
    tenant_id: str
    run_id: str
    kind: str
    uri: str
    sha256: str
    artifact_id: str = field(default_factory=lambda: f"artifact_{uuid4().hex}")
    classification: str = "internal"
    created_at: str = field(default_factory=utc_now)
