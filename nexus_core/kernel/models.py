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

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["risk"] = self.risk.value
        return value


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

    @property
    def success(self) -> bool:
        return self.verified and not self.timed_out and (
            self.exit_code is None or self.exit_code in self.accepted_exit_codes
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
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
