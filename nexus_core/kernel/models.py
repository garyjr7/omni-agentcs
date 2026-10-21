"""Canonical, serializable models shared by every NEXUS gateway."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from uuid import uuid4

from .domain_dto import (
    ToolCall as ToolCall, TaskComplete as TaskComplete,
    RequestClarification as RequestClarification, ToolResultDTO as ToolResultDTO,
    PolicyDecisionDTO as PolicyDecisionDTO, DomainEvent as DomainEvent,
    legacy_json_containers,
)

if TYPE_CHECKING:
    from nexus_core.scope.models import EngagementScope
    from .job_authority import JobAuthority


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
    #: Argument values the handler refuses although the JSON Schema accepts them,
    #: keyed by argument name: ``{"options": ["RHOSTS", "LHOST", ...]}`` (Fase
    #: 3b). The schema is permissive on purpose (any datastore key is a scalar),
    #: so the hand-written validator is the real contract and the model could only
    #: learn it by being rejected -measured in run_434f5eeadb104b11ba0c80bce16f8d08:
    #: two turns lost to ``options.RHOSTS``. Declaring it here is what lets the
    #: catalog publish the constraint. Optional: only a tool that has one declares
    #: it, and the handler keeps enforcing it (this field never authorizes).
    forbidden_argument_values: Dict[str, List[str]] = field(default_factory=dict)
    #: Arguments whose value is *the operator's*, taken from the environment,
    #: keyed by argument name: ``{"lhost": "MSF_LHOST"}`` (Fase 3d). The handler
    #: pins them and refuses anything else, so the schema cannot make them
    #: settable and the catalog has to publish who owns them. Measured in rerun 4
    #: (``run_44b43bad8c5e4a998cf06b513c3eba60``, iteration 11): the catalog line
    #: said ``lhost:string``, the model filled it with an invented ``10.65.175.1``
    #: and the turn was spent on a rejection it could not have avoided. A nested
    #: key (the callback living inside ``options``) is written as its argument
    #: path, e.g. ``options.LHOST``. Optional: only a tool that has one declares
    #: it, and the handler keeps enforcing it (this field never authorizes).
    fixed_by_env: Dict[str, str] = field(default_factory=dict)

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
    #: The channel worked and the command ran, but it exited non-zero: the
    #: *command* failed, not the credential nor the connection.
    "command_failed",
    #: The address the call named is outside the signed engagement scope, so it
    #: was refused before anything ran. ``nexus.web.request`` raises it at the
    #: gateway; ``nexus.shell.exec`` returns it for the destination of a
    #: ``curl``/``wget``/``nc``. Same outcome name in both channels, so the model
    #: reads one rule instead of two.
    "scope_denied",
    #: The caller's own input cannot answer the question it asks: hydra's
    #: ``failure_string`` is present in both branches of the login, so a sweep
    #: with it can never report the credential it walks past (Brute It v6,
    #: iteration 8: 600 s with ``F=LOGIN`` against a panel whose button says
    #: ``Login``). Determinate *before* the sweep, so it completes instead of
    #: raising: the model gets the reason and one more turn to fix the marker.
    "invalid_failure_string",
    #: A bounded slice of the wordlist ran to its end without a hit, and the list
    #: has more entries (Brute It v7, iteration 16: a full ``rockyou`` sweep ran
    #: 890 s only to be killed by the loop). It is a determinate observation
    #: about *that slice* -not about the target- so it completes, promotes
    #: nothing and closes no branch; ``next_start_at`` tells the caller where the
    #: next slice begins.
    "partial",
    #: Anything else, including an unparsed or corrupt answer.
    "error",
})

#: Outcomes that mean the invocation reached a determinate conclusion. They
#: complete the invocation (audited and journaled) instead of raising, and derive
#: no positive assertion.
#:
#: ``unavailable`` belongs here (Fase 3b): a body whose backend/binary is not
#: there has *decided* -the target was never contacted- and the loop must count
#: it, retire the tool after repeated attempts and pivot. Raising instead is what
#: turned a dead MSF RPC into the end of a whole run (measured in
#: run_434f5eeadb104b11ba0c80bce16f8d08). The distinction that matters is kept:
#: the outcome is ``unavailable``, never ``negative``, so nothing reads as "we
#: looked and there was nothing" and no assertion is derived. A *bare* failure
#: that declares no outcome still keeps its own error and does not complete.
#: ``command_failed`` is here too: reaching the target and getting a non-zero
#: exit status is a determinate observation about it. Raising instead turned
#: every failed `sudo` command into a broken post-condition, and the model read
#: the resulting message as a bad credential (measured in Simple CTF).
COMPLETED_OUTCOMES = frozenset({
    "negative", "denied", "unsupported", "unavailable", "command_failed",
    # A refusal of the *arguments* that ends the call before it starts. Raising
    # instead would journal an ``unknown`` effect for something that never ran
    # and block the corrected retry (Brute It v6, iterations 11-17).
    "invalid_failure_string",
    # A slice that finished with the list still having entries: the call decided
    # something about the slice it ran, so it must not raise (the caller asks for
    # the next one instead) nor be read as a negative verdict about the target.
    "partial",
})

#: ``verification_method`` suffixes that mean "the backend this tool talks to did
#: not serve the call" -MSF RPC down, missing RPC credentials, absent binary,
#: timeout- as opposed to "the check ran and the answer was no" (Fase 3b). These
#: are the shapes the handlers already emitted; what changes is that the gateway
#: re-classifies them instead of raising.
PROVIDER_UNAVAILABLE_SUFFIXES = (
    "_rpc_failed",
    "_credentials_missing",
    "_unavailable",
    "_timeout",
)
#: Method stamped on a result the gateway re-classified as ``unavailable``.
PROVIDER_UNAVAILABLE_METHOD = "provider_unavailable"
#: Method stamped on a result whose *operator* configuration is incomplete.
CONFIG_MISSING_METHOD = "config_missing"


def config_missing_result(
    tool_id: str, missing_env: "tuple[str, ...] | list[str]", *, detail: str = ""
) -> "ToolResult":
    """Result for a tool whose operator configuration is incomplete (Fase 3c).

    Measured in the rerun #3 of Fase 3 (commit 8de386b): ``MSF_LHOST`` was unset,
    ``msf_exploit`` answered ``msf_lhost_missing`` and the loop read that as a
    plain tool failure -the model kept retrying MSF while ``searchsploit`` or the
    ``impacket_*`` tools of the same profile were available. An incomplete
    *operator* configuration is not a broken tool and it is not invalid input
    from the model: it is ``unavailable`` (nobody can make it work from inside
    the run), audited with the exact variable that is missing, so the agent
    pivots and the operator has one actionable line to fix.

    Only the variables a tool really needs are passed here: the result never
    covers a value the tool can default (``MSF_LPORT`` has one), and the runtime
    precondition is also reported by ``omni --doctor`` *before* a run
    (see ``nexus_core/cli/doctor.py``).
    """
    env = tuple(str(name) for name in missing_env if str(name))
    return ToolResult(
        output={
            "status": "configuration_error",
            "reason": detail or f"{', '.join(env)} is required",
        },
        verified=False,
        outcome="unavailable",
        verification_method=f"{tool_id}_{CONFIG_MISSING_METHOD}",
        evidence={
            "missing_env": list(env),
            "tool_id": str(tool_id),
            **(({"detail": detail}) if detail else {}),
        },
    )


def provider_unavailable_result(tool_id: str, result: "ToolResult") -> "ToolResult":
    """Re-classify a backend failure as a determinate ``unavailable`` outcome.

    Measured in run_434f5eeadb104b11ba0c80bce16f8d08: ``msf_auxiliary`` could not
    reach ``msfrpcd``, the gateway raised ``ProviderFailure`` and a six-turn run
    with a live target ended as ``provider_error``. A backend that is not serving
    is not a broken tool and it is not the end of the mission: the tool says so
    (``outcome="unavailable"``, never ``negative`` -nothing was observed), the
    loop counts it like any other tool failure and retires the tool after
    repeated attempts so the agent pivots to the rest of the phase.

    The original method and the handler's evidence are kept under ``cause`` so no
    diagnostic is lost, and ``provider`` names the backend the way an operator
    would (``msf_rpc`` for ``msf_rpc_failed``): the trailing verdict
    (``_failed``) is stripped first, then the failure shape.
    """
    from dataclasses import replace

    method = str(result.verification_method or "unspecified")
    provider = method[: -len("_failed")] if method.endswith("_failed") else method
    for suffix in PROVIDER_UNAVAILABLE_SUFFIXES:
        if provider.endswith(suffix):
            provider = provider[: -len(suffix)]
            break
    provider = provider or tool_id or method
    evidence: Dict[str, Any] = {
        "provider": provider,
        "detail": f"{method} (the backend did not serve the call)",
    }
    if result.evidence:
        evidence["cause"] = dict(result.evidence)
    return replace(
        result,
        verified=False,
        outcome="unavailable",
        verification_method=f"{tool_id}_{PROVIDER_UNAVAILABLE_METHOD}",
        evidence=evidence,
    )


def tool_timeout_result(tool_id: str, timeout_seconds: Any) -> "ToolResult":
    """Result for a tool the engine had to cut off at its own ``timeout_seconds``.

    Measured in the rerun #7 (attempt 1, 2026-10-15): the model asked ``nmap -p-``
    for ``timeout_seconds=600`` against a slow target, the gateway's own
    ``asyncio.wait_for`` fired at 600 s, and the bare ``TimeoutError`` escaped the
    tool layer: the *whole run* closed as ``provider_error`` with
    ``summary: "TimeoutError"`` (exit 3) from iteration 1, while five other routes
    of the profile were still available. A tool that runs out of time is a tool
    failing *now*, exactly like a missing binary: it has to reach the loop as a
    determinate ``timeout`` outcome, count as one tool failure, and let the tool be
    retired after repeated attempts so the agent pivots.

    It is deliberately not ``unavailable`` (the backend answered; the call just did
    not finish inside the budget the caller declared) and never ``negative``
    (nothing was observed about the target). A *provider* (LLM) timeout keeps its
    own ``provider_error`` path: it is raised by the model call, never here.
    """
    return ToolResult(
        output={
            "status": "timeout",
            "reason": f"the handler exceeded its {timeout_seconds}s budget",
        },
        verified=False,
        timed_out=True,
        outcome="timeout",
        verification_method=f"{tool_id}_timeout",
        evidence={"timeout_seconds": timeout_seconds, "tool_id": str(tool_id)},
    )


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
        return dict(self.to_dto().to_dict())

    def to_dto(self) -> ToolResultDTO:
        """Validate the legacy handler result at the domain boundary."""
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
        return ToolResultDTO.model_validate(legacy_json_containers(value))

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
    #: ``--resume-policy`` of the run (``approve``/``skip``/``fail``), set by the
    #: engine only under ``--trust-mode``. It decides what a retry of an
    #: invocation the journal holds ``unknown`` may do without a human: an
    #: audited durable approval, a no-effect skip, or the fail-closed block.
    #: Never read from tool arguments.
    resume_policy: str = ""
    # Set by ToolGateway from the authenticated invocation, never tool arguments.
    authorized_permissions: tuple[str, ...] = field(default=(), repr=False, compare=False)

    # Engine-owned, immutable capability envelope; never read from tool arguments.
    job_authority: JobAuthority | None = field(default=None, repr=False, compare=False)

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

    def __post_init__(self) -> None:
        self.to_dto()

    def to_dto(self) -> PolicyDecisionDTO:
        return PolicyDecisionDTO.model_validate(asdict(self))


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
