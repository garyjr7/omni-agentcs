"""Explicit ReAct transitions with per-run state and injected boundary services."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import time
from typing import Any, Callable

from nexus_core.kernel.audit import AuditWriter
from nexus_core.llm.abstraction import LLMMessage, is_invalid_json_error
from nexus_core.scope import ScopeViolation

from . import memory
from nexus_core.kernel.errors import (
    ApprovalRequired,
    ProviderFailure,
    ReplayApprovalRequired,
)
from .preflight import unavailable_tools_from_env
from .project_context import load_project_instruction
from .skills import activate_skills
from .subagents import (
    filter_catalog,
    legacy_profiles,
    permits,
    select_run_profile,
    with_phase_grace,
)
from .parser import (
    ACTION_TASK_COMPLETE,
    ReActParseError,
)
from .branch_discipline import (
    BARRIER_ATTEMPT_WINDOW,
    BARRIER_INSISTENCE_LIMIT,
    BARRIER_MIN_DISTINCT_TOOLS,
    SKILL_LOAD_TOOL,
    barrier_refusal,
    closed_branch_refusal,
    redundant_fact_refusal,
    unknown_skill_refusal,
)

from .react_types import (
    BUDGET_EXEMPT_EVENT_TYPE,
    BUDGET_GRACE_EVENT_TYPE,
    DEFAULT_AGENT_ID,
    OBJECTIVE_GRACE_EVENT_TYPE,
    OBJECTIVE_GRACE_TURNS,
    SUBAGENT_SOFT_LIMIT_EVENT_TYPE,
    OBJECTIVE_COMPLETE_EVENT_TYPE,
    MAX_CONSECUTIVE_TOOL_FAILURES,
    MAX_REPEATED_FAILURE_STREAK,
    MAX_FREE_ARGUMENT_REJECTIONS,
    MAX_TOOL_FAILURES_BEFORE_UNAVAILABLE,
    RESURRECTING_FACT_TYPES,
    TOOL_RESURRECTED_EVENT_TYPE,
    TOOL_UNAVAILABLE_EVENT_TYPE,
    PHASE_TIMEOUT_EVENT_TYPE,
    STUCK_EVENT_TYPE,
    PREMATURE_COMPLETION_EVENT_TYPE,
    MAX_PREMATURE_COMPLETIONS,
    MAX_INVALID_JSON_TURNS,
    INVALID_JSON_EVENT_TYPE,
    INVALID_JSON_CORRECTION,
    RUN_EVIDENCE_MAX_OBSERVATIONS,
    PLAN_STATUS_REPEATED_EVENT_TYPE,
    STATUS_COMPLETED,
    STATUS_MAX_ITERATIONS,
    STATUS_CLARIFICATION,
    STATUS_FAILED,
    STATUS_PREMATURE_COMPLETION,
    STATUS_CANCELLED,
    STATUS_SCOPE_VIOLATION,
    STATUS_BLOCKED,
    STATUS_BUDGET_EXCEEDED,
    STATUS_SUBAGENT_BUDGET,
    STATUS_TIME_BUDGET,
    TIME_BUDGET_EVENT_TYPE,
    WORK_CLOCK_EVENT_TYPE,
    WRAP_UP_EVENT_TYPE,
    WRAP_UP_TOOLS,
    PROVIDER_REFUSAL_EVENT_TYPE,
    TERMINATION_PROVIDER_REFUSAL,
    SUBAGENT_EVENT_TYPE,
    BUDGET_EVENT_TYPE,
    BUDGET_SUBJECT_ID,
    SKILL_NUDGE_EVENT_TYPE,
    SKILL_NUDGE_TURNS,
    BARREN_REPEAT_MIN_SECONDS,
    FAST_REPEAT_MIN_NO_PROGRESS,
    FAST_REPEAT_WINDOW,
    SMART_BUDGET_EVENT_TYPE,
    WEBSHELL_STALL_EVENT_TYPE,
    COVERAGE_PIVOT_EVENT_TYPE,
    ROBOTS_HINT_EVENT_TYPE,
    LOOP_BARRIER_EVENT_TYPE,
    STALL_BARRIER_MULTIPLIER,
    STALLED_BRANCH_WINDOW,
    VECTOR_LOCKED_EVENT_TYPE,
    VECTOR_LOCKED_HINT,
    VECTOR_LOCK_NO_VECTORS,
    VECTOR_LOCK_SKIPPED_EVENT_TYPE,
    VECTOR_LOCK_WARNING,
    VECTOR_LOCK_WARNING_KIND,
    VECTOR_UNLOCKED_EVENT_TYPE,
    TARGET_REACHED_EVENT_TYPE,
    TARGET_REACHED_FORCED_EVENT_TYPE,
    TARGET_REACHED_GRACE_TURNS,
    ReActConfig,
    ReActResult,
)
from .turn_telemetry import (
    DETERMINATE_NON_FAILURE_OUTCOMES,
    FrictionFlag,
    TurnTelemetryRecorder,
)

#: Fact types that represent *actionable* progress: something the next decision
#: can use (a service/version, a user, an endpoint, a credential, a vulnerability,
#: access, loot or an artifact). `host` only repeats that the target answered;
#: `barrier`, `lead` and the agent's hypotheses are bookkeeping, and counting them
#: let a run reset its stagnation counter by writing barriers forever.
ACTIONABLE_FACT_TYPES = frozenset({
    "service",
    "endpoint",
    "credential",
    "session",
    "access",
    "privilege",
    "vulnerability",
    "loot",
    "artifact",
    "user",
})
from .react_support import (
    termination_summary,
    iteration_limit_for_time_budget,
    _task_payload,
    _cancellation_requested,
    _audit_step,
    _elapsed_ms,
    _failure_kind,
    _phase_timeout_seconds,
    clamp_tool_timeout,
    wrap_up_threshold,
    wrap_up_window,
    stuck_threshold,
    vector_lock_thresholds,
    _keep_going_after_failures,
    _run_messages,
    _premature_completion_message,
    missing_evidence,
    _persisted_actions,
    _last_persisted_iteration,
    _action_entry,
    _observation_payload,
    unavailable_guidance,
    timeout_guidance,
    command_failed_guidance,
    replay_guidance,
    PLAN_STATUS_TOOL,
    repeated_action_correction,
    unchanged_plan_status_correction,
    barren_repeat_correction,
    _invocation_signature,
    MEASURED_TOKENS_PER_TURN,
    _budget_tokens,
    _budget_used,
    subagent_budget_subject,
    _complete_turn,
    _record_response_tokens,
    _estimate_request_tokens,
    _inject_observation,
    _maybe_autospawn,
)
from enum import Enum
from .planner import (
    CREDENTIAL_FOUND_REASON,
    flag_tokens,
    target_reached,
    ENUMERATION_ENDPOINT_REASON,
    ENUMERATION_EXHAUSTED_REASON,
    SESSION_ESTABLISHED_REASON,
    CredentialHandover,
    EnumerationEscalation,
    Plan,
    SessionHandover,
    apply_objective_completion,
    credential_handover,
    endpoint_ceiling,
    enumeration_budget_hint,
    enumeration_escalation,
    enumeration_still_open,
    escalate_credential,
    escalate_enumeration,
    escalate_session,
    established_msf_session,
    LOGIN_PROBE_WITHHELD_TOOLS,
    login_probe_hint,
    login_probe_pending,
    objective_completion,
    pivot_gate,
    pivot_hint,
    pivot_target_host,
    robots_paths_hint,
    session_handover,
    verified_credential,
    webshell_stall_hint,
)
from .subagents import SubAgentDefinition
from .project_context import ProjectInstruction
from .skills import Skill
from typing import TYPE_CHECKING

#: Effects that act *on the objective*. With no engagement plan, the PLAN-FIRST
#: gate refuses every one of them: recon and scanning are already an action
#: against a target, and the plan is what says which action is worth taking.
#: ``state_write`` (the plan tools themselves, the blackboard) and
#: ``read_only`` stay available so the model can write the plan it needs.
ATTACK_EFFECTS = frozenset(
    {
        "active",
        "recon",
        "network_scan",
        "target_write",
        "exploit",
        "execution",
        "post_exploitation",
        "credential_access",
        "credential_dump",
        "lateral_movement",
        "pivoting",
        "c2_implant_build",
    }
)


def _touches_target(entry: Any) -> bool:
    """Whether this catalog entry acts on the objective (needs the plan)."""
    definition = entry[0] if isinstance(entry, tuple) and entry else entry
    if definition is None:
        return False
    tool_id = str(getattr(definition, "tool_id", "") or "")
    if tool_id.startswith("nexus.orchestrator."):
        return False
    if bool(getattr(definition, "scope_required", False)):
        return True
    return str(getattr(definition, "effect", "")) in ATTACK_EFFECTS


if TYPE_CHECKING:
    from nexus_core.hooks import HookRunner
from nexus_core.kernel.control_store import ControlStore
from nexus_core.scope import EngagementScope
from nexus_core.kernel.domain_dto import (
    Action,
    RequestClarification,
    SpawnSubAgent,
    TaskComplete,
    ToolCall,
    ToolCallBatch,
    ToolCallSpec,
)
from .task_manager import TaskManager, TaskManagerError, TaskRecord
from .parallel import (
    CallExecution,
    call_timeout,
    consolidate,
    execute_calls,
    parallel_limit,
)
from .react_services import (
    ContextBuilder,
    ContextSnapshot,
    ActionDecoder,
    ApprovalCoordinator,
    ToolExecutionService,
    CompletionVerifier,
)


class Transition(str, Enum):
    READY = "ready"
    NEXT_TURN = "next_turn"
    STOP = "stop"


#: Synthetic tool id of the single observation a parallel turn leaves behind. It
#: keys compaction and the artifact store; it is never a catalog entry.
BATCH_TOOL_ID = "parallel.tools"


class _BatchObservationAction:
    """What ``_inject_observation`` needs from an action: its tool id."""

    __slots__ = ("tool_id",)

    def __init__(self, tool_id: str) -> None:
        self.tool_id = tool_id


#: A tool that names an out-of-scope target is refused as an observation, not as
#: the end of the engagement (measured in blackbox-10.67.183.218: a single
#: ``https://bit.ly/...`` lookup aborted the run with exit code 4). Only a model
#: that insists on the *same* target this many turns in a row closes the run.
MAX_CONSECUTIVE_SCOPE_DENIALS = 3
#: Sweeps refused in a row because the operator has no route to their target,
#: and replays refused in a row because their effect is unconfirmed. Each is a
#: correction; insisting on the same blocked move this many turns ends the run as
#: ``blocked`` (the operator has to open the tunnel or approve the replay), never
#: as a silent failure.
MAX_CONSECUTIVE_PIVOT_GATES = 3
MAX_REPLAY_REFUSALS = 3
#: Denials of the *gateway* (policy, an approval that does not match the call,
#: a journal state) that a run tolerates in a row before closing. One denial is
#: about one invocation, not about the engagement: measured in the Hijack V1 run
#: (2026-10-29), the loop answered the very first ``install_tool`` denial -caused
#: by an approval registered for a different action string- with
#: ``governance_denial`` and ``Transition.STOP``, ending a run that had a verified
#: credential on the board, 1 M tokens of budget left and 82 iterations unused.
MAX_CONSECUTIVE_GOVERNANCE_DENIALS = 3

#: FIX 1: tools whose first argument is a *command*. ``nexus.shell.exec`` is the
#: catch-all of the catalog, so the lock on it is per binary inside the command
#: (``mount``, ``python3``, ``curl``) and never per tool: locking
#: ``(shell.exec, host)`` would also remove the ``curl`` that is exactly the
#: pivot this fix exists to force (measured in hijack_v2: twelve
#: ``python3 -c`` calls against NFS while port 80 stayed unvisited).
SHELL_COMMAND_TOOLS = frozenset({"nexus.shell.exec"})
#: Leading binaries that hide the real command (``sudo -u x bash -c ...``) or
#: have no stable one. Such a command is only *warned* about, never locked: a
#: wrong attribution would close a vector that never ran.
SHELL_WRAPPERS = frozenset(
    {
        "sh", "bash", "zsh", "dash", "ksh", "fish", "env", "nohup", "sudo",
        "doas", "timeout", "xargs", "watch", "screen", "tmux", "su", "command",
        "exec", "eval", "source",
    }
)
#: Arguments that name the target of an invocation, in priority order, for the
#: tools that do not declare ``scope_target_field``.
TARGET_ARGUMENT_KEYS = (
    "target", "targets", "url", "urls", "host", "hosts", "domain", "rhost",
)
_URL_TOKEN_RE = re.compile(r"https?://[^\s'\"<>|;&]+", re.IGNORECASE)
_IPV4_TOKEN_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_HOST_TOKEN_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w.-])",
    re.IGNORECASE,
)
#: Last labels that look like a TLD inside a shell command but are files
#: (``exploit.py``, ``auth.conf``): they are never a target.
_FILE_SUFFIXES = frozenset(
    {
        "py", "sh", "txt", "json", "xml", "log", "conf", "cfg", "md", "yml",
        "yaml", "php", "html", "htm", "js", "css", "csv", "ini", "pem", "key",
        "pub", "tar", "gz", "zip", "c", "h", "rb", "pl", "bin", "out", "db",
        "sql", "bak", "tmp", "lock", "service", "socket", "nfs", "exe", "dll",
    }
)
#: Outcomes that mean "this vector did not work", whatever ``success`` says. A
#: handler may report ``partial`` with ``verified=True`` in the future and the
#: counter must not depend on that detail (nfs.py builds it with
#: ``verified=False`` today; http_request.py declares ``partial`` when the
#: session is not authenticated, also ``verified=False``).
VECTOR_FAILURE_OUTCOMES = frozenset({"failed", "partial", "unavailable", "timeout"})
#: Outcomes that are *not* a verdict about the vector: the signed scope refused
#: the call (its own streak governs), the channel ran but the command failed
#: (the tool works), or governance/approval denied it before reaching the target.
VECTOR_NEUTRAL_OUTCOMES = frozenset(
    {
        "scope_denied", "command_failed", "governance_denial", "approval_required",
        "denied_by_operator", "replay_approval_required", "cancelled",
    }
)
#: Tool suggested for each service name an open vector may carry. The warning
#: has to name a next action, not just list ports.
_VECTOR_TOOL_SUGGESTIONS = {
    "http": "nexus.web.request",
    "https": "nexus.web.request",
    "http-proxy": "nexus.web.request",
    "ssh": "nexus.post.ssh_exec",
    "telnet": "nexus.post.ssh_exec",
    "ftp": "nexus.recon.ftp",
    "nfs": "nexus.recon.nfs",
    "rpcbind": "nexus.recon.nfs",
    "smb": "nexus.recon.smb",
    "netbios-ssn": "nexus.recon.smb",
    "microsoft-ds": "nexus.recon.smb",
    "domain": "nexus.recon.netexec",
    "ldap": "nexus.recon.netexec",
    "mysql": "nexus.cred.bruteforce",
}
#: Ceiling of the open-vector list injected into the prompt. The warning is a
#: nudge, not a second catalogue.
VECTOR_OPEN_LIMIT = 6
#: Iterations without a new failure after which a vector's counter expires.
#: The only two escapes are an explicit ``barrier`` and this TTL: a success does
#: not clear the counter, because the key is coarse (``nexus.recon.nfs`` shares
#: one key between ``action=exports`` and ``action=list``, measured in Hijack v3)
#: and because the model's own exit-0 introspection calls were "successes" that
#: blanched the streak while the vector stayed dead.
VECTOR_TTL_ITERATIONS = 10


def _canonical_target(value: Any) -> str:
    """Host identity of a target: no scheme, no user, no path, no port.

    The same host reached as ``http://10.0.0.5/x.php``, ``10.0.0.5:80`` and
    ``10.0.0.5`` is one vector; comparing the raw strings would let the model
    dodge the counter by writing the target differently each turn.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split("?", 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("["):
        return text.split("]", 1)[0].lstrip("[").lower()
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text.strip(".,;:'\"()[]{}").lower()


def _targets_in(text: str) -> list[str]:
    """Targets named anywhere inside a free-form string (a shell command)."""
    found = [_canonical_target(match.group(0)) for match in _URL_TOKEN_RE.finditer(text)]
    found += [_canonical_target(match.group(0)) for match in _IPV4_TOKEN_RE.finditer(text)]
    for match in _HOST_TOKEN_RE.finditer(text):
        token = match.group(0).lower()
        if token.rsplit(".", 1)[-1] in _FILE_SUFFIXES:
            continue
        found.append(_canonical_target(token))
    unique: list[str] = []
    for item in found:
        if item and item not in unique:
            unique.append(item)
    return unique


def _scope_field(definition: Any) -> str:
    if isinstance(definition, dict):
        return str(definition.get("scope_target_field") or "")
    return str(getattr(definition, "scope_target_field", "") or "")


def _vector_target(definition: Any, arguments: Any) -> tuple[str, list[str]]:
    """``(target_canonical, candidates)`` of one invocation.

    ``candidates`` is non-empty only when the arguments name more than one
    distinct target (``nmap 10.0.0.5 && curl 10.0.0.6``): the attribution would
    be a guess, so the caller logs it and counts nothing.
    """
    args = arguments if isinstance(arguments, dict) else {}
    field = _scope_field(definition)
    if field and args.get(field) not in (None, "", [], ()):
        value = args[field]
        first = value[0] if isinstance(value, (list, tuple)) and value else value
        target = _canonical_target(first)
        if target:
            return target, []
    for key in TARGET_ARGUMENT_KEYS:
        value = args.get(key)
        first = value[0] if isinstance(value, (list, tuple)) and value else value
        if not isinstance(first, str) or not first.strip() or any(ch.isspace() for ch in first):
            continue
        target = _canonical_target(first)
        if target:
            return target, []
    candidates: list[str] = []
    for value in args.values():
        strings = (
            [item for item in value if isinstance(item, str)]
            if isinstance(value, (list, tuple))
            else [value]
            if isinstance(value, str)
            else []
        )
        for item in strings:
            for found in _targets_in(item):
                if found not in candidates:
                    candidates.append(found)
    if len(candidates) == 1:
        return candidates[0], []
    return "", candidates if len(candidates) > 1 else []


def _shell_subcommand(command: Any) -> str:
    """Binary a shell command runs (``python3``, ``mount``), or ``""``.

    Empty means the command cannot be attributed to one binary (an unparsable
    quote, a wrapper such as ``bash -c``): the pair then only gets the warning,
    never the hard lock.
    """
    if isinstance(command, (list, tuple)):
        command = " ".join(str(part) for part in command)
    text = str(command or "").strip()
    if not text:
        return ""
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        return ""
    while tokens and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
        tokens = tokens[1:]
    if not tokens:
        return ""
    binary = tokens[0].rsplit("/", 1)[-1].strip().lower()
    if not binary or binary in SHELL_WRAPPERS:
        return ""
    return binary


def _vector_key(
    tool_id: str, definition: Any, arguments: Any
) -> tuple[tuple[str, str, str] | None, list[str]]:
    """``((tool_id, subcommand, target), ambiguous_candidates)`` for one call."""
    args = arguments if isinstance(arguments, dict) else {}
    subcommand = _shell_subcommand(args.get("command")) if tool_id in SHELL_COMMAND_TOOLS else ""
    target, ambiguous = _vector_target(definition, args)
    if ambiguous:
        return None, ambiguous
    if not target:
        return None, []
    return (tool_id, subcommand, target), []


def _vector_lockable(key: tuple[str, str, str]) -> bool:
    """Fallback A: an unattributable shell command is warned about, not locked."""
    return not (key[0] in SHELL_COMMAND_TOOLS and not key[1])


def _is_vector_failure(observation: Any) -> bool:
    """Whether a tool observation is a verdict against the *vector*.

    ``partial`` counts by outcome even when a handler ever reports it with
    ``success=True``; governance refusals and a failed command inside a working
    channel do not count at all.

    A call the engine refused on its *arguments* is not a verdict about the
    target either. Measured in hijack_v5 (2026-10-29): ``nmap --script`` was
    rejected twice as a forbidden flag and counted as two failures of the
    ``(nmap, '', host)`` vector, which locked nmap for the rest of the run; an
    ``invalid_failure_string`` did the same to ``cred.bruteforce``. The model's
    malformed call says nothing about the port. What keeps that from looping
    forever is ``MAX_FREE_ARGUMENT_REJECTIONS``, which already charges the third
    consecutive rejection as a barren turn.
    """
    if not isinstance(observation, dict):
        return False
    if observation.get("input_rejected"):
        return False
    outcome = str(observation.get("outcome") or "").strip()
    if outcome in VECTOR_NEUTRAL_OUTCOMES or outcome.startswith("invalid_"):
        return False
    if outcome in VECTOR_FAILURE_OUTCOMES:
        return True
    return observation.get("success") is False


def _render_vectors(vectors: list[dict[str, str]]) -> str:
    if not vectors:
        return VECTOR_LOCK_NO_VECTORS
    return "; ".join(f"{item['key']} → {item['suggested_tool']}" for item in vectors)


#: Sentences that mean the *model itself* declined the action (a refusal), as
#: opposed to a question it needs answered. Measured in Blue (2026-10-31): after
#: ``nmap --script smb-vuln-ms17-010`` proved the vector, the answer to the next
#: prompt was ``request_clarification`` with "No puedo ayudar a explotar el
#: host", and the run record said nothing about the stop being the model's own
#: decision. Deliberately narrow: an unambiguous first-person refusal only, so a
#: conditional question ("¿no puedo continuar sin credenciales?") never matches.
_REFUSAL_MARKERS: tuple[str, ...] = (
    "no puedo ayudar",
    "no puedo colaborar",
    "no puedo asistir",
    "no voy a ayudar",
    "no voy a explotar",
    "no realizaré la explotación",
    "no llevaré a cabo la explotación",
    "no puedo ejecutar la explotación",
    "me niego a",
    "declino",
    "i can't help",
    "i cannot help",
    "i can't assist",
    "i cannot assist",
    "i won't help",
    "i will not help",
    "i must decline",
    "i'm not able to help",
    "i am not able to help",
)


def _refusal_kind(text: str) -> str:
    """``"model_declined"`` when the model's own words decline the action.

    Empty for every other answer, including a genuine clarification request: the
    classifier only labels the stop, it never changes the status, the evidence or
    what the operator is asked.
    """
    normalized = " ".join(str(text or "").lower().split())
    if not normalized:
        return ""
    return "model_declined" if any(marker in normalized for marker in _REFUSAL_MARKERS) else ""


class ReActCoordinator:
    """One run's state and explicit transitions; services own boundary logic."""

    store: ControlStore
    tenant_id: str
    run_id: str
    payload: dict[str, Any]
    agent_id: str
    catalog: dict[str, Any]
    subagent_override: Any
    audit: AuditWriter
    scope: EngagementScope | None
    project_instruction: ProjectInstruction | None
    active_skills: list[Skill]
    hooks: HookRunner
    budget: int
    actions: list[dict[str, Any]]
    iteration: int
    status: str
    final_summary: str
    #: Machine-readable reason for a stop the status alone does not explain
    #: (``provider_refusal``), empty when the status *is* the reason.
    termination_reason: str
    findings: list[dict[str, Any]]
    question: str | None
    consecutive_failures: int
    #: Model answers in a row that were not the requested JSON object. Reset by
    #: every usable answer; after ``MAX_INVALID_JSON_TURNS`` the run closes as
    #: ``provider_error`` (a provider that only emits garbage is truly unhealthy).
    invalid_json_turns: int
    last_phase: str | None
    last_plan: Plan | None
    last_subagent_id: str | None
    last_selected: SubAgentDefinition | None
    previous_profile: SubAgentDefinition | None
    active_subagent_id: str | None
    subagent_iterations: int
    unavailable_tools: set[str]
    tool_failures: dict[str, int]
    #: FIX 3: tools retiradas por *rechazo* (``repeated_*_action``: la llamada no
    #: se ejecutó) y las que ya gastaron su única resurrección del run.
    refusal_retired: set[str]
    resurrected_tools: set[str]
    #: FIX 1: fallos consecutivos por ``(tool_id, subcommand, target)``, los
    #: pares ya avisados y los que están bloqueados. El estado es del run: un
    #: run reanudado desde historial empieza con los vectores libres.
    vector_failures: dict[tuple[str, str, str], int]
    vector_warned: set[tuple[str, str, str]]
    vector_locked: set[tuple[str, str, str]]
    #: Umbrales efectivos del run (``NEXUS_VECTOR_LOCK_WARN``/
    #: ``NEXUS_VECTOR_LOCK_HARD``), leídos una vez en ``_initialize``.
    vector_warn_threshold: int
    vector_lock_threshold: int
    phase_started: float
    phase_timeout_seconds: float
    run_evidence: list[dict[str, Any]]
    evidence_stats: dict[str, int] | None
    premature_rejections: int
    completion_objections: list[str]
    #: Target of the current run of consecutive ``ScopeViolation`` refusals and
    #: how many times in a row the model named it. Any other tool call resets it.
    scope_denial_target: str | None
    scope_denial_streak: int
    #: Turns in a row without a new verified fact (Fase 3 fixes). Drives the
    #: ``react.stuck_detected`` signal and the enumeration→exploit hand-over.
    consecutive_no_progress: int
    stuck_threshold: int
    #: WP4: turns in a row that repeated the *same* tool with no new fact. At
    #: ``SKILL_NUDGE_TURNS`` the next prompt offers the skill catalogue.
    same_tool_no_progress: int
    last_turn_tool: str | None
    #: Reason of the last deterministic phase change, copied into the
    #: ``orchestrator.plan`` event so the hand-over is auditable and never reads
    #: as a model inference.
    plan_reason: str | None
    #: The enumeration→exploit hand-over is one-way. The plan is rebuilt from the
    #: blackboard on every turn, so without this the phase would flap back to
    #: ``enumeration`` as soon as the active profile is ``exploit`` - which is
    #: exactly what the hand-over asked for (Fase 3 fixes).
    enumeration_escalated: bool
    #: The session→post-exploitation hand-over (V1-25) is one-way for the same
    #: reason: ``session`` evidence is what closes ``exploitation`` for the plan
    #: table, so a non-sticky rule would be undone by the next rebuild.
    session_handed_over: bool
    #: The credential→initial-access hand-over (V1-34) is one-way while the plan
    #: still computes ``enumeration`` (the profile that owns credential-testing
    #: cannot close its own phase); it is dropped as soon as the evidence moves
    #: the phase forward, so it never drags the plan backwards.
    credential_handed_over: bool
    #: The endpoint-ceiling hand-over (Simple CTF 2026-10-18) is one-way while
    #: the plan still computes ``enumeration``: once 5 endpoints are mapped the
    #: phase is closed by decision and must not flap back on the next rebuild.
    endpoint_ceiling_applied: bool
    #: Smart-budget correction for the prompt of this turn ("" when the rule does
    #: not apply) and whether its ``react.budget_hint`` event was already audited.
    budget_hint: str
    budget_hint_emitted: bool
    #: Surface-ledger correction for the prompt of this turn ("" when the rule
    #: does not apply) and whether its ``react.coverage_pivot`` event was already
    #: audited. It orders the next branch when the run is attacking a documented
    #: dead end or stalling while another service is unexplored.
    coverage_hint: str
    coverage_hint_emitted: bool
    #: Index-file correction for the prompt of this turn ("" when the rule does
    #: not apply) and whether its ``react.robots_paths`` event was already
    #: audited. It orders the GETs of the routes a ``robots.txt``/``sitemap.xml``
    #: listed and this run never requested.
    robots_hint: str
    robots_hint_emitted: bool
    login_hint: str
    login_hint_emitted: bool
    #: Order to open the SOCKS pivot (P8: nineteen iterations aimed at the DC
    #: from a host with no route to it).
    pivot_hint: str
    #: The exact texts already injected. The rule has two strengths ("nothing
    #: probed" and "probed with invented payloads"), and the second one must
    #: reach the model even though the first already fired -while neither may
    #: be repeated turn after turn.
    login_hints_sent: set[str]
    #: The board already proves the objective (verified top privilege + verified
    #: loot). Refreshed every turn from the facts; it adds the closure hint to the
    #: plan and exempts the active profile's token ceiling (V1-35, V1-38).
    objective_complete: bool
    #: Whether the ``orchestrator.objective_complete`` event was already emitted
    #: for this run (the signal is per run, not per turn).
    objective_complete_emitted: bool
    #: Whether the last budget check was waived because the objective is complete.
    budget_exempt: bool
    #: WP5: the objective's flags were captured (verified loot on the board or in
    #: the successful output of this run). Once true it latches for the run: the
    #: prompt orders the closure and the margin below is spent.
    target_reached: bool
    target_reached_emitted: bool
    #: flag -> source (invocation id, target, ref) of every captured flag.
    captured_flag_refs: dict[str, dict[str, Any]]
    #: Tool calls the model proposed after the warning; at
    #: ``TARGET_REACHED_GRACE_TURNS`` the next one is intercepted.
    tool_calls_since_target_reached: int
    #: The run was closed by the loop (not by the model) because the objective was
    #: reached and the margin ran out. ``completion_verified`` is then decided by
    #: the captured evidence, not by the old "no objections" derivation.
    forced_completion: bool
    completion_verified_override: bool | None
    #: Last report that really produced deliverables (``directory`` and the
    #: invocation that made it), or ``None``. The technical objective and the
    #: engagement report are two different claims: a flag capture must not make
    #: the run say "engaged and reported" when no artifact exists.
    report_artifact: dict[str, Any] | None
    #: Per-turn operational telemetry (tokens, reasoning duration, friction,
    #: blackboard delta). Built in ``_initialize`` and published one record per
    #: iteration; it is the only place those four signals are joined.
    telemetry: TurnTelemetryRecorder
    snapshot: ContextSnapshot
    plan: Plan
    #: The engagement's own contract (``loot/ENGAGEMENT_PLAN.md``), loaded and
    #: reconciled against the board every turn. ``None`` when the engagement has
    #: no plan yet -which is exactly what the PLAN-FIRST gate refuses to work
    #: around.
    engagement_plan: Any | None
    engagement_plan_text: str
    subagent: SubAgentDefinition
    allowed_catalog: dict[str, Any]
    messages: list[LLMMessage]
    raw_response: str
    action: Action
    entry: dict[str, Any]
    tool_payload: dict[str, Any]
    observation: dict[str, Any]

    def __init__(
        self,
        *,
        context: Any,
        objective: str,
        engagement_id: str | None,
        llm_client: Any,
        config: ReActConfig = ReActConfig(),
        tool_catalog: dict[str, Any] | None = None,
        conversation_id: str | None = None,
        budget_tokens: int | None = None,
        cancel_event: asyncio.Event | None = None,
        isolated_child: bool = False,
        phase_timeout_seconds: float | None = None,
        initial_unavailable_tools: set[str] | None = None,
        context_builder: ContextBuilder | None = None,
        action_decoder: ActionDecoder | None = None,
        approval_coordinator: ApprovalCoordinator | None = None,
        tool_execution: ToolExecutionService | None = None,
        completion_verifier: CompletionVerifier | None = None,
        model_selector: Any | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.context = context
        self.objective = objective
        self.engagement_id = engagement_id
        self.llm_client = llm_client
        #: ``[model_routing]`` resolved once per run. ``None`` (the default, and
        #: what an unconfigured operator gets) keeps the historical single
        #: client: every task runs on ``llm_client``.
        self.model_selector = model_selector
        self.config = config
        self.tool_catalog = tool_catalog
        self.conversation_id = conversation_id or ""
        self.budget_tokens = budget_tokens
        self.cancel_event = cancel_event
        self.isolated_child = isolated_child
        self.context_builder = context_builder or ContextBuilder()
        self.action_decoder = action_decoder or ActionDecoder()
        self.approval_coordinator = approval_coordinator or ApprovalCoordinator()
        self.tool_execution = tool_execution or ToolExecutionService()
        self.completion_verifier = completion_verifier or CompletionVerifier()
        self._phase_timeout_override = phase_timeout_seconds
        self._initial_unavailable_tools = initial_unavailable_tools
        #: Monotonic clock of the work-time budget. Injectable so the wrap-up and
        #: the deadline are tested without sleeping; production keeps
        #: ``time.monotonic`` (immune to system clock changes).
        self._clock = clock or time.monotonic

    async def _initialize(self) -> None:
        from nexus_core.kernel import runtime as runtime_module
        from nexus_core.kernel.scope_loader import load_engagement_scope
        from nexus_core.tools.registry import durable_tool_definitions

        self.store = self.context.store
        self.tenant_id = self.context.tenant_id
        self.run_id = self.context.run_id
        self.payload = _task_payload(self.context)
        self.agent_id = str(self.payload.get("agent_id") or DEFAULT_AGENT_ID)
        self.catalog = (
            self.tool_catalog
            if self.tool_catalog is not None
            else durable_tool_definitions(self.tenant_id)
        )
        self.subagent_override = self.payload.get("subagent") or None
        self.audit = AuditWriter(self.store)
        from nexus_core.kernel.sandbox_modes import SandboxPolicy

        SandboxPolicy.resolve()
        self.scope = load_engagement_scope(self.store, self.tenant_id, self.engagement_id)
        project_root = self.payload.get("project_root") or None
        self.project_instruction = (
            None if self.isolated_child else load_project_instruction(project_root)
        )
        self.engagement_plan = None
        self.engagement_plan_text = ""
        from nexus_core.kernel.scope_loader import scope_signing_secret

        #: R2: skills whose body this run already delivered to the prompt. From
        #: the next successful turn the block carries the index line only.
        self.skill_bodies_sent: set[str] = set()
        self.active_skills, refused_skills = activate_skills(
            [] if self.isolated_child else self.payload.get("active_skills") or [],
            project_root,
            secret=scope_signing_secret(),
        )
        if self.project_instruction is not None or self.active_skills or refused_skills:
            self.audit.append(
                tenant_id=self.tenant_id,
                trace_id=self.run_id,
                actor_id=self.agent_id,
                action="project.context_loaded",
                resource_type="run",
                resource_id=self.run_id,
                payload={
                    "project": self.project_instruction.to_dict()
                    if self.project_instruction
                    else None,
                    "skills": [skill.to_dict() for skill in self.active_skills],
                    "refused_skills": list(refused_skills),
                },
                decision="allow",
            )
        self.conversation_id = self.conversation_id or memory.ensure_conversation(
            self.store, self.tenant_id, self.run_id, self.agent_id
        )
        from nexus_core.hooks import HookRunner

        hook_context = runtime_module._build_run_context(
            {
                **self.payload,
                "engagement_id": self.engagement_id,
                "session_id": self.conversation_id,
            },
            self.context,
        )
        self.hooks = HookRunner(
            hook_context,
            project_root=project_root,
            engagement_id=self.engagement_id,
            workspace=project_root or os.getenv("NEXUS_WORKSPACE_ROOT") or os.getcwd(),
        )
        await self.hooks.emit(
            "session_start", objective=self.objective, engagement_id=self.engagement_id
        )
        if self.cancel_event is None:
            self.cancel_event = getattr(self.context, "cancel_event", None)
        # Work-time budget: it counts only the time this loop spends working, so
        # a resumed run keeps the seconds it already spent and never inherits the
        # wall clock (and the downtime) of the process that wrote the history.
        # The payload is the durable source (a queued run carries it); the config
        # is the in-process one. ``0`` is a real value (unlimited), so only an
        # absent payload field falls back to the config.
        raw_budget = self.payload.get("time_budget_seconds")
        if raw_budget in (None, ""):
            raw_budget = getattr(self.config, "time_budget_seconds", 0)
        self.time_budget_seconds = max(0, int(raw_budget or 0))
        persisted_used, persisted_budget = self._persisted_clock()
        if not self.time_budget_seconds:
            # The ceiling is a property of the run, not of the invocation: a
            # resume that omits ``--time-budget`` inherits the one the engagement
            # was started with instead of silently becoming unlimited.
            self.time_budget_seconds = persisted_budget
        # Precedence: an explicit work-time budget is the primary ceiling. The
        # default ``--max-iterations 20`` used to close a 4-hour Wreath run at
        # twelve minutes; with a time budget the iteration count becomes a
        # secondary safety net derived from the clock (and at least the
        # operator's value), and the token ceiling follows that same net so it
        # cannot stop the run early either.
        self.iteration_limit = iteration_limit_for_time_budget(
            self.time_budget_seconds, self.config.max_iterations
        )
        # R1: the token ceiling follows the iteration ceiling. A run asked for 50
        # turns with a fixed 250k dies at ~21 of them (HackPark V12); the
        # operator's ``--max-iterations`` is a promise the budget has to keep.
        self.budget = _budget_tokens(
            self.payload, self.budget_tokens, max_iterations=self.iteration_limit
        )
        self.wrap_up_seconds = wrap_up_window(
            self.time_budget_seconds,
            getattr(self.config, "wrap_up_seconds", 0) or wrap_up_threshold(),
        )
        self._work_base_seconds = persisted_used
        self._work_started = self._clock()
        self.wrap_up = False
        self._wrap_up_announced = False
        self._time_budget_closed = False
        self._persist_work_clock(iteration=0)
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.budget_plan",
            {
                "budget_tokens": self.budget,
                "max_iterations": self.config.max_iterations,
                "iteration_limit": self.iteration_limit,
                "iteration_limit_source": (
                    "time_budget" if self.time_budget_seconds else "max_iterations"
                ),
                "tokens_per_turn_estimate": MEASURED_TOKENS_PER_TURN,
                "budget_turns": (
                    self.budget // MEASURED_TOKENS_PER_TURN if self.budget else 0
                ),
                "source": (
                    "explicit"
                    if self.budget_tokens is not None
                    or self.payload.get("budget_tokens") not in (None, "")
                    else "derived"
                ),
                # Work-time ceiling: the operator's ``--time-budget`` and the
                # clock this run inherits from a previous process. ``deadline_at``
                # is informational (wall clock if the loop keeps working without
                # pauses); the authoritative number is ``work_seconds_remaining``.
                "time_budget_seconds": self.time_budget_seconds,
                "wrap_up_seconds": self.wrap_up_seconds,
                "work_seconds_used": round(self._work_base_seconds, 1),
                "work_seconds_remaining": self._remaining_seconds(),
                "deadline_at": self._deadline_at(),
            },
        )
        history = memory.load_history(self.store, self.tenant_id, self.conversation_id, limit=500)
        if not any(
            (
                memory.message_kind(message) == memory.SYSTEM_MESSAGE_KIND
                and str(message.get("run_id") or "") == str(self.run_id)
                for message in history
            )
        ):
            memory.append_step(
                self.store,
                self.tenant_id,
                self.conversation_id,
                "system",
                self.objective,
                {
                    "kind": memory.SYSTEM_MESSAGE_KIND,
                    "objective": self.objective,
                    "run_id": self.run_id,
                },
            )
            history = memory.load_history(
                self.store, self.tenant_id, self.conversation_id, limit=500
            )
        run_history = _run_messages(history, self.run_id)
        self.actions = _persisted_actions(run_history)
        self.iteration = _last_persisted_iteration(self.actions)
        self.status = STATUS_MAX_ITERATIONS
        self.final_summary = ""
        self.termination_reason = ""
        self.findings = []
        self.question = None
        self.consecutive_failures = 0
        #: Same tool + same error in a row: the route is broken *as invoked*,
        #: so the run stops instead of burning turns on it.
        self.repeated_failure_tool: str | None = None
        self.repeated_failure_detail = ""
        self.repeated_failure_streak = 0
        self.scope_denial_target = None
        self.scope_denial_streak = 0
        self.governance_denial_streak = 0
        self.invalid_json_turns = 0
        self.last_phase = None
        self.last_plan = None
        self.last_subagent_id = None
        self.last_selected = None
        self.previous_profile = None
        self.active_subagent_id = None
        self.subagent_iterations = 0
        self.unavailable_tools = set(
            unavailable_tools_from_env()
            if self._initial_unavailable_tools is None
            else self._initial_unavailable_tools
        )
        self.tool_failures = {}
        self.refusal_retired = set()
        self.resurrected_tools = set()
        self.vector_failures = {}
        self.vector_last_failure: dict[tuple[str, str, str], int] = {}
        self.vector_warned = set()
        self.vector_locked = set()
        self.vector_warn_threshold, self.vector_lock_threshold = vector_lock_thresholds()
        self.phase_started = time.monotonic()
        self.phase_timeout_seconds = (
            self._phase_timeout_override
            if self._phase_timeout_override is not None
            else _phase_timeout_seconds()
        )
        self.run_evidence = []
        #: Completed turns spent with each phase as ``current`` (V1-46). The plan
        #: for a turn is built with this history, so a phase that declares
        #: ``min_turns`` cannot be closed by its evidence before it has had its
        #: turn. Empty means "no turn spent yet in any phase", which is exactly the
        #: state the loop starts in -and why ``post_exploitation`` can never close
        #: instantly. A run resumed from history starts untracked for the phases it
        #: already ran, which at worst costs one extra turn.
        self.phase_turns: dict[str, int] = {}
        # Recover the retirements, locked vectors and phase turns of a previous
        # process of this same run (``--resume`` keeps the run id).
        self._restore_run_state()
        #: WP2: the only hard ceiling of a run (``NEXUS_RUN_BUDGET_TOKENS``) and
        #: the 5-turn grace the board grants once the objective is complete.
        # ``iteration_limit`` was resolved in ``_initialize`` before the budget:
        # it already accounts for a work-time ceiling.
        self.grace_turns_remaining: int | None = None
        self.grace_granted = False
        self.soft_limits_reported: set[str] = set()
        self.evidence_stats = None
        self.premature_rejections = 0
        self.completion_objections = []
        self.consecutive_no_progress = 0
        #: Last ``(actionable facts, closed branches)`` reading, the baseline of
        #: the stagnation guard. A turn that only adds a model-written barrier
        #: does not move it: the streak must survive a branch that refuses to
        #: produce evidence (see ``_actionable_progress``).
        self._progress_baseline: tuple[int, int] | None = None
        #: R7: consecutive turns rejected for their *arguments* (schema, flag,
        #: placeholder, ``invalid_*`` verdict). They are friction, not a target
        #: verdict, so they do not move the pivot until the free budget is spent.
        self.argument_rejections = 0
        self.stuck_threshold = stuck_threshold()
        self.same_tool_no_progress = 0
        #: Fingerprint of the state the last ``get_plan_status`` answer described
        #: (plan + board + ledger) and how many identical polls were refused.
        self.plan_status_fingerprint = ""
        self.plan_status_polls = 0
        #: Set when the model idles on an unchanged plan poll while a background
        #: task is still running: the loop waits for that task instead of paying
        #: a model turn to ask again (see ``_wait_for_background_result``).
        self.idle_background_wait = False
        self.last_turn_tool = None
        #: Wall time of the previous *executed* tool call, used to tell a slow,
        #: fact-free repeat from a fast idempotent one (see
        #: ``_repeated_barren_action``).
        self.last_tool_elapsed_ms = 0
        self.plan_reason = None
        self.enumeration_escalated = False
        self.session_handed_over = False
        self.credential_handed_over = False
        self.endpoint_ceiling_applied = False
        self.budget_hint = ""
        self.budget_hint_emitted = False
        self.webshell_hint = ""
        self.webshell_hint_emitted = False
        self.coverage_hint = ""
        self.coverage_hint_emitted = False
        self.robots_hint = ""
        self.robots_hint_emitted = False
        self.login_hint = ""
        self.login_hint_emitted = False
        self.login_hints_sent = set()
        # B3: what the board proved and no action has spent yet. Text-keyed so a
        # stalled run is not re-told the same list on every turn.
        self.reflection_hint = ""
        self.reflection_hints_sent: set[str] = set()
        #: Tools withheld while the login form has no canonical probe (P9: the
        #: order arrived and the run still went to gobuster).
        self.login_withheld: set[str] = set()
        self.login_withheld_announced = False
        self.pivot_hint = ""
        self.pivot_hint_emitted = False
        #: Sweeps refused *before* running because the operator has no route to
        #: their target (P10: the order arrived after 600 s of nmap). Refusals in
        #: a row close the run; a single one is a correction.
        self.pivot_gate_streak = 0
        #: Replays of an invocation whose effect is unconfirmed (P10 iteration 47:
        #: the fence was right, ending the run was not). Same counting.
        self.replay_refusals = 0
        #: ``barrier`` facts refused for lack of attempts. After
        #: :data:`BARRIER_INSISTENCE_LIMIT` the fact is accepted *and* stamped as
        #: unsubstantiated instead of refused again: a gate the model cannot
        #: satisfy only spends turns (hijack_v7 refused the same barrier nine
        #: times over seventeen barren turns).
        self.barrier_refusals = 0
        #: ``host:port`` refs the *loop* closed with a barrier fact this run (see
        #: ``_close_stalled_branch``). Two reasons to keep them: never write the
        #: same barrier twice, and never let the loop's own reflex read as
        #: progress -it would reset the streak that made it act.
        self.closed_branches: set[str] = set()
        #: Iteration each of those branches was closed on. The name survives in
        #: ``closed_branches`` for the code that only asks "was it closed?", but
        #: the gate needs *when*, because a branch the loop closed stays refused
        #: for :data:`branch_discipline.CLOSED_BRANCH_BLOCK_TURNS` turns instead
        #: of being refused forever (measured in DeadDrop P12: the loop closed
        #: ``192.168.11.200:80`` at iteration 44 and the model kept calling
        #: ``web.*`` on it for fifteen more turns).
        self.closed_branch_at: dict[str, int] = {}
        self.objective_complete = False
        self.objective_complete_emitted = False
        self.budget_exempt = False
        self.target_reached = False
        self.target_reached_emitted = False
        self.captured_flag_refs = {}
        self.tool_calls_since_target_reached = 0
        self.forced_completion = False
        self.completion_verified_override = None
        self.report_artifact = None
        self.telemetry = TurnTelemetryRecorder(
            store=self.store, tenant_id=self.tenant_id, run_id=self.run_id
        )
        # Background scheduling: the runner is the same governed invocation a
        # foreground call uses, so ``spawn_subagent`` changes *when* the loop
        # awaits, never what is authorized. One manager per run keeps the caps
        # and the wake-up signal scoped to this engagement.
        self.task_manager = TaskManager(
            runner=self._background_runner,
            on_complete=self._background_completed,
        )
        for tool_id in sorted(self.unavailable_tools):
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                TOOL_UNAVAILABLE_EVENT_TYPE,
                {"tool_id": tool_id, "reason": "binary_missing", "iteration": 0},
            )

    # ------------------------------------------------------------ work clock
    def _persisted_clock(self) -> tuple[float, int]:
        """``(work seconds, budget)`` a previous process left for this run.

        The last ``react.work_clock`` wins; ``react.budget_plan`` and a forced
        closure are fallbacks for a run that died before its first turn. Reading
        the journal keeps the clock and the ceiling durable without a new table:
        a resumed run cannot restart its budget by being resumed, and omitting
        ``--time-budget`` does not turn a timed engagement into an unlimited one.
        """
        try:
            events = self.store.list_run_events(self.tenant_id, self.run_id)
        except Exception:  # noqa: BLE001 - a clock must never break the run
            return 0.0, 0
        for event in reversed(events):
            if event.get("event_type") not in {
                WORK_CLOCK_EVENT_TYPE,
                TIME_BUDGET_EVENT_TYPE,
                "react.budget_plan",
            }:
                continue
            payload = event.get("payload") or {}
            try:
                used = max(0.0, float(payload.get("work_seconds_used") or 0))
            except (TypeError, ValueError):
                used = 0.0
            try:
                budget = max(0, int(payload.get("time_budget_seconds") or 0))
            except (TypeError, ValueError):
                budget = 0
            return used, budget
        return 0.0, 0

    def _persisted_work_seconds(self) -> float:
        """Work seconds a previous process already spent on this run."""
        return self._persisted_clock()[0]

    # ------------------------------------------------------- durable run state
    def _restore_run_state(self) -> None:
        """Recover what a previous process learned about this run.

        The loop retires a tool after three consecutive failures and locks a
        vector after repeated failures on the same target. Keeping that only in
        memory made ``--resume`` forget it: the broken route looked new and the
        run spent its first failure again (and, on a full restart, the three of
        them). The state is one row per key in ``kernel_run_state``, so it is
        also inspectable by an operator.
        """
        try:
            state = self.store.load_run_state(self.tenant_id, self.run_id) or {}
        except Exception:  # noqa: BLE001 - a run must start without its history
            return
        unavailable = state.get("unavailable_tools")
        if isinstance(unavailable, list):
            self.unavailable_tools.update(str(tool) for tool in unavailable if tool)
        failures = state.get("tool_failures")
        if isinstance(failures, dict):
            for tool_id, count in failures.items():
                try:
                    self.tool_failures[str(tool_id)] = max(0, int(count))
                except (TypeError, ValueError):
                    continue
        for name, target in (
            ("refusal_retired", self.refusal_retired),
            ("resurrected_tools", self.resurrected_tools),
        ):
            values = state.get(name)
            if isinstance(values, list):
                target.update(str(tool) for tool in values if tool)
        turns = state.get("phase_turns")
        if isinstance(turns, dict):
            for phase, count in turns.items():
                try:
                    self.phase_turns[str(phase)] = max(0, int(count))
                except (TypeError, ValueError):
                    continue
        vectors = state.get("vectors")
        for entry in vectors if isinstance(vectors, list) else ():
            if not isinstance(entry, dict):
                continue
            key = (
                str(entry.get("tool") or ""),
                str(entry.get("subcommand") or ""),
                str(entry.get("target") or ""),
            )
            if not key[0]:
                continue
            try:
                count = max(0, int(entry.get("failures") or 0))
                iteration = max(0, int(entry.get("last_iteration") or 0))
            except (TypeError, ValueError):
                continue
            if count:
                self.vector_failures[key] = count
            if iteration:
                self.vector_last_failure[key] = iteration
            if entry.get("locked"):
                self.vector_locked.add(key)

    def _persist_run_state(self) -> None:
        """Commit the retirements, locked vectors and phase turns of this run.

        Best-effort by design: a database hiccup must not stop the loop. Called
        when a retirement happens (so a crash right after it is remembered) and
        once per completed turn for the counters.
        """
        keys = set(self.vector_failures) | set(self.vector_locked)
        vectors = [
            {
                "tool": key[0],
                "subcommand": key[1],
                "target": key[2],
                "failures": int(self.vector_failures.get(key, 0)),
                "last_iteration": int(self.vector_last_failure.get(key, 0)),
                "locked": key in self.vector_locked,
            }
            for key in sorted(keys)
        ]
        try:
            self.store.save_run_state(
                self.tenant_id,
                self.run_id,
                {
                    "unavailable_tools": sorted(self.unavailable_tools),
                    "tool_failures": dict(self.tool_failures),
                    "refusal_retired": sorted(self.refusal_retired),
                    "resurrected_tools": sorted(self.resurrected_tools),
                    "phase_turns": dict(self.phase_turns),
                    "vectors": vectors,
                },
            )
        except Exception:  # noqa: BLE001 - durability must never break a turn
            return

    def _work_seconds(self) -> float:
        """Work time of this run: persisted base plus this process's uptime."""
        return self._work_base_seconds + max(0.0, self._clock() - self._work_started)

    def _remaining_seconds(self) -> float | None:
        """Work seconds left before the hard deadline (``None`` when unlimited)."""
        if not self.time_budget_seconds:
            return None
        return self.time_budget_seconds - self._work_seconds()

    def _deadline_at(self) -> str:
        """Wall-clock estimate of the deadline (informational, never enforced)."""
        remaining = self._remaining_seconds()
        if remaining is None:
            return ""
        from datetime import datetime, timedelta, timezone

        moment = datetime.now(timezone.utc) + timedelta(seconds=max(0, int(remaining)))
        return moment.isoformat()

    def _persist_work_clock(self, *, iteration: int) -> None:
        """Publish the durable clock once per turn (the resume anchor)."""
        if not self.time_budget_seconds:
            return
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            WORK_CLOCK_EVENT_TYPE,
            {
                "iteration": iteration,
                "work_seconds_used": round(self._work_seconds(), 3),
                "work_seconds_remaining": round(self._remaining_seconds() or 0, 3),
                "time_budget_seconds": self.time_budget_seconds,
                "wrap_up": self.wrap_up,
            },
        )

    def _refresh_time_budget(self) -> bool:
        """Open the wrap-up window or report the hard deadline (``True``).

        Called at the top of every iteration, before the context is built: the
        prompt and the allowed catalog of the turn must already say that the run
        is closing, not learn it one turn later.
        """
        remaining = self._remaining_seconds()
        if remaining is None:
            return False
        if remaining <= 0:
            return True
        if not self.wrap_up and remaining <= self.wrap_up_seconds:
            self.wrap_up = True
            self._announce_wrap_up(remaining)
        return False

    def _announce_wrap_up(self, remaining: float) -> None:
        """Tell the operator (and the audit trail) that the run is closing."""
        if self._wrap_up_announced:
            return
        self._wrap_up_announced = True
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            WRAP_UP_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "work_seconds_used": round(self._work_seconds(), 1),
                "work_seconds_remaining": round(max(0.0, remaining), 1),
                "time_budget_seconds": self.time_budget_seconds,
                "wrap_up_seconds": self.wrap_up_seconds,
                "tools": sorted(WRAP_UP_TOOLS),
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="time_budget_wrap_up",
            decision="allow",
            remaining_seconds=round(max(0.0, remaining), 1),
            tools=sorted(WRAP_UP_TOOLS),
        )

    def _tool_timeout_seconds(self) -> float:
        """Ceiling of one tool call, never longer than the work time left."""
        return clamp_tool_timeout(
            self.config.timeout_per_tool_seconds, self._remaining_seconds()
        )

    def _force_time_completion(self) -> Transition:
        """Close for time with a synthesized ``task_complete`` (never a cancel).

        The deadline is a decision of the engine, so it must read as one: the
        partial summary, the findings already proved, the open TODOs and the
        report artifact (when one was generated) are persisted, the run is
        audited with ``time_budget_exhausted`` and the status is
        ``time_budget``. Cancelling the coroutine instead would journal the
        in-flight call ``unknown`` and lose what the engagement had proved.
        """
        if self._time_budget_closed:
            return Transition.STOP
        self._time_budget_closed = True
        self.forced_completion = True
        used = round(self._work_seconds(), 1)
        flags = list(self.captured_flag_refs)
        board_facts = [
            {
                "fact_type": str(fact.get("fact_type") or ""),
                "key": str(fact.get("key") or ""),
                "verified": bool(fact.get("verified")),
                "verification_method": str(fact.get("verification_method") or ""),
            }
            for fact in self._blackboard_facts()[:50]
            if isinstance(fact, dict)
        ]
        plan = getattr(self, "engagement_plan", None)
        open_todos = [todo.id for todo in (plan.pending if plan is not None else ())]
        # The partial report is what the engagement proved, not what the model
        # promised: verified board facts (``info``) plus the flags this run
        # captured, deduplicated by title so a loot fact is not listed twice.
        preserved = self._preserved_findings()
        titles = {str(finding.get("title") or "") for finding in preserved}
        self.findings = preserved + [
            finding
            for finding in self._flag_findings()
            if str(finding.get("title") or "") not in titles
        ]
        self.status = STATUS_TIME_BUDGET
        self.completion_verified_override = False
        tail = (
            f"; TODOs abiertos: {', '.join(open_todos[:6])}" if open_todos else ""
        )
        self.final_summary = (
            "⚠️ Presupuesto de tiempo agotado. Se guardó el estado para "
            f"--resume. {used:.0f}s de {self.time_budget_seconds}s de trabajo; "
            f"{len(flags)} flag(s) capturada(s){tail}; {self._report_status_line()}"
        )
        self.actions.append(
            _action_entry(
                self.iteration,
                ACTION_TASK_COMPLETE,
                thought=(
                    "Cierre forzado: se agotó el presupuesto de tiempo de trabajo "
                    "y el motor cierra con la evidencia ya verificada."
                ),
                summary=self.final_summary,
                findings=self.findings,
                forced=True,
                time_budget=True,
                flags=flags,
                board_facts=board_facts,
                open_todos=open_todos,
            )
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            TIME_BUDGET_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "work_seconds_used": used,
                "time_budget_seconds": self.time_budget_seconds,
                "wrap_up_seconds": self.wrap_up_seconds,
                "wrap_up": self.wrap_up,
                "open_todos": open_todos,
                "flags": flags,
                "board_facts": board_facts,
                "report": self.report_artifact or {"generated": False},
                "subagent_id": self.last_subagent_id,
            },
        )
        memory.append_step(
            self.store,
            self.tenant_id,
            self.conversation_id,
            "assistant",
            json.dumps(
                {"summary": self.final_summary, "findings": self.findings},
                ensure_ascii=False,
            ),
            {
                "kind": "react.final",
                "iteration": self.iteration,
                "findings_count": len(self.findings),
                "forced": True,
                "time_budget": True,
                "work_seconds_used": used,
                "run_id": self.run_id,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=ACTION_TASK_COMPLETE,
            decision="allow",
            reason="time_budget_exhausted",
            forced=True,
            open_todos=open_todos,
            findings_count=len(self.findings),
            report=self.report_artifact or {"generated": False},
        )
        return Transition.STOP

    def audit_step(self, *, iteration: int, action: str, decision: str, **extra: Any) -> None:
        "Audit one step, always tagged with the active subagent (3C)."
        _audit_step(
            self.audit,
            tenant_id=self.tenant_id,
            run_id=self.run_id,
            agent_id=self.agent_id,
            subagent_id=self.active_subagent_id,
            iteration=iteration,
            action=action,
            decision=decision,
            **extra,
        )

    def _grant_objective_grace(self, completion: Any = None) -> None:
        """Extend the run by ``OBJECTIVE_GRACE_TURNS`` once the board is complete.

        WP2: a run with root + loot verified does not die of bookkeeping. The
        grace is granted once, extends the iteration ceiling the model can use to
        emit ``task_complete``, and is measured separately from the legacy
        per-profile waiver so telemetry can tell them apart.
        """
        if getattr(self, "grace_granted", False) or legacy_profiles():
            return
        self.grace_granted = True
        self.grace_turns_remaining = OBJECTIVE_GRACE_TURNS
        limit = getattr(self, "iteration_limit", None)
        if limit is None:
            limit = getattr(getattr(self, "config", None), "max_iterations", 0)
        self.iteration_limit = max(int(limit or 0), self.iteration + OBJECTIVE_GRACE_TURNS)
        payload: dict[str, Any] = {
            "grace_turns": OBJECTIVE_GRACE_TURNS,
            "iteration_limit": self.iteration_limit,
            "iteration": self.iteration,
            "phase": str(getattr(self.plan, "current", "") or ""),
        }
        if completion is not None and hasattr(completion, "to_payload"):
            payload.update(completion.to_payload())
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            OBJECTIVE_GRACE_EVENT_TYPE,
            payload,
        )

    def _guard(self) -> Transition:
        used = _budget_used(self.store, self.tenant_id, self.run_id) if self.budget else 0
        if self.budget and used >= self.budget:
            grace = False
            if not legacy_profiles():
                # The board is re-read here on purpose: the fact that completes
                # the objective may have landed in the turn that just spent the
                # last token, and the next guard used to kill the run before the
                # context turn could even see it (the rerun-13 shape).
                if not self.objective_complete:
                    completion = objective_completion(
                        self._blackboard_facts(), subagent_id=self.last_subagent_id
                    )
                    if completion.complete:
                        self.objective_complete = True
                        self._grant_objective_grace(completion)
                if self.objective_complete:
                    if not self.grace_granted:
                        self._grant_objective_grace()
                    remaining = int(self.grace_turns_remaining or 0)
                    if remaining > 0:
                        self.grace_turns_remaining = remaining - 1
                        grace = True
                        self.store.append_run_event(
                            self.tenant_id,
                            self.run_id,
                            BUDGET_GRACE_EVENT_TYPE,
                            {
                                "used": used,
                                "budget": self.budget,
                                "grace_turns_remaining": self.grace_turns_remaining,
                                "iteration": self.iteration,
                            },
                        )
                        self.telemetry.flag(FrictionFlag.BUDGET_EXEMPT)
            if not grace:
                self.status = STATUS_BUDGET_EXCEEDED
                self.final_summary = (
                    f"token budget exhausted: {used} >= {self.budget} without task_complete"
                )
                self.store.append_run_event(
                    self.tenant_id,
                    self.run_id,
                    BUDGET_EVENT_TYPE,
                    {"used": used, "budget": self.budget, "iteration": self.iteration},
                )
                return Transition.STOP
        if self.cancel_event is not None and self.cancel_event.is_set():
            self.status = STATUS_CANCELLED
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.cancelled",
                {"iteration": self.iteration, "phase": "between_iterations"},
            )
            return Transition.STOP
        if _cancellation_requested(self.store, self.tenant_id, self.run_id):
            self.status = STATUS_CANCELLED
            self.store.append_run_event(
                self.tenant_id, self.run_id, "react.cancelled", {"iteration": self.iteration}
            )
            return Transition.STOP
        return Transition.READY

    def _model_client(self, task: str, *, journal: bool = False) -> Any:
        """The client for one kind of turn, and the reason it was chosen.

        ``[model_routing]`` may pin a different provider/model per task. This is
        the only place the loop asks for one, so every turn (and the context
        summariser that runs before it) goes through the same policy. A selector
        that cannot answer never ends a run: ``llm_client`` -the client the run
        was started with- is the floor.

        With ``journal`` the decision is written as ``model.route`` *before* the
        call, so a provider failure later in the turn still leaves the operator
        the model that failed and the policy that picked it.
        """
        selector = self.model_selector
        if selector is None:
            return self.llm_client
        try:
            routed = selector.routed(task, event_sink=self._model_event)
        except Exception:  # noqa: BLE001 - routing never aborts a run
            return self.llm_client
        if journal:
            from nexus_core.llm.dynamic_selector import ROUTE_EVENT_TYPE

            decision = getattr(routed, "decision", None)
            if decision is not None:
                self._model_event(
                    ROUTE_EVENT_TYPE,
                    {**decision.as_payload(), "iteration": self.iteration},
                )
        return routed

    def _model_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """Route model telemetry to the run journal; never break the turn."""
        try:
            self.store.append_run_event(self.tenant_id, self.run_id, event_type, payload)
        except Exception:  # noqa: BLE001 - telemetry is best-effort
            return

    async def _build_context(self) -> Transition:
        self.iteration += 1
        self.snapshot = await self.context_builder.gather(
            store=self.store,
            tenant_id=self.tenant_id,
            run_id=self.run_id,
            conversation_id=self.conversation_id,
            # Context compaction is a *reflection* turn: it can run on a cheaper
            # model than the executor without affecting the action quality.
            llm_client=self._model_client("reflection"),
            config=self.config,
            hooks=self.hooks,
            engagement_id=self.engagement_id,
            phase_turns=self.phase_turns,
        )
        self.plan = self.snapshot.plan
        # The reason of a deterministic hand-over is *per iteration*: the plan is
        # rebuilt from the blackboard on every turn, so a reason from an earlier
        # turn must never ride along on a later, organic phase change.
        self.plan_reason = None
        # WP2: the hand-overs existed because a phase locked the tool subset. The
        # default loop has one profile with every tool, so they are dead code
        # there; they stay exactly as measured behind the legacy flag.
        if legacy_profiles():
            self._apply_enumeration_exhaustion()
            self._apply_credential_handover()
            self._apply_session_handover()
        # The endpoint ceiling is a property of the board, not of the legacy
        # profile gate: it applies to the default loop too.
        self._apply_endpoint_ceiling()
        self._refresh_objective_complete()
        # WP5: the same board (plus the flags this run already saw in a tool
        # output) decides whether the objective's flags are in hand. It is read
        # every turn, so a flag captured after the previous turn is announced on
        # the very next prompt instead of when the budget runs out.
        self._refresh_target_reached()
        # PLAN MODE's contract: the TODOs of ``ENGAGEMENT_PLAN.md`` are ticked from
        # the verified facts before the prompt is built, so the model reads the
        # real state of the plan (never its own memory of it).
        self._refresh_engagement_plan()
        # WP6: a wide surface after ten turns without access gets one explicit
        # order to stop enumerating (see ``enumeration_budget_hint``).
        self._refresh_budget_hint()
        # The Vulnversity stall: build/pack work pushed through a webshell for
        # ten turns without a new fact gets one explicit order to stabilize.
        self._refresh_webshell_hint()
        # The surface ledger: a service already documented as a dead end, or a
        # branch held while another port is unexplored, gets one order to move.
        self._refresh_coverage_hint()
        # The index files: reading ``robots.txt``/``sitemap.xml`` is not
        # following them; the routes it lists get one explicit order.
        self._refresh_robots_hint()
        # A login form read but never probed gets the three deterministic
        # probes, before any wordlist (DeadDrop P1/P3).
        self._refresh_login_hint()
        self._refresh_reflection_hint()
        # A host in another network reached from a proven access needs the SOCKS
        # tunnel, not a local tool that has no route (DeadDrop P8).
        self._refresh_pivot_hint()
        self.last_plan = self.plan
        return Transition.READY

    def _apply_enumeration_exhaustion(self) -> None:
        """Hand an exhausted enumeration over to initial access (Fase 3 fixes).

        The rule lives in the planner (deterministic, unit-tested); here it is
        only *applied* to the plan of this iteration. The new phase makes the
        profile selector pick ``exploit`` on its own, and ``_advance_phase``
        audits the change with its reason. Nothing is authorized by this: the
        gateway keeps governing every tool of the new profile.
        """
        if self.enumeration_escalated:
            # Already handed over: keep it handed over *while the evidence still
            # describes an enumeration phase*, instead of falling back to the
            # profile that just failed. Evidence that closes the phase (a
            # credential, an access) moves ``current`` forward on its own, and
            # from that turn on the latch lets go (V1-36): an unconditional
            # re-apply monopolised the phase forever, so a run that once escaped
            # an exhausted enumeration could never reach
            # ``privilege_escalation``/``post_exploitation`` again.
            if enumeration_still_open(self.plan):
                self.plan = escalate_enumeration(
                    self.plan,
                    EnumerationEscalation(
                        phase="exploitation",
                        subagent="exploit",
                        reason=ENUMERATION_EXHAUSTED_REASON,
                    ),
                )
                self.plan_reason = ENUMERATION_EXHAUSTED_REASON
            return
        escalation = enumeration_escalation(
            self.plan,
            subagent_id=self.last_subagent_id,
            no_progress=self.consecutive_no_progress,
            services=self._blackboard_services(),
        )
        if escalation is None:
            return
        self.plan = escalate_enumeration(self.plan, escalation)
        self.plan_reason = escalation.reason
        self.enumeration_escalated = True

    def _apply_credential_handover(self) -> None:
        """Hand a validated credential over to initial access (V1-34).

        The rule lives in the planner (deterministic, unit-tested); here it is
        only *applied* to the plan of this iteration, exactly like the enumeration
        and session hand-overs. Measured in rerun 9: ``cred`` held the validated
        credential but carries no access tool, so without this it re-enumerated FTP
        and re-ran hydra until its 6-iteration budget killed the run.
        """
        if self.credential_handed_over:
            # Already handed over: keep it handed over only while the plan still
            # computes ``enumeration``. Evidence that closes the phase (a session,
            # an access) moves ``current`` forward and the rule stops applying,
            # so it can never drag a later phase backwards.
            if str(getattr(self.plan, "current", "")) == "enumeration":
                self.plan = escalate_credential(
                    self.plan,
                    CredentialHandover(
                        phase="exploitation",
                        subagent="exploit",
                        reason=CREDENTIAL_FOUND_REASON,
                    ),
                )
                self.plan_reason = CREDENTIAL_FOUND_REASON
            return
        handover = credential_handover(
            self.plan,
            subagent_id=self.last_subagent_id,
            credential_found=self._verified_credential(),
        )
        if handover is None:
            return
        self.plan = escalate_credential(self.plan, handover)
        self.plan_reason = handover.reason
        self.credential_handed_over = True

    def _apply_endpoint_ceiling(self) -> None:
        """Force ``enumeration`` → ``exploitation`` once the surface is mapped.

        The rule lives in the planner (deterministic, unit-tested); here it is
        only *applied*. Measured in Simple CTF (2026-10-18 02:35 UTC): gobuster
        put 17 endpoints on the board and the model kept enumerating routes, so
        the run spent >150k tokens before reaching ``/simple/``. The ceiling
        closes the phase by decision, keeping the statuses coherent, and the
        change is audited with :data:`ENUMERATION_ENDPOINT_REASON`.

        It is latched for the same reason as the other hand-overs: the plan is
        rebuilt from the blackboard every turn, so a non-sticky rule would be
        undone by the next rebuild while the same endpoints remain on the board.
        """
        if self.endpoint_ceiling_applied:
            if str(getattr(self.plan, "current", "")) == "enumeration":
                self.plan = endpoint_ceiling(self.plan) or self.plan
                self.plan_reason = ENUMERATION_ENDPOINT_REASON
            return
        closed = endpoint_ceiling(self.plan)
        if closed is None:
            return
        self.plan = closed
        self.plan_reason = ENUMERATION_ENDPOINT_REASON
        self.endpoint_ceiling_applied = True

    def _refresh_budget_hint(self) -> None:
        """Tell a run that keeps mapping routes to pick one and exploit it.

        The rule lives in the planner (deterministic, unit-tested); the loop only
        injects its text into this turn's prompt and audits it once. It never
        stops the run, never changes the plan and never authorizes a tool: it is
        the cheapest correction before the token budget does the deciding.
        """
        self.budget_hint = enumeration_budget_hint(self.plan, iteration=self.iteration)
        if not self.budget_hint or self.budget_hint_emitted:
            return
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            SMART_BUDGET_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "services": int(self.plan.counts.get("service", 0)),
                "endpoints": int(self.plan.counts.get("endpoint", 0)),
                "endpoint_leads": int((getattr(self.plan, "leads", {}) or {}).get("endpoint", 0)),
                "budget": self.budget,
                "used": _budget_used(self.store, self.tenant_id, self.run_id) if self.budget else 0,
                "hint": self.budget_hint,
            },
        )
        self.budget_hint_emitted = True

    def _refresh_webshell_hint(self) -> None:
        """Order a real interactive shell out of a webshell build loop.

        The rule lives in the planner (deterministic, unit-tested); the loop only
        injects its text into this turn's prompt and audits it once per run. It
        never stops the run, never changes the plan and never authorizes a tool:
        the model still has to open the session (``nexus.session.pty``) or the
        listener (``nexus.post.listener``).
        """
        self.webshell_hint = webshell_stall_hint(
            self.actions, no_progress=self.consecutive_no_progress
        )
        if not self.webshell_hint or self.webshell_hint_emitted:
            return
        # ``_build_context`` runs before ``_select_profile``: on the first turn
        # the profile of *this* turn is not chosen yet, so fall back to the last.
        subagent = getattr(self, "subagent", None)
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            WEBSHELL_STALL_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "subagent_id": str(
                    getattr(subagent, "id", "") or self.last_subagent_id or ""
                ),
                "no_progress": self.consecutive_no_progress,
                "last_tools": self._last_tools(),
                "hint": self.webshell_hint,
            },
        )
        self.webshell_hint_emitted = True

    def _refresh_coverage_hint(self) -> None:
        """Stop a run from insisting on a branch the ledger already closed.

        The rule lives in :mod:`nexus_core.agent.coverage` (deterministic and
        unit-tested); the loop only injects its text and audits it once. It has
        two triggers, both measured as real stalls: the turn's action aims at a
        service a ``barrier`` fact already closed (the Blackbox run kept probing
        the patched service instead of documenting it and moving on), or the
        run reached the stuck threshold while the ledger still has open work.

        It never changes the plan, never stops the run and never authorizes a
        tool: the model still chooses the branch and the gateway still governs
        it.
        """
        from nexus_core.agent.coverage import (
            STATUS_CLOSED,
            focus_entry,
            parse_directive,
            pivot_hint,
        )

        coverage = getattr(self.snapshot, "coverage", None)
        arguments = getattr(getattr(self, "action", None), "arguments", None)
        focus = focus_entry(coverage, arguments if isinstance(arguments, dict) else None)
        # The human's objective is the highest-order instruction the run has; the
        # ledger is a heuristic map. Parsed here (not stored) so a resumed run
        # reads the objective it was given, not a cached copy.
        directive = parse_directive(getattr(self, "objective", ""))
        # A branch the ledger reports as closed is one the loop has already
        # declared dead -and the pivot below is about to order the model off it-,
        # so this is the moment to start the refusal window. The window needs a
        # *when*, and ``closed_branch_at`` only knew the closures
        # ``_close_stalled_branch`` wrote itself: the measured DeadDrop P12 v2 run
        # resumed with a persisted ``barrier`` on ``192.168.11.200:80``, the pivot
        # fired on iteration 4 and the model kept calling ``web.*`` on that host
        # for 43 turns because nothing stamped it. An active directive is the
        # exception: an objective that names the branch outranks the ledger.
        #   It is stamped **once**: the window is five turns from the moment the
        #   loop acknowledged the closure, not five turns from the last attempt -
        #   re-stamping on every attempt would never expire while the model
        #   insists, and ``branch_discipline`` already measured that the window
        #   has to end so a real retry is still possible-.
        if (
            focus is not None
            and focus.status == STATUS_CLOSED
            and not directive.active
            and focus.ref not in (getattr(self, "closed_branch_at", None) or {})
        ):
            self._mark_branch_closed(focus.ref)
        self.coverage_hint = pivot_hint(
            coverage,
            no_progress=self.consecutive_no_progress,
            threshold=self.stuck_threshold,
            focus=focus,
            directive=directive,
        )
        if not self.coverage_hint or self.coverage_hint_emitted:
            return
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            COVERAGE_PIVOT_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "no_progress": self.consecutive_no_progress,
                "focus": focus.ref if focus is not None else None,
                "focus_status": focus.status if focus is not None else None,
                "counts": dict(getattr(coverage, "counts", {}) or {}),
                "open_work": [item.ref for item in getattr(coverage, "open_work", ())][:12],
                "directive": directive.to_dict(),
                "hint": self.coverage_hint,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="coverage_pivot",
            decision="degrade",
            focus=focus.ref if focus is not None else None,
        )
        self.coverage_hint_emitted = True

    def _refresh_robots_hint(self) -> None:
        """Order the GETs of an index file the run read but never followed.

        The rule lives in the planner (``robots_paths_hint``, deterministic and
        unit-tested over the persisted action history); the loop only injects
        its text and audits it once. It never stops the run, never changes the
        plan and never authorizes a tool.
        """
        self.robots_hint = robots_paths_hint(self.actions)
        if not self.robots_hint or self.robots_hint_emitted:
            return
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            ROBOTS_HINT_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "last_tools": self._last_tools(),
                "hint": self.robots_hint,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="robots_paths",
            decision="degrade",
        )
        self.robots_hint_emitted = True

    def _refresh_login_hint(self) -> None:
        """Order the three login probes on a form the run read but never tested.

        The rule lives in the planner (``login_probe_hint``, deterministic and
        unit-tested over the persisted action history); the loop only injects
        its text and audits it once.
        """
        # A read form with no canonical probe also withholds the directory
        # sweeps: asking twice was not enough (P9, 2026-10-22).
        pending = login_probe_pending(self.actions)
        self.login_withheld = set(LOGIN_PROBE_WITHHELD_TOOLS) if pending else set()
        if pending and not self.login_withheld_announced:
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.login_probe_withheld",
                {
                    "iteration": self.iteration,
                    "withheld": sorted(self.login_withheld),
                    "reason": "login_form_not_probed",
                },
            )
            self.login_withheld_announced = True
        self.login_hint = login_probe_hint(self.actions)
        if not self.login_hint or self.login_hint in self.login_hints_sent:
            return
        self.login_hints_sent.add(self.login_hint)
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.login_probe",
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "last_tools": self._last_tools(),
                "hint": self.login_hint,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="login_probe",
            decision="degrade",
        )
        self.login_hint_emitted = True

    def _refresh_reflection_hint(self) -> None:
        """Name the verified facts this run has not spent yet, once per list.

        The rule lives in ``agent/reflection.py`` (deterministic: substring over
        the action history, no model). The loop injects the text and audits it;
        it never changes the plan, stops the run or authorizes a tool.
        """
        from nexus_core.agent.reflection import render_reflection

        hint = render_reflection(
            self._blackboard_facts(),
            self.actions,
            no_progress=self.consecutive_no_progress,
        )
        self.reflection_hint = hint
        if not hint or hint in self.reflection_hints_sent:
            return
        self.reflection_hints_sent.add(hint)
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.reflection",
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "no_progress": self.consecutive_no_progress,
                "hint": hint,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="reflection",
            decision="degrade",
        )

    def _refresh_pivot_hint(self) -> None:
        """Order the SOCKS pivot when the run aims at a host it cannot route to.

        The rule lives in the planner (``pivot_hint``, deterministic over the
        persisted action history); the loop injects its text once.
        """
        self.pivot_hint = pivot_hint(self.actions, facts=self._blackboard_facts())
        if not self.pivot_hint or self.pivot_hint_emitted:
            return
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.pivot",
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "last_tools": self._last_tools(),
                "hint": self.pivot_hint,
            },
        )
        self.audit_step(iteration=self.iteration, action="pivot", decision="degrade")
        self.pivot_hint_emitted = True

    def _stalled_branch(self, coverage: Any) -> Any | None:
        """The one service the recent actions were aimed at (``None`` if unclear).

        Attribution reads the *arguments* of the last :data:`STALLED_BRANCH_WINDOW`
        actions through the ledger's own resolver, so it inherits its rules (an
        explicit port, or a bare ``http(s)://host`` for the scheme default).
        Unanimity is required: a window that touches two services is breadth, not
        a stall on one, and closing either of them would be a guess -the loop
        only acts where the evidence names a single target.
        """
        from nexus_core.agent.coverage import focus_entry

        if coverage is None or not getattr(coverage, "entries", None):
            return None
        refs: list[str] = []
        for record in self.actions[-STALLED_BRANCH_WINDOW:]:
            arguments = record.get("arguments")
            focus = focus_entry(
                coverage, arguments if isinstance(arguments, dict) else None
            )
            if focus is not None:
                refs.append(focus.ref)
        # One attributable call is a sample, not a stall: the loop waits until the
        # window itself is evidence of insistence.
        if len(refs) < 2 or len(set(refs)) != 1:
            return None
        return coverage.find(refs[0])

    def _close_stalled_branch(self) -> str | None:
        """Write the ``barrier`` the pivot ordered and the model never wrote.

        The advisory line tells the model to close a dead branch with
        ``nexus.knowledge.record_fact``; measured in
        ``run_c71035d9818047eaa80dfd859e887b7c`` (Joomla, 2026-10-20) that text
        was ignored for 43 turns while the ledger kept the two services as open
        work, so nothing in the planner or the prompt could move to the next
        branch. From :data:`STALL_BARRIER_MULTIPLIER` stuck thresholds the loop
        takes the decision: one ``barrier`` fact on the branch the recent actions
        unanimously targeted, unverified and attributed to ``react.loop``.

        Three refusals keep it honest:

        * it acts only when the recent window names a single service (see
          ``_stalled_branch``): closing one of two hammered branches is a guess;
        * a branch with a registered ``vulnerability`` is not closed -hiding a
          proven vector behind a dead branch is worse than stalling, and the
          ledger would then send the run to a port the vector does not live on;
        * a branch the ledger already marks ``descartado`` (or one this loop
          already closed) is left alone: the correction is idempotent.

        ``build_coverage`` reopens a closed branch when a *newer* vulnerability
        appears on it, so a later finding still wins over this verdict.
        """
        from nexus_core.agent.coverage import STATUS_CLOSED

        snapshot = getattr(self, "snapshot", None)
        entry = self._stalled_branch(getattr(snapshot, "coverage", None))
        if entry is None or entry.status == STATUS_CLOSED:
            return None
        if entry.ref in self.closed_branches or entry.vector_count:
            return None
        if not self.engagement_id or not getattr(self, "store", None):
            return None
        reason = (
            "el bucle cerró la rama: "
            f"{self.consecutive_no_progress} turnos consecutivos sin hechos nuevos "
            f"sobre {entry.label}"
        )
        try:
            from nexus_core.kernel.blackboard import Blackboard

            Blackboard(self.store).record(
                tenant_id=self.tenant_id,
                engagement_id=self.engagement_id,
                fact_type="barrier",
                key=entry.ref,
                value={
                    "reason": reason,
                    "source": "loop",
                    "barren_turns": int(self.consecutive_no_progress),
                    "last_tools": self._last_tools(),
                    # R6: this barrier carries its provenance. The vector *was*
                    # attempted (the measured stall is the attempt), so it may
                    # close the branch; a model-written barrier without a tested
                    # attempt may not (see ``coverage.barrier_is_conclusive``).
                    "sweep_attempted": True,
                    "outcome": "stalled",
                },
                source="react.loop",
                created_by="react.loop",
                verified=False,
            )
        except Exception:  # noqa: BLE001 - memory must never abort a run
            return None
        self.closed_branches.add(entry.ref)
        self._mark_branch_closed(entry.ref)
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            LOOP_BARRIER_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "branch": entry.ref,
                "label": entry.label,
                "barren_turns": int(self.consecutive_no_progress),
                "last_tools": self._last_tools(),
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="branch_closed",
            decision="degrade",
            branch=entry.ref,
            barren_turns=int(self.consecutive_no_progress),
        )
        return entry.ref

    def _mark_branch_closed(self, ref: str) -> None:
        """Start the refusal window of ``ref`` on this iteration.

        Two callers, one rule: the loop's own stall barrier
        (:meth:`_close_stalled_branch`) and the pivot's acknowledgement that the
        ledger already marks the branch ``descartado``
        (:meth:`_refresh_coverage_hint`). ``__init__`` owns the dict in a real run;
        a coordinator rebuilt by a test (or resumed from an older object) must not
        lose the closure, so the dict is created on demand.
        """
        name = str(ref or "").strip()
        if not name:
            return
        closed_at = getattr(self, "closed_branch_at", None)
        if closed_at is None:
            closed_at = self.closed_branch_at = {}
        closed_at[name] = int(self.iteration)

    def _note_completed_turn(self) -> None:
        """Record that the phase of this turn has been *current* once more (V1-46).

        The plan of a turn is built with this history, so ``min_turns`` holds a
        phase open until it has really had its turn. Called only after the turn
        finished: a turn that raised never counts as spent.
        """
        phase = str(getattr(self.plan, "current", "") or "")
        if not phase:
            return
        self.phase_turns[phase] = self.phase_turns.get(phase, 0) + 1

    def _refresh_objective_complete(self) -> None:
        """Detect that the engagement's objective is already met (V1-35).

        The rule lives in the planner (deterministic, unit-tested); here it is
        only *applied*: the plan carries a hint that says the objective is met,
        and the run audits the verdict once with the refs that prove it. Nothing
        is authorized and nothing is closed by this - the phases were closed by
        their own evidence, and ``task_complete`` stays the model's decision.
        """
        # WP2: board only. The profile that happens to hold the turn is not an
        # input of the verdict anymore (rerun 13 died with root+loot verified and
        # the reporter profile active).
        completion = objective_completion(
            self._blackboard_facts(), subagent_id=self.last_subagent_id
        )
        self.objective_complete = completion.complete
        if not completion.complete:
            return
        self.plan = apply_objective_completion(self.plan, completion)
        self._grant_objective_grace(completion)
        if self.objective_complete_emitted:
            return
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            OBJECTIVE_COMPLETE_EVENT_TYPE,
            {
                **completion.to_payload(),
                "hint": completion.hint,
                "iteration": self.iteration,
                "phase": self.plan.current,
                "subagent_id": self.last_subagent_id,
            },
        )
        self.objective_complete_emitted = True

    def _refresh_target_reached(self) -> None:
        """Detect that the flags the objective asked for were captured (WP5).

        The rule lives in the planner (deterministic, unit-tested); here it is
        only *applied*. Once reached the state latches for the run -captured
        evidence never disappears- so the margin counter cannot be reset by a
        later turn that writes no new fact.
        """
        if self.target_reached:
            return
        verdict = target_reached(
            self._blackboard_facts(),
            objective=self.objective,
            observed_flags=self.captured_flag_refs,
        )
        for source in verdict.sources:
            flag = str(source.get("flag") or "")
            if flag and flag not in self.captured_flag_refs:
                self.captured_flag_refs[flag] = dict(source)
        if not verdict.reached:
            return
        self.target_reached = True
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            TARGET_REACHED_EVENT_TYPE,
            {
                **verdict.to_payload(),
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "subagent_id": self.last_subagent_id,
            },
        )
        self.target_reached_emitted = True

    def _refresh_engagement_plan(self) -> None:
        """Load the durable plan and tick what the board already proves.

        The database is authoritative (``kernel_plan_todos``); the Markdown file
        is written from it as a projection for the operator and isolated
        children. A TODO ticked here is a verifier assertion, never a model
        claim. A concurrent writer that advanced the version makes this reload
        and re-reconcile once instead of overwriting its TODO.

        Never raises: a plan that cannot be read degrades to "no plan" and the
        gate below decides what that means for this run.
        """
        from nexus_core.agent.engagement_plan import (
            load_plan_for,
            prompt_block,
            reconcile,
            save_plan,
        )
        from nexus_core.kernel.errors import PlanConflict

        # The same directory the CLI wrote the plan into: the payload's
        # ``project_root`` (the operator's workspace), never an implicit cwd. A
        # bound local workspace lives in ``scope.notes``, so the two can differ.
        root = str(self.payload.get("project_root") or "") or None
        store = getattr(self, "store", None)
        plan = None
        try:
            facts = [
                fact for fact in self._blackboard_facts() if fact.get("verified") is True
            ]
            # Flags this run read out of a tool output are evidence too, and
            # the verifier does not always derive a loot fact for them.
            facts.extend(
                {
                    "fact_type": "loot",
                    "key": str(source.get("ref") or "flag"),
                    "value": {"flag": flag},
                    "verified": True,
                }
                for flag, source in self.captured_flag_refs.items()
            )
            for _attempt in range(2):
                plan = load_plan_for(
                    self.engagement_id,
                    root,
                    store=store,
                    tenant_id=self.tenant_id,
                )
                if plan is None:
                    break
                updated, ticks = reconcile(
                    plan, facts, engagement_id=self.engagement_id
                )
                if not ticks or updated is None:
                    break
                try:
                    save_plan(
                        updated,
                        root,
                        store=store,
                        tenant_id=self.tenant_id,
                    )
                except PlanConflict:
                    # Another writer committed first: its TODOs are newer than
                    # this reconciliation. Reload and re-apply the facts.
                    continue
                plan = updated
                self.store.append_run_event(
                    self.tenant_id,
                    self.run_id,
                    "orchestrator.plan_todos",
                    {
                        "iteration": self.iteration,
                        "done": list(ticks),
                        "pending": [todo.id for todo in plan.pending],
                    },
                )
                break
        except Exception:  # noqa: BLE001 - the plan must never abort a turn
            plan = None
        self.engagement_plan = plan
        self.engagement_plan_text = prompt_block(plan)

    def _plan_required_missing(self) -> bool:
        """Whether this turn must refuse an attack tool until there is a plan.

        A bounded order ("escanea los puertos 80 y 443") is not an engagement:
        demanding a plan for it is what made the measured run scan the whole
        host and then deadlock on the report TODO.
        """
        from .react_support import objective_is_micro_task

        return bool(
            self.config.require_plan_first
            and self.engagement_id
            and self.engagement_plan is None
            and not objective_is_micro_task(self.objective)
        )

    def _flag_todos_pending(self) -> bool:
        """Whether the plan still promises a flag that was not captured."""
        plan = self.engagement_plan
        return bool(plan is not None and plan.flags_pending)

    def _note_report_artifact(self, spec: Any | None = None) -> None:
        """Remember a report that really wrote its deliverables.

        Only a successful ``nexus.report.generate`` counts: the handler returns
        the directory it created plus the artifact hashes, so a failed run of the
        tool (``outcome=unavailable``/``negative``) leaves this ``None`` and the
        closure can say "objective met, report pending" instead of implying a
        report that does not exist.
        """
        action = spec if spec is not None else self.action
        if str(getattr(action, "tool_id", "") or "") != "nexus.report.generate":
            return
        observation = self.observation or {}
        if not observation.get("success"):
            return
        raw_output = observation.get("output")
        output: dict[str, Any] = raw_output if isinstance(raw_output, dict) else {}
        raw_evidence = observation.get("evidence")
        evidence: dict[str, Any] = raw_evidence if isinstance(raw_evidence, dict) else {}
        directory = str(output.get("directory") or "")
        if not directory:
            return
        self.report_artifact = {
            "directory": directory,
            "findings_count": output.get("findings_count"),
            "report_sha256": output.get("report_sha256") or evidence.get("report_sha256"),
            "invocation_id": str(observation.get("invocation_id") or ""),
        }

    def _note_observed_flags(self, spec: Any | None = None) -> None:
        """Keep every flag seen in the successful output of this run (WP5).

        The verifier only derives ``loot`` for the tools it parses; a webshell
        command (``nexus.shell.exec``) reports a flag in its stdout with no
        assertion at all. The literal token in a *successful* tool output is the
        same evidence the bench scores, so it is recorded here and fed to
        :func:`target_reached` as an observation source.
        """
        observation = self.observation or {}
        if not observation.get("success"):
            return
        tokens = flag_tokens(observation.get("output"))
        if not tokens:
            return
        # ``spec`` is the call that produced the observation. A parallel batch
        # passes it explicitly: ``self.action`` names several tools and only the
        # one that ran may be credited with the flag.
        action = spec if spec is not None else self.action
        arguments = getattr(action, "arguments", None) or {}
        target = str(
            arguments.get("target") or arguments.get("url") or arguments.get("host") or ""
        )
        for token in tokens:
            if token in self.captured_flag_refs:
                continue
            self.captured_flag_refs[token] = {
                "flag": token,
                "ref": str(getattr(action, "tool_id", "") or ""),
                "fact_type": "loot",
                "invocation_id": str(observation.get("invocation_id") or ""),
                "verification_method": str(
                    observation.get("verification_method") or ""
                ),
                "target": target,
                "source": "observation",
                "verified": True,
            }
        self._refresh_target_reached()

    def _blackboard_facts(self) -> list[dict[str, Any]]:
        """Every fact of the engagement, up to the board's key ceiling.

        The ceiling is passed explicitly: with the default page (100 keys) a
        large board silently dropped facts from coverage, reflection and the
        planner (V0-2). Most recent keys win when the ceiling is reached.
        """
        if not self.engagement_id or not getattr(self, "store", None):
            return []
        try:
            from nexus_core.kernel.blackboard import FACT_KEYS_CEILING, Blackboard

            return list(
                Blackboard(self.store).list_facts(
                    self.tenant_id, self.engagement_id, limit=FACT_KEYS_CEILING
                )
            )
        except Exception:  # noqa: BLE001 - a missing board must not abort a run
            return []

    def _verified_credential(self) -> bool:
        """Whether the board holds a verified credential fact (never raises)."""
        if not self.engagement_id or not getattr(self, "store", None):
            return False
        try:
            from nexus_core.kernel.blackboard import Blackboard

            facts = Blackboard(self.store).list_facts(
                self.tenant_id, self.engagement_id, fact_type="credential"
            )
            return verified_credential(facts)
        except Exception:  # noqa: BLE001 - a missing board must not abort a run
            return False

    def _apply_session_handover(self) -> None:
        """Hand an established session over to post-exploitation (V1-25).

        The rule lives in the planner (deterministic, unit-tested); here it is
        only *applied* to the plan of this iteration, exactly like the
        enumeration hand-over above. Measured in rerun 6: the MSF session was
        verified and registered but the plan stayed on ``exploitation`` until the
        ``exploit`` profile exhausted its token budget, because nothing connected
        the session to the profile that owns ``session.*`` / ``post.*`` tools.
        """
        if self.session_handed_over:
            # Already handed over: keep it handed over while the session evidence
            # is on the board, instead of falling back, every turn, to the phase
            # the blackboard's own counts compute (``privilege_escalation``).
            self.plan = escalate_session(
                self.plan,
                SessionHandover(
                    phase="post_exploitation",
                    subagent="postexploit",
                    reason=SESSION_ESTABLISHED_REASON,
                ),
            )
            self.plan_reason = SESSION_ESTABLISHED_REASON
            return
        handover = session_handover(
            self.plan,
            subagent_id=self.last_subagent_id,
            session_established=self._msf_session_established(),
        )
        if handover is None:
            return
        self.plan = escalate_session(self.plan, handover)
        self.plan_reason = handover.reason
        self.session_handed_over = True

    def _msf_session_established(self) -> bool:
        """Whether the board holds a verified MSF session fact (never raises).

        Read from the facts, not from counts: the flag must be able to tell a
        session this engine proved from the lead the model records by hand.
        """
        if not self.engagement_id or not getattr(self, "store", None):
            return False
        try:
            from nexus_core.kernel.blackboard import Blackboard

            facts = Blackboard(self.store).list_facts(
                self.tenant_id, self.engagement_id, fact_type="session"
            )
            return established_msf_session(facts)
        except Exception:  # noqa: BLE001 - a missing board must not abort a run
            return False

    def _note_soft_limit(self, kind: str, detail: dict[str, Any]) -> None:
        """Record a per-profile limit once; it never stops the run (WP2).

        The per-subagent numbers survived as *telemetry*: they tell the operator
        when a phase spent its calibrated allowance, but only the global run
        budget (and the model's own completion) can end the engagement.
        """
        key = f"{self.subagent.id}:{kind}"
        if key in self.soft_limits_reported:
            return
        self.soft_limits_reported.add(key)
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            SUBAGENT_SOFT_LIMIT_EVENT_TYPE,
            {
                "subagent_id": self.subagent.id,
                "limit": kind,
                "soft": True,
                "iteration": self.iteration,
                **detail,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="subagent_soft_limit",
            decision="allow",
            limit=kind,
            **detail,
        )

    async def _select_profile(self) -> Transition:
        selected = select_run_profile(self.plan, override=self.subagent_override)
        if self.plan.current != self.last_phase:
            self.phase_started = time.monotonic()
        changed = selected.id != self.last_subagent_id
        if changed:
            self.subagent_iterations = 0
            self.previous_profile = self.last_selected
        self.subagent_iterations += 1
        self.subagent = with_phase_grace(
            selected, self.previous_profile, iterations=self.subagent_iterations
        )
        self.last_selected = selected
        self.active_subagent_id = self.subagent.id
        if changed:
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                SUBAGENT_EVENT_TYPE,
                {
                    "subagent_id": self.subagent.id,
                    "previous": self.last_subagent_id,
                    "phase": self.plan.current,
                    "read_only": self.subagent.read_only,
                    "token_budget": self.subagent.token_budget,
                    "tools": (
                        sorted(self.catalog)
                        if self.subagent.unrestricted
                        else sorted(self.subagent.tools)
                    ),
                    "tools_count": (
                        len(self.catalog)
                        if self.subagent.unrestricted
                        else len(self.subagent.tools)
                    ),
                    "unrestricted": self.subagent.unrestricted,
                    "iteration": self.iteration,
                },
            )
            await _maybe_autospawn(
                store=self.store,
                tenant_id=self.tenant_id,
                run_id=self.run_id,
                context=self.context,
                llm_client=self.llm_client,
                config=self.config,
                engagement_id=self.engagement_id,
                objective=self.objective,
                previous_subagent_id=self.last_subagent_id,
                subagent_id=selected.id,
                payload=self.payload,
                conversation_id=self.conversation_id,
                iteration=self.iteration,
                audit_step=self.audit_step,
            )
            self.last_subagent_id = selected.id
        legacy = legacy_profiles()
        if self.subagent_iterations > self.subagent.max_iterations:
            if legacy:
                self.status = STATUS_SUBAGENT_BUDGET
                self.final_summary = f"subagent '{self.subagent.id}' exceeded its iteration budget ({self.subagent.max_iterations})"
                return Transition.STOP
            self._note_soft_limit(
                "iterations",
                {"iterations": self.subagent_iterations,
                 "max_iterations": self.subagent.max_iterations},
            )
        if self.subagent.token_budget:
            spent = _budget_used(
                self.store, self.tenant_id, self.run_id, subagent_budget_subject(self.subagent.id)
            )
            if spent >= self.subagent.token_budget:
                # V1-38: an engagement whose objective is already met does not die
                # of bookkeeping. Spending a few more turns closing (with
                # ``task_complete``) is worth more than stopping with the work done
                # and the run reported as failed (measured in rerun 10: 63 224 of
                # 60 000 tokens spent by ``privesc`` *after* root.txt was on the
                # board, and the run ended without ``task_complete``). The ceiling
                # is waived, audited and counted as friction - never silently.
                if not legacy:
                    self._note_soft_limit(
                        "tokens",
                        {"spent": spent, "token_budget": self.subagent.token_budget},
                    )
                elif self.objective_complete:
                    self.budget_exempt = True
                    self.store.append_run_event(
                        self.tenant_id,
                        self.run_id,
                        BUDGET_EXEMPT_EVENT_TYPE,
                        {
                            "subagent_id": self.subagent.id,
                            "spent": spent,
                            "token_budget": self.subagent.token_budget,
                            "budget_exempt_if_objective_complete": True,
                            "iteration": self.iteration,
                        },
                    )
                    self.telemetry.flag(FrictionFlag.BUDGET_EXEMPT)
                else:
                    self.status = STATUS_SUBAGENT_BUDGET
                    self.final_summary = f"subagent '{self.subagent.id}' exhausted its token budget: {spent} >= {self.subagent.token_budget}"
                    return Transition.STOP
        return Transition.READY

    def _advance_phase(self) -> Transition:
        if (
            self.phase_timeout_seconds
            and time.monotonic() - self.phase_started > self.phase_timeout_seconds
        ):
            stalled = sorted(
                (
                    tool_id
                    for tool_id in self.tool_failures
                    if tool_id in self.subagent.tools and tool_id not in self.unavailable_tools
                )
            )
            if stalled:
                self.unavailable_tools.update(stalled)
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                PHASE_TIMEOUT_EVENT_TYPE,
                {
                    "phase": self.plan.current,
                    "subagent_id": self.subagent.id,
                    "elapsed_seconds": round(time.monotonic() - self.phase_started, 3),
                    "iteration": self.iteration,
                    "retired_tools": stalled,
                },
            )
            self.audit_step(
                iteration=self.iteration,
                action="phase_timeout",
                decision="degrade",
                phase=self.plan.current,
                retired_tools=stalled,
            )
            self.phase_started = time.monotonic()
        if self.wrap_up:
            # Wrap-up: the deliverable, not a new branch. The subset is built from
            # the engine catalog on purpose -a profile that lacks the report tool
            # must still be able to close- and ``_call_refusal`` is the gate that
            # actually enforces it (the prompt only reflects it).
            self.allowed_catalog = {
                tool_id: entry
                for tool_id, entry in self.catalog.items()
                if tool_id in WRAP_UP_TOOLS
            }
        else:
            self.allowed_catalog = {
                tool_id: entry
                for tool_id, entry in filter_catalog(self.subagent, self.catalog).items()
                if tool_id not in self.unavailable_tools
                and tool_id not in getattr(self, "login_withheld", set())
            }
        if self.plan.current != self.last_phase:
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "orchestrator.plan",
                {
                    "phase": self.plan.current,
                    "previous": self.last_phase,
                    "progress": list(self.plan.progress),
                    "facts_total": self.plan.facts_total,
                    "subagent_id": self.subagent.id,
                    "iteration": self.iteration,
                    # Present only when the change came from a deterministic
                    # rule (never from the model); absent on organic progress.
                    **({"reason": self.plan_reason} if self.plan_reason else {}),
                },
            )
            self.last_phase = self.plan.current
        return Transition.READY

    async def _request_action(self) -> Transition:
        self.messages = self.context_builder.render(
            self.snapshot,
            allowed_catalog=self.allowed_catalog,
            objective=self.objective,
            engagement_id=self.engagement_id,
            scope=self.scope,
            subagent=self.subagent,
            project_instruction=self.project_instruction,
            active_skills=self.active_skills,
            # R2: the body travels once. Marked in ``_decode_action`` (after a
            # successful decode) so a JSON retry still sees the recipe.
            skill_bodies=frozenset(
                skill.name
                for skill in self.active_skills
                if skill.name not in self.skill_bodies_sent
            ),
            store=self.store,
            tenant_id=self.tenant_id,
            no_progress=self.consecutive_no_progress,
            stuck_threshold=self.stuck_threshold,
            same_tool_no_progress=self.same_tool_no_progress,
            target_reached=self.target_reached,
            iteration=self.iteration,
            budget_hint=self.budget_hint,
            webshell_hint=self.webshell_hint,
            coverage_hint=self.coverage_hint,
            robots_hint=self.robots_hint,
            login_hint=self.login_hint,
            reflection_hint=self.reflection_hint,
            pivot_hint=self.pivot_hint,
            engagement_plan_summary=self.engagement_plan_text,
            wrap_up=self.wrap_up,
            wrap_up_seconds=max(0, int(self._remaining_seconds() or 0)),
        )
        reservation = None
        estimated = _estimate_request_tokens(self.messages)
        if self.config.before_provider_call is not None:
            from nexus_core.kernel.errors import BudgetExceeded

            try:
                reservation = self.config.before_provider_call(estimated)
            except BudgetExceeded as exc:
                self.status = STATUS_BUDGET_EXCEEDED
                self.final_summary = f"budget reservation refused: {exc}"
                self.telemetry.flag(FrictionFlag.BUDGET_REFUSED)
                self.audit_step(
                    iteration=self.iteration,
                    action="budget_exceeded",
                    decision="deny",
                    reason="reservation_refused",
                )
                return Transition.STOP
        reasoning_started = time.perf_counter()
        try:
            response = await _complete_turn(
                self._model_client("executor", journal=True), self.messages, self.config
            )
        except ProviderFailure as exc:
            # A provider failure raised directly by the client ends the run with
            # a typed terminal status instead of escaping ``run()`` (B8.2).
            return self._provider_error_stop(
                exc, estimated=estimated, started=reasoning_started, reservation=reservation
            )
        except Exception as exc:
            # A malformed answer is not a dead provider: retry the turn with a
            # correction before giving up (Run 3, Simple CTF 2026-10-17).
            if (
                is_invalid_json_error(exc)
                and self.invalid_json_turns < MAX_INVALID_JSON_TURNS
            ):
                return self._invalid_json_retry(
                    exc,
                    estimated=estimated,
                    started=reasoning_started,
                    reservation=reservation,
                )
            if is_invalid_json_error(exc):
                # The retry budget is spent: a provider that only emits garbage
                # is unhealthy, and the operator needs that reason in the
                # terminal summary (Run 3, Simple CTF 2026-10-17).
                return self._provider_error_stop(
                    ProviderFailure(
                        "model answered invalid JSON "
                        f"{self.invalid_json_turns} times in a row"
                    ),
                    estimated=estimated,
                    started=reasoning_started,
                    reservation=reservation,
                )
            # The failed turn still carries what it cost (the estimate) and how
            # long the provider took before it died; the run closes with the
            # terminal status instead of propagating ``ProviderFailure`` (B8.2).
            return self._provider_error_stop(
                ProviderFailure(type(exc).__name__),
                estimated=estimated,
                started=reasoning_started,
                reservation=reservation,
            )
        # A usable answer clears the malformed-answer streak: the budget is for
        # consecutive garbage, never for the whole run.
        self.invalid_json_turns = 0
        self.telemetry.note_reasoning(
            response, estimated=estimated, duration_ms=_elapsed_ms(reasoning_started)
        )
        if reservation is not None and self.config.after_provider_call is not None:
            actual = int(getattr(response, "tokens_input", 0) or 0) + int(
                getattr(response, "tokens_output", 0) or 0
            )
            self.config.after_provider_call(reservation, actual)
        _record_response_tokens(
            self.store,
            self.tenant_id,
            self.run_id,
            response,
            subject_ids=(BUDGET_SUBJECT_ID, subagent_budget_subject(self.subagent.id)),
        )
        self.raw_response = str(getattr(response, "content", "") or "")
        # R-4c: the provider's own reasoning travels as its own event. It never
        # replaces or rewrites the model's JSON ``thought``; the TUI only shows
        # it when that thought is too short to be useful.
        reasoning = str(getattr(response, "reasoning", "") or "").strip()
        if reasoning:
            self.context.event(
                "react.reasoning", reasoning=reasoning[:2000], iteration=self.iteration
            )
        return Transition.READY

    def _invalid_json_retry(
        self,
        exc: Exception,
        *,
        estimated: int,
        started: float,
        reservation: Any,
    ) -> Transition:
        """Ask the model again after a non-JSON answer (Simple CTF Run 3).

        ``DeepSeekClient._check_content`` raises before the loop can see the
        text, so this path has no raw answer to decode: the only way to keep the
        mission alive is to re-issue the turn with a correction in the history.
        The failed attempt still books its estimate with zero actual tokens and
        releases its reservation, exactly like ``_provider_error_stop``, so no
        hold is left open. The streak is capped by
        :data:`MAX_INVALID_JSON_TURNS`; a provider that only emits garbage ends
        the run as ``provider_error`` instead of looping forever.
        """
        self.invalid_json_turns += 1
        self.telemetry.note_reasoning(
            None, estimated=estimated, duration_ms=_elapsed_ms(started)
        )
        if reservation is not None and self.config.after_provider_call is not None:
            self.config.after_provider_call(reservation, 0)
        memory.append_step(
            self.store,
            self.tenant_id,
            self.conversation_id,
            "user",
            INVALID_JSON_CORRECTION,
            {
                "kind": "react.correction",
                "iteration": self.iteration,
                "run_id": self.run_id,
                "reason": "invalid_json",
                "attempt": self.invalid_json_turns,
            },
        )
        self.telemetry.flag(FrictionFlag.PARSE_ERROR)
        self.context.event(
            INVALID_JSON_EVENT_TYPE,
            iteration=self.iteration,
            attempt=self.invalid_json_turns,
            limit=MAX_INVALID_JSON_TURNS,
            error=str(exc)[:300],
        )
        self.audit_step(
            iteration=self.iteration,
            action="parse_error",
            decision="deny",
            reason="invalid_json",
            attempt=self.invalid_json_turns,
            limit=MAX_INVALID_JSON_TURNS,
            error=str(exc)[:300],
        )
        return Transition.NEXT_TURN

    def _provider_error_stop(
        self,
        exc: ProviderFailure,
        *,
        estimated: int,
        started: float,
        reservation: Any,
    ) -> Transition:
        """Close the run with ``provider_error`` when the model call fails (B8.2).

        A failed provider call must not escape :meth:`run` as ``ProviderFailure``:
        the process used to die without a terminal result or ``run.complete``
        (the Bounty Hacker RUN #6 abort). It becomes the same terminal status
        ``_execute_tool`` already assigns to a provider failure during a tool
        call. The failed turn still books its estimated cost and releases the
        durable reservation, so no hold is ever left open.
        """
        self.telemetry.note_reasoning(
            None, estimated=estimated, duration_ms=_elapsed_ms(started)
        )
        if reservation is not None and self.config.after_provider_call is not None:
            self.config.after_provider_call(reservation, 0)
        self.status = "provider_error"
        self.final_summary = f"provider failure during a model turn: {exc}"
        return Transition.STOP

    def _decode_action(self) -> Transition:
        try:
            self.action = self.action_decoder.decode(self.raw_response)
        except ReActParseError as exc:
            self.actions.append(_action_entry(self.iteration, "parse_error", error=str(exc)[:500]))
            memory.append_step(
                self.store,
                self.tenant_id,
                self.conversation_id,
                "assistant",
                self.raw_response,
                {
                    "kind": "react.action",
                    "iteration": self.iteration,
                    "action": "parse_error",
                    "warnings": [],
                    "run_id": self.run_id,
                },
            )
            memory.append_step(
                self.store,
                self.tenant_id,
                self.conversation_id,
                "user",
                f"Tu respuesta anterior no era JSON válido y no se ejecutó nada. Error del parser: {str(exc)[:300]}. Responde de nuevo con UN solo objeto JSON que cumpla el contrato (tool_call, tool_calls, spawn_subagent, task_complete o request_clarification).",
                {"kind": "react.correction", "iteration": self.iteration, "run_id": self.run_id},
            )
            self.telemetry.note_action(action="parse_error")
            self.telemetry.flag(FrictionFlag.PARSE_ERROR)
            self.context.event("react.parse_error", iteration=self.iteration, error=str(exc)[:300])
            self.audit_step(
                iteration=self.iteration,
                action="parse_error",
                decision="deny",
                error=str(exc)[:300],
                raw_response=self.raw_response[:2000],
            )
            return Transition.NEXT_TURN
        memory.append_step(
            self.store,
            self.tenant_id,
            self.conversation_id,
            "assistant",
            self.action.raw_response or self.raw_response,
            {
                "kind": "react.action",
                "iteration": self.iteration,
                "action": self.action.action,
                "thought": self.action.thought,
                "tool_id": self.action.tool_id,
                "arguments": memory._redact_arguments(self.action.arguments),
                "warnings": list(self.action.warnings),
                "run_id": self.run_id,
                # A batch names every call: the transcript keeps what the model
                # actually asked for, not only the first one.
                **(
                    {
                        "calls": [
                            {
                                "tool_id": call.tool_id,
                                "arguments": memory._redact_arguments(call.arguments),
                            }
                            for call in self.action.calls
                        ]
                    }
                    if isinstance(self.action, ToolCallBatch)
                    else {}
                ),
            },
        )
        self.telemetry.note_action(
            action=self.action.action,
            tool_id=getattr(self.action, "tool_id", None),
            arguments=getattr(self.action, "arguments", None),
        )
        # R2: the bodies that travelled in this turn's prompt were delivered.
        # Marking here (not at render time) keeps them available to a retry after
        # an invalid JSON answer.
        self.skill_bodies_sent.update(skill.name for skill in self.active_skills)
        self.context.event(
            "react.action",
            iteration=self.iteration,
            action=self.action.action,
            tool_id=self.action.tool_id,
        )
        return Transition.READY

    async def _complete(self) -> Transition:
        # Fase 1: si el usuario pidió una micro-tarea ("solo escanea puertos"),
        # el plan global no puede impedir el cierre. La puerta de evidencia
        # (citas fabricadas) sigue activa.
        from .react_support import objective_is_micro_task

        # Antes de verificar, cede el turno al job en vuelo: el cierre apagaba el
        # proceso y `cancel_all()` mataba el escaneo (CancelledError), dejando al
        # usuario sin el resultado que había pedido. La espera es la misma del
        # sondeo ocioso, acotada por el timeout de la llamada; si el job sigue
        # corriendo, la objeción de abajo rechaza el cierre y el próximo turno
        # vuelve a esperar.
        if self.task_manager.running_count():
            await self._wait_for_background_result()
        background_tasks = self.task_manager.list_tasks()

        assessment = await self.completion_verifier.verify(
            findings=self.action.findings,
            observations=self.run_evidence,
            run_id=self.run_id,
            plan=self.plan,
            config=self.config,
            engagement_id=self.engagement_id,
            store=self.store,
            tenant_id=self.tenant_id,
            hooks=self.hooks,
            objective=self.objective,
            # WP2: in the default loop the phase is a hint; only the legacy path
            # keeps refusing a task_complete because the plan is not on reporting.
            require_plan_phase=legacy_profiles(),
            # The engagement's own TODOs close the run (PLAN-FIRST): a plan the
            # model committed to outranks the phase hint.
            engagement_plan=self.engagement_plan,
            require_plan_first=self.config.require_plan_first,
            micro_task=objective_is_micro_task(self.objective),
            background_tasks=background_tasks,
        )
        annotated, self.evidence_stats = (assessment.findings, assessment.evidence_stats)
        self.completion_objections = assessment.objections
        if self.completion_objections:
            self.telemetry.flag(FrictionFlag.PREMATURE_COMPLETION)
            # El rechazo por trabajo en vuelo no gasta otro turno de modelo: el
            # bucle espera y entrega el resultado antes de reconstruir el prompt.
            if self.task_manager.running_count():
                self.idle_background_wait = True
        if self.completion_objections and self.premature_rejections < MAX_PREMATURE_COMPLETIONS:
            self.premature_rejections += 1
            self.actions.append(
                _action_entry(
                    self.iteration,
                    self.action.action,
                    thought=self.action.thought,
                    warnings=self.action.warnings,
                    summary=self.action.summary or "",
                    findings=annotated,
                    rejected=True,
                    objections=list(self.completion_objections),
                )
            )
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                PREMATURE_COMPLETION_EVENT_TYPE,
                {
                    "iteration": self.iteration,
                    "phase": self.plan.current,
                    "attempt": self.premature_rejections,
                    "objections": list(self.completion_objections),
                    "evidence": self.evidence_stats,
                    # WP2 (Fix 3): the exact finding and the reference that would
                    # satisfy it, not just a count of stale citations.
                    "missing_evidence": missing_evidence(self.evidence_stats),
                    "subagent_id": self.active_subagent_id,
                },
            )
            memory.append_step(
                self.store,
                self.tenant_id,
                self.conversation_id,
                "user",
                _premature_completion_message(self.completion_objections, self.plan),
                {
                    "kind": "react.correction",
                    "iteration": self.iteration,
                    "rejected_action": ACTION_TASK_COMPLETE,
                    "run_id": self.run_id,
                },
            )
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                reason="premature_task_complete",
                attempt=self.premature_rejections,
                objections=list(self.completion_objections),
                evidence=self.evidence_stats,
            )
            return Transition.NEXT_TURN
        if self.completion_objections:
            self.status = STATUS_PREMATURE_COMPLETION
            self.final_summary = (
                f"task_complete rechazado {self.premature_rejections} veces sin evidencia suficiente: "
                + "; ".join(self.completion_objections)
            )
            self.findings = annotated
            self.actions.append(
                _action_entry(
                    self.iteration,
                    self.action.action,
                    thought=self.action.thought,
                    warnings=self.action.warnings,
                    summary=self.action.summary or "",
                    findings=annotated,
                    rejected=True,
                    objections=list(self.completion_objections),
                )
            )
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                reason="premature_completion_exhausted",
                objections=list(self.completion_objections),
                evidence=self.evidence_stats,
            )
            return Transition.STOP
        self.status = STATUS_COMPLETED
        self.final_summary = self.action.summary or ""
        self.findings = annotated
        self.actions.append(
            _action_entry(
                self.iteration,
                self.action.action,
                thought=self.action.thought,
                warnings=self.action.warnings,
                summary=self.final_summary,
                findings=self.findings,
                evidence=self.evidence_stats,
            )
        )
        memory.append_step(
            self.store,
            self.tenant_id,
            self.conversation_id,
            "assistant",
            json.dumps(
                {"summary": self.final_summary, "findings": self.findings}, ensure_ascii=False
            ),
            {
                "kind": "react.final",
                "iteration": self.iteration,
                "findings_count": len(self.findings),
                "evidence": self.evidence_stats,
                "run_id": self.run_id,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="allow",
            thought=self.action.thought,
            findings_count=len(self.findings),
            evidence=self.evidence_stats,
        )
        return Transition.STOP

    def _clarify(self) -> Transition:
        """Pause for the operator without throwing away what the run proved.

        Measured in Blue (2026-10-31): the run stopped as ``clarification`` with
        ``findings: []`` although the board held a verified host and 13 verified
        services, and the record never said the model had *declined* to go on.
        The status stays ``clarification`` (an operator answer is still what
        unblocks the engagement); the summary, the findings and -when the model's
        own words are a refusal- ``termination_reason`` now say which of the two
        things stopped the run and what is still owed.
        """
        self.status = STATUS_CLARIFICATION
        self.question = self.action.question
        text = f"{getattr(self.action, 'thought', '') or ''}\n{self.question or ''}"
        refusal = _refusal_kind(text)
        # The evidence outlives the pause: a stop that is not ``task_complete``
        # must not publish an empty finding list over a full board.
        self.findings = self._preserved_findings()
        self.final_summary = self._clarification_summary(refusal)
        if refusal:
            self.termination_reason = TERMINATION_PROVIDER_REFUSAL
        self.actions.append(
            _action_entry(
                self.iteration,
                self.action.action,
                thought=self.action.thought,
                warnings=self.action.warnings,
                question=self.question,
            )
        )
        memory.append_step(
            self.store,
            self.tenant_id,
            self.conversation_id,
            "assistant",
            self.question or "",
            {"kind": "react.clarification", "iteration": self.iteration, "run_id": self.run_id},
        )
        if refusal:
            # An explicit, separate record: the provider/model declined. It is
            # neither an Omni defect, nor a tool failure, nor "no progress".
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                PROVIDER_REFUSAL_EVENT_TYPE,
                {
                    "iteration": self.iteration,
                    "refusal": refusal,
                    "question": self.question,
                    "findings_count": len(self.findings),
                    "open_work": self._open_branch_labels(),
                    "report": self.report_artifact or {"generated": False},
                    "note": (
                        "El modelo/proveedor declinó continuar: no es un fallo de "
                        "Omni, de una herramienta ni falta de progreso. Los "
                        "hallazgos no intrusivos ya verificados se conservan en "
                        "el tablero y en run.complete.findings."
                    ),
                },
            )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.clarification_requested",
            {
                "question": self.question,
                "refusal": refusal or None,
                "findings_count": len(self.findings),
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="allow",
            thought=self.action.thought,
            refusal=refusal or None,
            findings_count=len(self.findings),
        )
        return Transition.STOP

    def _open_branch_labels(self, limit: int = 4) -> str:
        """Labels of the surfaces the ledger still holds open (never raises)."""
        coverage = getattr(getattr(self, "snapshot", None), "coverage", None)
        open_work = list(getattr(coverage, "open_work", []) or [])
        labels = [str(getattr(entry, "label", "") or "") for entry in open_work[:limit]]
        return "; ".join(label for label in labels if label)

    def _clarification_summary(self, refusal: str = "") -> str:
        """What stopped the run, what was preserved and what is still owed."""
        preserved = len(self.findings)
        pending = self._open_branch_labels() or "ninguna identificada"
        head = (
            "Negativa del modelo/proveedor a continuar el engagement (no es un "
            "fallo de Omni, de una herramienta ni falta de progreso)"
            if refusal
            else "Pausa para aclaración del operador"
        )
        return (
            f"{head}: {preserved} hallazgo(s) no intrusivo(s) conservado(s); "
            f"ramas pendientes: {pending}; {self._report_status_line()}."
        )

    def _preserved_findings(self, limit: int = 25) -> list[dict[str, Any]]:
        """Verified board facts as findings for a stop that is not a closure.

        Only what the verifier proved is listed, each with its own invocation and
        method; nothing is promoted and no severity is invented beyond ``info``.
        A board that cannot be read yields ``[]`` (the stop must never raise).
        """
        findings: list[dict[str, Any]] = []
        for fact in self._blackboard_facts():
            if not isinstance(fact, dict) or not fact.get("verified"):
                continue
            fact_type = str(fact.get("fact_type") or "")
            key = str(fact.get("key") or "")
            if not fact_type or not key:
                continue
            findings.append(
                {
                    "severity": "info",
                    "title": f"{fact_type}: {key}",
                    "fact_type": fact_type,
                    "target": str(fact.get("target") or key),
                    "invocation_id": str(fact.get("invocation_id") or ""),
                    "verification_method": str(fact.get("verification_method") or ""),
                    "value": fact.get("value") if isinstance(fact.get("value"), dict) else {},
                    "evidence": "hecho verificado en el tablero durante el run",
                }
            )
            if len(findings) >= limit:
                break
        return findings

    def _tool_entry(self) -> Transition:
        self.entry = _action_entry(
            self.iteration,
            self.action.action,
            thought=self.action.thought,
            tool_id=self.action.tool_id,
            arguments=memory._redact_arguments(self.action.arguments),
            warnings=self.action.warnings,
            expected_outcome=self.action.expected_outcome,
            # Canonical identity of this call, computed from the raw arguments: it
            # is what lets the next turn recognise an identical repeat (V1-26)
            # without comparing redacted copies of the persisted entry.
            invocation_signature=_invocation_signature(
                self.action.tool_id, self.action.arguments
            ),
        )
        return Transition.READY

    def _call_refusal(self, spec: Any) -> tuple[str, dict[str, Any]] | None:
        """Why this call may not reach the gateway, or ``None`` when it may.

        One predicate for both shapes of a turn: a call inside a parallel batch is
        refused by exactly the same rules as a lone one -catalog membership, the
        active subagent's subset, PLAN-FIRST and a retired tool- so ``tool_calls``
        can never widen what the model is allowed to invoke. The caller owns the
        bookkeeping; this only decides and builds the observation.
        """
        tool_id = str(getattr(spec, "tool_id", "") or "")
        if tool_id not in self.catalog:
            return "unknown_tool", {
                "success": False,
                "error": f"tool '{tool_id}' does not exist in the catalog",
                "available_tools": sorted(self.catalog),
            }
        if self.wrap_up and tool_id not in WRAP_UP_TOOLS:
            # The deadline is not a suggestion: outside the wrap-up set the call
            # is refused before policy/approval, exactly like an out-of-catalog
            # tool. It is a closure order, not a tool failure (no retirement).
            return "time_budget_wrap_up", {
                "success": False,
                "status": "denied_time_budget",
                "tool_id": tool_id,
                "error": (
                    "el presupuesto de tiempo está en la ventana de cierre: solo "
                    "se admite nexus.report.generate y "
                    "nexus.orchestrator.update_plan; termina con task_complete"
                ),
                "available_tools": sorted(
                    tool_id for tool_id in WRAP_UP_TOOLS if tool_id in self.catalog
                ),
            }
        if not self.wrap_up and not permits(self.subagent, tool_id, self.catalog.get(tool_id)):
            return "subagent_tool_denied", {
                "success": False,
                "error": f"tool '{tool_id}' is outside subagent '{self.subagent.id}' subset",
                "subagent_id": self.subagent.id,
                "available_tools": sorted(self.allowed_catalog),
            }
        if self._plan_required_missing() and _touches_target(self.catalog.get(tool_id)):
            # PLAN-FIRST: an engagement does not start by attacking. The engine
            # refuses the call (it is not counted as a tool failure: it is an
            # ordering rule) and tells the model exactly what unblocks it.
            from nexus_core.tools.handlers.plan_engagement import CREATE_PLAN_TOOL

            return "plan_required", {
                "success": False,
                "status": "denied_no_plan",
                "tool_id": tool_id,
                "error": (
                    "hay que fijar el PLAN DEL ENGAGEMENT antes de atacar: "
                    f"llama a {CREATE_PLAN_TOOL} con los TODOs del objetivo "
                    "(id, description, fact_types). Mientras no exista el plan, "
                    "el motor solo admite lectura de contexto (query_facts, "
                    "workspace.read) y las tools nexus.orchestrator.*."
                ),
                "next": CREATE_PLAN_TOOL,
            }
        # FIX 1: the vector of this exact call is dead. It is refused before
        # policy, approval and the gateway -it is a behavioural brake, not a
        # governance decision- and only asks the model to change tool or branch.
        locked = self._vector_lock_refusal(spec)
        if locked is not None:
            return "vector_locked", locked
        if tool_id in self.unavailable_tools:
            return "tool_unavailable", {
                "success": False,
                "tool_id": tool_id,
                "error": f"tool '{tool_id}' is unavailable after repeated failures; use another tool from the available list",
                "subagent_id": self.subagent.id,
                "available_tools": sorted(self.allowed_catalog),
            }
        return None

    def _check_tool(self) -> Transition:
        refusal = self._call_refusal(self.action)
        if refusal is not None and refusal[0] == "unknown_tool":
            self.observation = refusal[1]
            self.consecutive_failures += 1
            self.entry["tool_result"] = self.observation
            self.actions.append(self.entry)
            _inject_observation(
                self.store,
                self.tenant_id,
                self.conversation_id,
                self.run_id,
                self.iteration,
                self.action,
                self.observation,
                subagent_id=self.active_subagent_id,
            )
            self.telemetry.note_tool(duration_ms=0, success=False, error_type="ValueError")
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                tool_id=self.action.tool_id,
                reason="unknown_tool",
            )
            if not _keep_going_after_failures(
                self.subagent,
                self.unavailable_tools,
                self.consecutive_failures,
                self.catalog,
            ):
                self.status = STATUS_FAILED
                self.final_summary = f"aborted after {self.consecutive_failures} consecutive tool failures (last: unknown tool '{self.action.tool_id}'; no usable tools remain for subagent '{self.subagent.id}')"
                return Transition.STOP
            self.consecutive_failures = 0
            return Transition.NEXT_TURN
        if refusal is not None and refusal[0] == "subagent_tool_denied":
            self.observation = refusal[1]
            self.consecutive_failures += 1
            self.entry["tool_result"] = self.observation
            self.actions.append(self.entry)
            _inject_observation(
                self.store,
                self.tenant_id,
                self.conversation_id,
                self.run_id,
                self.iteration,
                self.action,
                self.observation,
                subagent_id=self.active_subagent_id,
            )
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                tool_id=self.action.tool_id,
                reason="subagent_tool_denied",
            )
            if not _keep_going_after_failures(
                self.subagent,
                self.unavailable_tools,
                self.consecutive_failures,
                self.catalog,
            ):
                self.status = STATUS_FAILED
                self.final_summary = f"aborted after {self.consecutive_failures} consecutive tool failures (last: '{self.action.tool_id}' outside subagent '{self.subagent.id}'; no usable tools remain)"
                return Transition.STOP
            self.consecutive_failures = 0
            return Transition.NEXT_TURN
        if refusal is not None and refusal[0] == "plan_required":
            self.observation = refusal[1]
            self.entry["tool_result"] = self.observation
            self.actions.append(self.entry)
            _inject_observation(
                self.store,
                self.tenant_id,
                self.conversation_id,
                self.run_id,
                self.iteration,
                self.action,
                self.observation,
                subagent_id=self.active_subagent_id,
            )
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "orchestrator.plan_required",
                {
                    "iteration": self.iteration,
                    "tool_id": self.action.tool_id,
                    "subagent_id": self.active_subagent_id,
                },
            )
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                tool_id=self.action.tool_id,
                reason="plan_required",
            )
            return Transition.NEXT_TURN
        if refusal is not None and refusal[0] == "time_budget_wrap_up":
            # The wrap-up window is a closure order, not a broken tool: record the
            # correction, tell the model what it may still call and spend no
            # failure budget on it.
            self.observation = refusal[1]
            self.entry["tool_result"] = self.observation
            self.actions.append(self.entry)
            _inject_observation(
                self.store,
                self.tenant_id,
                self.conversation_id,
                self.run_id,
                self.iteration,
                self.action,
                self.observation,
                subagent_id=self.active_subagent_id,
            )
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                tool_id=self.action.tool_id,
                reason="time_budget_wrap_up",
            )
            return Transition.NEXT_TURN
        if refusal is not None and refusal[0] == "vector_locked":
            self.observation = refusal[1]
            self.entry["tool_result"] = self.observation
            self.actions.append(self.entry)
            _inject_observation(
                self.store,
                self.tenant_id,
                self.conversation_id,
                self.run_id,
                self.iteration,
                self.action,
                self.observation,
                subagent_id=self.active_subagent_id,
            )
            self.telemetry.flag(FrictionFlag.REPEATED_ACTION)
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                VECTOR_LOCKED_EVENT_TYPE,
                {
                    "iteration": self.iteration,
                    "tool_id": self.observation.get("tool_id"),
                    "subcommand": self.observation.get("subcommand", ""),
                    "target": self.observation.get("target"),
                    "fail_count": self.observation.get("failures"),
                    "refused": True,
                },
            )
            # A refusal is not a tool failure: it never moves
            # ``consecutive_failures`` nor retires the tool, because the vector
            # (not the tool) is what the loop closed.
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                tool_id=self.action.tool_id,
                reason="vector_locked",
                target=self.observation.get("target"),
            )
            return Transition.NEXT_TURN
        if refusal is not None and refusal[0] == "tool_unavailable":
            self.observation = refusal[1]
            self.entry["tool_result"] = self.observation
            self.actions.append(self.entry)
            _inject_observation(
                self.store,
                self.tenant_id,
                self.conversation_id,
                self.run_id,
                self.iteration,
                self.action,
                self.observation,
                subagent_id=self.active_subagent_id,
            )
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                tool_id=self.action.tool_id,
                reason="tool_unavailable",
            )
            return Transition.NEXT_TURN
        return Transition.READY

    def _call_payload(self, spec: Any) -> dict[str, Any]:
        """The engine data one gateway invocation carries (never the model's word)."""
        from nexus_core.kernel.job_authority import JobAuthority

        payload = {
            "tool_id": str(spec.tool_id),
            "arguments": dict(spec.arguments or {}),
            "identity": self.payload.get("identity") or {},
            "engagement_id": self.engagement_id,
            "permissions": tuple(self.payload.get("permissions") or ()),
            "approval_id": self.payload.get("approval_id"),
            "trace_id": self.run_id,
            "session_id": self.conversation_id,
            "phase": getattr(self.plan, "current", "") or "",
            "objective": self.objective,
            # The operator's workspace, so a handler writes/reads the same
            # directory as the engine (the plan file, the loot, the wordlists).
            "project_root": str(self.payload.get("project_root") or ""),
            # V1-54: how a retry of an ``unknown`` invocation is resolved. The
            # engine set it from ``--resume-policy`` (only under trust mode).
            "resume_policy": str(getattr(self.config, "resume_policy", "") or ""),
        }
        payload["job_authority"] = JobAuthority(
            run_id=self.run_id, engagement_id=self.engagement_id or "", profile_id=self.subagent.id,
            tools=tuple(sorted(self.subagent.tools)),
            token_budget=self.subagent.token_budget,
            run_token_budget=max(0, self.budget),
            job_limit=max(0, self.subagent.max_iterations - self.subagent_iterations),
        ).model_dump(mode="json")
        return payload

    def _review_call(self, spec: Any, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Policy + operator approval for one call; a denial observation or ``None``.

        Runs the very same :class:`ApprovalCoordinator` the single-call path uses,
        once per call: a batch of three tools asks three questions, never one
        blanket approval for all of them.
        """
        if self.config.on_approval_needed is None:
            return None
        resolved = self.catalog[str(spec.tool_id)]
        definition = resolved[0] if isinstance(resolved, tuple) else resolved
        return self.approval_coordinator.review(
            config=self.config,
            context=self.context,
            definition=definition,
            tool_payload=payload,
        )

    def _approve_tool(self) -> Transition:
        assert isinstance(self.action, ToolCall)
        self.tool_payload = self._call_payload(self.action)
        if self.config.on_approval_needed is not None:
            denial = self._review_call(self.action, self.tool_payload)
            if denial is not None:
                self.entry["tool_result"] = denial
                self.actions.append(self.entry)
                _inject_observation(
                    self.store,
                    self.tenant_id,
                    self.conversation_id,
                    self.run_id,
                    self.iteration,
                    self.action,
                    denial,
                    subagent_id=self.active_subagent_id,
                )
                self.telemetry.flag(FrictionFlag.OPERATOR_DENIAL)
                self.audit_step(
                    iteration=self.iteration,
                    action=self.action.action,
                    decision="deny",
                    tool_id=self.action.tool_id,
                    reason="denied_by_operator",
                    operator_reason=denial["reason"],
                )
                return Transition.NEXT_TURN
        return Transition.READY

    def _repeated_failed_action(self) -> str | None:
        """Tool id when this turn repeats, adjacently, an action that just failed (V1-26).

        Measured in the rerun #7 (2026-10-15): iteration 9 spent ``msf_exploit``
        (``method=msf_exploit_failed``) and iteration 10 proposed the byte-identical
        invocation. The gateway keeps a failed invocation journaled as ``unknown``
        -its effect may have happened- so the repeat demanded a human approval the
        ``--trust-mode`` run does not hold: ``termination_reason="blocked"`` with the
        ``exploit`` profile 10 iterations and ~17k tokens short of its budget. In the
        rerun #6 the same failure produced a correction instead, and the model
        pivoted to ``psexec``, which opened the session.

        The trigger is the measured one, and only that: same ``tool_id``, same
        canonical arguments, and the *immediately preceding* turn. A repeat somewhere
        else in the history, or a repeat of something that worked, is a different
        case (the latter belongs to the gateway's dedup, V1-14) and keeps its own
        governance.
        """
        previous = self.actions[-1] if self.actions else None
        if not previous or not isinstance(self.action, ToolCall):
            return None
        signature = previous.get("invocation_signature")
        if not signature:
            return None
        result = previous.get("tool_result")
        if not isinstance(result, dict) or result.get("success"):
            return None
        if signature != _invocation_signature(self.action.tool_id, self.action.arguments):
            return None
        return str(self.action.tool_id)

    def _note_scope_denial(self, target: str) -> int:
        """Count one refusal of *target* and return the current insistence streak.

        A different target starts a new streak; the streak is reset by any tool
        call that is not a scope denial (``_execute_tool`` does it on the result
        path), so only *consecutive* insistence on the same target can close.
        """
        if target and target == self.scope_denial_target:
            self.scope_denial_streak += 1
        else:
            self.scope_denial_target = target or None
            self.scope_denial_streak = 1
        return self.scope_denial_streak

    def _repeat_scope_denial(self, tool_id: str, previous: dict[str, Any]) -> Transition:
        """Count a byte-identical repeat of an already-denied target (V1-26).

        The repeat never reaches the gateway -the invocation journal would ask
        for an approval a trust-mode run cannot grant- so without this branch the
        insistence would be answered as a generic ``repeated_action`` and the
        scope streak would never grow. It counts as one more refusal of the same
        target: two corrections, the third closes the run.
        """
        target = str(previous.get("target") or "").strip()
        streak = self._note_scope_denial(target)
        aborted = streak >= MAX_CONSECUTIVE_SCOPE_DENIALS
        named = target or "el objetivo solicitado"
        self.telemetry.flag(FrictionFlag.SCOPE_VIOLATION)
        self.observation = {
            "success": False,
            "outcome": "scope_denied",
            "verified": False,
            "scope_violation": True,
            "target": target,
            "scope_denial_streak": streak,
            "repeated_action": True,
            "guidance": (
                f"El objetivo {named} está fuera del alcance firmado. "
                "Ignora esa URL y busca otra ruta."
            ),
            "available_tools": sorted(self.allowed_catalog),
        }
        if aborted:
            self.status = STATUS_SCOPE_VIOLATION
            self.final_summary = (
                "scope violation aborted the loop: the model insisted "
                f"{streak} times on {named}"
            )
            self.observation["aborted"] = True
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.scope_violation",
            {
                "iteration": self.iteration,
                "tool_id": tool_id,
                "target": target,
                "streak": streak,
                "aborted": aborted,
                "repeated": True,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=tool_id,
            reason="scope_violation",
            error_type="ScopeViolation",
        )
        return Transition.STOP if aborted else Transition.NEXT_TURN

    def _correct_repeated_action(self, tool_id: str, *, barren: bool = False) -> Transition:
        """Answer an identical repeat of a failed or fact-free action with a correction.

        ``barren=True`` is the slow-but-successful variant: the previous call did
        not fail, it simply returned nothing new after burning seconds of the
        run's wall clock (see ``_repeated_barren_action``).

        The turn is a normal turn of the loop -it consumes the iteration and the
        tokens of the active subagent- and it never reaches the gateway. The policy
        gate of the turn (``_approve_tool``) already ran; what is avoided here is the
        journal's ``retry:invocation:<id>`` approval for an unknown outcome, which a
        ``--trust-mode`` run cannot grant and which closed the rerun #7 as
        ``blocked``. So no approval is requested or consumed and the run continues:
        the model gets text telling it what to do next, never a silent refusal.
        """
        previous_result = self.actions[-1].get("tool_result") if self.actions else None
        if isinstance(previous_result, dict) and previous_result.get("outcome") == "scope_denied":
            return self._repeat_scope_denial(tool_id, previous_result)
        self.telemetry.flag(FrictionFlag.REPEATED_ACTION)
        correction = (
            barren_repeat_correction(tool_id, max(1, self.last_tool_elapsed_ms // 1000))
            if barren
            else repeated_action_correction(tool_id)
        )
        self.observation = {
            "success": False,
            "outcome": "repeated_action",
            "tool_id": tool_id,
            "error": correction,
            "failure_kind": "repeated_action",
            "guidance": correction,
            "available_tools": sorted(self.allowed_catalog),
        }
        # The repeat counts as a tool failure (B3): a model that keeps insisting on a
        # route that produced nothing ends up with the tool retired after repeated
        # attempts -exactly as if it had failed again- so the next prompt only offers
        # the remaining routes. Without this, insisting could burn the whole profile
        # budget one correction at a time without ever retiring anything. It is the
        # per-tool counter that moves, never the run-level ``consecutive_failures``:
        # a correction must not be able to abort an engagement.
        self._note_tool_failure(tool_id, cause="refusal")
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=tool_id,
            reason="repeated_barren_action" if barren else "repeated_failed_action",
        )
        return Transition.NEXT_TURN

    def _repeated_barren_action(self) -> str | None:
        """Tool id when this turn repeats, adjacently, a slow call that learned nothing.

        The V1-26 guard above only intercepts a repeat of a *failed* call; the
        gateway's dedup (V1-14) lets a repeat of a successful one through. Neither
        helps the measured failure of 2026-10-19
        (``run_1052d63f9bba4838902b3aa21bd27d21``): the agent ran the same sqlmap
        probe twice, 500 s each, with ``blackboard_delta = 0`` both times, while
        the coverage ledger still had two open branches, and burned its budget
        without a finding.

        The trigger is deliberately narrow: same ``tool_id``, same canonical
        arguments, the *immediately preceding* turn, that call succeeded, the run
        has not seen a new verified fact since, and it took at least
        ``BARREN_REPEAT_MIN_SECONDS``. Fast idempotent repeats keep their existing
        governance (dedup), and a first retry after a fact-producing turn is
        untouched.
        """
        previous = self.actions[-1] if self.actions else None
        if not previous or not isinstance(self.action, ToolCall):
            return None
        if self.consecutive_no_progress <= 0:
            return None
        current = _invocation_signature(self.action.tool_id, self.action.arguments)
        result = previous.get("tool_result")
        if isinstance(result, dict) and result.get("outcome") == "scope_denied":
            # A denied target never ran, so it produced no work to repeat: that
            # case belongs to the scope-insistence streak, which only counts the
            # same target consecutively (alternating two denied hosts is a
            # first-and-first, not an insistence).
            return None
        if (
            previous.get("invocation_signature") == current
            and isinstance(result, dict)
            and result.get("success")
            and self.last_tool_elapsed_ms >= BARREN_REPEAT_MIN_SECONDS * 1000
        ):
            return str(self.action.tool_id)
        # The light path: a *fast* call is not automatically harmless. The
        # gateway dedup this docstring used to defer to is keyed on the
        # invocation id, so every turn is a fresh invocation and an identical
        # cheap probe is never deduplicated. Measured in
        # run_c71035d9818047eaa80dfd859e887b7c (Joomla, 2026-10-20): the same
        # 0.3 s SQLi URL three times and the same ``hashcat`` sweep four times,
        # across 49 barren turns and 0 findings. From
        # ``FAST_REPEAT_MIN_NO_PROGRESS`` barren turns, a signature that already
        # ran inside the recent window gets the same correction the slow one
        # gets: after three turns with nothing new, re-sending the same request
        # is the loop, not a retry. A signature that is not in the window and any
        # turn that added a verified fact are untouched.
        if (
            self.consecutive_no_progress >= FAST_REPEAT_MIN_NO_PROGRESS
            and self._signature_occurrences(current) >= 1
        ):
            return str(self.action.tool_id)
        return None

    def _signature_occurrences(self, signature: str) -> int:
        """How many of the last :data:`FAST_REPEAT_WINDOW` actions used ``signature``.

        Wider than the immediately preceding turn because the measured loop
        alternated two probes (A, B, A, B) and so never repeated adjacently.
        Entries synthesised by a correction carry no signature and are skipped.
        """
        recent = self.actions[-FAST_REPEAT_WINDOW:]
        return sum(
            1 for entry in recent if entry.get("invocation_signature") == signature
        )

    def _coverage_snapshot(self) -> Any:
        """The ledger attached to this turn's snapshot (``None`` before recon)."""
        return getattr(getattr(self, "snapshot", None), "coverage", None)

    def _refuse_before_execution(
        self, *, outcome: str, guidance: str, extra: dict[str, Any] | None = None
    ) -> Transition:
        """Answer a deterministic refusal as an observation the model can use.

        Same shape as the pivot and replay gates: the call never reaches the
        gateway, the model gets the exact next step, and the refusal is audited
        and persisted as an event. It never aborts the run by itself; what stops
        a run is insisting on a *failed* call, which is the existing governance.
        """
        tool_id = str(self.action.tool_id)
        payload = dict(extra or {})
        self.observation = {
            "success": False,
            "outcome": outcome,
            "verified": False,
            "refused_before_execution": True,
            "tool_id": tool_id,
            "guidance": guidance,
            "available_tools": sorted(self.allowed_catalog),
            **payload,
        }
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.branch_refused",
            {
                "iteration": self.iteration,
                "tool_id": tool_id,
                "reason": outcome,
                **payload,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=tool_id,
            reason=outcome,
        )
        return Transition.READY

    def _refuse_closed_branch(self) -> Transition | None:
        """Refuse ``web.*``/directory sweeps against a branch the loop closed.

        ``react.branch_closed`` used to be descriptive: it wrote the barrier and
        the model kept attacking the same ``host:port`` (DeadDrop P12, iteration
        44, fifteen more turns). The window lives in
        :data:`branch_discipline.CLOSED_BRANCH_BLOCK_TURNS` and coverage still
        owns reopening through a newer ``vulnerability`` fact.
        """
        arguments = self.action.arguments if isinstance(self.action.arguments, dict) else None
        guidance = closed_branch_refusal(
            tool_id=self.action.tool_id,
            arguments=arguments,
            coverage=self._coverage_snapshot(),
            closed_at=getattr(self, "closed_branch_at", {}),
            iteration=self.iteration,
        )
        if not guidance:
            return None
        return self._refuse_before_execution(
            outcome="branch_closed_recent",
            guidance=guidance,
            extra={"branch_closed_recent": True},
        )

    def _plan_status_fingerprint(self) -> str:
        """Identity of the state a ``get_plan_status`` answer would describe.

        The tool reconciles the plan against the verified board and the surface
        ledger, so those three are what a new answer could change: the TODOs and
        their evidence, the newest stamp on the board, and the ledger's counts.
        Anything else (a different thought, a rephrased argument) is not state.
        """
        plan = getattr(self, "engagement_plan", None)
        facts = self._blackboard_facts()
        coverage = self._coverage_snapshot()
        stamps = [
            str(fact.get("recorded_at") or "")
            for fact in facts
            if isinstance(fact, dict)
        ]
        parts = {
            "todos": [
                (todo.id, todo.status, todo.verified_by)
                for todo in getattr(plan, "todos", ()) or ()
            ],
            "plan_updated_at": str(getattr(plan, "updated_at", "") or ""),
            "facts": len(facts),
            "fact_stamp": max(stamps) if stamps else "",
            "coverage": dict(getattr(coverage, "counts", {}) or {}),
        }
        return json.dumps(parts, sort_keys=True, default=str)

    def _refuse_unchanged_plan_status(self) -> Transition | None:
        """Refuse a ``get_plan_status`` whose answer cannot differ from the last one.

        The plan block travels in every system prompt and the tool reconciles the
        same board, so polling it while nothing moved buys a repeated checklist
        for a full turn -repeated until the budget ends, with every TODO still
        pending. The gate is state-based, never a blanket ban: as soon as a TODO
        is ticked, a fact lands or the ledger moves, the poll runs exactly as
        before (``_plan_status_fingerprint``).

        The refusal closes nothing: the pending TODOs stay pending and the
        correction names the one to work and the next open branch. Insisting is
        counted like any other failing call, so after three consecutive
        corrections the tool leaves the catalog while the plan keeps travelling
        in the prompt -no evidence is hidden by retiring a read-only echo.
        """
        if str(getattr(self.action, "tool_id", "") or "") != PLAN_STATUS_TOOL:
            return None
        fingerprint = self._plan_status_fingerprint()
        if fingerprint != getattr(self, "plan_status_fingerprint", ""):
            self.plan_status_fingerprint = fingerprint
            self.plan_status_polls = 0
            return None
        self.plan_status_polls = int(getattr(self, "plan_status_polls", 0)) + 1
        plan = getattr(self, "engagement_plan", None)
        pending = list(getattr(plan, "pending", ()) or ())
        following = pending[0] if pending else None
        coverage = self._coverage_snapshot()
        branch = coverage.first_open() if coverage is not None else None
        guidance = unchanged_plan_status_correction(
            todo_id=str(getattr(following, "id", "") or ""),
            todo_description=str(getattr(following, "description", "") or ""),
            next_branch=str(getattr(branch, "label", "") or ""),
        )
        transition = self._refuse_before_execution(
            outcome="plan_status_unchanged",
            guidance=guidance,
            extra={"plan_status_polls": self.plan_status_polls},
        )
        # The state cannot change by asking again, but a background task can
        # change it: yield to it here instead of spending the next turn on the
        # same checklist. The wait never cancels anything and never closes a
        # TODO; it only hands the finished result to the next model turn.
        if self.task_manager.running_count():
            self.idle_background_wait = True
        self._note_tool_failure(PLAN_STATUS_TOOL, cause="refusal")
        self.telemetry.flag(FrictionFlag.REPEATED_ACTION)
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            PLAN_STATUS_REPEATED_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "polls": self.plan_status_polls,
                "pending": [todo.id for todo in pending][:10],
                "next_branch": str(getattr(branch, "ref", "") or ""),
            },
        )
        return transition

    def _refuse_repeated_unknown_skill(self) -> Transition | None:
        """Refuse a second load of a skill name the catalogue already refused.

        The handler answers the first miss with the real catalogue; repeating the
        name is a loop that costs a model call per turn and was measured in the
        Bounty Hacker run (2026-10-30). The rule is pure and unit-tested in
        ``branch_discipline.unknown_skill_refusal``; here the catalogue is read
        once so the refusal can name it instead of only forbidding the call.
        """
        if str(getattr(self.action, "tool_id", "") or "") != SKILL_LOAD_TOOL:
            return None
        arguments = self.action.arguments if isinstance(self.action.arguments, dict) else None
        if not arguments:
            return None
        try:
            from nexus_core.agent.skills import default_skills_root, discover_skills

            known = sorted(discover_skills())
            catalogue = str(default_skills_root())
        except Exception:  # noqa: BLE001 - a catalogue read must never abort a turn
            known, catalogue = [], ""
        guidance = unknown_skill_refusal(
            self.actions, arguments, known=known, catalogue=catalogue
        )
        if guidance is None:
            return None
        return self._refuse_before_execution(
            outcome="unknown_skill",
            guidance=guidance,
            extra={
                "unknown_skill": str(arguments.get("name") or ""),
                "skill_catalogue": known,
                "skill_catalogue_root": catalogue,
            },
        )

    def _refuse_redundant_fact(self) -> Transition | None:
        """Refuse a ``record_fact`` of something the verifier already proved.

        Measured in hijack_v7 (2026-10-30, iterations 3-11): the ``nmap`` turn
        derived all ten facts (host + nine services) from the XML, and the model
        then spent nine turns writing each one back with
        ``nexus.knowledge.record_fact``. Every call succeeded, every turn added
        zero facts, and the loop read the sequence as a dead end until it closed
        the only web branch. The rule lives in ``branch_discipline`` (pure and
        unit-tested); here it only decides the turn.
        """
        if str(getattr(self.action, "tool_id", "")) != "nexus.knowledge.record_fact":
            return None
        arguments = self.action.arguments if isinstance(self.action.arguments, dict) else None
        if not arguments:
            return None
        coverage = self._coverage_snapshot()
        following = coverage.first_open() if coverage is not None else None
        guidance = redundant_fact_refusal(
            self._blackboard_facts(),
            arguments,
            next_branch=following.label if following is not None else "",
        )
        if guidance is None:
            return None
        return self._refuse_before_execution(
            outcome="redundant_fact",
            guidance=guidance,
            extra={
                "redundant_fact": True,
                "fact_type": str(arguments.get("fact_type") or ""),
                "key": str(arguments.get("key") or ""),
            },
        )

    def _refuse_barrier_without_attempts(self) -> Transition | None:
        """Refuse a ``barrier`` that one guess does not justify.

        Two measured false verdicts motivate it: an executed ``/preview`` module
        read as plain text (DeadDrop P12, iteration 21) and a sweep that never
        ran reported as "no session" (HackPark V12, iteration 17). The second is
        already handled by ``sweep_attempted`` in the ledger; this gate answers
        before the fact is written, so the branch is not even marked.
        """
        arguments = self.action.arguments if isinstance(self.action.arguments, dict) else None
        guidance = barrier_refusal(
            self.actions,
            self._coverage_snapshot(),
            arguments,
            no_progress=self.consecutive_no_progress,
        )
        # ``getattr``: a resumed run (and the unit tests) may hand the gate a
        # coordinator built without ``__init__``; the counter starts at zero.
        if not guidance:
            self.barrier_refusals = 0
            return None
        self.barrier_refusals = int(getattr(self, "barrier_refusals", 0)) + 1
        if arguments is not None and self.barrier_refusals >= BARRIER_INSISTENCE_LIMIT:
            # The model insists: record its verdict so it stops re-asking, but
            # stamp it as unsubstantiated. ``coverage.barrier_is_conclusive``
            # keeps the branch open for an ``invalid_*`` outcome, so this can
            # never be the false "descartado" the gate exists to prevent.
            value = arguments.get("value")
            if not isinstance(value, dict):
                value = {}
                arguments["value"] = value
            value["sweep_attempted"] = False
            value["outcome"] = "invalid_unsubstantiated"
            value.setdefault(
                "reason",
                "barrier registrado tras insistir: no llegó a "
                f"{BARRIER_MIN_DISTINCT_TOOLS} herramientas distintas en "
                f"{BARRIER_ATTEMPT_WINDOW} turnos, así que no cierra la rama",
            )
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.barrier_downgraded",
                {
                    "iteration": self.iteration,
                    "tool_id": str(self.action.tool_id),
                    "refusals": self.barrier_refusals,
                    "reason": (
                        f"{BARRIER_MIN_DISTINCT_TOOLS} distinct tools in "
                        f"{BARRIER_ATTEMPT_WINDOW} turns were not reached"
                    ),
                },
            )
            self.barrier_refusals = 0
            return None
        return self._refuse_before_execution(
            outcome="barrier_refused",
            guidance=guidance,
            extra={
                "barrier_refused": True,
                "attempt_window": BARRIER_ATTEMPT_WINDOW,
            },
        )

    async def _correct_unroutable_sweep(self) -> Transition | None:
        """Refuse a sweep that has no route, instead of paying its timeout.

        Measured in DeadDrop P10 (2026-10-22): with SSH on ``192.168.11.200`` and
        no tunnel, ``nmap`` against the DC ``192.168.11.100`` ran its whole 600 s
        budget and returned nothing -the order to pivot only arrived *after* it,
        because ``pivot_hint`` reads the history-. The same rule applied to the
        pending call, plus a one-second TCP probe, answers before the budget is
        committed. The refusal is an observation (the model gets the exact tunnel
        command); only insisting ``MAX_CONSECUTIVE_PIVOT_GATES`` times closes the
        run, and then as ``blocked`` on the tunnel, not as a failure.
        """
        tool_id = str(self.action.tool_id)
        target = pivot_target_host(tool_id, self.action.arguments)
        if not target:
            return None
        # The board, not the history, is what can turn the gate off: a verified
        # ``route`` fact is proof of reachability, and an attempted ``ssh -D`` is
        # not (DeadDrop P11 stayed gated on a tunnel that had already died).
        hint = await pivot_gate(
            tool_id,
            self.action.arguments,
            self.actions,
            facts=self._blackboard_facts(),
        )
        if not hint:
            return None
        self.pivot_gate_streak += 1
        aborted = self.pivot_gate_streak >= MAX_CONSECUTIVE_PIVOT_GATES
        self.observation = {
            "success": False,
            "outcome": "unroutable_target",
            "verified": False,
            "target": target,
            "tool_id": tool_id,
            "refused_before_execution": True,
            "pivot_gate_streak": self.pivot_gate_streak,
            "guidance": hint,
            "available_tools": sorted(self.allowed_catalog),
        }
        if aborted:
            self.status = STATUS_BLOCKED
            self.final_summary = (
                f"blocked on the pivot: {self.pivot_gate_streak} sweeps aimed at "
                f"{target} with no route from the operator and no tunnel opened"
            )
            self.observation["aborted"] = True
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.pivot_gate",
            {
                "iteration": self.iteration,
                "tool_id": tool_id,
                "target": target,
                "streak": self.pivot_gate_streak,
                "aborted": aborted,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=tool_id,
            reason="unroutable_target",
        )
        return Transition.STOP if aborted else Transition.READY

    def _correct_replayed_invocation(self, exc: Exception) -> Transition:
        """Answer a fenced replay with what to do instead of closing the run.

        Measured in DeadDrop P10 (2026-10-22, iteration 47): an ``ssh_exec``
        timed out, the journal kept it ``unknown`` and the model's identical
        retry met ``unknown invocation requires human approval``. The refusal is
        correct -the effect may have happened-, but it closed the run as
        ``blocked`` (exit 2) with the room still reachable: a refusal is an
        observation, exactly like a scope denial. The streak is what stops a
        model that keeps asking for the same replay.
        """
        self.replay_refusals += 1
        aborted = self.replay_refusals >= MAX_REPLAY_REFUSALS
        tool_id = str(self.action.tool_id)
        self.observation = {
            "success": False,
            "outcome": "replay_refused",
            "verified": False,
            "error_type": type(exc).__name__,
            "error": str(exc)[:500],
            "failure_kind": "replay_requires_approval",
            "replay_refusals": self.replay_refusals,
            "guidance": replay_guidance(tool_id),
            "available_tools": sorted(self.allowed_catalog),
        }
        if aborted:
            self.status = STATUS_BLOCKED
            self.final_summary = (
                f"blocked: {self.replay_refusals} replays of an invocation whose "
                f"effect is unconfirmed ({tool_id}) and no approval to replay them"
            )
            self.observation["aborted"] = True
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.replay_refused",
            {
                "iteration": self.iteration,
                "tool_id": tool_id,
                "streak": self.replay_refusals,
                "aborted": aborted,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=tool_id,
            reason="replay_requires_approval",
        )
        return Transition.STOP if aborted else Transition.READY

    # ------------------------------------------------------- parallel turns
    def _batch_entry(self, index: int, spec: ToolCallSpec, size: int) -> dict[str, Any]:
        """One action log entry per call, so the run stays audit-able per tool."""
        return _action_entry(
            self.iteration,
            "tool_call",
            thought=self.action.thought,
            tool_id=spec.tool_id,
            arguments=memory._redact_arguments(spec.arguments),
            warnings=self.action.warnings,
            expected_outcome=spec.expected_outcome,
            invocation_signature=_invocation_signature(spec.tool_id, spec.arguments),
            batch_index=index,
            batch_size=size,
        )

    def _record_batch_denial(
        self, spec: ToolCallSpec, entry: dict[str, Any], reason: str, observation: dict[str, Any]
    ) -> dict[str, Any]:
        """A call that never reached the gateway: refusal is local to that call."""
        entry["tool_result"] = observation
        self.actions.append(entry)
        if reason in {"unknown_tool", "subagent_tool_denied"}:
            self.consecutive_failures += 1
        if reason == "plan_required":
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "orchestrator.plan_required",
                {
                    "iteration": self.iteration,
                    "tool_id": spec.tool_id,
                    "subagent_id": self.active_subagent_id,
                    "batch": True,
                },
            )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=spec.tool_id,
            reason=reason,
            batch=True,
            **({"operator_reason": observation["reason"]} if "reason" in observation else {}),
        )
        detail = observation.get("error") or observation.get("reason") or reason
        return {
            "tool_id": spec.tool_id,
            "arguments": memory._redact_arguments(spec.arguments),
            "success": False,
            "outcome": "denied",
            "reason": reason,
            "error": str(detail)[:800],
            "guidance": str(observation.get("guidance") or detail)[:800],
            **({"next": observation["next"]} if observation.get("next") else {}),
        }

    def _account_call(self, spec: ToolCallSpec, execution: CallExecution) -> dict[str, Any]:
        """Turn one execution into its ``results`` entry, updating the run's counters.

        Same rules as the single-call path, applied in batch order: a success
        clears the failure streaks, ``command_failed`` is about the command (not
        the tool), ``timeout``/``unavailable`` retire the tool after repeated
        attempts, and a ``scope_denied`` target extends the insistence streak -so
        three denials of the same host still close the run, even spread across
        parallel calls.
        """
        result: dict[str, Any] = {
            "tool_id": spec.tool_id,
            "arguments": memory._redact_arguments(spec.arguments),
            "duration_ms": int(round(execution.duration_ms)),
        }
        if execution.cancelled:
            result.update(success=False, outcome="cancelled", error="cancelación solicitada")
            return result
        error = execution.error
        if error is not None:
            return self._account_call_error(spec, error, result)
        observation = _observation_payload(execution.invocation or {})
        self.observation = observation
        self._note_observed_flags(spec)
        self._note_report_artifact(spec)
        success = bool(observation.get("success"))
        outcome = str(observation.get("outcome") or "")
        result.update(
            success=success,
            outcome=outcome,
            verification_method=observation.get("verification_method"),
            invocation_id=observation.get("invocation_id"),
            evidence=observation.get("evidence"),
            assertions=list(observation.get("assertions") or []),
            output=observation.get("output"),
            error=observation.get("error"),
        )
        self.telemetry.note_tool(
            duration_ms=result["duration_ms"], success=success, outcome=outcome
        )
        if success:
            self.scope_denial_target = None
            self.scope_denial_streak = 0
            self.consecutive_failures = 0
            self.tool_failures.clear()
            self.run_evidence.extend(result["assertions"])
            del self.run_evidence[:-RUN_EVIDENCE_MAX_OBSERVATIONS]
            self._account_vector(spec.tool_id, spec.arguments, observation)
            return result
        if outcome == "scope_denied":
            handler_output = observation.get("output")
            if not isinstance(handler_output, dict):
                handler_output = {}
            target = str(
                observation.get("target") or handler_output.get("target") or ""
            ).strip()
            if handler_output.get("error") and not result.get("error"):
                result["error"] = handler_output["error"]
            if handler_output.get("guidance"):
                result["guidance"] = handler_output["guidance"]
            streak = self._note_scope_denial(target)
            result["scope_denial_streak"] = streak
            self.telemetry.flag(FrictionFlag.SCOPE_VIOLATION)
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.scope_violation",
                {
                    "iteration": self.iteration,
                    "tool_id": spec.tool_id,
                    "error": str(result.get("error") or "")[:500],
                    "target": target,
                    "streak": streak,
                    "aborted": streak >= MAX_CONSECUTIVE_SCOPE_DENIALS,
                    "batch": True,
                },
            )
        else:
            self.scope_denial_target = None
            self.scope_denial_streak = 0
        if outcome in DETERMINATE_NON_FAILURE_OUTCOMES or outcome == "command_failed":
            # A determinate answer (including "no") proves the tool works: it
            # neither retires the tool nor extends the failure streak.
            self.consecutive_failures = 0
            self.tool_failures.clear()
        else:
            self.consecutive_failures += 1
        if outcome in {"unavailable", "timeout"}:
            self.observation = result
            self._note_tool_failure(spec.tool_id)
            if outcome == "timeout":
                result["guidance"] = timeout_guidance(spec.tool_id)
            else:
                reason = observation.get("failure_kind") or "backend unavailable"
                evidence = observation.get("evidence")
                if isinstance(evidence, dict):
                    reason = str(
                        evidence.get("cause_code")
                        or evidence.get("detail")
                        or evidence.get("provider")
                        or reason
                    )
                result["guidance"] = unavailable_guidance(spec.tool_id, reason)
        elif outcome == "command_failed":
            result["guidance"] = command_failed_guidance(spec.tool_id)
        self._account_vector(spec.tool_id, spec.arguments, observation)
        return result

    def _account_call_error(
        self, spec: ToolCallSpec, error: BaseException, result: dict[str, Any]
    ) -> dict[str, Any]:
        """A call that raised: the batch keeps the others, the run learns why."""
        self.telemetry.note_tool(
            duration_ms=result.get("duration_ms", 0),
            success=False,
            error_type=type(error).__name__,
        )
        if isinstance(error, TimeoutError):
            self._note_tool_failure(spec.tool_id)
            result.update(
                success=False,
                outcome="timeout",
                error=(str(error) or "la llamada excedió su presupuesto de tiempo")[:1000],
                guidance=timeout_guidance(spec.tool_id),
            )
            self.consecutive_failures += 1
        elif isinstance(error, ScopeViolation):
            self.telemetry.flag(FrictionFlag.SCOPE_VIOLATION)
            target = str(getattr(error, "target", "") or "").strip()
            streak = self._note_scope_denial(target)
            result.update(
                success=False,
                outcome="scope_denied",
                error=str(error)[:500],
                target=target,
                scope_denial_streak=streak,
                guidance=(
                    f"El objetivo {target or 'solicitado'} está fuera del alcance "
                    "firmado. Ignora esa ruta y busca otra."
                ),
            )
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.scope_violation",
                {
                    "iteration": self.iteration,
                    "tool_id": spec.tool_id,
                    "error": str(error)[:500],
                    "target": target,
                    "streak": streak,
                    "aborted": streak >= MAX_CONSECUTIVE_SCOPE_DENIALS,
                    "batch": True,
                },
            )
        elif isinstance(error, ReplayApprovalRequired):
            result.update(
                success=False,
                outcome="replay_approval_required",
                error=str(error)[:500],
            )
            self.consecutive_failures += 1
        elif isinstance(error, ApprovalRequired):
            # Never local: without the approval the run cannot continue, exactly
            # as on the single-call path.
            result.update(
                success=False,
                outcome="approval_required",
                error=str(error)[:500],
                guidance=(
                    "La llamada necesita aprobación humana y no la tiene: el run "
                    "se detiene para que la concedas."
                ),
            )
            self.consecutive_failures += 1
        elif isinstance(error, PermissionError):
            # Another call of the same batch being authorized says nothing about
            # this one: the denial is this call's, and the batch reports it.
            result.update(
                success=False,
                outcome="governance_denial",
                error=str(error)[:500],
                guidance="La política denegó esta llamada; las demás ya pasaron la suya.",
            )
            self.consecutive_failures += 1
        else:
            kind = _failure_kind(error)
            result.update(
                success=False,
                outcome="error",
                error=str(error)[:1000],
                failure_kind=kind,
            )
            if kind == "tool":
                self._note_tool_failure(spec.tool_id)
            self.consecutive_failures += 1
        self._account_vector(spec.tool_id, spec.arguments, result)
        return result

    async def _batch_turn(self) -> Transition:
        """Run several independent tools at once and answer with one observation.

        Each call is governed exactly like a lone one -catalog/subagent/PLAN-FIRST
        refusal, then policy + operator approval, then the gateway, which repeats
        scope/RoE and audits- and only then are the survivors executed
        concurrently, bounded by ``PARALLEL_MAX_CONCURRENCY``. A refusal or a
        failure is local to its call: the others were authorized on their own
        merit, already hold their approvals and finish.

        ``ApprovalRequired`` is the one non-local outcome (the run stops, as
        always), and the scope-insistance streak still closes the run after
        ``MAX_CONSECUTIVE_SCOPE_DENIALS`` denials of the same target.
        """
        batch = self.action
        assert isinstance(batch, ToolCallBatch)
        calls = list(batch.calls)
        entries = {
            index: self._batch_entry(index, spec, len(calls))
            for index, spec in enumerate(calls)
        }
        results: dict[int, dict[str, Any]] = {}
        prepared: list[dict[str, Any]] = []
        for index, spec in enumerate(calls):
            refusal = self._call_refusal(spec)
            if refusal is not None:
                reason, observation = refusal
                results[index] = self._record_batch_denial(
                    spec, entries[index], reason, observation
                )
                continue
            payload = self._call_payload(spec)
            try:
                denial = self._review_call(spec, payload)
            except PermissionError as exc:
                # The policy engine refused this call at the approval gate. It is
                # this call's denial, not the batch's: the others are reviewed on
                # their own merits below.
                self.consecutive_failures += 1
                results[index] = self._record_batch_denial(
                    spec,
                    entries[index],
                    "governance_denial",
                    {"success": False, "error": str(exc)},
                )
                continue
            if denial is not None:
                self.telemetry.flag(FrictionFlag.OPERATOR_DENIAL)
                results[index] = self._record_batch_denial(
                    spec, entries[index], "denied_by_operator", denial
                )
                continue
            prepared.append(
                {
                    "index": index,
                    "tool_id": spec.tool_id,
                    "arguments": dict(spec.arguments),
                    "payload": payload,
                }
            )
        started = time.perf_counter()
        executions: list[CallExecution] = []
        if prepared:
            executions = await execute_calls(
                prepared,
                execute=lambda payload, timeout, cancel_event: self.tool_execution.execute(
                    payload, self.context, timeout=timeout, cancel_event=cancel_event
                ),
                limit=parallel_limit(),
                timeout=call_timeout(self._tool_timeout_seconds()),
                cancel_event=self.cancel_event,
            )
        cancelled_now = False
        approval_required = ""
        for execution in executions:
            spec = calls[execution.index]
            result = self._account_call(spec, execution)
            results[execution.index] = result
            entries[execution.index]["tool_result"] = result
            self.actions.append(entries[execution.index])
            if execution.cancelled:
                cancelled_now = True
            self.audit_step(
                iteration=self.iteration,
                action=batch.action,
                decision=(
                    "allow"
                    if result.get("success")
                    or str(result.get("outcome") or "")
                    in (DETERMINATE_NON_FAILURE_OUTCOMES | {"command_failed"})
                    else "deny"
                ),
                tool_id=spec.tool_id,
                success=bool(result.get("success")),
                outcome=str(result.get("outcome") or ""),
                batch=True,
                batch_index=execution.index,
            )
            if isinstance(execution.error, ApprovalRequired):
                approval_required = str(execution.error)
        consolidated = consolidate([results[index] for index in sorted(results)])
        consolidated["duration_ms"] = int(round((time.perf_counter() - started) * 1000))
        consolidated["concurrency"] = parallel_limit()
        consolidated["executed"] = len(executions)
        consolidated["refused"] = len(calls) - len(prepared)
        if cancelled_now:
            consolidated["outcome"] = "cancelled"
        self.observation = consolidated
        self.entry = entries[0]
        # The model reads ONE message with every result; ``parallel.tools`` is the
        # synthetic tool id (the artifact/compaction key) of that block.
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            _BatchObservationAction(BATCH_TOOL_ID),
            consolidated,
            subagent_id=self.active_subagent_id,
        )
        self.last_tool_elapsed_ms = int(consolidated["duration_ms"])
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.parallel_batch",
            {
                "iteration": self.iteration,
                "subagent_id": self.active_subagent_id,
                "tool_ids": list(batch.tool_ids),
                "tool_calls": consolidated["tool_calls"],
                "succeeded": consolidated["succeeded"],
                "failed": consolidated["failed"],
                "executed": consolidated["executed"],
                "refused": consolidated["refused"],
                "concurrency": consolidated["concurrency"],
                "duration_ms": consolidated["duration_ms"],
            },
        )
        if cancelled_now:
            self.status = STATUS_CANCELLED
            self.final_summary = "cancellation requested during a parallel tool batch"
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.cancelled",
                {"iteration": self.iteration, "phase": "parallel_tools"},
            )
            return Transition.STOP
        if approval_required:
            self.status = STATUS_BLOCKED
            self.final_summary = approval_required
            return Transition.STOP
        if self.scope_denial_streak >= MAX_CONSECUTIVE_SCOPE_DENIALS:
            self.status = STATUS_SCOPE_VIOLATION
            self.final_summary = (
                "scope violation aborted the loop: the model insisted on a target "
                f"outside the signed scope {self.scope_denial_streak} times"
            )
            return Transition.STOP
        if not _keep_going_after_failures(
            self.subagent,
            self.unavailable_tools,
            self.consecutive_failures,
            self.catalog,
        ):
            self.status = STATUS_FAILED
            self.final_summary = (
                f"aborted after {self.consecutive_failures} consecutive tool failures "
                f"(no usable tools remain for subagent '{self.subagent.id}')"
            )
            return Transition.STOP
        if self.consecutive_failures >= MAX_CONSECUTIVE_TOOL_FAILURES:
            self.consecutive_failures = 0
        return Transition.READY

    def _record_governance_denial(
        self, exc: BaseException, *, reason: str = "governance_denial", guidance: str = ""
    ) -> None:
        """Persist a denied call as this turn's observation (never a crash)."""
        self.observation = {
            "success": False,
            "outcome": "governance_denial",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "failure_kind": "governance",
        }
        if guidance:
            self.observation["guidance"] = guidance
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=self.action.tool_id,
            reason=reason,
        )

    async def _execute_tool(self) -> Transition:
        # The plan poll is answered before the generic repeat guards: both would
        # correct it, but only this one can name the pending TODO and the branch.
        unchanged_plan = self._refuse_unchanged_plan_status()
        if unchanged_plan is not None:
            return unchanged_plan
        repeated_tool = self._repeated_failed_action()
        if repeated_tool is not None:
            return self._correct_repeated_action(repeated_tool)
        barren_tool = self._repeated_barren_action()
        if barren_tool is not None:
            return self._correct_repeated_action(barren_tool, barren=True)
        closed = self._refuse_closed_branch()
        if closed is not None:
            return closed
        premature_barrier = self._refuse_barrier_without_attempts()
        if premature_barrier is not None:
            return premature_barrier
        redundant_fact = self._refuse_redundant_fact()
        if redundant_fact is not None:
            return redundant_fact
        unknown_skill = self._refuse_repeated_unknown_skill()
        if unknown_skill is not None:
            return unknown_skill
        unroutable = await self._correct_unroutable_sweep()
        if unroutable is not None:
            return unroutable
        self.last_tool_elapsed_ms = 0
        tool_started = time.perf_counter()
        scope_aborted = False
        try:
            invocation, cancelled_now = await self.tool_execution.execute(
                self.tool_payload,
                self.context,
                # Never longer than the work time left: a sweep started two
                # minutes before the deadline must not eat the wrap-up window.
                timeout=self._tool_timeout_seconds(),
                cancel_event=self.cancel_event,
            )
        except ScopeViolation as exc:
            self.telemetry.note_tool(
                duration_ms=_elapsed_ms(tool_started),
                success=False,
                error_type=type(exc).__name__,
            )
            self.telemetry.flag(FrictionFlag.SCOPE_VIOLATION)
            target = str(getattr(exc, "target", "") or "").strip()
            streak = self._note_scope_denial(target)
            aborted = streak >= MAX_CONSECUTIVE_SCOPE_DENIALS
            named = target or "el objetivo solicitado"
            self.observation = {
                "success": False,
                "outcome": "scope_denied",
                "verified": False,
                "error_type": type(exc).__name__,
                "error": str(exc)[:500],
                "scope_violation": True,
                "target": target,
                "scope_denial_streak": streak,
                "guidance": (
                    f"El objetivo {named} está fuera del alcance firmado. "
                    "Ignora esa URL y busca otra ruta."
                ),
                "available_tools": sorted(self.allowed_catalog),
            }
            if aborted:
                # The model spent the grace turns insisting on the same target:
                # the refusal is now the loop's verdict, not a correction.
                self.status = STATUS_SCOPE_VIOLATION
                self.final_summary = (
                    "scope violation aborted the loop: the model insisted "
                    f"{self.scope_denial_streak} times on {named}: {exc}"
                )
                self.observation["aborted"] = True
            self.entry["tool_result"] = self.observation
            self.actions.append(self.entry)
            _inject_observation(
                self.store,
                self.tenant_id,
                self.conversation_id,
                self.run_id,
                self.iteration,
                self.action,
                self.observation,
                subagent_id=self.active_subagent_id,
            )
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.scope_violation",
                {
                    "iteration": self.iteration,
                    "tool_id": self.action.tool_id,
                    "error": str(exc)[:500],
                    "target": target,
                    "streak": self.scope_denial_streak,
                    "aborted": aborted,
                },
            )
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                tool_id=self.action.tool_id,
                reason="scope_violation",
                error_type=type(exc).__name__,
            )
            # A refusal is an observation: the loop continues unless the model
            # insists on the same target ``MAX_CONSECUTIVE_SCOPE_DENIALS`` times.
            return Transition.STOP if aborted else Transition.READY
        except Exception as exc:
            self.telemetry.note_tool(
                duration_ms=_elapsed_ms(tool_started),
                success=False,
                error_type=type(exc).__name__,
            )
            if isinstance(exc, ReplayApprovalRequired):
                return self._correct_replayed_invocation(exc)
            if isinstance(exc, ApprovalRequired):
                # Nobody can answer an unattended run: without the approval the
                # loop cannot continue, so it stops -and says so as ``blocked``.
                self.status = STATUS_BLOCKED
                self.final_summary = str(exc)
                self._record_governance_denial(exc, reason=STATUS_BLOCKED)
                return Transition.STOP
            if isinstance(exc, PermissionError):
                # A governance denial is about *this* invocation, not about the
                # engagement: record it as the turn's observation and let the
                # model correct itself (another tool, other arguments, a
                # barrier). Only insisting on it closes the run. Measured in the
                # Hijack V1 run: the first denial ended a run with 82 iterations
                # and 1 M tokens of budget unused.
                self.governance_denial_streak += 1
                self.consecutive_failures += 1
                self.telemetry.flag(FrictionFlag.GOVERNANCE_DENIAL)
                self._record_governance_denial(
                    exc,
                    guidance=(
                        "El gateway denegó esta invocación (política, aprobación "
                        "inválida o estado del journal): NO la repitas. Elige otra "
                        "acción, otros argumentos u otra herramienta; si el vector "
                        "entero está bloqueado, registra un barrier y pivota."
                    ),
                )
                if self.governance_denial_streak >= MAX_CONSECUTIVE_GOVERNANCE_DENIALS:
                    self.status = "governance_denial"
                    self.final_summary = (
                        "governance denial repeated "
                        f"{self.governance_denial_streak} times in a row: {exc}"
                    )
                    return Transition.STOP
                return Transition.READY
            backend_unavailable = (
                isinstance(exc, ProviderFailure) and getattr(exc, "kind", "fatal") == "unavailable"
            )
            if isinstance(exc, TimeoutError):
                # V1-27: the per-call ceiling of the loop (or a timeout raised by
                # the tool layer) is the *tool* running out of time, never the
                # provider failing. It becomes the same determinate ``timeout``
                # observation the gateway returns for a handler that outlived its
                # contract (``tool_timeout_result``), so it counts as one tool
                # failure and the tool is retired after repeated attempts instead
                # of closing the run as ``provider_error`` -the measured death of
                # the rerun #7 attempt 1: a 600 s ``nmap -p-`` ended the whole run
                # with ``summary: "TimeoutError"`` (exit 3) from iteration 1.
                self.observation = {
                    "success": False,
                    "outcome": "timeout",
                    "error_type": type(exc).__name__,
                    "error": (str(exc) or "the tool call exceeded its time budget")[:1000],
                    "failure_kind": "tool_timeout",
                    "evidence": {
                        "tool_id": str(self.action.tool_id),
                        "timeout_seconds": self.config.timeout_per_tool_seconds,
                    },
                    "guidance": timeout_guidance(self.action.tool_id),
                }
                self._note_tool_failure(str(self.action.tool_id))
            elif backend_unavailable:
                # Fase 3b: a backend that is not serving *now* is not a fatal
                # provider error. It becomes the same ``unavailable`` observation
                # a handler returns (never ``negative``: nothing was observed),
                # counted like any other tool failure, so the tool is retired
                # after repeated attempts and the run pivots to the rest of the
                # phase (measured in run_434f5eeadb104b11ba0c80bce16f8d08).
                reason = str(exc) or type(exc).__name__
                self.observation = {
                    "success": False,
                    "outcome": "unavailable",
                    "error_type": type(exc).__name__,
                    "error": reason[:1000],
                    "failure_kind": "provider_unavailable",
                    "evidence": {"provider": reason},
                    "guidance": unavailable_guidance(self.action.tool_id, reason),
                }
                self._note_tool_failure(str(self.action.tool_id))
            elif isinstance(exc, (ProviderFailure, ConnectionError)):
                # A provider failure (the model call) still ends the run as
                # ``provider_error``; a *tool* timeout never reaches this branch
                # (V1-27, handled above).
                self.status = "provider_error"
                self.final_summary = type(exc).__name__
                return Transition.STOP
            else:
                kind = _failure_kind(exc)
                self.scope_denial_target = None
                self.scope_denial_streak = 0
                self.observation = {
                    "success": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:1000],
                    "failure_kind": kind,
                }
                if kind == "tool":
                    self._note_tool_failure(str(self.action.tool_id))
            self.consecutive_failures += 1
        else:
            # The call ran: whatever the model was insisting on no longer applies,
            # so the pivot-gate and replay streaks start over.
            self.pivot_gate_streak = 0
            self.replay_refusals = 0
            self.barrier_refusals = 0
            # The insistence streak is decided below: a successful turn or a
            # failure that is not a scope denial breaks it, while a handler that
            # returned ``scope_denied`` (``nexus.shell.exec`` validating the
            # destination of a ``curl``) extends it like the gateway's exception.
            if cancelled_now:
                self.telemetry.flag(FrictionFlag.CANCELLED)
                self.status = STATUS_CANCELLED
                self.final_summary = "cancellation requested during a tool call"
                self.entry["tool_result"] = {"success": False, "cancelled": True}
                self.actions.append(self.entry)
                self.store.append_run_event(
                    self.tenant_id,
                    self.run_id,
                    "react.cancelled",
                    {"iteration": self.iteration, "phase": "tool", "tool_id": self.action.tool_id},
                )
                return Transition.STOP
            self.observation = _observation_payload(invocation or {})
            self._note_observed_flags()
            self._note_report_artifact()
            self.telemetry.note_tool(
                duration_ms=_elapsed_ms(tool_started),
                success=bool(self.observation.get("success")),
                outcome=str(self.observation.get("outcome") or ""),
            )
            if self.observation.get("success"):
                self.scope_denial_target = None
                self.scope_denial_streak = 0
                self.governance_denial_streak = 0
                self.consecutive_failures = 0
                # A successful turn breaks every per-tool failure streak: the
                # retirement below is about *consecutive* failures, never about
                # the accumulated count of a long run. Measured in
                # blackbox-10.67.183.218 (2026-10-19): ``shell.exec`` failed on
                # turns 12, 31 and 48 with 17 successful shell calls in between
                # and was retired anyway, so the agent lost the only tool that
                # could extract the credentials it had already located.
                self.tool_failures.clear()
                self.run_evidence.extend(self.observation.get("assertions") or [])
                del self.run_evidence[:-RUN_EVIDENCE_MAX_OBSERVATIONS]
            else:
                failure_outcome = str(self.observation.get("outcome") or "")
                if failure_outcome == "scope_denied":
                    # Same rule as the gateway path above, for the channels that
                    # report the refusal as a result instead of raising: three
                    # consecutive denials of the same target close the run.
                    # ``_observation_payload`` keeps the handler's own output
                    # nested, so the target and the message are read from there.
                    handler_output = self.observation.get("output")
                    if not isinstance(handler_output, dict):
                        handler_output = {}
                    target = str(
                        self.observation.get("target")
                        or handler_output.get("target")
                        or ""
                    ).strip()
                    if handler_output.get("error") and not self.observation.get("error"):
                        self.observation["error"] = handler_output["error"]
                    if handler_output.get("guidance"):
                        self.observation["guidance"] = handler_output["guidance"]
                    streak = self._note_scope_denial(target)
                    self.observation["scope_denial_streak"] = streak
                    scope_aborted = streak >= MAX_CONSECUTIVE_SCOPE_DENIALS
                    if scope_aborted:
                        self.status = STATUS_SCOPE_VIOLATION
                        self.final_summary = (
                            "scope violation aborted the loop: the model insisted "
                            f"{streak} times on {target or 'the requested target'}"
                        )
                        self.observation["aborted"] = True
                    self.store.append_run_event(
                        self.tenant_id,
                        self.run_id,
                        "react.scope_violation",
                        {
                            "iteration": self.iteration,
                            "tool_id": self.action.tool_id,
                            "error": str(self.observation.get("error") or "")[:500],
                            "target": target,
                            "streak": streak,
                            "aborted": scope_aborted,
                        },
                    )
                else:
                    # The model tried something other than the denied target:
                    # the insistence streak is broken, whatever the outcome.
                    self.scope_denial_target = None
                    self.scope_denial_streak = 0
                if (
                    failure_outcome in DETERMINATE_NON_FAILURE_OUTCOMES
                    or failure_outcome == "command_failed"
                ):
                    # The tool worked: the channel reached the target and it
                    # answered. A ``negative`` SMB listing, a ``denied`` share or
                    # a command that exited non-zero are observations about the
                    # target, not the "this tool is broken" signal. Counting
                    # them here retired the tool and made a legitimate "no" read
                    # as a tool failure in telemetry. The stuck/no-progress
                    # counter still sees the barren turn.
                    self.consecutive_failures = 0
                    self.tool_failures.clear()
                else:
                    self.consecutive_failures += 1
                if failure_outcome == "unavailable":
                    # Fase 3b: a handler (or the gateway) declared that the
                    # backend did not serve the call. It is a *tool* failure -
                    # not invalid input- so it retires the tool after repeated
                    # attempts and the next prompt offers the remaining routes.
                    reason = self.observation.get("failure_kind") or "backend unavailable"
                    evidence = self.observation.get("evidence")
                    if isinstance(evidence, dict):
                        # A concrete cause (``authentication_failed``,
                        # ``module_unavailable``, ``rpc_unreachable``) is what
                        # tells the model whether a retry can ever help; the bare
                        # provider name did not.
                        reason = str(
                            evidence.get("cause_code")
                            or evidence.get("detail")
                            or evidence.get("provider")
                            or reason
                        )
                    self.observation["guidance"] = unavailable_guidance(
                        self.action.tool_id, reason
                    )
                    self._note_tool_failure(str(self.action.tool_id))
                elif failure_outcome == "timeout":
                    # V1-27: a tool that ran out of time is a *tool* failure. It
                    # counts, the model is told the call was cut off (so a repeat
                    # with the same arguments is pointless) and the tool is retired
                    # after repeated attempts so the phase pivots.
                    self.observation["guidance"] = timeout_guidance(self.action.tool_id)
                    self._note_tool_failure(str(self.action.tool_id))
                elif failure_outcome == "command_failed":
                    # The channel reached the target and the command ran: the
                    # credential is fine, so the tool does NOT retire. The model
                    # is told *what* failed and which strategy replaces it; an
                    # identical repeat is already intercepted by the V1-26 guard.
                    # Measured in Simple CTF: `sudo -n -l` failed after a working
                    # SSH login, the agent blamed the password and looped.
                    self.observation["guidance"] = command_failed_guidance(
                        self.action.tool_id
                    )
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        # FIX 3: the world changed this turn (a credential/session/vulnerability
        # landed), so a tool retired only for insisting gets its one extra chance.
        if self.observation.get("success"):
            self._resurrect_tools_for_new_context()
        # FIX 1: one executed call is one count against its vector (or a clear).
        # The observation is already in the history, so a warning appended here
        # is read by the very next turn.
        self._account_vector(
            str(self.action.tool_id), self.action.arguments, self.observation
        )
        determinate = str(self.observation.get("outcome") or "") in (
            DETERMINATE_NON_FAILURE_OUTCOMES | {"command_failed"}
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="allow" if (self.observation.get("success") or determinate) else "deny",
            tool_id=self.action.tool_id,
            success=bool(self.observation.get("success")),
            outcome=str(self.observation.get("outcome") or ""),
            consecutive_failures=self.consecutive_failures,
            error=self.observation.get("error"),
        )
        repeated_failure = self._repeated_failure_summary()
        if repeated_failure:
            self.status = STATUS_FAILED
            self.final_summary = repeated_failure
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.repeated_failure",
                {
                    "iteration": self.iteration,
                    "tool_id": self.repeated_failure_tool,
                    "error": self.repeated_failure_detail,
                    "streak": self.repeated_failure_streak,
                },
            )
            return Transition.STOP
        if not _keep_going_after_failures(
            self.subagent,
            self.unavailable_tools,
            self.consecutive_failures,
            self.catalog,
        ):
            self.status = STATUS_FAILED
            self.final_summary = f"aborted after {self.consecutive_failures} consecutive tool failures (no usable tools remain for subagent '{self.subagent.id}')"
            return Transition.STOP
        if self.consecutive_failures >= MAX_CONSECUTIVE_TOOL_FAILURES:
            self.consecutive_failures = 0
        self.last_tool_elapsed_ms = _elapsed_ms(tool_started)
        return Transition.STOP if scope_aborted else Transition.READY

    def _repeated_failure_summary(self) -> str | None:
        """Stop after the same tool fails repeatedly with the same error.

        Third-party guardrail requested on 2026-11-07 after a 19-minute run:
        ``nexus.recon.nmap`` returned ``nmap xml is empty`` on every call (the
        OCI sandbox has no ``CAP_NET_RAW`` for ``-sS``), the model tried the
        shell as a workaround, and the run burned 14 iterations and ~103k
        tokens. Retiring the tool after three failures did not stop it because
        ``omni`` still had the rest of the catalog, which is by design; the
        missing signal is "this exact error already happened the last turns".
        The tests pin that two identical failures must never close a run (they
        can still be transient) and that three retire the tool; this brake is
        the next step.

        Only execution turns count (a batch is ambiguous about which failure
        is "last"), and a determinate answer such as ``command_failed`` resets
        the streak: a wrong password is not a broken tool. Policy refusals
        (``scope_denied``, ``vector_locked``, …) are excluded on purpose: they
        are not a broken tool but a governance decision, and they already have
        their own brake. The threshold is 4 rather than 2 because the reviewed
        contract pins that two failures are transient and that three retire the
        tool / arm the vector lock, which is what the fourth call would hit; the
        case this covers is a model varying arguments (different profiles,
        ports or paths) so the vector lock never matches while the error never
        changes.
        """
        if isinstance(self.action, ToolCallBatch):
            return None
        observation = self.observation or {}
        outcome = str(observation.get("outcome") or "")
        # A success (or a determinate answer) breaks the streak before any other
        # filter: it may not carry an invocation_id either.
        if observation.get("success") or outcome in (
            DETERMINATE_NON_FAILURE_OUTCOMES | {"command_failed"}
        ):
            self.repeated_failure_tool = None
            self.repeated_failure_detail = ""
            self.repeated_failure_streak = 0
            return None
        if outcome in {
            "scope_denied",
            "vector_locked",
            "tool_unavailable",
            "subagent_tool_denied",
            "unknown_tool",
            "plan_required",
            "reviewer_denied",
        }:
            return None
        # Only a real invocation can fail: a refusal has no invocation_id.
        if not observation.get("invocation_id"):
            return None
        tool_id = str(getattr(self.action, "tool_id", "") or "")
        payload = observation.get("output")
        detail = ""
        if isinstance(payload, dict):
            detail = str(payload.get("error") or payload.get("reason") or "")
        detail = detail or str(
            observation.get("error")
            or observation.get("verification_method")
            or outcome
        )
        detail = " ".join(detail.split())[:300]
        if (
            tool_id
            and tool_id == self.repeated_failure_tool
            and detail == self.repeated_failure_detail
        ):
            self.repeated_failure_streak += 1
        else:
            self.repeated_failure_tool = tool_id
            self.repeated_failure_detail = detail
            self.repeated_failure_streak = 1
        # The reviewed contract handles two (transient) and three (retire the
        # tool / lock the vector). This brake catches the fourth identical
        # error, which the vector lock misses when the arguments vary.
        if self.repeated_failure_streak < MAX_REPEATED_FAILURE_STREAK:
            return None
        return (
            f"herramienta '{tool_id}' falló {self.repeated_failure_streak} veces "
            f"seguidas con el mismo error ({detail or 'sin detalle'}); abortando "
            "para no gastar tokens. Prueba otros argumentos, otra tool del "
            "catálogo o registra un barrier y pivota."
        )

    def _note_tool_failure(self, tool_id: str, *, cause: str = "failure") -> int:
        """Count one *consecutive* tool failure and retire it once exhausted (B3).

        The counter is a streak, not a tally: any successful turn clears it
        (``_execute_tool``), so only three failures in a row retire a tool. The
        accumulated reading was measured in blackbox-10.67.183.218 (2026-10-19):
        ``shell.exec`` failed on turns 12, 31 and 48 with successful shell calls
        in between, was retired at turn 48, and the agent lost the tool that was
        one command away from the credentials.

        A retired tool leaves the phase's catalog (``_advance_phase``), so the
        next prompt offers the remaining routes and the refusal path names what
        is left. Fase 3b routes a backend that stopped serving through here as
        well: ``unavailable`` is a tool failing *now*, and that is what turns
        "MSF RPC is down" into a pivot instead of the end of the run (measured in
        run_434f5eeadb104b11ba0c80bce16f8d08).
        """
        count = self.tool_failures.get(tool_id, 0) + 1
        self.tool_failures[tool_id] = count
        if (
            count >= MAX_TOOL_FAILURES_BEFORE_UNAVAILABLE
            and tool_id not in self.unavailable_tools
        ):
            self.unavailable_tools.add(tool_id)
            if cause == "refusal":
                # FIX 3: retirada por insistencia, no por avería. Queda anotada
                # para poder devolverla cuando el tablero cambie.
                self.refusal_retired.add(tool_id)
            self.telemetry.flag(FrictionFlag.TOOL_RETIRED)
            self.observation["tool_retired"] = True
            # ``subagent`` is chosen when the turn's context is built; a resumed
            # or rebuilt coordinator may retire before that, and losing the whole
            # turn over a missing label is worse than an empty one.
            subagent = getattr(self, "subagent", None)
            tools = tuple(getattr(subagent, "tools", ()) or ())
            self.observation["available_tools"] = sorted(
                (tool for tool in tools if tool not in self.unavailable_tools)
            )
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                TOOL_UNAVAILABLE_EVENT_TYPE,
                {
                    "tool_id": tool_id,
                    "subagent_id": getattr(subagent, "id", ""),
                    "failures": count,
                    "cause": cause,
                    "iteration": self.iteration,
                },
            )
            self.audit_step(
                iteration=self.iteration,
                action="tool_unavailable",
                decision="degrade",
                tool_id=tool_id,
                failures=count,
            )
            # A crash right after the retirement must not resurrect the tool.
            self._persist_run_state()
        return count

    def _resurrect_tools_for_new_context(self) -> None:
        """Return the tools retired for insisting, once, when the board changed.

        ``_correct_repeated_action`` counts a refusal as a tool failure so that a
        model insisting on a dead route ends up with that route retired (V1-26/B3).
        The brake is right for the *route* and wrong for the *tool*: the call was
        rejected before the handler ran, so nothing proved the tool broken.
        Measured in hijack_v4 (2026-10-29): ``nexus.web.request`` was retired at
        iteration 29 by three ``repeated_barren_action`` refusals, and the
        credential discovered at iteration 30 could not be used because the only
        tool that consumes a ``session_ref`` was gone for the rest of the run.

        A new ``credential``/``session``/``vulnerability`` fact is a different
        world: the blocked tool has new material. Each tool gets this exactly once
        per run and its streak is reset, so the model cannot ping-pong between a
        refusal and a fact forever. Tools retired by a real failure, or absent
        from the environment (``binary_missing``, decided at iteration 0 through
        ``_call_refusal``), never enter ``refusal_retired`` and are never touched.
        """
        observed = {
            str(assertion.get("fact_type") or "")
            for assertion in (self.observation.get("assertions") or [])
            if isinstance(assertion, dict)
        }
        if str(getattr(self.action, "tool_id", "")) == "nexus.knowledge.record_fact":
            observed.add(str((self.action.arguments or {}).get("fact_type") or ""))
        landed = observed & RESURRECTING_FACT_TYPES
        if not landed:
            return
        candidates = sorted(
            tool_id
            for tool_id in self.refusal_retired
            if tool_id not in self.resurrected_tools
        )
        if not candidates:
            return
        for tool_id in candidates:
            self.unavailable_tools.discard(tool_id)
            self.tool_failures.pop(tool_id, None)
            self.resurrected_tools.add(tool_id)
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            TOOL_RESURRECTED_EVENT_TYPE,
            {
                "tools": candidates,
                "reason": "new_context",
                "fact_types": sorted(landed),
                "iteration": self.iteration,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="tool_resurrected",
            decision="allow",
            tools=candidates,
            fact_types=sorted(landed),
        )
        self._persist_run_state()
        # The observation this turn already carries the retired catalog: name the
        # returned tools there so the very next prompt offers them again.
        available = self.observation.get("available_tools")
        if isinstance(available, list):
            self.observation["available_tools"] = sorted(set(available) | set(candidates))

    # ----------------------------------------------------------- vector lock
    def _vector_key_for(
        self, tool_id: str, arguments: Any
    ) -> tuple[tuple[str, str, str] | None, list[str]]:
        resolved = self.catalog.get(tool_id) if getattr(self, "catalog", None) else None
        definition = resolved[0] if isinstance(resolved, tuple) else resolved
        return _vector_key(tool_id, definition, arguments)

    def _vector_lock_refusal(self, spec: Any) -> dict[str, Any] | None:
        """Observation that refuses a call on a vector the loop already closed."""
        # A stale streak must not reject a call: the TTL is evaluated at the
        # decision point, before ``vector_locked`` is read.
        self._expire_vectors()
        locked = getattr(self, "vector_locked", None)
        if not locked:
            return None
        tool_id = str(getattr(spec, "tool_id", "") or "")
        key, _ambiguous = self._vector_key_for(tool_id, getattr(spec, "arguments", None))
        if key is None or key not in locked:
            return None
        failures = int(self.vector_failures.get(key, self.vector_lock_threshold))
        named = f"`{key[1]}` " if key[1] else ""
        return {
            "success": False,
            "outcome": "vector_locked",
            "error": "vector_locked",
            "reason": f"{failures} fallos consecutivos en {key[0]} {named}sobre {key[2]}".replace(
                "  ", " "
            ),
            "tool_id": key[0],
            "subcommand": key[1],
            "target": key[2],
            "failures": failures,
            "hint": VECTOR_LOCKED_HINT.format(
                failures=failures, vectors=_render_vectors(self._open_vectors())
            ),
            "available_tools": sorted(self.allowed_catalog),
        }

    def _account_vector(
        self, tool_id: str, arguments: Any, observation: Any
    ) -> None:
        """Count one executed call against its vector, or clear it on success.

        Single calls (``_execute_tool``) and parallel ones (``_account_call``)
        share this rule, so a batch of three failures on the same vector closes
        it exactly like three turns would.
        """
        if isinstance(observation, dict) and observation.get("success"):
            self._account_vector_success(tool_id, arguments)
            return
        self._note_vector_failure(tool_id, arguments, observation)

    def _note_vector_failure(self, tool_id: str, arguments: Any, observation: Any) -> None:
        """Warn at the first threshold, lock at the second (FIX 1)."""
        if not _is_vector_failure(observation):
            return
        key, ambiguous = self._vector_key_for(tool_id, arguments)
        if ambiguous:
            command = arguments.get("command") if isinstance(arguments, dict) else ""
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                VECTOR_LOCK_SKIPPED_EVENT_TYPE,
                {
                    "iteration": self.iteration,
                    "tool_id": tool_id,
                    "subcommand": _shell_subcommand(command),
                    "command_preview": str(command or "")[:200],
                    "detected_targets": list(ambiguous),
                },
            )
            return
        if key is None:
            return
        count = self.vector_failures.get(key, 0) + 1
        self.vector_failures[key] = count
        self.vector_last_failure[key] = self.iteration
        if count >= self.vector_warn_threshold and key not in self.vector_warned:
            self.vector_warned.add(key)
            self._warn_vector_lock(key, count)
        if (
            count >= self.vector_lock_threshold
            and _vector_lockable(key)
            and key not in self.vector_locked
        ):
            self.vector_locked.add(key)
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                VECTOR_LOCKED_EVENT_TYPE,
                {
                    "iteration": self.iteration,
                    "tool_id": key[0],
                    "subcommand": key[1],
                    "target": key[2],
                    "fail_count": count,
                },
            )
            self.audit_step(
                iteration=self.iteration,
                action="vector_locked",
                decision="deny",
                tool_id=key[0],
                subcommand=key[1],
                target=key[2],
                failures=count,
            )
            self._persist_run_state()

    def _warn_vector_lock(self, key: tuple[str, str, str], count: int) -> None:
        """Inject the system warning as a history turn and journal the event."""
        vectors = self._open_vectors()
        text = VECTOR_LOCK_WARNING.format(
            failures=count, tool_id=key[0], target=key[2], vectors=_render_vectors(vectors)
        )
        memory.append_step(
            self.store,
            self.tenant_id,
            self.conversation_id,
            "user",
            text,
            {
                "kind": VECTOR_LOCK_WARNING_KIND,
                "iteration": self.iteration,
                "run_id": self.run_id,
                "tool_id": key[0],
                "subcommand": key[1],
                "target": key[2],
                "failures": count,
                "open_vectors": vectors,
            },
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            VECTOR_LOCK_WARNING_KIND,
            {
                "iteration": self.iteration,
                "tool_id": key[0],
                "subcommand": key[1],
                "target": key[2],
                "fail_count": count,
                "open_vectors": vectors,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="vector_lock_warning",
            decision="degrade",
            tool_id=key[0],
            subcommand=key[1],
            target=key[2],
            failures=count,
        )

    def _account_vector_success(self, tool_id: str, arguments: Any) -> None:
        """An explicit ``barrier`` clears the vector; a success only its own streak.

        Measured in ``run_3a188d2c2bd440f8bca8d88ad922a024`` (Hijack v3): the NFS
        ``action=list`` failure was cleared by *any* other tool succeeding on the
        target (``reason=other_tool_success``), so the counter never reached two
        and FIX 1 never fired. That target-wide reset is gone. The tool's own
        success still breaks its streak -the counter is "consecutive failures"-
        and the TTL covers the case the model keeps failing a vector without ever
        succeeding on it.
        """
        key, ambiguous = self._vector_key_for(tool_id, arguments)
        if ambiguous:
            return
        if key is not None:
            target = key[2]
        else:
            target, _ambiguous = _vector_target(None, arguments)
        if not target:
            return
        barrier = (
            tool_id == "nexus.knowledge.record_fact"
            and isinstance(arguments, dict)
            and str(arguments.get("fact_type") or "") == "barrier"
        )
        if barrier:
            self._release_vectors(target, reason="barrier")
            return
        # The successful tool's own streak is broken by definition; nothing is
        # unlocked, the pair simply stops counting.
        for stale in [
            item
            for item in self.vector_failures
            if item[0] == tool_id and item[2] == target
        ]:
            self.vector_failures.pop(stale, None)
            getattr(self, "vector_last_failure", {}).pop(stale, None)
            self.vector_warned.discard(stale)

    def _expire_vectors(self) -> None:
        """Drop counters older than ``VECTOR_TTL_ITERATIONS`` and journal it.

        The TTL is the escape that does not need the model to recognise the dead
        vector, and it keeps an ancient streak from rejecting a tool that has
        been working since. It runs at the decision point (before
        ``vector_locked`` is read), so a lock armed ten iterations ago no longer
        refuses anything.
        """
        failures = getattr(self, "vector_failures", None)
        if not failures:
            return
        last_failures = getattr(self, "vector_last_failure", {})
        for key in list(failures):
            last = last_failures.get(key, self.iteration)
            if self.iteration - last < VECTOR_TTL_ITERATIONS:
                continue
            failures.pop(key, None)
            last_failures.pop(key, None)
            warned = key in self.vector_warned
            was_locked = key in self.vector_locked
            self.vector_warned.discard(key)
            self.vector_locked.discard(key)
            if not (warned or was_locked):
                continue
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                VECTOR_UNLOCKED_EVENT_TYPE,
                {
                    "iteration": self.iteration,
                    "tool_id": key[0],
                    "subcommand": key[1],
                    "target": key[2],
                    "reason": "ttl_expired",
                },
            )

    def _release_vectors(self, target: str, *, reason: str, keep_tool: str = "") -> None:
        """Drop every counter of *target* (except ``keep_tool``) and journal it."""
        name = _canonical_target(target)
        if not name:
            return
        for key in [
            item
            for item in getattr(self, "vector_failures", {})
            if item[2] == name and (not keep_tool or item[0] != keep_tool)
        ]:
            self.vector_failures.pop(key, None)
            getattr(self, "vector_last_failure", {}).pop(key, None)
            warned = key in self.vector_warned
            was_locked = key in self.vector_locked
            self.vector_warned.discard(key)
            self.vector_locked.discard(key)
            if not (warned or was_locked):
                continue
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                VECTOR_UNLOCKED_EVENT_TYPE,
                {
                    "iteration": self.iteration,
                    "tool_id": key[0],
                    "subcommand": key[1],
                    "target": key[2],
                    "reason": reason,
                },
            )

    def _open_vectors(self) -> list[dict[str, str]]:
        """Open services and endpoints of the board, with the tool to use next.

        A ``service`` counts when nmap saw it open (``state`` in ``open``/``up``,
        the shape ``fact_verification`` persists); an ``endpoint`` counts when
        an HTTP answer carried a 2xx-4xx ``status_code`` -it has no ``state``
        key, which is why filtering on ``state`` alone used to hide the web
        pivots the warning exists to suggest.
        """
        vectors: list[dict[str, str]] = []
        seen: set[str] = set()
        for fact in self._blackboard_facts():
            fact_type = str(fact.get("fact_type") or "")
            key = str(fact.get("key") or "")
            value = fact.get("value")
            if not key or key in seen or not isinstance(value, dict):
                continue
            if fact_type == "service":
                if str(value.get("state") or "").strip().lower() not in {"open", "up"}:
                    continue
                name = str(
                    value.get("service") or value.get("name") or value.get("protocol") or ""
                ).strip().lower()
                suggested = _VECTOR_TOOL_SUGGESTIONS.get(name, "nexus.recon.nmap")
            elif fact_type == "endpoint":
                code = value.get("status_code")
                if not isinstance(code, int) or not 200 <= code <= 499:
                    continue
                suggested = "nexus.web.request"
            else:
                continue
            seen.add(key)
            vectors.append({"type": fact_type, "key": key, "suggested_tool": suggested})
            if len(vectors) >= VECTOR_OPEN_LIMIT:
                break
        return vectors

    def _blackboard_counts(self) -> dict[str, int] | None:
        """Counts of the blackboard *after* the turn's tool call (never raises).

        The plan snapshot the loop renders was built before the tool ran, so the
        per-turn telemetry reads the board again: the whole point of the signal
        is what the turn actually learned.

        Both proven facts *and* the agent's own registrations count. Only the
        verifier can mark a fact ``verified``, so counting proven facts alone
        made every turn that recorded a finding read as barren: measured in
        ``run_7661dda481784eebb17a76e037c5722b`` (2026-10-20), where the run
        extracted the DB version, the table prefix and the complete ``jonah``
        hash through ``nexus.knowledge.record_fact`` and still accumulated 35
        ``consecutive_no_progress`` turns, three ``stuck_detected`` and a budget
        death. A repeated registration does not grow a count, so the streak can
        only be reset by a fact the board did not already hold.
        """
        if not self.engagement_id or not getattr(self, "store", None):
            return None
        try:
            from nexus_core.kernel.blackboard import Blackboard

            summary = Blackboard(self.store).summary(self.tenant_id, self.engagement_id)
            if not isinstance(summary, dict):
                return None
            counts: dict[str, int] = {}
            for bucket in (summary.get("counts"), summary.get("leads")):
                if not isinstance(bucket, dict):
                    continue
                for key, value in bucket.items():
                    counts[str(key)] = counts.get(str(key), 0) + int(value or 0)
            if self.closed_branches:
                # The barriers the *loop* wrote are its own reflex, not something
                # the run learned: counting them as progress would reset the very
                # streak that made the loop act, and the next branch would get a
                # free margin of barren turns. They are unverified, so
                # ``summary`` files them under ``leads``; subtracting here keeps
                # the delta honest (a barrier the model wrote still counts, as
                # the model following the instruction *is* progress).
                remaining = max(0, counts.get("barrier", 0) - len(self.closed_branches))
                if remaining:
                    counts["barrier"] = remaining
                else:
                    counts.pop("barrier", None)
            return counts
        except Exception:  # noqa: BLE001 - telemetry must never abort a run
            return None

    def _turn_was_argument_rejection(self) -> bool:
        """Whether the last turn failed on its arguments, not on the target.

        Measured in HackPark V12 (2026-10-21, iterations 13-15): ``form_url``
        with a query string, a missing ``^PASS^`` and an invalid
        ``failure_string`` -three rejections of the *call*, none of them a
        statement about the login page- raised ``consecutive_no_progress`` to 5,
        fired ``react.stuck_detected`` and pushed the run to RDP. The target had
        not been tested even once.
        """
        observation = getattr(self, "observation", None)
        if not isinstance(observation, dict) or observation.get("success"):
            return False
        if observation.get("input_rejected"):
            return True
        outcome = str(observation.get("outcome") or "").strip().lower()
        if outcome.startswith("invalid_"):
            return True
        return str(observation.get("failure_kind") or "") == "input"

    def _track_no_progress(self) -> None:
        """Count turns without a new verified fact and signal a stuck loop.

        Measured in run_abe04509c5064c6e8e475f46ba8f8c60: 10 consecutive turns
        with ``blackboard_delta = 0`` went unnoticed and the model kept proposing
        the same enumeration until its profile budget killed the run. The signal
        is informational -it never stops the run nor changes the phase by
        itself-; what asks for a pivot is the line injected into the next system
        prompt (see ``ContextBuilder.render``). Emitted at the threshold and then
        once per further threshold, so the log records a long stall without one
        event per turn.
        """
        delta = self.telemetry.current_delta()
        if delta is None:
            return
        # Progress is *actionable*: new service/version/user/endpoint/credential/
        # vulnerability/access/loot/artifact information, or a branch that really
        # closed (with a reason and a scope). A new ``barrier`` otherwise is
        # bookkeeping: the run can write one per turn and keep the same branch,
        # and before this the streak reset on it every time (the measured
        # dynamic-RPC loop: barriers counted as learning while nothing was
        # identified).
        actionable, closures = self._actionable_progress()
        previous = getattr(self, "_progress_baseline", None)
        if previous is None:
            # The first reading is the baseline: a board that was already
            # populated when the run started is not something *this* turn
            # learned, so only a real delta counts.
            progressed = delta > 0 and actionable > 0
        else:
            progressed = actionable > previous[0] or closures > previous[1]
        self._progress_baseline = (actionable, closures)
        # R7: an argument rejection is friction (it already carries its own
        # telemetry flag), never a reason to abandon the branch. The first two
        # consecutive ones leave the pivot counter untouched; from the third the
        # model is guessing, and the turn counts like any other barren one so a
        # run cannot loop on malformed calls until the budget dies.
        if self._turn_was_argument_rejection():
            self.argument_rejections += 1
            if self.argument_rejections <= MAX_FREE_ARGUMENT_REJECTIONS:
                self.telemetry.note_no_progress(consecutive=self.consecutive_no_progress)
                self._track_repeated_tool(delta)
                return
        else:
            self.argument_rejections = 0
        self.consecutive_no_progress = (
            0 if progressed else self.consecutive_no_progress + 1
        )
        self.telemetry.note_no_progress(consecutive=self.consecutive_no_progress)
        self._track_repeated_tool(delta)
        threshold = self.stuck_threshold
        if threshold <= 0 or self.consecutive_no_progress < threshold:
            return
        # The first threshold is the advisory line; from the second one the loop
        # stops asking and closes the branch itself, because the measured stall
        # outlived eight advisory events (see ``_close_stalled_branch``).
        if self.consecutive_no_progress >= threshold * STALL_BARRIER_MULTIPLIER:
            self._close_stalled_branch()
        if self.consecutive_no_progress % threshold:
            return
        self.context.event(
            STUCK_EVENT_TYPE,
            iterations_stuck=self.consecutive_no_progress,
            phase=self.plan.current,
            subagent_id=self.subagent.id,
            last_tools=self._last_tools(),
        )

    def _actionable_progress(self) -> tuple[int, int]:
        """``(actionable facts on the board, branch closures)`` of this turn.

        The first number counts only :data:`ACTIONABLE_FACT_TYPES`, so a model
        that registers barriers (or hypotheses) turn after turn cannot make the
        loop believe it is learning. The second adds the branches the loop
        closed itself plus a model-written barrier that *proves an attempt* and
        carries its reason: that is the other legitimate form of progress the
        loop is allowed to reward -a branch closed with evidence, not a branch
        marked with a wish.
        """
        counts = self._blackboard_counts() or {}
        actionable = sum(
            int(amount or 0)
            for fact_type, amount in counts.items()
            if str(fact_type) in ACTIONABLE_FACT_TYPES
        )
        closures = len(getattr(self, "closed_branches", ()) or ())
        action = getattr(self, "action", None)
        observation = getattr(self, "observation", None)
        executed = isinstance(observation, dict) and observation.get("success") is True
        if executed and str(getattr(action, "tool_id", "") or "") == "nexus.knowledge.record_fact":
            arguments = getattr(action, "arguments", None)
            arguments = arguments if isinstance(arguments, dict) else {}
            value = arguments.get("value")
            value = value if isinstance(value, dict) else {}
            reason = str(value.get("reason") or value.get("detail") or "").strip()
            if (
                str(arguments.get("fact_type") or "") == "barrier"
                and value.get("sweep_attempted") is True
                and reason
            ):
                closures += 1
        return actionable, closures

    def _track_repeated_tool(self, delta: int) -> None:
        """Count turns that repeat one tool without adding a fact (WP4).

        The stuck signal above counts *any* barren turn; this one is narrower:
        a run that keeps asking the same capability is not exploring, it is
        guessing at the same door, and the cheapest way out is the curated
        recipe the skill catalogue already ships. When the streak reaches
        ``SKILL_NUDGE_TURNS`` the next prompt says so and names the loader; the
        signal never stops the run nor changes the phase.
        """
        # A turn that could not be decoded (a parse error) never sets
        # ``self.action``, and its barren turn still has to be counted safely.
        action = getattr(self, "action", None)
        tool_id = str(getattr(action, "tool_id", "") or "")
        if delta <= 0 and tool_id and tool_id == self.last_turn_tool:
            self.same_tool_no_progress += 1
        else:
            self.same_tool_no_progress = 1 if (delta <= 0 and tool_id) else 0
        self.last_turn_tool = tool_id or None
        if self.same_tool_no_progress != SKILL_NUDGE_TURNS:
            return
        self.context.event(
            SKILL_NUDGE_EVENT_TYPE,
            iterations_stuck=self.same_tool_no_progress,
            tool_id=tool_id,
            phase=self.plan.current,
            subagent_id=self.subagent.id,
        )

    def _last_tools(self, limit: int = 5) -> list[str]:
        """Tool ids of the most recent tool calls (payload of the stuck event)."""
        tools: list[str] = []
        for entry in reversed(self.actions):
            tool_id = entry.get("tool_id")
            if tool_id and str(tool_id) not in tools:
                tools.append(str(tool_id))
            if len(tools) >= limit:
                break
        return tools

    def _blackboard_services(self) -> list[str]:
        """Keys of the verified ``service`` facts (never raises).

        The deterministic enumeration→exploit rule needs to know *which* surface
        is on the board; counts alone cannot tell SMB from HTTP.
        """
        if not self.engagement_id or not getattr(self, "store", None):
            return []
        try:
            from nexus_core.kernel.blackboard import Blackboard

            facts = Blackboard(self.store).list_facts(
                self.tenant_id, self.engagement_id, fact_type="service"
            )
            return [str(fact.get("key") or "") for fact in facts if isinstance(fact, dict)]
        except Exception:  # noqa: BLE001 - a missing board must not abort a run
            return []

    def _turn_outcome(self, transition: Transition) -> str:
        """Outcome label of a finished turn (the run status when it stopped)."""
        if transition is Transition.STOP and self.status:
            return self.status
        return "next_turn" if transition is Transition.NEXT_TURN else "completed_turn"

    def _target_margin_spent(self) -> bool:
        """Count a tool call made after the warning; ``True`` when it must be cut.

        The warning turn itself counts as the first tool call, so two more are
        executed and the third is intercepted (``TARGET_REACHED_GRACE_TURNS``).
        """
        if not self.target_reached:
            return False
        self.tool_calls_since_target_reached += 1
        return self.tool_calls_since_target_reached >= TARGET_REACHED_GRACE_TURNS

    def _flag_findings(self) -> list[dict[str, Any]]:
        """One finding per captured flag, citing the evidence that proved it."""
        findings: list[dict[str, Any]] = []
        for flag, source in self.captured_flag_refs.items():
            findings.append(
                {
                    "severity": "critical",
                    "title": f"Flag capturada: {flag}",
                    "invocation_id": str(source.get("invocation_id") or ""),
                    "target": str(source.get("target") or ""),
                    "fact_type": "loot",
                    "value": {"flag": flag},
                    "evidence": (
                        f"la salida de la herramienta devolvió {flag}"
                        if source.get("source") == "observation"
                        else f"hecho loot verificado en el tablero: {flag}"
                    ),
                }
            )
        return findings

    def _force_target_completion(self) -> Transition:
        """Close the run with a synthesized ``task_complete`` (WP5).

        The model ignored the imperative warning for the whole margin, so the
        loop closes on the evidence it already has. The completion is grounded in
        the captured flags themselves (verified loot facts or the successful tool
        output that printed them), which is why it can be marked verified without
        asking the model for anything else.
        """
        self.forced_completion = True
        flags = list(self.captured_flag_refs)
        # The board facts the closure reports, without inventing any: type, key and
        # provenance of what the engagement already proved (capped for the record).
        board_facts = [
            {
                "fact_type": str(fact.get("fact_type") or ""),
                "key": str(fact.get("key") or ""),
                "verified": bool(fact.get("verified")),
                "verification_method": str(fact.get("verification_method") or ""),
            }
            for fact in self._blackboard_facts()[:50]
            if isinstance(fact, dict)
        ]
        self.findings = self._flag_findings()
        # Two different claims: the technical objective (access/privileges/loot
        # verified) and the engagement deliverable (a report that really exists).
        # The measured Bounty Hacker v2 run closed as "objective met" while
        # ``report.generate`` had failed, and the operator had no line saying the
        # report was still owed.
        self.final_summary = (
            "Cierre forzado por objetivo técnico cumplido: "
            f"{len(flags)} flag(s) capturada(s) - " + ", ".join(flags) + "; "
            + self._report_status_line()
        )
        self.status = STATUS_COMPLETED
        # The evidence is the captured flags, not a model summary: the closure is
        # verified when at least one of them came from a verifier assertion or a
        # successful tool output (both are true by construction of the state).
        self.completion_verified_override = bool(flags)
        self.actions.append(
            _action_entry(
                self.iteration,
                ACTION_TASK_COMPLETE,
                thought="Cierre forzado: el objetivo estaba cumplido y el margen de 3 turnos se agotó.",
                summary=self.final_summary,
                findings=self.findings,
                forced=True,
                flags=flags,
                board_facts=board_facts,
            )
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            TARGET_REACHED_FORCED_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "tool_calls": self.tool_calls_since_target_reached,
                "flags": flags,
                "board_facts": board_facts,
                "report": self.report_artifact or {"generated": False},
                "tool_id": str(getattr(self.action, "tool_id", "") or ""),
                "subagent_id": self.last_subagent_id,
            },
        )
        memory.append_step(
            self.store,
            self.tenant_id,
            self.conversation_id,
            "assistant",
            json.dumps(
                {"summary": self.final_summary, "findings": self.findings},
                ensure_ascii=False,
            ),
            {
                "kind": "react.final",
                "iteration": self.iteration,
                "findings_count": len(self.findings),
                "forced": True,
                "flags": flags,
                "run_id": self.run_id,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=ACTION_TASK_COMPLETE,
            decision="allow",
            reason="target_reached_forced",
            forced=True,
            flags=flags,
            findings_count=len(self.findings),
        )
        return Transition.STOP

    def _report_status_line(self) -> str:
        """One operator-facing sentence about the report, never an assumption."""
        report = self.report_artifact or {}
        directory = str(report.get("directory") or "")
        if directory:
            return f"informe generado en {directory}"
        return (
            "informe PENDIENTE: nexus.report.generate no produjo un artefacto "
            "verificable"
        )

    def _result(self) -> ReActResult:
        if self.status == STATUS_MAX_ITERATIONS and (not self.final_summary):
            # The terminal state must say what is true: the limit was reached, the
            # work did not close, and which branches are still open. Without the
            # last part the operator reads a budget number and nothing about the
            # engagement (the measured Bounty Hacker run ended exactly so).
            coverage = getattr(getattr(self, "snapshot", None), "coverage", None)
            open_work = list(getattr(coverage, "open_work", []) or [])
            closed_work = list(getattr(coverage, "closed", []) or [])
            # Verified facts are the run's actual output; hiding them because the
            # findings list ended up empty made a run with a proven surface read
            # as "nothing was done". The counts are the planner's own snapshot of
            # ``Blackboard.summary`` (verifier-owned facts), never the model's.
            self.final_summary = termination_summary(
                reason=(
                    "⚠️ Presupuesto de ejecución agotado. Se guardó el estado "
                    "para --resume. Trabajo incompleto"
                ),
                termination_reason=STATUS_MAX_ITERATIONS,
                max_iterations=self.config.max_iterations,
                counts=getattr(self.plan, "counts", {}) or {},
                findings=len(self.findings),
                closed_branches=len(closed_work),
                open_labels=[
                    str(getattr(entry, "label", "") or "") for entry in open_work[:4]
                ],
                report_line=self._report_status_line(),
            )
        self.context.event(
            "react.finished",
            status=self.status,
            iterations=self.iteration,
            conversation_id=self.conversation_id,
            findings_count=len(self.findings),
            subagent_id=self.last_subagent_id,
        )
        return ReActResult(
            status=self.status,
            iterations=self.iteration,
            final_summary=self.final_summary,
            findings=self.findings,
            conversation_id=self.conversation_id,
            actions=self.actions,
            turns=self.telemetry.as_dicts(),
            question=self.question,
            plan=self.last_plan.to_dict() if self.last_plan is not None else None,
            subagent_id=self.last_subagent_id,
            evidence_stats=self.evidence_stats,
            engagement_plan=(
                self.engagement_plan.to_dict()
                if self.engagement_plan is not None
                else None
            ),
            completion_objections=list(self.completion_objections),
            report_artifact=(
                dict(self.report_artifact) if self.report_artifact else None
            ),
            termination_reason=self.termination_reason,
            budget_tokens=int(self.budget or 0),
            budget_used=(
                _budget_used(self.store, self.tenant_id, self.run_id)
                if self.budget
                else 0
            ),
            completion_verified=(
                bool(self.completion_verified_override)
                if self.completion_verified_override is not None
                else (
                    self.status == STATUS_COMPLETED
                    and self.config.enforce_completion_gates
                    and (not self.completion_objections)
                    and bool(self.run_evidence)
                )
            ),
        )

    async def run(self) -> ReActResult:
        await self._initialize()
        try:
            while self.iteration < self.iteration_limit:
                # The clock is read before any model call: when the work budget is
                # spent the loop closes itself, and inside the window it turns the
                # next turn into a closure instead of an exploration.
                if self._refresh_time_budget():
                    self._force_time_completion()
                    break
                if self._guard() is Transition.STOP:
                    break
                # A model that idles on an unchanged plan while a scan runs is
                # waiting, not thinking: the task is awaited here (one bounded
                # wait, no extra model turn) and its result is delivered below.
                if self.idle_background_wait:
                    self.idle_background_wait = False
                    await self._wait_for_background_result()
                # Background results are injected *before* the context is built,
                # so the model reads them in the same turn that decides the next
                # step instead of one turn later.
                self._deliver_background_results()
                await self._build_context()
                if await self._select_profile() is Transition.STOP:
                    break
                self._advance_phase()
                # The turn is opened only once the phase, the profile and the
                # allowed catalog of this iteration are known, so the record is
                # attributable from the first millisecond.
                self.telemetry.begin_turn(
                    iteration=self.iteration,
                    phase=self.plan.current,
                    subagent_id=self.subagent.id,
                    facts_total=self.plan.facts_total,
                    counts=self.plan.counts,
                )
                turn_started = time.perf_counter()
                try:
                    transition = await self._iteration_body()
                except BaseException:
                    # A turn that died mid-way is exactly what the operator needs to
                    # see, so the record is published before the exception travels on.
                    self.telemetry.finish(
                        outcome=self.status or "exception",
                        turn_ms=_elapsed_ms(turn_started),
                    )
                    raise
                counts = self._blackboard_counts()
                if counts is not None:
                    self.telemetry.note_blackboard(
                        facts_total=sum(counts.values()), counts=counts
                    )
                    self._track_no_progress()
                self.telemetry.finish(
                    outcome=self._turn_outcome(transition),
                    turn_ms=_elapsed_ms(turn_started),
                )
                self._note_completed_turn()
                self._persist_run_state()
                # Durable anchor for a resumed run: the work spent up to here is
                # never re-spent, and the clock does not restart from zero.
                self._persist_work_clock(iteration=self.iteration)
                if transition is Transition.STOP:
                    break
            await self.telemetry.flush()
            return self._result()
        finally:
            # No background task outlives the run that spawned it: a scan still
            # writing after the loop ended would be an unattributed effect.
            await self.task_manager.cancel_all()

    async def _request_action_or_wakeup(self) -> Transition:
        """Await the model, unless a background task finishes first.

        Wake-on-change: a scan that completes while the model is still thinking
        makes that thought stale. The in-flight request is cancelled (it is only
        a provider call; no tool ran) and the finished result is delivered
        *before* the next prompt, so the model never spends a turn discovering
        that nothing changed. The iteration is charged -an extra model call is
        cheaper than acting on a world that no longer exists- and quota
        reservations are excluded because the reservation is settled around the
        provider call in ``_request_action``.
        """
        if (
            self.task_manager.running_count() <= 0
            or self.config.before_provider_call is not None
        ):
            return await self._request_action()
        request = asyncio.ensure_future(self._request_action())
        wakeup = asyncio.ensure_future(self.task_manager.wait_for_change())
        try:
            done, _ = await asyncio.wait(
                {request, wakeup}, return_when=asyncio.FIRST_COMPLETED
            )
            if wakeup in done and wakeup.result() and request not in done:
                request.cancel()
                try:
                    await request
                except asyncio.CancelledError:
                    pass
                finished = self.task_manager.pending_results()
                if finished:
                    self._deliver_background_results(finished)
                    return Transition.NEXT_TURN
            return await request
        finally:
            for pending in (request, wakeup):
                if not pending.done():
                    pending.cancel()

    async def _iteration_body(self) -> Transition:
        """One model turn and the transition it asked for (the loop's unit)."""
        # ``_request_action`` may also answer ``NEXT_TURN``: a malformed JSON
        # answer is corrected and the turn re-issued instead of decoded.
        request = await self._request_action_or_wakeup()
        if request is not Transition.READY:
            return request
        if self._decode_action() is Transition.NEXT_TURN:
            return Transition.NEXT_TURN
        if isinstance(self.action, SpawnSubAgent):
            return await self._spawn_turn()
        if isinstance(self.action, TaskComplete):
            return await self._complete()
        if isinstance(self.action, RequestClarification):
            return self._clarify()
        # WP5: once the objective is reached the model gets an imperative warning
        # and a fixed margin of tool calls. When it spends them without closing,
        # the next call is intercepted: the run ends with a synthesized
        # ``task_complete`` instead of dying at the budget with the work done.
        if self._target_margin_spent():
            # PLAN-FIRST: a capture is not the engagement while the plan still
            # promises a flag (run v8 closed on the first one). The margin is
            # reset instead of forcing the closure, so the model keeps working
            # on the open TODO; without a plan the old WP5 behavior stands.
            if self._flag_todos_pending():
                self.tool_calls_since_target_reached = 0
                self.store.append_run_event(
                    self.tenant_id,
                    self.run_id,
                    "orchestrator.plan_open_at_target",
                    {
                        "iteration": self.iteration,
                        "pending": [
                            todo.id for todo in (self.engagement_plan.flags_pending if self.engagement_plan else ())
                        ],
                    },
                )
            else:
                return self._force_target_completion()
        if isinstance(self.action, ToolCallBatch):
            return await self._batch_turn()
        return await self._tool_turn()

    # ------------------------------------------------- background sub-agents
    async def _background_runner(
        self, payload: dict[str, Any], cancel_event: asyncio.Event
    ) -> dict[str, Any]:
        """Execute one spawned call through the same governed path.

        ``spawn_subagent`` is a scheduling decision, not a waiver: the payload is
        the engine's own (catalog, subagent subset, scope, RoE, policy, approval
        and journal all still apply) and the gateway sees exactly what a
        foreground call would have sent. ``cancel_event`` belongs to the task, so
        cancelling it cannot stop the run.
        """
        invocation, cancelled = await self.tool_execution.execute(
            payload,
            self.context,
            timeout=self._tool_timeout_seconds(),
            cancel_event=cancel_event,
        )
        if cancelled or invocation is None:
            return {"success": False, "outcome": "cancelled"}
        return _observation_payload(invocation)

    async def _background_completed(self, record: TaskRecord) -> None:
        """Persist a finished task: blackboard fact, run event and audit.

        The fact is agent-asserted on purpose (``verified=False``): a background
        scan is evidence to *parse*, and only a verifier can promote it. The
        completion hook never raises back into the task, so a store problem
        cannot turn a finished scan into a lost result.
        """
        if self.engagement_id:
            try:
                from nexus_core.kernel.blackboard import Blackboard

                Blackboard(self.store).record(
                    tenant_id=self.tenant_id,
                    engagement_id=self.engagement_id,
                    fact_type="task",
                    key=f"{record.tool_id}:{record.task_id}",
                    value={
                        "label": record.label,
                        "status": record.status,
                        "outcome": (record.result or {}).get("outcome"),
                        "verification_method": (record.result or {}).get(
                            "verification_method"
                        ),
                        "evidence": (record.result or {}).get("evidence"),
                        "error": record.error,
                    },
                    source=f"tool:{record.tool_id}",
                    created_by=self.agent_id,
                )
            except Exception:  # noqa: BLE001 - the delivery must survive a bad write
                pass
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.background_finished",
            {**record.to_dict(), "iteration": self.iteration},
        )
        self.audit_step(
            iteration=self.iteration,
            action="spawn_subagent",
            decision="allow",
            tool_id=record.tool_id,
            task_id=record.task_id,
            status=record.status,
        )

    async def _wait_for_background_result(self) -> None:
        """Wait for a running task instead of spending a turn asking for status.

        Reached only when the model polls an unchanged plan while work is in
        flight: the answer cannot change by asking again, and the *task* is what
        will change it. ``TaskManager.wait_for_result`` is the internal yield -
        no tool call, no journal entry, no model turn - and the finished result
        is delivered right here so it lands before the next context is built.

        Bounded by the per-call timeout the spawn already carries (a task cannot
        outlive it) and cooperative: the run's cancel event ends the wait, and
        the wake-up is awaited, never spun on.
        """
        limit = float(self.config.timeout_per_tool_seconds or 0) + 5.0
        remaining = self._remaining_seconds()
        if remaining is not None:
            # Waiting for a long scan must not spend the wrap-up window: at the
            # deadline the loop closes with what it already has.
            limit = max(0.0, min(limit, remaining))
        deadline = time.monotonic() + limit
        while self.task_manager.running_count():
            if self.cancel_event is not None and self.cancel_event.is_set():
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            finished = await self.task_manager.wait_for_result(
                timeout=min(remaining, 1.0)
            )
            if finished:
                self._deliver_background_results(finished)
                return

    def _deliver_background_results(self, records=None) -> None:
        """Feed finished background tasks back to the model, exactly once."""
        for record in (self.task_manager.pending_results() if records is None else records):
            observation = {
                **record.observation(),
                "running_tasks": [
                    item
                    for item in self.task_manager.list_tasks()
                    if item["status"] == "running"
                ],
            }
            _inject_observation(
                self.store,
                self.tenant_id,
                self.conversation_id,
                self.run_id,
                self.iteration,
                _BatchObservationAction(record.tool_id),
                observation,
                subagent_id=self.active_subagent_id,
            )
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.background_delivered",
                {**record.to_dict(), "iteration": self.iteration},
            )

    async def _spawn_turn(self) -> Transition:
        """Start one long call in the background and answer the model at once.

        The order is the same as a foreground turn up to the spawn: catalog and
        subagent subset, PLAN-FIRST, vector lock, then policy + operator
        approval. Only the *await* moves to a task.
        """
        assert isinstance(self.action, SpawnSubAgent)
        spawn = self.action
        self.entry = _action_entry(
            self.iteration,
            spawn.action,
            thought=spawn.thought,
            tool_id=spawn.tool_id,
            arguments=memory._redact_arguments(spawn.arguments),
            warnings=spawn.warnings,
            expected_outcome=spawn.expected_outcome,
            label=spawn.label,
            invocation_signature=_invocation_signature(spawn.tool_id, spawn.arguments),
        )
        refusal = self._call_refusal(spawn)
        if refusal is not None:
            reason, observation = refusal
            return self._record_background_refusal(reason, observation)
        # The identical call is already running (or already produced evidence):
        # reconcile with that task instead of spawning a second copy. The old
        # behavior launched it and the journal then refused the execution with a
        # ``PermissionError``, which the model read as a broken tool (Bounty
        # Hacker and Blue, 2026-10-31: four ``nmap full_tcp`` spawns for one
        # target). A *different* target/profile/port set is a different
        # signature and still runs, so a real rescan is never blocked.
        equivalent = self.task_manager.find_equivalent(spawn.tool_id, spawn.arguments)
        if equivalent is not None:
            return self._reconcile_background(equivalent)
        payload = self._call_payload(spawn)
        if self.config.on_approval_needed is not None:
            denial = self._review_call(spawn, payload)
            if denial is not None:
                self.telemetry.flag(FrictionFlag.OPERATOR_DENIAL)
                return self._record_background_refusal(
                    "denied_by_operator", denial, operator_reason=denial.get("reason")
                )
        try:
            record = await self.task_manager.spawn_task(
                tool_id=spawn.tool_id,
                arguments=spawn.arguments,
                payload=payload,
                label=spawn.label,
                timeout_seconds=self._tool_timeout_seconds(),
            )
        except TaskManagerError as error:
            return self._record_background_refusal(
                "background_refused",
                {
                    "success": False,
                    "outcome": "background_refused",
                    "error": str(error)[:500],
                    "running_tasks": self.task_manager.list_tasks(),
                    "guidance": (
                        "No se pudo lanzar en background. Sigue con trabajo de bajo "
                        "riesgo y reintenta cuando una tarea termine, o ejecútala "
                        "como tool_call normal si necesitas el resultado ya."
                    ),
                },
            )
        observation = {
            "success": True,
            "outcome": "background_task_started",
            "background": True,
            "task_id": record.task_id,
            "label": record.label,
            "tool_id": record.tool_id,
            "status": record.status,
            # The model can only reason about what it can see: the snapshot is
            # what makes "what is still running" answerable without a new tool.
            "running_tasks": self.task_manager.list_tasks(),
            "guidance": (
                f"Tarea '{record.label}' ({record.task_id}) lanzada en background con el "
                "mismo gobierno que una llamada normal. NO esperes su resultado ni "
                "inventes una acción `wait` (no existe): continúa con trabajo "
                "independiente de bajo riesgo. Cuando termine llegará como observación "
                "con `background: true` y su `task_id`; si no tienes otra acción, "
                "`task_complete` cede el turno y el bucle espera el job por ti."
            ),
        }
        self.observation = observation
        self.entry["tool_result"] = observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            spawn,
            observation,
            subagent_id=self.active_subagent_id,
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.background_started",
            {**record.to_dict(), "iteration": self.iteration},
        )
        self.audit_step(
            iteration=self.iteration,
            action=spawn.action,
            decision="allow",
            tool_id=spawn.tool_id,
            task_id=record.task_id,
            label=record.label,
        )
        return Transition.NEXT_TURN

    def _reconcile_background(self, record: TaskRecord) -> Transition:
        """Answer a duplicate spawn with the task that already covers it.

        A turn spent here is cheaper than a second ``nmap -p-`` and it teaches
        the loop the right model of the world: background work is delivered, not
        re-requested. Nothing is invented -the record is the task's own state-;
        a finished task carries exactly the outcome it had.
        """
        assert isinstance(self.action, SpawnSubAgent)
        running = record.status == "running"
        outcome = "background_already_running" if running else "background_already_completed"
        observation: dict[str, Any] = {
            "success": False,
            "outcome": outcome,
            "background": True,
            "task_id": record.task_id,
            "label": record.label,
            "tool_id": record.tool_id,
            "status": record.status,
            "running_tasks": self.task_manager.list_tasks(),
            "guidance": (
                f"Ya hay una tarea idéntica en curso ({record.task_id}). No lances "
                "otra: su resultado llegará como observación. Mientras tanto avanza "
                "en una rama distinta."
                if running
                else (
                    f"La tarea idéntica {record.task_id} ya terminó con "
                    f"outcome='{(record.result or {}).get('outcome') or record.status}'. "
                    "Usa su resultado (está en la observación de entrega) en lugar de "
                    "repetir el escaneo."
                )
            ),
        }
        if not running and record.result is not None:
            observation["result"] = {
                key: record.result.get(key)
                for key in ("outcome", "verification_method", "evidence", "assertions")
                if record.result.get(key) not in (None, [], {})
            }
        self.observation = observation
        self.entry["tool_result"] = observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            observation,
            subagent_id=self.active_subagent_id,
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.background_reconciled",
            {
                "iteration": self.iteration,
                "task_id": record.task_id,
                "status": record.status,
                "tool_id": record.tool_id,
                "outcome": outcome,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="allow",
            tool_id=self.action.tool_id,
            reason=outcome,
            task_id=record.task_id,
        )
        return Transition.NEXT_TURN

    def _record_background_refusal(
        self, reason: str, observation: dict[str, Any], **extra: Any
    ) -> Transition:
        """A spawn that never started: refusal observation, turn consumed."""
        assert isinstance(self.action, SpawnSubAgent)
        self.observation = observation
        self.consecutive_failures += 1
        self.entry["tool_result"] = observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            observation,
            subagent_id=self.active_subagent_id,
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=self.action.tool_id,
            reason=reason,
            **extra,
        )
        return Transition.NEXT_TURN

    async def _tool_turn(self) -> Transition:
        self._tool_entry()
        transition = self._check_tool()
        if transition is not Transition.READY:
            return transition
        transition = self._approve_tool()
        if transition is not Transition.READY:
            return transition
        return await self._execute_tool()
