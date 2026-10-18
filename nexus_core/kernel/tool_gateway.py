"""Policy-enforced tool invocation shared by every gateway."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import time
from dataclasses import replace
from uuid import uuid4
from typing import Any, Awaitable, Callable, Dict

from .approvals import ApprovalService
from .errors import ApprovalRequired
from .audit import AuditWriter
from .models import (
    PROVIDER_UNAVAILABLE_SUFFIXES,
    Resource,
    RunContext,
    ToolDefinition,
    ToolResult,
    provider_unavailable_result,
    tool_timeout_result,
)
from .policy import PolicyEngine
from .redaction import sanitize
from .schema_validation import validate
from .telemetry import metrics, telemetry

from .artifacts import ArtifactStore
from .control_store import ControlStore

ToolHandler = Callable[[Dict[str, Any], RunContext], ToolResult | Awaitable[ToolResult]]


def _journal_artifact_store(store: ControlStore) -> ArtifactStore:
    """Resolve storage explicitly; setup failures must not silently lose evidence."""
    from nexus_core.config.loader import load_config
    from nexus_core.config.xdg import resolve_xdg_paths
    from .artifacts import configured_artifact_store

    paths = resolve_xdg_paths()
    config = load_config(paths)
    configured = config.get('artifacts_dir') if isinstance(config, dict) else getattr(config, 'artifacts_dir', None)
    return configured_artifact_store(store, configured or (paths.data_dir / 'artifacts'))



#: Bound on the redacted handler-output fragment attached to a post-condition
#: failure, so a large evidence blob cannot flood the error, the CLI or the
#: agent's context.
_FAILURE_DETAIL_MAX = 480


def _bounded(text: str, limit: int = _FAILURE_DETAIL_MAX) -> str:
    """Truncate a diagnostic string to a fixed budget with a visible marker."""
    return text if len(text) <= limit else text[:limit] + "..."


#: Verification method of a result answered from the journal instead of being
#: executed again. The data of the previous invocation travels with it; what the
#: model was missing is the *fact* that it is the same data.
ALREADY_INVOKED_METHOD = "tool_already_invoked"


def _already_invoked(result: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
    """Mark a reused result as a repeat, without losing what it reported.

    The journal has always refused to repeat a succeeded effect, but it answered
    with the previous result verbatim, so the model could not tell a fresh
    observation from an old one. Measured in run_abe04509c5064c6e8e475f46ba8f8c60,
    the model re-issued ``netexec shares`` (iterations 3 and 8) and ``netexec
    rid_brute`` (iterations 4 and 11) with identical arguments, read the same data
    twice as progress, and enumerated until its profile budget killed the run.

    The previous output and evidence are kept (callers that parse them keep
    working) and the repeat becomes explicit: the method, the invocation it
    reused and a direct instruction to change strategy. ``invocation_id`` stays
    the previous one on purpose - no new invocation happened.
    """
    previous_id = str(previous.get("invocation_id") or "")
    marked = dict(result)
    output = dict(marked.get("output") or {})
    output.update(
        {
            "deduplicated": True,
            "previous_invocation_id": previous_id,
            "previous_outcome": "succeeded",
            "message": (
                f"Esta misma invocación ya se ejecutó con éxito en este run "
                f"(invocación previa {previous_id}): devuelve los mismos datos y no "
                f"aporta información nueva. Considera cambiar de estrategia."
            ),
        }
    )
    evidence = dict(marked.get("evidence") or {})
    evidence.update(
        {
            "previous_invocation_id": previous_id,
            "previous_outcome": "succeeded",
        }
    )
    marked["output"] = output
    marked["evidence"] = evidence
    # A determinate completion: nothing failed, nothing new happened.
    marked["success"] = True
    marked["verified"] = True
    marked["verification_method"] = ALREADY_INVOKED_METHOD
    return marked


def _failure_detail(result: ToolResult) -> str:
    """Redacted, bounded view of the output that failed its post-condition.

    A failed post-condition used to surface only the method name, which hides
    *what the tool observed*: the NTLM catcher knows the peer it refused, the
    DNS updater knows the server RCODE. That evidence exists in the handler and
    was discarded here, which is where "why did the primitive fail" became
    unanswerable. Only the handler's own observation is included, redacted with
    the same rules as every persisted record, and always bounded.
    """
    try:
        detail = json.dumps(
            sanitize(result.output), default=str, ensure_ascii=False, sort_keys=True
        )
    except Exception:  # noqa: BLE001 - the diagnostic must never mask the failure
        return ""
    if detail in ("", "null", "{}"):
        return ""
    return f" output={_bounded(detail)}"


class ToolGateway:
    def __init__(
        self,
        policy: PolicyEngine,
        audit: AuditWriter,
        approvals: ApprovalService | None = None,
        scope_validator: Callable[[RunContext, ToolDefinition, Dict[str, Any]], None]
        | None = None,
        roe_validator: Callable[[RunContext, ToolDefinition, Dict[str, Any]], None]
        | None = None,
    ):
        self.policy = policy
        self.audit = audit
        self.approvals = approvals
        self.scope_validator = scope_validator
        self.roe_validator = roe_validator
        self._definitions: Dict[str, ToolDefinition] = {}
        self._handlers: Dict[str, ToolHandler] = {}

    def _resolve_unknown_retry(
        self,
        action: str,
        context: RunContext,
        *,
        tool_id: str,
        invocation_id: str,
        journal,
    ) -> str | None:
        """Apply the run's ``resume_policy`` to a retry the journal holds ``unknown``.

        Measured in the Simple CTF run of 2026-10-18 15:49 UTC: ``enum_system``
        timed out, the journal kept the invocation ``unknown`` and the model's own
        retry met ``unknown invocation requires human approval``. A headless
        ``--trust-mode`` run has nobody to ask, so the engine closed as
        ``blocked`` (exit 2) with the target still reachable.

        The policy is engine-set (``--resume-policy`` plus ``--trust-mode``),
        never model-supplied:

        * ``approve`` registers the durable approval the gateway would otherwise
          demand and consumes it in the same call. The row still exists (requested
          by the run, decided by the operator identity of the worker), so the
          audit trail says *who* authorized the replay of an unconfirmed effect.
        * ``skip`` records the operator's no-effect decision (``mark_failed``) and
          returns ``None`` so the call proceeds as a fresh invocation.
        * anything else keeps today's fail-closed behaviour.

        Returns the invocation id to fence as ``retry_of`` (or ``None`` after a
        skip); raises ``ApprovalRequired`` when no policy authorizes the replay.
        """
        policy = str(getattr(context, "resume_policy", "") or "")
        if policy == "skip":
            journal.mark_failed(
                invocation_id, context.tenant_id,
                reason="resume policy skip: operator asserts no effect",
            )
            self.audit.append(
                tenant_id=context.tenant_id, trace_id=context.trace_id,
                actor_id=context.identity.subject_id, action="invocation.retry_skipped",
                resource_type="invocation", resource_id=invocation_id,
                payload={"tool_id": tool_id, "run_id": context.run_id,
                         "policy": policy,
                         "operator": str(getattr(context, "worker_id", "") or "")},
                decision="allow",
            )
            return None
        if policy == "approve" and self.approvals is not None:
            operator = str(getattr(context, "worker_id", "") or "") or "operator:trust_mode"
            try:
                approval = self.approvals.request(context, action)
                self.approvals.decide(
                    approval["id"], context.tenant_id, operator, True,
                    f"resume policy approve for {tool_id}",
                )
            except Exception as exc:  # noqa: BLE001 - fail closed, but say why
                self.audit.append(
                    tenant_id=context.tenant_id, trace_id=context.trace_id,
                    actor_id=context.identity.subject_id,
                    action="invocation.retry_auto_approval_failed",
                    resource_type="invocation", resource_id=invocation_id,
                    payload={"tool_id": tool_id, "run_id": context.run_id,
                             "error": _bounded(f"{type(exc).__name__}: {exc}")},
                    decision="deny",
                )
                raise ApprovalRequired(
                    "unknown invocation requires human approval: " + action
                ) from exc
            if not self.approvals.consume(approval["id"], context, action):
                raise ApprovalRequired(
                    "unknown invocation requires human approval: " + action
                )
            self.audit.append(
                tenant_id=context.tenant_id, trace_id=context.trace_id,
                actor_id=operator, action="invocation.retry_auto_approved",
                resource_type="invocation", resource_id=invocation_id,
                payload={"tool_id": tool_id, "run_id": context.run_id,
                         "policy": policy, "approval_id": approval["id"],
                         "trust_mode": True},
                decision="allow",
            )
            return invocation_id
        raise ApprovalRequired('unknown invocation requires human approval: ' + action)

    def register(self, definition: ToolDefinition, handler: ToolHandler) -> None:
        if definition.tool_id in self._definitions:
            raise ValueError(f"tool already registered: {definition.tool_id}")
        if os.getenv("NEXUS_ENV", "development").lower() == "production" and not inspect.iscoroutinefunction(handler):
            raise TypeError("production tool handlers must be async and sandbox-backed")
        self._definitions[definition.tool_id] = definition
        self._handlers[definition.tool_id] = handler

    async def invoke(
        self,
        tool_id: str,
        arguments: Dict[str, Any],
        context: RunContext,
        permissions: tuple[str, ...] = (),
        approval_id: str | None = None,
        retry_approval_id: str | None = None,
    ) -> Any:
        with telemetry.span("nexus.tool.invoke", {
            "nexus.tenant.id": context.tenant_id,
            "nexus.run.id": context.run_id,
            "nexus.trace.id": context.trace_id,
            "nexus.tool.id": tool_id,
        }):
            definition = self._definitions.get(tool_id)
            if not definition or not definition.enabled:
                raise KeyError("tool is unavailable")
            from .sandbox_modes import SandboxPolicy

            SandboxPolicy.resolve()
            from .operator_mode import OperatorMode
            modes = OperatorMode(self.audit.store)
            modes.constrain(context, definition)
            context = replace(context, invocation_id=uuid4().hex)
            validate(arguments, definition.input_schema or {"type": "object"})
            if context.scope is not None:
                from .scope_loader import validate_scope_authentication

                validate_scope_authentication(context.scope, self.audit.store, context.tenant_id,
                                              context.trace_id, context.identity.subject_id)
            if definition.scope_required or definition.scope_target_field:
                if context.scope is None:
                    if definition.scope_required:
                        self.audit.append(
                            tenant_id=context.tenant_id,
                            trace_id=context.trace_id,
                            actor_id=context.identity.subject_id,
                            action="scope.denied",
                            resource_type="tool",
                            resource_id=tool_id,
                            payload={"reason": "no_scope"},
                            decision="deny",
                        )
                        raise PermissionError("scope is required but not provided")
                else:
                    try:
                        if self.scope_validator is None:
                            from nexus_core.scope import make_scope_validator
                            from .scope_loader import scope_signing_secret
                            validator = make_scope_validator(signing_secret=scope_signing_secret())
                        else:
                            validator = self.scope_validator
                        if definition.scope_target_field is None:
                            # Engagement-scoped tools (sessions, C2) carry no
                            # per-call target: validate the engagement itself
                            # instead of a scope_target_field.
                            from .sessions import validate_session_scope

                            validate_session_scope(context)
                        else:
                            validator(context, definition, arguments)
                    except Exception as exc:
                        self.audit.append(
                            tenant_id=context.tenant_id,
                            trace_id=context.trace_id,
                            actor_id=context.identity.subject_id,
                            action="scope.denied",
                            resource_type="tool",
                            resource_id=tool_id,
                            payload={
                                "target_keys": [definition.scope_target_field],
                                "reason": str(exc)[:500],
                            },
                            decision="deny",
                        )
                        raise
            if self.roe_validator is not None:
                # Rules of Engagement run after the signed scope and can only
                # narrow it: the kill switch, a forbidden target or a rate limit
                # denies the call before policy, approval or execution.
                try:
                    self.roe_validator(context, definition, arguments)
                except Exception as exc:
                    self.audit.append(
                        tenant_id=context.tenant_id,
                        trace_id=context.trace_id,
                        actor_id=context.identity.subject_id,
                        action="roe.denied",
                        resource_type="tool",
                        resource_id=tool_id,
                        payload={
                            "reason": type(exc).__name__,
                            "detail": str(exc)[:500],
                        },
                        decision="deny",
                    )
                    raise
            decision = self.policy.decide(
                context.identity,
                "execute:tool",
                Resource(tool_id, definition.tenant_id, "tool"),
                permissions,
                definition,
            )
            self.audit.append(
                tenant_id=context.tenant_id,
                trace_id=context.trace_id,
                actor_id=context.identity.subject_id,
                action="tool.invoke",
                resource_type="tool",
                resource_id=tool_id,
                # The arguments make the transcript self-contained; credentials
                # are scrubbed with the audit writer's own field policy, so the
                # redaction is identical to every other durable record.
                payload={
                    "invocation_id": context.invocation_id,
                    "argument_keys": sorted(arguments),
                    "arguments": self.audit._sanitize(dict(arguments)),
                    "run_id": context.run_id,
                },
                decision="allow" if decision.allowed else "deny",
            )
            if not decision.allowed:
                raise PermissionError(decision.reason)
            decision = modes.constrain(context, definition, decision)
            action = f"execute:tool:{tool_id}"
            install_plan = None
            if tool_id == "nexus.system.install_tool":
                from nexus_core.provisioner.installer import approval_action, plan_install
                install_plan = plan_install(arguments["tool_name"], arguments.get("manager"))
                action = approval_action(install_plan, dry_run=arguments.get("dry_run", False))
            if decision.requires_approval:
                if not self.approvals or not approval_id:
                    raise ApprovalRequired("durable human approval is required")
                if not self.approvals.consume(approval_id, context, action):
                    raise PermissionError("approval is invalid or already used")

            if install_plan is not None:
                # ``consume`` already ran above when the policy asked for an
                # approval; consuming again would fail. Only claim the approval
                # here for plans the policy lets through without one.
                if not decision.requires_approval and (
                    not self.approvals
                    or not approval_id
                    or not self.approvals.consume(approval_id, context, action)
                ):
                    raise PermissionError("exact install plan requires durable human approval")
                context = replace(context, approved_install_plan=install_plan)

            from nexus_core.hooks import HookRunner
            # The engagement workspace is passed explicitly (never the process
            # cwd) so tool hooks agree with the session hooks on the directory.
            hooks = HookRunner(
                replace(context, store=self.audit.store),
                project_root=context.project_root or None,
                workspace=context.project_root or None,
            )
            blockers = await hooks.emit('pre_tool_use', tool_id=tool_id, arguments=arguments)
            if blockers:
                raise PermissionError('hook blocked tool: ' + '; '.join(blockers))

            store = self.audit.store
            from .invocation_journal import InvocationJournal
            journal_artifacts = _journal_artifact_store(store)
            journal = InvocationJournal(store)
            # P2-D1: the gateway derives the intent key; the model cannot supply
            # it. Only the engine-provided phase/objective distinguish two calls
            # that happen to share arguments.
            step_key = journal.step_key(
                tool_id, arguments, phase=getattr(context, 'phase', ''),
                objective=getattr(context, 'objective', ''),
            )
            previous = journal.matching(context, tool_id, arguments, step_key=step_key)
            retry_of = None
            if previous and previous['state'] == 'succeeded' and not definition.idempotent:
                # The reuse branch *is* the deduplication (Fase 3 fixes): the
                # effect already happened, so it never happens twice. What changed
                # is the answer - it now says so (``_already_invoked``) instead of
                # handing back the same data as if it were new. Keyed by the
                # engine's ``step_key``, so a repeat in another phase or against
                # another objective stays a different intent and really runs.
                self.audit.append(tenant_id=context.tenant_id, trace_id=context.trace_id,
                    actor_id=context.identity.subject_id, action='invocation.reused',
                    resource_type='tool', resource_id=tool_id,
                    payload={'invocation_id': previous['invocation_id'], 'run_id': context.run_id,
                             'step_key': step_key,
                             'verification_method': ALREADY_INVOKED_METHOD}, decision='allow')
                reused = journal.result_of(
                    previous, artifact_store=journal_artifacts)
                return _already_invoked(reused, previous)
            if previous and previous['state'] in {'running', 'prepared'}:
                raise PermissionError('invocation is already running or prepared; reconcile before retry')
            if previous and previous['state'] == 'unknown':
                retry_of = previous['invocation_id']
                if not definition.idempotent:
                    retry_action = f'retry:invocation:{retry_of}'
                    retry_id = retry_approval_id or (approval_id if not decision.requires_approval else None)
                    if not self.approvals or not retry_id or not self.approvals.consume(retry_id, context, retry_action):
                        retry_of = self._resolve_unknown_retry(
                            retry_action, context, tool_id=tool_id,
                            invocation_id=previous['invocation_id'], journal=journal,
                        )
                if retry_of:
                    journal.claim_retry(retry_of, context.tenant_id)
            target = arguments.get(definition.scope_target_field, '') if definition.scope_target_field else ''
            journal.prepare(context, tool_id, arguments, target, retry_of=retry_of,
                            step_key=step_key, lease_id=getattr(context, 'worker_id', '') or None)
            journal.start(context.invocation_id, context.tenant_id)
            store.record_usage(
                context.tenant_id, context.run_id, "tool", tool_id, "calls", 1,
                {"trace_id": context.trace_id},
            )
            context = replace(context, authorized_permissions=tuple(permissions))
            handler = self._handlers[tool_id]
            # V1-29: a credential the agent carries as a *handle* is resolved here,
            # in this process, and only into the handler's own copy of the
            # arguments. The audit row, the journal and the hooks keep seeing the
            # reference, so the plaintext never enters a durable record, a result
            # or the model's context; a manual ``password`` is passed through
            # untouched (same dict, no resolution).
            call_arguments = arguments
            if arguments.get("credential_ref"):
                from .secret_store import resolve_secret_reference

                call_arguments = resolve_secret_reference(
                    arguments, field="password", tenant_id=context.tenant_id
                )
            started = time.monotonic()
            try:
                # Only the timeout the gateway itself has to impose is a V1-27
                # ``timeout``; a handler that declares its own subprocess timeout
                # keeps the Fase 3b reading (``unavailable``: the backend did not
                # serve the call).
                handler_timed_out = False
                if inspect.iscoroutinefunction(handler):
                    try:
                        result = await asyncio.wait_for(
                            handler(call_arguments, context), timeout=definition.timeout_seconds
                        )
                    except (TimeoutError, asyncio.TimeoutError):
                        # V1-27: the handler outlived the budget of its own contract.
                        # That is a *tool* running out of time -never the provider
                        # failing- so it becomes the determinate ``timeout`` result
                        # of ``tool_timeout_result`` instead of a bare ``TimeoutError``
                        # that used to close the whole run as ``provider_error``.
                        result = tool_timeout_result(tool_id, definition.timeout_seconds)
                        handler_timed_out = True
                else:
                    result = handler(call_arguments, context)
                if not isinstance(result, ToolResult):
                    raise TypeError("tool handlers must return ToolResult with deterministic evidence")
                result.to_dto()  # Validate before domain decisions or assertions.
                # V1-54: a handler that *declares* ``timeout`` is saying the same
                # thing ``tool_timeout_result`` says -the call ran out of time-
                # and is handled identically: determinate result for the loop, no
                # assertion, journal kept ``unknown`` so the effect is never
                # answered later as data this run did not obtain. Before this, an
                # SSH client ``TimeoutError`` reached the branch below, was
                # re-labelled ``unavailable``, finished as ``succeeded`` and the
                # next retry was blocked on an approval (Simple CTF
                # 2026-10-18 15:49 UTC).
                declared_timeout = result.outcome == "timeout"
                if not result.completed and not handler_timed_out and not declared_timeout:
                    # V0-22: a declared ``negative``/``denied``/``unsupported``
                    # result is an observation about the target and completes
                    # below. What is left is "could not look": a timeout, an
                    # absent binary or an unparsed answer. Fase 3b separates the
                    # one case that is *not* a defect of the tool - its backend
                    # is not serving right now- from an invariant a handler
                    # broke, which still fails closed.
                    if result.timed_out or result.verification_method.endswith(
                        PROVIDER_UNAVAILABLE_SUFFIXES
                    ):
                        # Measured in run_434f5eeadb104b11ba0c80bce16f8d08: this
                        # used to raise ``ProviderFailure``, and a dead MSF RPC
                        # ended the whole run (exit 3, ``provider_error``) with
                        # five other routes still available. Now the tool answers
                        # ``unavailable`` -audited and journaled like the other
                        # determinate outcomes- so the loop can count it, retire
                        # the tool after repeated attempts and pivot.
                        result = provider_unavailable_result(tool_id, result)
                    else:
                        raise RuntimeError(
                            "tool post-condition was not verified "
                            f"(method={result.verification_method})"
                            f"{_failure_detail(result)}"
                        )
                from nexus_core.tools.parsers import PARSERS_VERSION

                from .fact_verification import derive_assertions, persist_assertions

                # Pin the contract and parser revision that produced this result
                # (V1-8) before deriving assertions from it.
                result = result.stamp_versions(tool_id, definition.version, PARSERS_VERSION)
                # A call that timed out observed nothing about the target: it derives
                # no assertion (V1-27), so a run that only collected timeouts can
                # never advance a phase.
                timed_out_call = handler_timed_out or declared_timeout
                assertions = (
                    [] if timed_out_call
                    else derive_assertions(tool_id, arguments, result, context)
                )
                result_value = result.to_dict()
                from .domain_dto import ToolResultDTO
                result_value = ToolResultDTO.model_validate({
                    **result_value, "invocation_id": context.invocation_id,
                    "run_id": context.run_id, "engagement_id": context.engagement_id, "assertions": assertions,
                }).to_dict()
                encoded = json.dumps(result_value, default=str).encode("utf-8")
                if len(encoded) > definition.max_output_bytes:
                    raise ValueError("tool output exceeds configured limit")
                self.audit.append(
                    tenant_id=context.tenant_id, trace_id=context.trace_id,
                    actor_id=context.identity.subject_id, action="tool.complete",
                    resource_type="tool", resource_id=tool_id,
                    payload={"duration_ms": round((time.monotonic() - started) * 1000, 3),
                             "output_bytes": len(encoded), "run_id": context.run_id,
                             "invocation_id": context.invocation_id, "assertions": assertions,
                             "outcome": result.outcome_class},
                    decision="allow",
                )
                metrics.increment(
                    "nexus_tool_calls_total", tool_id=tool_id, status="success",
                    tenant_id=context.tenant_id,
                )
                metrics.increment(
                    "nexus_tool_duration_ms_total",
                    (time.monotonic() - started) * 1000,
                    tool_id=tool_id, tenant_id=context.tenant_id,
                )
                persist_assertions(assertions, context, tool_id)
                if timed_out_call:
                    # The effect of a timed-out call is *not* confirmed, so the journal
                    # keeps it ``unknown`` exactly like any other failed invocation: a
                    # repeat is never answered with data this run never obtained
                    # (``tool_already_invoked`` is only for a confirmed success, V1-27).
                    journal.unknown(context.invocation_id, context.tenant_id)
                else:
                    journal.finish(context.invocation_id, context.tenant_id, result_value,
                                   artifact_store=journal_artifacts)
                await hooks.emit('post_tool_use', tool_id=tool_id, result=result_value)
                return result_value
            except BaseException as exc:
                journal.unknown(context.invocation_id, context.tenant_id)
                self.audit.append(
                    tenant_id=context.tenant_id, trace_id=context.trace_id,
                    actor_id=context.identity.subject_id, action="tool.failed",
                    resource_type="tool", resource_id=tool_id,
                    payload={"error_type": type(exc).__name__, "run_id": context.run_id,
                             "error": _bounded(str(exc))},
                    decision="error",
                )
                metrics.increment(
                    "nexus_tool_calls_total", tool_id=tool_id, status="error",
                    tenant_id=context.tenant_id,
                )
                raise
