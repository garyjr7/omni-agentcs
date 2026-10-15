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
from .errors import ApprovalRequired, ProviderFailure
from .audit import AuditWriter
from .models import Resource, RunContext, ToolDefinition, ToolResult
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
                self.audit.append(tenant_id=context.tenant_id, trace_id=context.trace_id,
                    actor_id=context.identity.subject_id, action='invocation.reused',
                    resource_type='tool', resource_id=tool_id,
                    payload={'invocation_id': previous['invocation_id'], 'run_id': context.run_id,
                             'step_key': step_key}, decision='allow')
                reused = journal.result_of(
                    previous, artifact_store=journal_artifacts)
                return reused
            if previous and previous['state'] in {'running', 'prepared'}:
                raise PermissionError('invocation is already running or prepared; reconcile before retry')
            if previous and previous['state'] == 'unknown':
                retry_of = previous['invocation_id']
                if not definition.idempotent:
                    retry_action = f'retry:invocation:{retry_of}'
                    retry_id = retry_approval_id or (approval_id if not decision.requires_approval else None)
                    if not self.approvals or not retry_id or not self.approvals.consume(retry_id, context, retry_action):
                        raise ApprovalRequired('unknown invocation requires human approval: ' + retry_action)
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
            started = time.monotonic()
            try:
                if inspect.iscoroutinefunction(handler):
                    result = await asyncio.wait_for(
                        handler(arguments, context), timeout=definition.timeout_seconds
                    )
                else:
                    result = handler(arguments, context)
                if not isinstance(result, ToolResult):
                    raise TypeError("tool handlers must return ToolResult with deterministic evidence")
                result.to_dto()  # Validate before domain decisions or assertions.
                if not result.completed:
                    # V0-22: a declared ``negative``/``denied``/``unsupported``
                    # result is an observation about the target and completes
                    # below. Timeouts, an absent binary and an unparsed answer
                    # keep their own exception type, so "could not look" never
                    # reads as "looked and found nothing".
                    if result.timed_out or result.verification_method.endswith(("_rpc_failed", "_credentials_missing", "_unavailable", "_timeout")):
                        raise ProviderFailure(result.verification_method)
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
                assertions = derive_assertions(tool_id, arguments, result, context)
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
