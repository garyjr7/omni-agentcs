"""Durable background tool jobs. Workers re-enter the ordinary policy gateway."""
from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from typing import Literal
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sessions import validate_session_scope
from nexus_core.kernel.job_authority import JobAuthority, check_authority, reserve_job


class JobRequest(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra='forbid')
    action: Literal['start', 'status']
    tool_id: str | None = Field(default=None, min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    job_id: str | None = Field(default=None, min_length=1, max_length=128)
    approval_id: str | None = Field(default=None, min_length=1, max_length=128)


def jobs_definition(tenant_id: str = 'system') -> ToolDefinition:
    return ToolDefinition(
        tool_id='nexus.post.job', tenant_id=tenant_id, name='Durable tool jobs',
        description='Encola herramientas gobernadas y consulta su estado durable.',
        input_schema=JobRequest.model_json_schema(), risk=RiskLevel.MEDIUM,
        effect='target_write', scope_required=True,
        required_permissions=['execute:tool:nexus.post.job'], timeout_seconds=30,
    )


async def jobs_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    request = JobRequest.model_validate(arguments)
    validate_session_scope(context)
    if request.action == 'status':
        if not request.job_id:
            raise ValueError('status requires job_id')
        with context.store.connect() as conn:
            row = conn.execute(
                'SELECT t.id,t.status,t.attempts,t.payload FROM kernel_tasks t '
                'JOIN kernel_runs r ON r.id=t.run_id AND r.tenant_id=t.tenant_id '
                'WHERE t.id=? AND t.tenant_id=?', (request.job_id, context.tenant_id),
            ).fetchone()
        owner = json.loads(row['payload']) if row else {}
        if (not row or owner.get('job_owner') != context.identity.subject_id
                or owner.get('engagement_id') != context.engagement_id):
            return ToolResult(verification_method='job_not_found')
        # Results remain in the governed journal; do not duplicate secret-bearing
        # output or load an arbitrarily large JSON result into an observation.
        return ToolResult(output={'job_id': row['id'], 'status': row['status'],
                                  'attempts': row['attempts']}, verified=True,
                          verification_method='durable_job_status')
    from nexus_core.tools.registry import durable_tool_definitions
    catalog = durable_tool_definitions(context.tenant_id)
    if request.tool_id not in catalog or request.tool_id == 'nexus.post.job':
        raise ValueError('start requires a registered non-job tool')
    definition, _ = catalog[request.tool_id]
    from nexus_core.kernel.schema_validation import validate
    validate(request.arguments, definition.input_schema)
    authority = context.job_authority
    if authority is None:
        # Direct operator calls retain their policy permissions, with a bounded
        # per-run allowance. Agent calls always carry an engine-owned profile.
        authority = JobAuthority(run_id=context.run_id, engagement_id=context.engagement_id, tools=(definition.tool_id,),
                                 token_budget=0, run_token_budget=context.budget_tokens,
                                 job_limit=100)
    if not isinstance(authority, JobAuthority):
        raise PermissionError('invalid job authority')
    if (definition.tool_id.startswith('nexus.orchestrator.')
            or request.arguments.get('llm_cvss') is True):
        raise PermissionError('LLM delegation requires the budgeted orchestration path')
    check_authority(authority, context, definition)
    if definition.scope_required:
        from nexus_core.scope import make_scope_validator
        from nexus_core.kernel.scope_loader import scope_signing_secret

        if definition.scope_target_field is None:
            validate_session_scope(context)
        else:
            make_scope_validator(signing_secret=scope_signing_secret())(context, definition, request.arguments)
    authority = reserve_job(authority, context)
    task = context.store.enqueue_task(
        tenant_id=context.tenant_id, run_id=context.run_id, task_type='tool.invoke',
        max_attempts=1, timeout_seconds=definition.timeout_seconds + 30,
        payload={'job_authority': authority.model_dump(mode='json'), 'job_owner': context.identity.subject_id, 'tool_id': request.tool_id, 'arguments': request.arguments,
                 'engagement_id': context.engagement_id,
                 'identity': {'subject_id': context.identity.subject_id,
                              'roles': list(context.identity.roles), 'kind': context.identity.kind},
                 'permissions': list(context.authorized_permissions),
                 'approval_id': request.approval_id, 'trace_id': context.trace_id,
                 'session_id': context.session_id, 'project_root': context.project_root},
    )
    return ToolResult(output={'job_id': task['id'], 'run_id': context.run_id, 'status': 'queued'},
                      verified=True, verification_method='durable_job_enqueued')
