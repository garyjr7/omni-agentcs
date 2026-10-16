"""Workspace-confined streaming uploads over the governed HTTP transport."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from .http_request import http_request_definition, http_request_handler


def web_upload_definition(tenant_id: str = 'system') -> ToolDefinition:
    base = http_request_definition(tenant_id)
    schema = deepcopy(base.input_schema)
    schema['required'] = ['url', 'upload']
    schema['properties']['method']['enum'] = ['POST', 'PUT']
    for inline_body in ('data', 'data_base64'):
        schema['properties'].pop(inline_body)
    return ToolDefinition(
        tool_id='nexus.web.upload', tenant_id=tenant_id, name='HTTP file upload',
        description='Subida POST multipart o PUT binario desde el workspace con memoria acotada.',
        effect='target_write', risk=RiskLevel.MEDIUM,
        input_schema=schema,
        required_permissions=['execute:tool:nexus.web.upload'],
        scope_target_field='url', scope_required=True, timeout_seconds=300,
        max_output_bytes=2_000_000,
    )


async def web_upload_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    validate(arguments, web_upload_definition().input_schema)
    args = dict(arguments)
    args.setdefault('method', 'POST')
    if args['method'] not in {'POST', 'PUT'}:
        raise ValueError('upload requires POST or PUT')
    if 'data' in args or 'data_base64' in args:
        raise ValueError('upload cannot be combined with an inline body')
    return await http_request_handler(args, context)
