"""Session-owned command adapter; transports retain their validation gates."""
from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urlencode, urlsplit
from pydantic import BaseModel, ConfigDict, Field
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sessions import SessionRegistry, validate_session_scope
from nexus_core.tools.passive_wait import PASSIVE_WAIT_GUIDANCE, passive_wait_reason
from .http_request import http_request_definition, http_request_handler, _validate_url
from .msf_session_interact import msf_session_interact_handler, validated_command
from .sliver_exec import sliver_exec_handler


class ShellRequest(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra='forbid')
    transport: Literal['metasploit', 'sliver', 'webshell']
    session_id: str = Field(min_length=1, max_length=128)
    command: str = Field(min_length=1, max_length=8192)
    url: str | None = Field(default=None, max_length=2048)
    parameter: str = Field(default='cmd', pattern=r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
    timeout_seconds: int = Field(default=60, ge=5, le=300)


def shell_exec_definition(tenant_id: str = 'system') -> ToolDefinition:
    return ToolDefinition(
        tool_id='nexus.post.shell_exec', tenant_id=tenant_id, name='Owned session execution',
        description='Ejecuta comandos mediante una sesión registrada en el engagement.',
        input_schema=ShellRequest.model_json_schema(), risk=RiskLevel.HIGH,
        effect='post_exploitation', scope_required=True, timeout_seconds=360,
        required_permissions=['execute:tool:nexus.post.shell_exec'],
    )


async def shell_exec_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    request = ShellRequest.model_validate(arguments)
    validate_session_scope(context)
    # V9 (Hijack): a ``sleep`` over an owned session is the same non-action as a
    # local one. Refused here, before the transport, so it never reaches the
    # target and the model gets the two tools that replace waiting.
    wait_reason = passive_wait_reason(request.command)
    if wait_reason is not None:
        return ToolResult(
            output={
                "error": "passive wait refused",
                "wait": wait_reason,
                "command": request.command,
                "guidance": PASSIVE_WAIT_GUIDANCE,
            },
            verified=False,
            outcome="denied",
            verification_method="session_passive_wait_denied",
            evidence={"session_id": request.session_id, "wait": wait_reason},
        )
    registry = SessionRegistry(context.store)
    denied = registry.denial(context, request.session_id)
    if denied is not None:
        return denied
    session = registry.get(context.tenant_id, request.session_id)
    session_type = str((session or {}).get("session_type", ""))
    if ((request.transport == "sliver" and not session_type.startswith("sliver:"))
            or (request.transport == "metasploit" and session_type not in {"shell", "meterpreter"})):
        return ToolResult(verification_method="session_transport_mismatch")
    command = validated_command(request.command)
    if request.transport == 'metasploit':
        return await msf_session_interact_handler({
            'session_uuid': request.session_id, 'command': command,
            'max_wait_seconds': request.timeout_seconds}, context)
    if request.transport == 'sliver':
        return await sliver_exec_handler({'session_id': request.session_id, 'command': command,
                                         'timeout_seconds': request.timeout_seconds}, context)
    session = registry.get(context.tenant_id, request.session_id)
    url = _validate_url(request.url)
    if (not session or session['session_type'] != 'webshell'
            or urlsplit(url).hostname != session['target_host']):
        return ToolResult(verification_method='webshell_session_target_mismatch')
    # Revalidate the full URL, including port, rather than only its hostname.
    from nexus_core.scope import make_scope_validator
    from nexus_core.kernel.scope_loader import scope_signing_secret
    definition = http_request_definition(context.tenant_id)
    make_scope_validator(signing_secret=scope_signing_secret())(context, definition, {'url': url})
    return await http_request_handler({
        'url': url, 'method': 'POST', 'data': urlencode({request.parameter: command}),
        'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
        'timeout_seconds': request.timeout_seconds}, context)
