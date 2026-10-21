"""Session-owned command adapter; transports retain their validation gates."""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any, Literal
from urllib.parse import quote, urlencode, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.pty_sessions import PTY_MAX_LINES, PtySessionManager
from nexus_core.kernel.redaction import redact_result, secrets_for_redaction
from nexus_core.kernel.sessions import (
    SessionRegistry,
    parse_webshell_ref,
    validate_session_scope,
)
from nexus_core.tools.passive_wait import PASSIVE_WAIT_GUIDANCE, passive_wait_reason

from .http_request import http_request_definition, http_request_handler, _validate_url
from .listener import LISTENER_TRANSPORTS, refresh_listener_session
from .msf_session_interact import msf_session_interact_handler, validated_command
from .session_pty import command_denial
from .sliver_exec import sliver_exec_handler
from .workspace import workspace_root

#: A command over a reverse shell is observed, not awaited forever: after the
#: output has been stable this long, the turn returns what the pane holds.
PTY_SETTLE_SECONDS = 0.75
PTY_POLL_SECONDS = 0.2


class ShellRequest(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra='forbid')
    transport: Literal['metasploit', 'sliver', 'webshell', 'pty', 'raw']
    session_id: str = Field(min_length=1, max_length=128)
    command: str = Field(min_length=1, max_length=8192)
    url: str | None = Field(default=None, max_length=2048)
    parameter: str = Field(default='cmd', pattern=r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
    timeout_seconds: int = Field(default=60, ge=5, le=300)


def shell_exec_definition(tenant_id: str = 'system') -> ToolDefinition:
    return ToolDefinition(
        tool_id='nexus.post.shell_exec', tenant_id=tenant_id, name='Owned session execution',
        description=(
            'Ejecuta comandos mediante una sesión registrada en el engagement '
            '(MSF, Sliver, webshell o un canal pty/raw capturado por el listener).'
        ),
        input_schema=ShellRequest.model_json_schema(), risk=RiskLevel.HIGH,
        effect='post_exploitation', scope_required=True, timeout_seconds=360,
        required_permissions=['execute:tool:nexus.post.shell_exec'],
    )


def _new_lines(before: str, after: str) -> str:
    """Lines appended to the pane since ``before`` (common prefix removed)."""
    old = before.splitlines()
    new = after.splitlines()
    index = 0
    while index < min(len(old), len(new)) and old[index] == new[index]:
        index += 1
    return "\n".join(new[index:]).strip("\n")


async def _pty_command(
    context: RunContext,
    request: ShellRequest,
    session: dict[str, Any],
    *,
    registry: SessionRegistry,
) -> ToolResult:
    """Send one command into a durable tmux channel and read what changed.

    Both ``pty`` (a real terminal) and ``raw`` (a reverse-shell socket bridged by
    the listener) are driven the same way: ``transport_ref`` names the run's tmux
    session, keys go in with ``send-keys`` and the pane is the observation. The
    ref comes from the database, so it is re-checked against this run's prefix
    before ``tmux`` ever sees it.
    """
    transport_ref = str(session.get('transport_ref') or '')
    session_ref = str(session['id'])
    manager = PtySessionManager(workspace_root(), context.run_id)
    if not transport_ref or not manager.owns(transport_ref):
        return ToolResult(
            output={
                'error': 'session transport is not owned by this run',
                'session_ref': session_ref,
                'transport': request.transport,
            },
            verified=False,
            outcome='denied',
            verification_method='session_transport_ref_foreign',
            evidence={'session_ref': session_ref, 'transport': request.transport},
        )

    # The channel can reach the target with any command, so it keeps the same
    # lexical gates as the PTY tool: no local privilege/destructive command and
    # no fetch to a host outside the signed scope.
    denial = command_denial(context, request.command)
    if denial is not None:
        return ToolResult(
            output={
                'error': 'command refused before reaching the session',
                'reason': denial['reason'],
                'command': request.command,
                'guidance': denial['guidance'],
                'session_ref': session_ref,
            },
            verified=False,
            outcome=denial['outcome'],
            verification_method=denial['method'],
            evidence={'session_ref': session_ref, denial['kind']: denial['reason']},
        )

    if not await manager.exists(transport_ref):
        return ToolResult(
            output={
                'error': 'session is no longer alive',
                'session_ref': session_ref,
                'transport': request.transport,
            },
            verified=False,
            outcome='negative',
            verification_method=f'session_{request.transport}_not_alive',
            evidence={'session_ref': session_ref, 'transport_ref': transport_ref},
        )

    started = time.monotonic()
    before = await manager.capture(transport_ref, lines=PTY_MAX_LINES)
    sent = await manager.send(transport_ref, request.command)
    if sent.error is not None:
        return ToolResult(
            output={
                'error': sent.error,
                'session_ref': session_ref,
                'transport': request.transport,
            },
            verified=False,
            outcome='timeout' if sent.timed_out else 'error',
            verification_method=f'session_{request.transport}_send_failed',
            evidence={'session_ref': session_ref, 'transport_ref': transport_ref},
            timed_out=sent.timed_out,
        )

    deadline = started + min(request.timeout_seconds, 60)
    latest = before.output or ''
    last_change = time.monotonic()
    alive = True
    while time.monotonic() < deadline:
        await asyncio.sleep(PTY_POLL_SECONDS)
        current = await manager.capture(transport_ref, lines=PTY_MAX_LINES)
        alive = current.alive
        if not alive:
            break
        text = current.output or ''
        if text != latest:
            latest = text
            last_change = time.monotonic()
        elif time.monotonic() - last_change >= PTY_SETTLE_SECONDS:
            break
    output = _new_lines(before.output or '', latest)
    if output:
        latest = output
    duration_ms = int((time.monotonic() - started) * 1000)
    registry.touch(context, session_ref)

    digest = hashlib.sha256(latest.encode('utf-8')).hexdigest()
    return ToolResult(
        output={
            'session_ref': session_ref,
            'transport': request.transport,
            'transport_ref': transport_ref,
            'target': session.get('target_host'),
            'command': request.command,
            'output': latest,
            'alive': alive,
            'duration_ms': duration_ms,
            'sha256': digest,
        },
        verified=alive,
        verification_method=f'session_{request.transport}_command',
        evidence={
            'session_ref': session_ref,
            'transport': request.transport,
            'transport_ref': transport_ref,
            'alive': alive,
            'duration_ms': duration_ms,
            'sha256': digest,
            'bytes': len(latest.encode('utf-8')),
        },
        stdout=latest[:65536],
        stderr='',
    )


async def _shell_exec_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
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
    record = registry.get(context.tenant_id, request.session_id)
    if record is not None and str(record.get("transport") or "") in LISTENER_TRANSPORTS:
        # A keep-open listener binds its peer on first use; the row may have been
        # ``pending`` when the model started it.
        refresh_listener_session(context, registry, record)
        record = registry.get(context.tenant_id, request.session_id)
    denied = registry.denial(context, request.session_id)
    if denied is not None:
        return denied
    session = record or registry.get(context.tenant_id, request.session_id)
    session_type = str((session or {}).get("session_type", ""))
    if request.transport in LISTENER_TRANSPORTS:
        if str((session or {}).get("transport") or "") != request.transport:
            return ToolResult(verification_method="session_transport_mismatch")
        return await _pty_command(context, request, session or {}, registry=registry)
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
    if not session or session['session_type'] != 'webshell':
        return ToolResult(verification_method='webshell_session_target_mismatch')
    # The handle written by the producer carries the URL *and* how to drive it;
    # a model-supplied URL is only accepted when it is the same target.
    try:
        handle = parse_webshell_ref(session.get('transport_ref'))
    except ValueError:
        return ToolResult(verification_method='webshell_transport_ref_invalid')
    url = _validate_url(handle['url'])
    if request.url and _validate_url(request.url) != url:
        return ToolResult(verification_method='webshell_session_target_mismatch')
    if urlsplit(url).hostname != session['target_host']:
        return ToolResult(verification_method='webshell_session_target_mismatch')
    # Revalidate the full URL, including port, rather than only its hostname.
    from nexus_core.scope import make_scope_validator
    from nexus_core.kernel.scope_loader import scope_signing_secret
    definition = http_request_definition(context.tenant_id)
    make_scope_validator(signing_secret=scope_signing_secret())(context, definition, {'url': url})
    if handle['method'] == 'GET':
        separator = '&' if urlsplit(url).query else '?'
        request_args: dict[str, Any] = {
            'url': f"{url}{separator}{handle['parameter']}={quote(command)}",
            'method': 'GET',
            'timeout_seconds': request.timeout_seconds,
        }
    else:
        request_args = {
            'url': url, 'method': 'POST',
            'data': urlencode({handle['parameter']: command}),
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            'timeout_seconds': request.timeout_seconds,
        }
    http_result = await http_request_handler(request_args, context)
    body = str((http_result.output or {}).get('body_preview') or '')
    alive = bool(http_result.verified)
    digest = (http_result.output or {}).get('body_sha256')
    return ToolResult(
        output={
            'session_ref': request.session_id,
            'transport': 'webshell',
            'transport_ref': str(session.get('transport_ref') or ''),
            'target': session['target_host'],
            'url': url,
            'command': request.command,
            'output': body,
            'status': (http_result.output or {}).get('status'),
            'alive': alive,
            'sha256': digest,
        },
        verified=alive,
        verification_method='session_webshell_command',
        evidence={
            'session_ref': request.session_id,
            'transport': 'webshell',
            'url': url,
            'alive': alive,
            'sha256': digest,
            'bytes': len(body.encode('utf-8')),
        },
        stdout=body[:65536],
        stderr=http_result.stderr,
        exit_code=http_result.exit_code,
    )


async def shell_exec_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Run through the owned session, then redact every known vault secret.

    The transport handlers already redact the secret they resolved for their own
    call (SSH/HTTP). This boundary covers what the *remote command* prints: a
    session can echo a password the engagement proved earlier, and that value
    must not reach the prompt just because it arrived through Metasploit or
    Sliver instead of SSH (V1-6).
    """
    result = await _shell_exec_handler(arguments, context)
    return redact_result(result, secrets_for_redaction(context, arguments))
