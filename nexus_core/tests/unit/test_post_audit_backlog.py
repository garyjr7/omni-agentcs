"""Offline contract tests; all network transports are replaced with fixtures."""
from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import urllib.request
import zipfile
import zlib
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from nexus_core.kernel.models import Identity, RunContext, ToolResult
from nexus_core.report.checksums import write_checksums
from nexus_core.tools.handlers.http_request import HTTP_CLIENT_SCRIPT
from nexus_core.tools.handlers.git_dump import GIT_SCRIPT
from nexus_core.tools.handlers._tcp_credentials import TCP_CREDENTIAL_SCRIPT
from nexus_core.tools.handlers import jobs, shell_exec, web_upload


class Response(io.BytesIO):
    status = 200
    reason = 'OK'
    headers: dict[str, str] = {}


def run_script(monkeypatch: pytest.MonkeyPatch, script: str, args: list[str]) -> dict[str, Any]:
    monkeypatch.setattr(sys, 'argv', ['client', *args])
    out = io.StringIO()
    with redirect_stdout(out):
        exec(compile(script, '<sandbox-fixture>', 'exec'), {})
    return dict(json.loads(out.getvalue()))


@pytest.mark.parametrize('size,limit,ok', [(2_500_000, 3_000_000, True), (4097, 4096, False), (4096, 4096, True)])
def test_stream_download(monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                         size: int, limit: int, ok: bool) -> None:
    body = b'x' * size
    response = Response(body)
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(urllib.request, 'build_opener', lambda *a: opener)
    target = tmp_path / 'binary'
    payload = run_script(monkeypatch, HTTP_CLIENT_SCRIPT, [
        'GET', 'https://fixture.test/file', '{}', '', 'null', '0', '1024', '10',
        str(target), '0', str(limit)])
    assert payload['ok'] is ok
    assert payload['body_complete'] is ok
    assert len(payload['body_preview']) == 1024
    assert payload['preview_truncated']
    assert not list(tmp_path.glob('.http-*'))
    if ok:
        assert target.read_bytes() == body
        assert payload['body_sha256'] == hashlib.sha256(body).hexdigest()
    else:
        assert not target.exists()


@pytest.mark.parametrize('mode', ['multipart', 'raw'])
def test_upload_iterates_chunks(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str) -> None:
    source = tmp_path / 'wordlist'
    source.write_bytes(b'p' * 2_500_000)
    transmitted: list[bytes] = []
    def open_request(request: urllib.request.Request, **kwargs: Any) -> Response:
        assert not isinstance(request.data, bytes)
        transmitted.extend(request.data)  # type: ignore[arg-type]
        assert sum(map(len, transmitted)) == int(request.get_header('Content-length') or '0')
        return Response(b'ok')
    monkeypatch.setattr(urllib.request, 'build_opener', lambda *a: Mock(open=open_request))
    payload = run_script(monkeypatch, HTTP_CLIENT_SCRIPT, [
        'PUT', 'https://fixture.test/file', '{}', '',
        json.dumps({'field': 'file', 'path': str(source), 'mode': mode}),
        '0', '1024', '10', '', '0'])
    assert payload['ok']
    assert payload['uploaded']['size'] == 2_500_000
    assert max(map(len, transmitted)) <= 65536
    if mode == 'raw':
        assert b''.join(transmitted) == source.read_bytes()


def test_real_checksum_validation(tmp_path: Path) -> None:
    (tmp_path / 'report.json').write_text('{"report_sha256":"semantic"}\n')
    (tmp_path / 'report.md').write_text('# Fixture\n')
    write_checksums(tmp_path, ['report.md', 'report.json'])
    checked = subprocess.run(['sha256sum', '-c', 'report.sha256'], cwd=tmp_path,
                             capture_output=True, text=True, check=False)
    assert checked.returncode == 0
    (tmp_path / 'report.json').write_text('tampered')
    checked = subprocess.run(['sha256sum', '-c', 'report.sha256'], cwd=tmp_path,
                             capture_output=True, text=True, check=False)
    assert checked.returncode != 0


def test_git_object_reconstruction(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    objects: dict[str, bytes] = {}
    def object_id(kind: bytes, content: bytes) -> str:
        raw = kind + b' ' + str(len(content)).encode() + b'\0' + content
        oid = hashlib.sha1(raw).hexdigest()
        objects['objects/' + oid[:2] + '/' + oid[2:]] = zlib.compress(raw)
        return oid
    blob = object_id(b'blob', b'fixture\n')
    tree = object_id(b'tree', b'100644 file.txt\0' + bytes.fromhex(blob))
    commit = object_id(b'commit', f'tree {tree}\n\nfixture\n'.encode())
    objects.update({'HEAD': b'ref: refs/heads/main\n', 'refs/heads/main': commit.encode()})
    def open_url(url: str, **kwargs: Any) -> Response:
        return Response(objects[url.split('/.git/', 1)[1]])
    monkeypatch.setattr(urllib.request, 'build_opener', lambda *a: Mock(open=open_url))
    archive = tmp_path / 'repo.zip'
    payload = run_script(monkeypatch, GIT_SCRIPT, ['https://fixture.test/.git', str(archive), '10'])
    assert payload['ok'] and payload['objects'] == 3
    with zipfile.ZipFile(archive) as recovered:
        assert recovered.read('HEAD') == objects['HEAD']
        assert len(recovered.namelist()) == 6
    objects['objects/' + commit[:2] + '/' + commit[2:]] = zlib.compress(b'blob 1\0x')
    payload = run_script(monkeypatch, GIT_SCRIPT, ['https://fixture.test/.git', str(archive), '10'])
    assert payload['ok'] is False


@pytest.mark.parametrize('telnet', ['0', '1'])
def test_tcp_password_only_probe(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, telnet: str) -> None:
    import socket
    wordlist = tmp_path / 'passwords'
    wordlist.write_text('fixture-password\n')
    sock = Mock()
    sock.__enter__ = Mock(return_value=sock)
    sock.__exit__ = Mock(return_value=False)
    sock.recv.side_effect = ([b'\xff', b'\xfb\x01Password:', b'router>'] if telnet == '1'
                             else [b'Password:', b'router>'])
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: sock)
    payload = run_script(monkeypatch, TCP_CREDENTIAL_SCRIPT,
                         ['fixture.test', '23', '', str(wordlist), 'Password:', 'router>', '', telnet])
    assert len(payload['valid_credentials']) == 1
    if telnet == '1':
        sock.sendall.assert_any_call(b'\xff\xfe\x01')
    sock.sendall.assert_any_call(b'fixture-password\r\n')


async def test_upload_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = AsyncMock(return_value=ToolResult(verified=True))
    monkeypatch.setattr(web_upload, 'http_request_handler', handler)
    context = RunContext('t', Identity('u', 't'))
    await web_upload.web_upload_handler({'url': 'https://fixture.test',
                                        'upload': {'field': 'f', 'path': 'f'}}, context)
    assert handler.call_args.args[0]['method'] == 'POST'
    with pytest.raises(ValueError):
        await web_upload.web_upload_handler({'url': 'https://fixture.test', 'method': 'DELETE',
                                            'upload': {'field': 'f', 'path': 'f'}}, context)


async def test_shell_denied_before_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shell_exec, 'validate_session_scope', lambda context: None)
    registry = Mock()
    registry.denial.return_value = ToolResult(verification_method='session_closed')
    monkeypatch.setattr(shell_exec, 'SessionRegistry', lambda store: registry)
    transport = AsyncMock()
    monkeypatch.setattr(shell_exec, 'msf_session_interact_handler', transport)
    result = await shell_exec.shell_exec_handler({'transport': 'metasploit', 'session_id': 'owned',
                                                  'command': 'id'}, RunContext('t', Identity('u', 't')))
    assert result.verification_method == 'session_closed'
    transport.assert_not_called()


async def test_job_uses_durable_gateway_task(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from nexus_core.kernel.control_store import ControlStore
    monkeypatch.setattr(jobs, 'validate_session_scope', lambda context: None)
    monkeypatch.setattr('nexus_core.scope.make_scope_validator', lambda **kw: lambda *a: None)
    store = ControlStore(tmp_path / 'jobs.db')
    store.initialize()
    run = store.create_run('system', {})
    context = RunContext('system', Identity('u', 'system', roles=('operator',)),
                         store=store, run_id=run['id'],
                         authorized_permissions=('execute:tool:nexus.web.request',))
    result = await jobs.jobs_handler({'action': 'start', 'tool_id': 'nexus.web.request',
                                      'arguments': {'url': 'https://fixture.test'}}, context)
    assert result.output['status'] == 'queued'
    queued = store.claim_task('fixture-worker')
    assert queued is not None
    assert queued['task_type'] == 'tool.invoke'
    assert queued['payload']['identity']['roles'] == ['operator']
    assert queued['max_attempts'] == 1
    assert queued['payload']['permissions'] == ['execute:tool:nexus.web.request']
    assert queued['payload']['job_authority']['reservation_id']
    with pytest.raises(ValueError):
        await jobs.jobs_handler({'action': 'start', 'tool_id': 'nexus.post.job'}, context)


def test_failed_download_does_not_replace_existing_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class BrokenResponse(Response):
        def read(self, size: int | None = -1, /) -> bytes:
            raise OSError('fixture read failure')
    monkeypatch.setattr(urllib.request, 'build_opener', lambda *a: Mock(open=lambda *a, **k: BrokenResponse()))
    target = tmp_path / 'existing'
    target.write_bytes(b'original')
    payload = run_script(monkeypatch, HTTP_CLIENT_SCRIPT, [
        'GET', 'https://fixture.test', '{}', '', 'null', '0', '1024', '10', str(target), '0'])
    assert payload['ok'] is False
    assert target.read_bytes() == b'original'
    assert not list(tmp_path.glob('.http-*'))


async def test_job_status_is_owner_scoped(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from nexus_core.kernel.control_store import ControlStore
    monkeypatch.setattr(jobs, 'validate_session_scope', lambda context: None)
    store = ControlStore(tmp_path / 'jobs.db')
    store.initialize()
    store.create_tenant('tenant', tenant_id='t')
    run = store.create_run('t', {})
    monkeypatch.setattr('nexus_core.scope.make_scope_validator', lambda **kw: lambda *a: None)
    context = RunContext('t', Identity('owner', 't', roles=('operator',)), run_id=run['id'], store=store)
    started = await jobs.jobs_handler({'action': 'start', 'tool_id': 'nexus.web.request',
                                      'arguments': {'url': 'https://fixture.test'}}, context)
    job_id = started.output['job_id']
    own = await jobs.jobs_handler({'action': 'status', 'job_id': job_id}, context)
    assert own.output['status'] == 'queued'
    other = RunContext('t', Identity('other', 't'), run_id=run['id'], store=store)
    denied = await jobs.jobs_handler({'action': 'status', 'job_id': job_id}, other)
    assert not denied.verified and denied.verification_method == 'job_not_found'
    task = store.claim_task('worker')
    assert task is not None and task['payload']['identity']['subject_id'] == 'owner'
    assert task['run_id'] == run['id']  # existing approvals remain bound to this run


def test_tcp_errors_are_explicit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import socket
    monkeypatch.setattr(socket, 'create_connection', Mock(side_effect=OSError('offline')))
    wordlist = tmp_path / 'words'
    wordlist.write_text('fixture\n')
    payload = run_script(monkeypatch, TCP_CREDENTIAL_SCRIPT,
                         ['fixture.test', '23', '', str(wordlist), 'Password:', 'router>', '', '1'])
    assert payload == {'valid_credentials': [], 'attempts': 1, 'errors': 1}


def test_premature_eof_is_not_published(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    response = Response(b'short')
    response.headers = {'Content-Length': '100'}
    monkeypatch.setattr(urllib.request, 'build_opener', lambda *a: Mock(open=lambda *a, **k: response))
    target = tmp_path / 'download'
    payload = run_script(monkeypatch, HTTP_CLIENT_SCRIPT, [
        'GET', 'https://fixture.test', '{}', '', 'null', '0', '1024', '10', str(target), '0'])
    assert not payload['ok'] and payload['error'] == 'incomplete_response'
    assert not target.exists()


def test_redirects_preserve_origin_when_enabled() -> None:
    namespace: dict[str, Any] = {}
    exec(compile(HTTP_CLIENT_SCRIPT.rsplit('main()', 1)[0], '<http-fixture>', 'exec'), namespace)
    redirect = namespace['_NoRedirect']()
    redirect.allow_same_origin = True
    request = urllib.request.Request('https://fixture.test/start')
    assert redirect.redirect_request(request, None, 302, '', {}, 'https://outside.test/end') is None
    assert redirect.redirect_request(request, None, 302, '', {}, 'http://fixture.test/end') is None
    assert redirect.redirect_request(request, None, 302, '', {}, 'https://fixture.test:8443/end') is None
    redirected = redirect.redirect_request(request, None, 302, '', {}, 'https://fixture.test/end')
    assert redirected.full_url == 'https://fixture.test/end'


def test_runtime_does_not_promote_empty_roles(monkeypatch: pytest.MonkeyPatch) -> None:
    from nexus_core.kernel import scope_loader
    from nexus_core.kernel.runtime import ExecutionContext, _build_run_context
    monkeypatch.setattr(scope_loader, 'load_engagement_scope', lambda *args: None)
    execution = ExecutionContext(store=Mock(), task={'tenant_id': 't', 'run_id': 'run', 'payload': {}},
                                 worker_id='worker')
    context = _build_run_context({'identity': {'subject_id': 'guest', 'roles': []},
                                  'session_id': 'session'}, execution)
    assert context.identity.subject_id == 'guest'
    assert context.identity.roles == ()


async def test_gateway_stamps_permissions_from_invocation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from nexus_core.kernel.audit import AuditWriter
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.kernel.models import ToolDefinition
    from nexus_core.kernel.policy import PolicyEngine
    from nexus_core.kernel.tool_gateway import ToolGateway
    monkeypatch.setenv('NEXUS_ARTIFACT_ROOT', str(tmp_path / 'artifacts'))
    store = ControlStore(tmp_path / 'permissions.db')
    store.initialize()
    run = store.create_run('t', {})
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store))
    async def echo(args: dict[str, Any], context: RunContext) -> ToolResult:
        return ToolResult(output={'permissions': list(context.authorized_permissions)}, verified=True)
    gateway.register(ToolDefinition(name='fixture', tenant_id='t', tool_id='test.echo',
                                    input_schema={'type': 'object'}, effect='read_only'), echo)
    context = RunContext('t', Identity('guest', 't', roles=()), run_id=run['id'], store=store,
                         authorized_permissions=('*',))
    result = await gateway.invoke('test.echo', {}, context, permissions=('execute:tool',))
    assert result['output']['permissions'] == ['execute:tool']


async def test_http_timeout_cleans_staging(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from nexus_core.kernel.sandbox import SandboxResult
    from nexus_core.tools.handlers import http_request
    monkeypatch.setenv('NEXUS_WORKSPACE_ROOT', str(tmp_path))
    monkeypatch.setattr(http_request, 'sandbox_for_environment', lambda *a, **k: Mock())
    async def killed(sandbox: Any, argv: list[str], **kwargs: Any) -> SandboxResult:
        staging = Path(argv[-1])
        (staging / 'partial').write_bytes(b'partial download')
        return SandboxResult(-1, '', '', timed_out=True)
    monkeypatch.setattr(http_request, 'run_in_sandbox', killed)
    result = await http_request.http_request_handler(
        {'url': 'https://fixture.test', 'save_path': 'downloads/file'}, RunContext('t', Identity('u', 't')))
    assert result.timed_out and not result.verified
    assert not list((tmp_path / 'downloads').iterdir())


def test_download_cannot_name_workspace_root(tmp_path: Path) -> None:
    from nexus_core.tools.handlers.http_request import _resolve_save_path
    with pytest.raises(ValueError):
        _resolve_save_path('.', str(tmp_path))
