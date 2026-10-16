"""Bounded loose-object Git recovery into a tenant-addressed archive."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from nexus_core.kernel.artifacts import configured_artifact_store
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox
from .http_request import _parse_last_json, _validate_url
from .report_generate import default_artifact_root
from .workspace import workspace_root

# No checkout, hooks, local git configuration, executable files or symlinks.
# The recovered bare object database can be inspected offline with Git.
GIT_SCRIPT = r'''
import hashlib, json, re, sys, urllib.request, zipfile, zlib
base, destination, max_objects = sys.argv[1:4]
max_objects = int(max_objects)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
opener = urllib.request.build_opener(NoRedirect())
total = 0
files = {}
def fetch(name):
    global total
    with opener.open(base + '/' + name, timeout=15) as response:
        content = response.read(min(4194305, 8388609-total))
    total += len(content)
    if len(content) > 4194304 or total > 8388608:
        raise ValueError('repository download quota exceeded')
    files[name] = content
    return content
try:
    head = fetch('HEAD').decode('ascii').strip()
    if head.startswith('ref: '):
        ref = head[5:]
        if not re.fullmatch(r'refs/[A-Za-z0-9_./-]+', ref) or '..' in ref:
            raise ValueError('invalid HEAD ref')
        oid = fetch(ref).decode('ascii').strip()
    else:
        oid = head
    queue = [oid]
    seen = set()
    while queue:
        oid = queue.pop()
        if oid in seen:
            continue
        if not re.fullmatch('[a-f0-9]{40}', oid):
            raise ValueError('invalid object id')
        seen.add(oid)
        if len(seen) > max_objects:
            raise ValueError('object count quota exceeded')
        compressed = fetch('objects/' + oid[:2] + '/' + oid[2:])
        decoder = zlib.decompressobj()
        raw = decoder.decompress(compressed, 4194305)
        if len(raw) > 4194304 or not decoder.eof or decoder.unused_data:
            raise ValueError('invalid or oversized object')
        if hashlib.sha1(raw).hexdigest() != oid:
            raise ValueError('object digest mismatch')
        header, content = raw.split(b'\0', 1)
        kind, length = header.split(b' ', 1)
        if int(length) != len(content):
            raise ValueError('invalid object size')
        if kind in (b'commit', b'tag'):
            for line in content.split(b'\n\n', 1)[0].splitlines():
                if line.startswith((b'tree ', b'parent ', b'object ')):
                    queue.append(line.split(b' ', 1)[1].decode('ascii'))
        elif kind == b'tree':
            while content:
                entry, content = content.split(b'\0', 1)
                if len(content) < 20:
                    raise ValueError('truncated tree')
                if not entry.startswith(b'160000 '):  # external submodule
                    queue.append(content[:20].hex())
                content = content[20:]
        elif kind != b'blob':
            raise ValueError('unsupported object type')
    files['config'] = b'[core]\n\trepositoryformatversion = 0\n\tbare = true\n'
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, content in sorted(files.items()):
            archive.writestr(name, content)
    print(json.dumps({'ok': True, 'objects': len(seen), 'download_bytes': total}))
except Exception as exc:
    print(json.dumps({'ok': False, 'error_type': type(exc).__name__,
                      'status': 'incomplete', 'download_bytes': total}))
'''


class GitDumpRequest(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra='forbid')
    url: str = Field(min_length=8, max_length=2048)
    max_objects: int = Field(default=1000, ge=1, le=2000)
    timeout_seconds: int = Field(default=120, ge=5, le=300)


def git_dump_definition(tenant_id: str = 'system') -> ToolDefinition:
    return ToolDefinition(
        tool_id='nexus.web.git_dump', tenant_id=tenant_id, name='Exposed Git recovery',
        description='Recupera HEAD y objetos sueltos de .git en un artefacto bare, sin checkout.',
        input_schema=GitDumpRequest.model_json_schema(), risk=RiskLevel.MEDIUM,
        effect='read_only', scope_target_field='url', scope_required=True, timeout_seconds=330,
        required_permissions=['execute:tool:nexus.web.git_dump'],
    )


async def git_dump_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    request = GitDumpRequest.model_validate(arguments)
    url = _validate_url(request.url).rstrip('/')
    if not url.endswith('/.git') or '?' in url or '#' in url:
        raise ValueError('url must identify the exposed /.git directory')
    root = workspace_root()
    with tempfile.TemporaryDirectory(prefix='git-dump-', dir=root) as directory:
        archive = Path(directory) / 'repository.zip'
        result = await run_in_sandbox(
            sandbox_for_environment(root, allowed_programs=RECON_ALLOWED_PROGRAMS),
            ['python3', '-c', GIT_SCRIPT, url, str(archive), str(request.max_objects)],
            timeout_seconds=request.timeout_seconds, image_env='NEXUS_HTTP_IMAGE',
            default_image='python:3.12-alpine',
        )
        payload: dict[str, Any] = _parse_last_json(result.stdout) if result.stdout else {'ok': False}
        ok = payload.get('ok') is True and result.exit_code == 0 and not result.timed_out
        if ok:
            with archive.open('rb') as stream:
                content = stream.read(10_000_001)
            if len(content) > 10_000_000:
                raise ValueError('archive quota exceeded')
            artifact = configured_artifact_store(context.store, default_artifact_root()).put(
                context.tenant_id, content, 'application/zip', run_id=context.run_id,
                metadata={'engagement_id': context.engagement_id, 'kind': 'git_repository'},
            )
            payload['artifact'] = artifact
        return ToolResult(output=payload, verified=ok, timed_out=result.timed_out,
                          exit_code=result.exit_code, verification_method='git_loose_object_recovery',
                          evidence={'url': url, 'pack_support': False})
