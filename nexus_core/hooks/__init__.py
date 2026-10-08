"""Operator-owned lifecycle extensions; allow never replaces core governance."""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
from pathlib import Path
import shlex

from nexus_core.cli.tui.history import atomic_private
from nexus_core.config.xdg import resolve_xdg_paths
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.sandbox import OCISandbox
from nexus_core.kernel.sandbox_modes import SandboxPolicy

EVENTS = frozenset({'session_start','session_end','pre_tool_use','post_tool_use','pre_compact','stop'})
MAX_BYTES = 64 * 1024
PROJECT_HOOKS_RELPATH = Path('.agents') / 'hooks.json'


def _trust_path():
    return resolve_xdg_paths().config_dir / 'hooks-trust.json'


def _read_private_trust():
    try:
        data=json.loads(_trust_path().read_text())
        return data if isinstance(data,dict) else {}
    except (OSError,ValueError):
        return {}


def project_hooks_path(project_root) -> Path:
    """Canonical ``.agents/hooks.json`` path for a project root."""
    return (Path(project_root) / PROJECT_HOOKS_RELPATH).resolve()


def _config_hash(project_root) -> str:
    return hashlib.sha256(project_hooks_path(project_root).read_bytes()).hexdigest()


def approve_project_hooks(project_root, operator, *, expected_hash=None, approved_at=None):
    """Explicit operator action; never callable as a model tool.

    ``expected_hash`` pins a reviewed revision: if supplied it must match the
    bytes on disk, so approving cannot be fooled by a config that changed
    between review and approval.
    """
    if operator.kind != 'human' or not set(operator.roles) & {'operator','admin'}:
        raise PermissionError('human operator approval required for repository hooks')
    path=project_hooks_path(project_root)
    if not path.is_file():
        raise FileNotFoundError(f'no project hooks configuration at {path}')
    raw=path.read_bytes()
    if len(raw)>MAX_BYTES:
        raise ValueError('hooks configuration exceeds size limit')
    json.loads(raw)
    digest=hashlib.sha256(raw).hexdigest()
    if expected_hash is not None and str(expected_hash).lower()!=digest:
        raise ValueError('hooks.json hash does not match the reviewed revision')
    trust=_read_private_trust()
    trust[str(path)]={'sha256':digest,'tenant_id':operator.tenant_id,
                      'operator_id':operator.subject_id,
                      'approved_at':approved_at or _now()}
    atomic_private(_trust_path(),json.dumps(trust).encode())
    return trust[str(path)]


def trusted_project_hooks():
    """Return the approved project hook entries (path, hash, operator, date)."""
    entries=[]
    for path, record in sorted(_read_private_trust().items()):
        if not isinstance(record,dict):
            continue
        entries.append({'path':path,'sha256':record.get('sha256',''),
                        'operator_id':record.get('operator_id',''),
                        'approved_at':record.get('approved_at','')})
    return entries


def revoke_project_hooks(project_root):
    """Remove the approval for a project; returns whether one was present."""
    path=str(project_hooks_path(project_root))
    trust=_read_private_trust()
    if path not in trust:
        return False
    del trust[path]
    atomic_private(_trust_path(),json.dumps(trust).encode())
    return True


def _now() -> str:
    from nexus_core.kernel.models import utc_now
    return utc_now()


class HookRunner:
    def __init__(self, context, *, project_root=None, engagement_id=None, workspace=None):
        self.context=context
        self.audit=AuditWriter(context.store)
        self.project_trusted=False
        self.entries=[]
        self.verifiers=[]
        self.configuration_errors=[]
        self.engagement_id=engagement_id if engagement_id is not None else getattr(context,'engagement_id',None)
        # The workspace the hooks run in is supplied explicitly (or derived from
        # the environment), never silently from the process cwd: REPL, headless
        # and worker must agree on the same directory for the same engagement.
        self.workspace=str(workspace or os.getenv('NEXUS_WORKSPACE_ROOT') or Path.cwd())
        self.root=Path(project_root).resolve() if project_root else Path(self.workspace).resolve()
        global_path=resolve_xdg_paths().config_dir/'hooks.json'
        paths=[(global_path,False)]
        if project_root:
            paths.append((self.root/PROJECT_HOOKS_RELPATH,True))
        for path,project in paths:
            if not path.is_file():
                continue
            try:
                canonical=path.resolve()
                raw=canonical.read_bytes()
                if len(raw)>MAX_BYTES:
                    raise ValueError('configuration size limit')
                if project:
                    trusted=_read_private_trust().get(str(canonical),{})
                    if trusted.get('sha256')!=hashlib.sha256(raw).hexdigest() or trusted.get('tenant_id')!=context.tenant_id:
                        self.record('hook.untrusted',{'path':str(canonical)},'deny')
                        continue
                    self.project_trusted=True
                data=json.loads(raw)
                if not isinstance(data,dict):
                    raise ValueError('configuration must be an object')
                hooks=data.get('hooks',{})
                if not isinstance(hooks,dict):
                    raise ValueError('hooks must be an event mapping')
                workspace=str(canonical.parent) if project else self.workspace
                for event,entries in hooks.items():
                    if event not in EVENTS or not isinstance(entries,list):
                        raise ValueError('invalid hook event/list')
                    for entry in entries:
                        self.entries.append((event,self._entry(entry,30),workspace))
                for entry in data.get('verifiers',[]):
                    self.verifiers.append((self._entry(entry,60),workspace))
            except (OSError,ValueError,TypeError,KeyError) as exc:
                self.configuration_errors.append(f'{path}: invalid configuration')
                self.record('hook.failed',{'path':str(path),'error':str(exc)[:500]},'error')

    @staticmethod
    def _entry(entry,default_timeout):
        if not isinstance(entry,dict):
            raise ValueError('hook entry must be an object')
        argv=entry.get('command')
        argv=shlex.split(argv) if isinstance(argv,str) else argv
        if not isinstance(argv,list) or not argv or not all(isinstance(v,str) and v for v in argv):
            raise ValueError('command must be an argv list or shlex string')
        timeout=float(entry.get('timeout',default_timeout))
        if not math.isfinite(timeout) or not 0<timeout<=300:
            raise ValueError('timeout must be finite, positive and <=300')
        fail_closed=entry.get('fail_closed',True)
        if type(fail_closed) is not bool:
            raise ValueError('fail_closed must be boolean')
        return {**entry,'command':argv,'timeout':timeout,'fail_closed':fail_closed}

    def record(self,action,payload,decision='allow'):
        ctx=self.context
        self.audit.append(tenant_id=ctx.tenant_id,trace_id=ctx.trace_id,
            actor_id=ctx.identity.subject_id,action=action,resource_type='run',
            resource_id=ctx.run_id,payload=payload,decision=decision)

    async def execute(self,entry,workspace,payload):
        sanitized=self.audit._sanitize(payload)
        # These are runtime-assigned correlation identifiers, not credentials.
        for key in ('event','session_id','run_id','tool_id'):
            if key in payload:
                sanitized[key]=payload[key]
        encoded=json.dumps(sanitized,default=str).encode()
        if len(encoded)>MAX_BYTES:
            return {'error':'input size limit'}
        argv=entry['command']
        try:
            _,sandbox,_=SandboxPolicy.resolve(workspace_root=workspace,allowed_programs=(argv[0],))
            options={'image':os.getenv('NEXUS_HOOK_IMAGE','python:3.12-alpine')} if isinstance(sandbox,OCISandbox) else {}
            async with sandbox.open_stdio(argv,**options) as process:
                async def exchange():
                    async def write():
                        process.stdin.write(encoded)
                        await process.stdin.drain()
                        process.stdin.close()
                    async def read():
                        chunks=[];size=0
                        while True:
                            chunk=await process.stdout.read(4096)
                            if not chunk: break
                            size+=len(chunk)
                            if size>MAX_BYTES:
                                raise ValueError('output size limit')
                            chunks.append(chunk)
                        return b''.join(chunks)
                    _,raw=await asyncio.gather(write(),read())
                    await process.wait()
                    return raw
                raw=await asyncio.wait_for(exchange(),entry['timeout'])
                if process.returncode!=0:
                    return {'error':f'exit {process.returncode}'}
                if not raw.strip():
                    return {'decision':'allow'}
                data=json.loads(raw)
                if not isinstance(data,dict) or data.get('decision','allow') not in {'allow','block'}:
                    raise ValueError('invalid hook decision')
                if data.get('decision')=='block' and not isinstance(data.get('reason'),str):
                    raise ValueError('block requires reason')
                return data
        except asyncio.TimeoutError:
            return {'error':'timeout'}
        except (OSError,ValueError,PermissionError,TypeError) as exc:
            return {'error':f'{type(exc).__name__}: {exc}'[:500]}

    async def emit(self,event,**extra):
        if event not in EVENTS:
            raise ValueError('unknown hook event')
        ctx=self.context
        payload={'event':event,'session_id':ctx.session_id,'run_id':ctx.run_id,
                 'engagement_id':self.engagement_id,'workspace':self.workspace,**extra}
        blockers=[]
        for configured,entry,workspace in self.entries:
            if configured!=event: continue
            result=await self.execute(entry,workspace,payload)
            details={'event':event,'name':entry.get('name','hook'),**result}
            if 'error' in result:
                self.record('hook.failed',details,'error')
            elif result.get('decision')=='block':
                # Only pre-tool and stop have blocking semantics.
                self.record('hook.blocked',details,'deny')
                if event in {'pre_tool_use','stop'}:
                    blockers.append(result['reason'][:2000])
            else:
                self.record('hook.executed',details)
        return blockers

    async def verify_stop(self,**payload):
        blockers=list(self.configuration_errors)
        blockers.extend(await self.emit('stop',**payload))
        for entry,workspace in self.verifiers:
            name=entry.get('name','verifier')
            self.record('verifier.executed',{'name':name})
            result=await self.execute(entry,workspace,payload)
            if 'error' in result:
                action='verifier.timeout' if result['error']=='timeout' else 'verifier.failed'
                self.record(action,{'name':name,**result},'deny' if entry['fail_closed'] else 'error')
                if entry['fail_closed']:
                    reason=f"{name}: {result['error']}"
                    blockers.append(reason)
                    self.record('verifier.blocked',{'name':name,'reason':reason},'deny')
            elif result.get('decision')=='block':
                blockers.append(result['reason'][:2000])
                self.record('verifier.blocked',{'name':name,**result},'deny')
            else:
                self.record('verifier.passed',{'name':name})
        return blockers


__all__ = [
    'EVENTS', 'MAX_BYTES', 'PROJECT_HOOKS_RELPATH', 'HookRunner',
    'approve_project_hooks', 'trusted_project_hooks', 'revoke_project_hooks',
    'project_hooks_path',
]
