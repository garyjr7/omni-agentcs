#!/usr/bin/env python3
"""Offline reproductions of S-01/S-02/S-03/O-01/O-05. Exit 0 iff all closed."""
from __future__ import annotations
import io
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def sandbox_probe(root):
    from nexus_core.kernel.sandbox import OCISandbox, sandbox_for_environment
    from nexus_core.kernel.sandbox_modes import SandboxPolicy
    with patch.dict(os.environ, NEXUS_ENV='development', NEXUS_SANDBOX_MODE='oci'):
        mode, executor, guarantees = SandboxPolicy.resolve(workspace_root=root)
        assert mode.value == 'oci' and isinstance(executor, OCISandbox)
        assert isinstance(sandbox_for_environment(root), OCISandbox)
        assert guarantees['filesystem_isolation'] is True


def scope_probe(root):
    from datetime import datetime, timedelta, timezone
    from nexus_core.scope import EngagementScope, ScopeSignatureInvalid, EngagementStore
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.kernel.scope_loader import load_engagement_scope
    from nexus_core.kernel.audit import AuditWriter
    now = datetime.now(timezone.utc)
    scope = EngagementScope(engagement_id='unsigned', tenant_id='system', name='probe',
                            client='offline', owner_id='probe', valid_from=(now-timedelta(days=1)).isoformat(),
                            valid_until=(now+timedelta(days=1)).isoformat(), cidrs=('203.0.113.0/24',),domains=(),urls=(),exclusions=())
    store = ControlStore(root / 'scope.db')
    store.initialize()
    EngagementStore(store).create(scope)
    with patch.dict(os.environ, NEXUS_SCOPE_MODE='governed'):
        try:
            load_engagement_scope(store, 'system', 'unsigned')
        except ScopeSignatureInvalid:
            assert any(e['action'] == 'scope.denied' for e in AuditWriter(store).export('system'))
        else:
            raise AssertionError('unsigned governed scope accepted')


def mcp_probe(root):
    from nexus_core.integrations.mcp.client import MCPServerConfig, MCPTool
    from nexus_core.integrations.mcp.gateway_bridge import make_definition_factory
    from nexus_core.agent.subagents import SUBAGENTS, permits
    try:
        make_definition_factory(MCPServerConfig('x', allowed_tools=('exec',)), MCPTool('x','exec',''))('system')
    except ValueError:
        pass
    else:
        raise AssertionError('MCP accepted without manifest')
    assert all(not permits(p, 'mcp.x.exec') for p in SUBAGENTS if p.read_only)


def fact_probe(root):
    from nexus_core.agent.planner import build_plan
    from nexus_core.agent.evidence import annotate_findings, fabricated_evidence
    from nexus_core.kernel.blackboard import Blackboard
    from nexus_core.kernel.control_store import ControlStore
    store = ControlStore(root / 'facts.db')
    store.initialize()
    board = Blackboard(store)
    for kind in ('host','endpoint','access','privilege','artifact'):
        board.record(tenant_id='system', engagement_id='eng', fact_type=kind,key=kind,
                     value={},source='agent',created_by='probe',verified=False)
    plan = build_plan(counts=board.summary('system','eng')['counts'])
    assert plan.current == 'recon'
    _, stats = annotate_findings([{'title':'10.10.10.10 acceso root confirmado'},
                                  {'title':'fabricated-9999 compromise'}],
                                 observations=[{'output':{'host':'10.10.10.10','state':'alive'}}])
    assert stats['grounded'] == 0 and fabricated_evidence(stats)


def headless_probe(root):
    from nexus_core.cli.session import OmniSession
    from nexus_core.cli.headless import run_headless
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.llm.abstraction import LLMResponse, LLMProvider

    class OfflineClient:
        async def complete(self, messages, **kwargs):
            return LLMResponse(content=json.dumps(dict(action='request_clarification',
                               thought='probe', question='offline probe')),
                               model='offline-probe',provider=LLMProvider.FAKE)

    store = ControlStore(root / 'headless.db')
    store.initialize()
    session = OmniSession(store=store, tenant_id='system', engagement=None,
                          llm_client=OfflineClient(),use_tui=False,operator_id='probe')
    output = io.StringIO()
    with patch.dict(os.environ, NEXUS_PREFLIGHT_BINARIES='0', NEXUS_SANDBOX_MODE='local_strict'):
        code = run_headless(session, 'Offline exit-code probe', stream=output, max_iterations=1)
    payload = json.loads(output.getvalue().splitlines()[-1])
    assert code == payload['exit_code'] == 1
    assert payload['termination_reason'] == 'clarification'
    assert payload['completion_verified'] is False


def main():
    failures = []
    with TemporaryDirectory(prefix='omni-phase0-') as directory:
        for name, probe in [('P0-1',sandbox_probe),('P0-2',scope_probe),('P0-3',mcp_probe),
                            ('P0-4',fact_probe),('P0-5',headless_probe)]:
            try:
                probe(Path(directory))
                print(f'{name}: CLOSED')
            except Exception as exc:
                failures.append(name)
                print(f'{name}: FAILED ({type(exc).__name__}: {exc})')
    print(f'{len(failures)} fallos reproducidos')
    return int(bool(failures))


if __name__ == '__main__':
    raise SystemExit(main())
