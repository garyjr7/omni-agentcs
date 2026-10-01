"""Real gateway/store/approval boundary, with transport prohibited."""
import asyncio
from dataclasses import replace

import pytest

from nexus_core.kernel.sessions import SessionRegistry
from nexus_core.tests.msf_support import context, scope, gateway_with_approvals, fake_client
from nexus_core.tools.handlers import msf_session_interact as module


def test_cross_engagement_denied_even_with_approval(tmp_path, monkeypatch):
    gw, audit, approvals, store = gateway_with_approvals(tmp_path)
    ctx = replace(context(scope()), store=store)
    SessionRegistry(store).register(session_uuid='foreign-session', tenant_id='system',
        engagement_id='other-engagement', run_id='original-run', session_type='shell',
        target_host='203.0.113.10', opened_by_tool='test')
    approval = approvals.request(ctx, 'execute:tool:nexus.session.interact')
    approvals.decide(approval['id'], 'system', 'reviewer', True)
    client = fake_client(monkeypatch, module)
    with pytest.raises(RuntimeError, match='post-condition'):
        asyncio.run(gw.invoke('nexus.session.interact',
            {'session_uuid': 'foreign-session', 'command': 'id'}, ctx,
            approval_id=approval['id']))
    client.authenticate.assert_not_awaited()
    client.run_in_session.assert_not_awaited()
    assert audit.verify_chain()[0]
