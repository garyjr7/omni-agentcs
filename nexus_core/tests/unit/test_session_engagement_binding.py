"""Ownership checks must fail before any Metasploit connection is opened."""
import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.sessions import SessionRegistry
from nexus_core.tests.msf_support import context, scope, fake_client
from nexus_core.tools.handlers import msf_session_interact as interact
from nexus_core.tools.handlers import msf_session_kill as kill
from nexus_core.tools.handlers import msf_session_list as listing


@pytest.fixture
def registered(tmp_path):
    store = ControlStore(tmp_path / 'sessions.db')
    store.initialize()
    ctx = replace(context(scope()), store=store)
    registry = SessionRegistry(store)
    registry.register(session_uuid='owned', tenant_id=ctx.tenant_id,
                      engagement_id=ctx.scope.engagement_id, run_id=ctx.run_id,
                      session_type='shell', target_host='203.0.113.10', opened_by_tool='test')
    registry.register(session_uuid='foreign', tenant_id=ctx.tenant_id,
                      engagement_id='other-engagement', run_id='another-run',
                      session_type='shell', target_host='203.0.113.11', opened_by_tool='test')
    return ctx, registry


@pytest.mark.parametrize('module,args', [
    (interact, {'session_uuid': 'foreign', 'command': 'whoami'}),
    (kill, {'session_uuid': 'foreign'}),
])
def test_session_denied_for_other_engagement(registered, monkeypatch, module, args):
    ctx, registry = registered
    client = fake_client(monkeypatch, module)
    handler = getattr(module, module.__name__.rsplit('.', 1)[1] + '_handler')
    result = asyncio.run(handler(args, ctx))
    assert result.verification_method == 'session_engagement_mismatch'
    assert not result.success
    client.authenticate.assert_not_awaited()
    client.stop_session.assert_not_awaited()
    client.run_in_session.assert_not_awaited()


@pytest.mark.parametrize('case,method', [
    ('unknown', 'session_not_registered'), ('closed', 'session_closed'),
    ('tenant', 'session_scope_required'), ('scope', 'session_scope_required'),
    ('expired', 'session_scope_required'), ('target', 'session_target_out_of_scope'),
])
def test_unauthorized_sessions_fail_closed(registered, monkeypatch, case, method):
    ctx, registry = registered
    uuid = 'owned'
    if case == 'unknown': uuid = 'missing'
    if case == 'closed': registry.close(ctx, uuid)
    if case == 'tenant': ctx = replace(ctx, tenant_id='other-tenant')
    if case == 'scope': ctx = replace(ctx, scope=None)
    if case == 'expired':
        ctx = replace(ctx, scope=replace(ctx.scope, valid_until=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat()))
    if case == 'target': ctx = replace(ctx, scope=replace(ctx.scope, cidrs=('198.51.100.0/24',)))
    client = fake_client(monkeypatch, interact)
    result = asyncio.run(interact.msf_session_interact_handler({'session_uuid': uuid, 'command': 'id'}, ctx))
    assert result.verification_method == method
    client.authenticate.assert_not_awaited()


def test_session_list_only_shows_current_engagement(registered, monkeypatch):
    ctx, registry = registered
    client = fake_client(monkeypatch, listing)
    client.list_sessions.return_value = {
        '1': {'uuid': 'owned', 'type': 'shell'},
        '2': {'uuid': 'foreign', 'type': 'shell', 'info': 'hidden'},
        '3': {'uuid': 'unregistered', 'type': 'shell'},
    }
    result = asyncio.run(listing.msf_session_list_handler({}, ctx))
    assert [item['uuid'] for item in result.output['sessions']] == ['owned']
    assert result.output['total'] == 1
    assert result.evidence['total'] == 1
    assert 'hidden' not in str(result.to_dict())


def test_session_cannot_be_reassigned(registered):
    ctx, registry = registered
    with pytest.raises(PermissionError):
        registry.register(session_uuid='owned', tenant_id=ctx.tenant_id,
                          engagement_id='other-engagement', run_id=ctx.run_id,
                          session_type='shell', target_host='203.0.113.10', opened_by_tool='test')
    assert registry.get(ctx.tenant_id, 'owned')['engagement_id'] == ctx.scope.engagement_id


def test_successful_kill_marks_registry_closed(registered, monkeypatch):
    ctx, registry = registered
    fake_client(monkeypatch, kill)
    assert asyncio.run(kill.msf_session_kill_handler({'session_uuid': 'owned'}, ctx)).success
    assert registry.get(ctx.tenant_id, 'owned')['closed_at']


def test_cli_inventory_filters_ownership(registered, monkeypatch):
    from nexus_core.cli.session import OmniSession
    ctx, registry = registered
    cli = OmniSession(store=ctx.store, tenant_id=ctx.tenant_id, use_tui=False)
    cli.engagement = ctx.scope
    monkeypatch.setattr('nexus_core.cli.session.fetch_sessions', lambda: {
        '1': {'uuid': 'owned'}, '2': {'uuid': 'foreign'}})
    assert list(cli.fetch_sessions()) == ['1']
    cli.engagement = None
    assert cli.fetch_sessions() == {}
