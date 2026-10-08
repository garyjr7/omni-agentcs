"""P0-2: authenticated scope is mandatory unless the operator opts into lab."""
from unittest.mock import MagicMock
import pytest
from nexus_core.scope import ScopeValidator, ScopeSignatureInvalid
from nexus_core.tests.unit.test_scope import make_scope


def test_governed_mode_rejects_unsigned_scope(monkeypatch):
    monkeypatch.delenv('NEXUS_SCOPE_MODE', raising=False)
    with pytest.raises(ScopeSignatureInvalid):
        ScopeValidator(make_scope()).validate('203.0.113.10')


def test_lab_mode_audits_unsigned_acceptance(monkeypatch):
    monkeypatch.setenv('NEXUS_SCOPE_MODE', 'lab')
    events = []
    ScopeValidator(make_scope(), audit=lambda action, detail: events.append(action)).validate('203.0.113.10')
    assert events == ['scope.unsigned_accepted']


def test_worker_bootstrap_loads_secrets_from_keyring(monkeypatch, tmp_path):
    from nexus_core.config import bootstrap, secrets
    monkeypatch.delenv('NEXUS_SCOPE_SIGNING_SECRET', raising=False)
    import sys
    from types import SimpleNamespace
    keyring = SimpleNamespace(get_password=MagicMock(return_value='test-signing-secret'))
    monkeypatch.setitem(sys.modules, 'keyring', keyring)
    index = tmp_path / 'index.json'
    index.write_text('{"names": ["NEXUS_SCOPE_SIGNING_SECRET"]}')
    backend = secrets.KeyringBackend(index_path=index)
    monkeypatch.setattr(secrets, 'select_backend', lambda **kw: backend)
    bootstrap.bootstrap_secrets_and_config(tmp_path, load_configuration=False)
    import os
    assert os.environ['NEXUS_SCOPE_SIGNING_SECRET'] == 'test-signing-secret'
    keyring.get_password.assert_called_once_with(secrets.SERVICE_NAME, 'NEXUS_SCOPE_SIGNING_SECRET')


def test_worker_rejects_unsigned_scope_in_governed_mode(monkeypatch):
    from nexus_core.kernel.scope_loader import load_engagement_scope
    monkeypatch.setenv('NEXUS_SCOPE_MODE', 'governed')
    monkeypatch.setattr('nexus_core.kernel.scope_loader.EngagementStore', lambda s: MagicMock(get=lambda *a: make_scope()))
    audit = MagicMock()
    monkeypatch.setattr('nexus_core.kernel.scope_loader.AuditWriter', lambda s: audit)
    with pytest.raises(ScopeSignatureInvalid):
        load_engagement_scope(MagicMock(), 'system', 'eng-1')
    assert audit.append.call_args.kwargs['action'] == 'scope.denied'


def test_signed_scope_without_key_fails_even_in_lab(monkeypatch):
    monkeypatch.setenv('NEXUS_SCOPE_MODE', 'lab')
    with pytest.raises(ScopeSignatureInvalid):
        ScopeValidator(make_scope(signature='invalid')).validate('203.0.113.10')


def test_governed_valid_signature_and_lab_tamper(monkeypatch):
    from nexus_core.tests.unit.test_scope import sign
    secret = 'offline-test-key'
    scope = sign(make_scope(), secret)
    assert ScopeValidator(scope, signing_secret=secret, mode='governed').validate('203.0.113.10')
    with pytest.raises(ScopeSignatureInvalid):
        ScopeValidator(scope, signing_secret='wrong-key', mode='lab').validate('203.0.113.10')


def test_lab_acceptance_is_in_durable_audit(tmp_path, monkeypatch):
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.kernel.scope_loader import load_engagement_scope
    from nexus_core.kernel.audit import AuditWriter
    from nexus_core.scope import EngagementStore
    monkeypatch.setenv('NEXUS_SCOPE_MODE','lab')
    store = ControlStore(tmp_path / 'lab.db')
    store.initialize()
    EngagementStore(store).create(make_scope())
    assert load_engagement_scope(store,'system','eng-1')
    rows = AuditWriter(store).export('system')
    assert rows[-1]['action'] == 'scope.unsigned_accepted'
    assert rows[-1]['payload']['mode'] == 'lab'
    assert AuditWriter(store).verify_chain() == (True,None)
