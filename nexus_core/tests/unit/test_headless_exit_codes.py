"""P0-5: versioned CI result semantics."""
from types import SimpleNamespace
from nexus_core.cli.headless import result_payload


def payload(status, verified=False):
    return result_payload(SimpleNamespace(status=status, completion_verified=verified), 'r1')


def test_max_iterations_exit_code_is_1():
    assert payload('max_iterations')['exit_code'] == 1


def test_clarification_exit_code_is_1():
    assert payload('clarification')['exit_code'] == 1


def test_blocked_by_approval_exit_code_is_2():
    assert payload('blocked')['exit_code'] == 2


def test_governance_denial_exit_code_is_4():
    assert payload('scope_violation_aborted')['exit_code'] == 4


def test_completed_and_verified_exit_code_is_0():
    assert payload('completed', True)['exit_code'] == 0
    assert payload('completed', False)['exit_code'] == 1


def test_run_complete_has_versioned_contract():
    result = payload('max_iterations')
    assert result['termination_reason'] == 'max_iterations'
    assert result['completion_verified'] is False
    assert result['exit_code_version'] == 1


def test_provider_error_and_sigint_exit_codes():
    assert payload('provider_error')['exit_code'] == 3
    assert payload('cancelled')['exit_code'] == 130


def test_headless_runtime_max_iterations_returns_1(tmp_path, monkeypatch):
    import io
    import json
    from nexus_core.cli import headless
    from nexus_core.cli.session import OmniSession
    from nexus_core.kernel.control_store import ControlStore
    store = ControlStore(tmp_path / 'run.db')
    store.initialize()
    session = OmniSession(store=store,tenant_id='system',engagement=None,use_tui=False,
                          operator_id='tester',llm_client=object())
    async def exhausted(**kwargs):
        return SimpleNamespace(status='max_iterations',completion_verified=False)
    monkeypatch.setattr(headless,'run_react_loop',exhausted)
    output = io.StringIO()
    assert headless.run_headless(session,'test',stream=output) == 1
    assert json.loads(output.getvalue())['termination_reason'] == 'max_iterations'


def test_headless_runtime_provider_failure_has_run_complete(tmp_path, monkeypatch):
    import io
    import json
    from nexus_core.cli import headless
    from nexus_core.cli.session import OmniSession
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.kernel.errors import ProviderFailure
    store = ControlStore(tmp_path / 'run.db')
    store.initialize()
    session = OmniSession(store=store,tenant_id='system',engagement=None,use_tui=False,
                          operator_id='tester',llm_client=object())
    async def failed(**kwargs):
        raise ProviderFailure('offline RPC timeout')
    monkeypatch.setattr(headless,'run_react_loop',failed)
    output = io.StringIO()
    assert headless.run_headless(session,'test',stream=output) == 3
    result = json.loads(output.getvalue())
    assert result['type'] == 'run.complete' and not result['completion_verified']
