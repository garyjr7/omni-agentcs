"""Named credentials must not survive malformed model output persistence."""
import json

import pytest

from nexus_core.agent.memory import _sanitize_content_for_persistence
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore


@pytest.mark.parametrize("content,secret", [
    ('{"action":"tool_call","password":"secret123"', 'secret123'),
    ('before {"args":{"password":"secret123","hash":"abcdef"}}', 'abcdef'),
    ('password=MiClave123 in config', 'MiClave123'),
    ("'password': 'two words'", 'two words'),
    ('"password": "escaped\\"secret"', 'secret'),
    ('"password": "unterminated secret123', 'secret123'),
    ('authorization=Bearer secret123', 'secret123'),
    ('{"password": ["secret123", "other"]}', 'secret123'),
    ('{"password":"a"} prose {"hash":"secret123"}', 'secret123'),
    ('```json\n{"api-key":"secret123"\n```', 'secret123'),
    ('PRIVATE_KEY: "secret123"', 'secret123'),
])
def test_named_secret_is_redacted(content, secret):
    result = _sanitize_content_for_persistence(content)
    assert secret not in result
    assert '[REDACTED]' in result
    assert _sanitize_content_for_persistence(result) == result
    assert secret not in json.dumps(AuditWriter._sanitize({"raw_response": content}))


def test_integrity_fields_and_prose_preserved():
    content = '{"event_hash":"abc","content_sha256":"abc","raw_sha256":"abc"}'
    assert _sanitize_content_for_persistence(content) == content
    assert _sanitize_content_for_persistence('ordinary response') == 'ordinary response'


def test_store_sanitizes_even_without_append_step(tmp_path):
    store = ControlStore(tmp_path / 'state.db')
    store.initialize()
    conversation = store.create_conversation('system', 'tester', 'test')
    store.append_message('system', conversation['id'], 'assistant',
                         '{"password":"secret123"', metadata={'raw_response': 'hash=abcdef'})
    with store.connect() as conn:
        row = conn.execute('SELECT content, metadata FROM kernel_messages').fetchone()
    assert 'secret123' not in row['content']
    assert 'abcdef' not in row['metadata']


def test_run_event_and_task_results_are_sanitized(tmp_path):
    store = ControlStore(tmp_path / 'events.db')
    store.initialize()
    run = store.create_run('system', {})
    store.append_run_event('system', run['id'], 'llm.error', {'raw_response': 'password=secret123'})
    task = store.enqueue_task(tenant_id='system', run_id=run['id'], task_type='test', payload={})
    claimed = store.claim_task('test-worker')
    store.complete_task(task['id'], 'test-worker', result={'summary': 'password=secret123'}, lease_generation=claimed["lease_generation"])
    with store.connect() as conn:
        for table, column in [('kernel_run_events', 'payload'), ('kernel_tasks', 'result'),
                              ('kernel_runs', 'result'), ('kernel_outbox', 'payload')]:
            for row in conn.execute(f'SELECT {column} FROM {table}').fetchall():
                assert 'secret123' not in str(row[column])
