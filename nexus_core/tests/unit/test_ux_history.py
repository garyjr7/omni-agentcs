"""U-02 regressions: exact, private and bounded history."""
import json
import stat
import pytest
from nexus_core.cli.tui.history import file_history


def test_history_preserves_multiline_unicode_tabs(tmp_path):
    path = tmp_path / 'history'
    text = 'hola\n\t世界\nfin\n'
    file_history(path).store_string(text)
    assert list(file_history(path).load_history_strings()) == [text]
    assert json.loads(path.read_text().splitlines()[-1])['version'] == 1
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_migration_backup_is_exact(tmp_path):
    path = tmp_path / 'history'
    original = b'first\nsecond\n'
    path.write_bytes(original)
    assert list(file_history(path).load_history_strings()) == ['second','first']
    assert path.with_suffix('.legacy.bak').read_bytes() == original
    assert json.loads(path.read_text().splitlines()[0])['version'] == 1


def test_history_retention_and_corruption(tmp_path):
    from nexus_core.cli.tui.history import JsonHistory
    path = tmp_path / 'history'
    history = JsonHistory(path, max_entries=2)
    for entry in ['one','two','three']:
        history.store_string(entry)
    assert list(history.load_history_strings()) == ['three','two']
    with path.open('a') as stream:
        stream.write('{bad json}\n')
    with pytest.raises(ValueError, match='history'):
        list(JsonHistory(path).load_history_strings())


def test_history_oversize_fails_without_losing_previous(tmp_path):
    from nexus_core.cli.tui.history import JsonHistory
    path = tmp_path / 'history'
    history = JsonHistory(path, max_bytes=100)
    history.store_string('one')
    with pytest.raises(ValueError):
        history.store_string('x'*101)
    assert list(history.load_history_strings()) == ['one']
