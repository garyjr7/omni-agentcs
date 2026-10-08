"""U-01: typed chips, exact payloads, bounded private side-buffer."""
import pytest


def test_large_paste_roundtrip_and_literal_marker(tui_factory):
    ui = tui_factory(enable_completion=False).session
    text = ('á\t世界\n' * 14000)
    ui._input.insert_text('before [Pegado #1] ')
    ui.paste_text(text)
    ui._input.insert_text(' between ')
    ui.paste_text('Z'*2000)
    ui._input.insert_text(' after')
    assert len(ui._input.text) < 80
    assert ui.input_document.render().count('caracteres') == 2
    assert ui.input_document.reconstruct() == 'before [Pegado #1] '+text+' between '+'Z'*2000+' after'
    ui._accept(ui._input)
    assert ui._answers.get_nowait().endswith('Z'*2000+' after')
    assert text not in ui.transcript


def test_chip_expand_edit_delete(tui_factory):
    ui = tui_factory(enable_completion=False).session
    ui.paste_text('x'*1500)
    ui.expand_paste()
    ui._input.insert_text('edit')
    assert ui.input_document.reconstruct() == 'x'*1500+'edit'
    ui.paste_text('z'*1500)
    ui.delete_paste()
    assert ui.input_document.reconstruct() == 'x'*1500+'edit'


def test_bracketed_paste_sends_intact_and_history_recovers(tui_factory, tmp_path):
    path = tmp_path / 'history'
    ui = tui_factory(history_path=path)
    text = 'a\n\tb世界\n' * 15000
    import threading
    sender = threading.Thread(target=ui.pipe.send_text, args=('\x1b[200~'+text+'\x1b[201~\r',), daemon=True)
    sender.start()
    assert ui.session.prompt() == text
    sender.join(timeout=2)
    ui.session.close()
    other = tui_factory(history_path=path)
    other.pipe.send_text('\x1b[A\r')
    assert other.session.prompt() == text


def test_paste_document_persists_and_recovers(tmp_path):
    from nexus_core.cli.tui.paste import InputDocument
    path = tmp_path / 'draft.json'
    doc = InputDocument(path=path)
    doc.insert_paste(0, 'a'*100000)
    restored = InputDocument(path=path)
    assert restored.reconstruct() == 'a'*100000
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError):
        doc.insert_paste(1, 'b'*(doc.max_bytes+1))
    assert doc.reconstruct() == 'a'*100000


def test_secret_paste_is_not_persisted(tui_factory,tmp_path):
    ui = tui_factory(history_path=tmp_path/'history', enable_completion=False).session
    ui._secret_mode = True
    ui.paste_text('secret'*1000)
    assert ui._input.text == 'secret'*1000
    assert not (tmp_path/'history.draft.json').exists()
