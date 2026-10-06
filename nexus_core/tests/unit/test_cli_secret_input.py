"""Secure secret entry: masked in the TUI, never echoed, never in history."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from nexus_core.cli import commands
from nexus_core.cli.tui.session import TuiSession
from nexus_core.config import secrets as secrets_module
from nexus_core.config.secrets import FileBackend, SecretStore

SECRET = "super-secret-value"


@pytest.fixture()
def store(tmp_path, monkeypatch):
    backend = FileBackend(tmp_path / "secrets.json")
    monkeypatch.setattr(secrets_module, "select_backend", lambda **_: backend)
    return SecretStore(backend)


class _SessionStub:
    """Minimal session exposing the ``secure_input`` seam ``cmd_secrets`` uses."""

    def __init__(self, value=SECRET):
        self.value = value
        self.prompts: list[str] = []

    def secure_input(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.value


# ------------------------------------------------------------- TUI masked input


def test_prompt_secret_returns_value_without_echoing_it(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text(f"{SECRET}\n")
    assert ui.session.prompt_secret("└─🔒 valor: ") == SECRET
    ui.session.flush()
    transcript = ui.session.transcript
    assert SECRET not in transcript
    assert "••••••" in transcript


def test_prompt_secret_restores_state_and_never_touches_history(tui_factory, tmp_path):
    path = tmp_path / "history"
    ui = tui_factory(history_path=path)
    original_prompt = ui.session.prompt_text
    ui.pipe.send_text(f"{SECRET}\n")
    ui.session.prompt_secret()
    ui.session.flush()
    assert ui.session._secret_mode is False
    assert ui.session.prompt_text == original_prompt
    assert not path.exists() or SECRET not in path.read_text()


def test_prompt_secret_is_masked_while_active(tui_factory):
    ui = tui_factory()
    # Feed the value, then assert the mask is in force right after the read.
    ui.pipe.send_text(f"{SECRET}\n")
    ui.session.prompt_secret()
    assert ui.session._secret_mode is False  # restored on exit


def test_prompt_secret_falls_back_to_getpass_without_tui(monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt: "from-getpass")
    session = TuiSession(use_tui=False)
    assert session.prompt_secret("p: ") == "from-getpass"


# ----------------------------------------------------------- OmniSession routing


def test_secure_input_prefers_the_injected_reader():
    from nexus_core.cli.session import OmniSession

    seen: list[str] = []
    session = OmniSession(store=None, use_tui=False, input_reader=lambda p: seen.append(p) or "v")
    assert session.secure_input("p: ") == "v"
    assert seen == ["p: "]


def test_secure_input_falls_back_to_getpass(monkeypatch):
    from nexus_core.cli.session import OmniSession

    monkeypatch.setattr("getpass.getpass", lambda prompt: "gp")
    session = OmniSession(store=None, use_tui=False)
    assert session.secure_input("p: ") == "gp"


# ------------------------------------------------------- /secrets visual contract


def test_set_uses_secure_input_and_reports_success(store, capsys):
    session = _SessionStub()
    commands.cmd_secrets(session, ["set", "GROQ_API_KEY"])
    out = capsys.readouterr().out
    assert "✓ Secreto GROQ_API_KEY guardado correctamente" in out
    assert SECRET not in out
    assert store.get("GROQ_API_KEY") == SECRET
    assert session.prompts and "GROQ_API_KEY" in session.prompts[0]


def test_rotate_reports_rotation(store, capsys):
    store.set("GROQ_API_KEY", "old")
    commands.cmd_secrets(_SessionStub(), ["rotate", "GROQ_API_KEY"])
    out = capsys.readouterr().out
    assert "✓ Secreto GROQ_API_KEY rotado correctamente" in out
    assert store.get("GROQ_API_KEY") == SECRET


def test_rotate_of_missing_secret_notes_creation(store, capsys):
    commands.cmd_secrets(_SessionStub(), ["rotate", "GROQ_API_KEY"])
    out = capsys.readouterr().out
    assert "no existía antes" in out


def test_empty_value_is_never_stored(store, capsys):
    commands.cmd_secrets(_SessionStub(value=""), ["set", "GROQ_API_KEY"])
    out = capsys.readouterr().out
    assert "no se modificó" in out
    assert store.get("GROQ_API_KEY") is None


def test_store_failure_is_reported_not_raised(store, capsys, monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("disk full")

    # ``cmd_secrets`` builds its own SecretStore over the patched backend, so the
    # failure has to be injected at the backend, not on this instance.
    monkeypatch.setattr(FileBackend, "set", boom)
    commands.cmd_secrets(_SessionStub(), ["set", "GROQ_API_KEY"])
    out = capsys.readouterr().out
    assert "no se pudo guardar GROQ_API_KEY" in out
    assert SECRET not in out


def test_read_secret_falls_back_to_getpass_without_session(monkeypatch):
    monkeypatch.setattr(commands.getpass, "getpass", lambda *a, **k: "gp")
    assert commands._read_secret(None, "p: ") == "gp"
    assert commands._read_secret(SimpleNamespace(), "p: ") == "gp"
