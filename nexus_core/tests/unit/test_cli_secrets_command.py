"""The ``/secrets`` meta command never prints a value and stores safely (H2)."""

from __future__ import annotations

import pytest

from nexus_core.cli import commands
from nexus_core.config import secrets as secrets_module
from nexus_core.config.secrets import FileBackend, SecretStore


@pytest.fixture()
def store(tmp_path, monkeypatch):
    backend = FileBackend(tmp_path / "secrets.json")
    monkeypatch.setattr(secrets_module, "select_backend", lambda **_: backend)
    return SecretStore(backend)


def test_set_prompts_and_never_prints_the_value(store, monkeypatch, capsys):
    monkeypatch.setattr(commands.getpass, "getpass", lambda *a, **k: "super-secret-value")
    commands.cmd_secrets(None, ["set", "GROQ_API_KEY"])
    out = capsys.readouterr().out
    assert "super-secret-value" not in out
    assert "GROQ_API_KEY" in out
    assert store.get("GROQ_API_KEY") == "super-secret-value"


def test_list_shows_names_only(store, capsys):
    store.set("OPENAI_API_KEY", "sk-leak-me-not")
    commands.cmd_secrets(None, ["list"])
    out = capsys.readouterr().out
    assert "OPENAI_API_KEY" in out
    assert "sk-leak-me-not" not in out
    assert store.backend_name in out


def test_delete_removes_the_secret(store, capsys):
    store.set("GROQ_API_KEY", "x")
    commands.cmd_secrets(None, ["delete", "GROQ_API_KEY"])
    capsys.readouterr()
    assert store.get("GROQ_API_KEY") is None


def test_set_without_name_errors(store, capsys):
    commands.cmd_secrets(None, ["set"])
    assert "uso" in capsys.readouterr().out.lower()


def test_unknown_action_errors(store, capsys):
    commands.cmd_secrets(None, ["frobnicate"])
    assert "desconocida" in capsys.readouterr().out


def test_import_env_reports_names_only(store, monkeypatch, capsys):
    monkeypatch.setenv("GROQ_API_KEY", "env-secret-value")
    commands.cmd_secrets(None, ["import-env"])
    out = capsys.readouterr().out
    assert "GROQ_API_KEY" in out
    assert "env-secret-value" not in out
    assert store.get("GROQ_API_KEY") == "env-secret-value"


def test_command_is_registered():
    assert "/secrets" in commands.COMMANDS
