"""Secret storage: file/keyring backends, env loading and the /secrets command (H2)."""

from __future__ import annotations

import json
import stat
import sys
import types

import pytest

from nexus_core.config.secrets import (
    FileBackend,
    KeyringBackend,
    SecretStore,
    import_from_env,
    load_secrets_into_env,
    select_backend,
)


def test_file_backend_round_trip(tmp_path):
    backend = FileBackend(tmp_path / "secrets.json")
    backend.set("GROQ_API_KEY", "s3cret")
    assert backend.get("GROQ_API_KEY") == "s3cret"
    assert backend.names() == ["GROQ_API_KEY"]
    assert backend.delete("GROQ_API_KEY") is True
    assert backend.get("GROQ_API_KEY") is None
    assert backend.delete("GROQ_API_KEY") is False


def test_file_backend_writes_0600(tmp_path):
    path = tmp_path / "secrets.json"
    FileBackend(path).set("A", "1")
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_store_rejects_empty_values(tmp_path):
    store = SecretStore(FileBackend(tmp_path / "s.json"))
    with pytest.raises(ValueError):
        store.set("", "v")
    with pytest.raises(ValueError):
        store.set("NAME", "")


def test_store_names_do_not_expose_values(tmp_path):
    store = SecretStore(FileBackend(tmp_path / "s.json"))
    store.set("OPENAI_API_KEY", "sk-very-secret")
    assert store.names() == ["OPENAI_API_KEY"]


def test_select_backend_falls_back_to_file_without_keyring(monkeypatch):
    monkeypatch.setattr(sys, "modules", {**sys.modules, "keyring": None})
    assert select_backend().name == "file"


def test_keyring_backend_uses_the_keyring(monkeypatch, tmp_path):
    stored: dict[tuple[str, str], str] = {}
    fake = types.SimpleNamespace(
        get_password=lambda service, name: stored.get((service, name)),
        set_password=lambda service, name, value: stored.__setitem__((service, name), value),
        delete_password=lambda service, name: stored.pop((service, name), None),
    )
    monkeypatch.setitem(sys.modules, "keyring", fake)
    backend = KeyringBackend(tmp_path / "index.json")
    backend.set("GROQ_API_KEY", "k")
    assert stored[("omni-agentcs", "GROQ_API_KEY")] == "k"
    assert backend.get("GROQ_API_KEY") == "k"
    assert backend.names() == ["GROQ_API_KEY"]
    assert backend.delete("GROQ_API_KEY") is True
    assert backend.names() == []


def test_keyring_backend_index_file_has_no_values(tmp_path, monkeypatch):
    fake = types.SimpleNamespace(
        get_password=lambda *a: "value",
        set_password=lambda *a: None,
        delete_password=lambda *a: None,
    )
    monkeypatch.setitem(sys.modules, "keyring", fake)
    index = tmp_path / "index.json"
    KeyringBackend(index).set("TOKEN", "top-secret-value")
    assert "top-secret-value" not in index.read_text(encoding="utf-8")
    assert json.loads(index.read_text(encoding="utf-8"))["names"] == ["TOKEN"]


def test_load_secrets_into_env_only_fills_unset(tmp_path):
    store = SecretStore(FileBackend(tmp_path / "s.json"))
    store.set("GROQ_API_KEY", "from-store")
    store.set("OPENAI_API_KEY", "from-store-2")
    env = {"OPENAI_API_KEY": "from-shell"}
    applied = load_secrets_into_env(env, store=store)
    assert applied == ["GROQ_API_KEY"]
    assert env["GROQ_API_KEY"] == "from-store"
    assert env["OPENAI_API_KEY"] == "from-shell"


def test_load_secrets_into_env_is_a_noop_without_store(tmp_path):
    store = SecretStore(FileBackend(tmp_path / "empty.json"))
    env: dict[str, str] = {}
    assert load_secrets_into_env(env, store=store) == []
    assert env == {}


def test_import_from_env_only_takes_present_known_keys(tmp_path):
    store = SecretStore(FileBackend(tmp_path / "s.json"))
    env = {"GROQ_API_KEY": "g", "PATH": "/bin", "OPENAI_API_KEY": ""}
    imported = import_from_env(env, store=store)
    assert imported == ["GROQ_API_KEY"]
    assert store.names() == ["GROQ_API_KEY"]
