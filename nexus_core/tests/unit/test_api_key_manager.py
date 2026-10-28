"""API key manager: store layout, provider API and the ``omni auth`` command."""

from __future__ import annotations

import getpass
import os
import stat

import pytest

from nexus_core.cli import auth_cli
from nexus_core.cli.auth_cli import run_auth_command
from nexus_core.config import secrets as secrets_module
from nexus_core.config.secrets import (
    CONFIG_DIRNAME,
    LOGIN_PROVIDERS,
    FileBackend,
    SecretStore,
    default_secrets_path,
    delete_secret,
    get_secret,
    provider_env_var,
    resolve_api_key,
    secrets_file_report,
    set_secret,
)


@pytest.fixture()
def backend(tmp_path, monkeypatch):
    """Isolate every ``SecretStore()`` built inside the module under test."""
    file_backend = FileBackend(tmp_path / "secrets.json")
    monkeypatch.setattr(secrets_module, "select_backend", lambda **_: file_backend)
    return file_backend


def mode_of(path):
    return stat.S_IMODE(path.stat().st_mode)


# --- layout -------------------------------------------------------------------


def test_default_path_lives_in_the_omni_config_dir(onboarding_env):
    path = default_secrets_path()
    assert path.parent == onboarding_env.paths.config_dir
    assert path.parent.name == CONFIG_DIRNAME
    assert path.name == "secrets.json"


def test_file_backend_creates_a_private_directory_and_a_0600_file(tmp_path, monkeypatch):
    root = tmp_path / "config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(root))
    monkeypatch.setattr(secrets_module, "select_backend", lambda **_: FileBackend())
    set_secret("openai", "sk-typed-once")
    path = root / "omni" / "secrets.json"
    assert path.is_file()
    assert mode_of(path) == 0o600
    # Directories created by mkdir(mode=0o700) are filtered by the umask, so the
    # module clears group/other bits explicitly.
    assert mode_of(path.parent) & 0o077 == 0


def test_existing_world_readable_directory_is_tightened(tmp_path, monkeypatch):
    root = tmp_path / "config"
    (root / "omni").mkdir(parents=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(root))
    os.chmod(root / "omni", 0o755)
    FileBackend().set("OPENAI_API_KEY", "v")
    assert mode_of(root / "omni") & 0o077 == 0


def test_a_caller_supplied_path_never_chmods_its_parent(tmp_path):
    """``FileBackend('/srv/x/secrets.json')`` must not chmod ``/srv/x``."""
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o755)
    FileBackend(shared / "secrets.json").set("OPENAI_API_KEY", "v")
    assert mode_of(shared) == 0o755
    assert mode_of(shared / "secrets.json") == 0o600


# --- provider API -------------------------------------------------------------


def test_provider_defaults_map_to_the_runtime_variables():
    assert provider_env_var("openai") == "OPENAI_API_KEY"
    assert provider_env_var("DeepSeek") == "DEEPSEEK_API_KEY"
    assert provider_env_var(" gemini ") == "GEMINI_API_KEY"
    assert set(LOGIN_PROVIDERS) == {"openai", "deepseek", "gemini", "anthropic"}


def test_unknown_provider_is_a_value_error():
    with pytest.raises(ValueError, match="proveedor desconocido"):
        provider_env_var("bitwarden")


def test_set_get_delete_round_trip(backend):
    assert set_secret("openai", "  sk-stored  ") == "OPENAI_API_KEY"
    assert get_secret("openai") == "sk-stored"
    assert delete_secret("openai") is True
    assert get_secret("openai") is None
    assert delete_secret("openai") is False


def test_empty_key_is_rejected_before_touching_the_backend(backend):
    with pytest.raises(ValueError):
        set_secret("openai", "   ")
    assert backend.names() == []


def test_select_backend_skips_an_installed_but_unusable_keyring(monkeypatch):
    """Headless box: the package is there, the ``fail`` backend is not a store."""
    import keyring
    from keyring.backends import fail

    monkeypatch.setattr(keyring, "get_keyring", lambda: fail.Keyring())
    assert secrets_module.select_backend().name == "file"


def test_select_backend_uses_a_working_keyring(monkeypatch, tmp_path):
    import keyring

    working = type(
        "Working",
        (),
        {
            "get_password": lambda self, service, name: None,
            "set_password": lambda self, service, name, value: None,
            "delete_password": lambda self, service, name: None,
        },
    )()
    monkeypatch.setattr(keyring, "get_keyring", lambda: working)
    monkeypatch.setattr(secrets_module, "_config_dir", lambda: tmp_path)
    assert secrets_module.select_backend().name == "keyring"


def test_resolve_api_key_reads_the_store_before_the_environment(backend):
    backend.set("OPENAI_API_KEY", "from-store")
    assert resolve_api_key("openai", env={"OPENAI_API_KEY": "from-env"}) == "from-store"


def test_resolve_api_key_falls_back_to_the_environment(backend):
    assert resolve_api_key("openai", env={"OPENAI_API_KEY": "from-env"}) == "from-env"
    assert resolve_api_key("openai", env={}) is None


def test_resolve_api_key_survives_a_broken_backend(monkeypatch):
    class Broken:
        name = "broken"

        def get(self, name):
            raise RuntimeError("keyring locked")

        def set(self, name, value):  # pragma: no cover - never used here
            raise RuntimeError("keyring locked")

    monkeypatch.setattr(secrets_module, "select_backend", lambda **_: Broken())
    assert resolve_api_key("gemini", env={"GEMINI_API_KEY": "env-wins"}) == "env-wins"


# --- doctor report ------------------------------------------------------------


def test_report_without_file(onboarding_env):
    report = secrets_file_report()
    assert report["exists"] is False
    assert report["mode"] is None
    assert report["path"].endswith("omni/secrets.json")


def test_report_flags_world_readable_file(onboarding_env):
    path = default_secrets_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"OPENAI_API_KEY": "x"}', encoding="utf-8")
    os.chmod(path, 0o644)
    report = secrets_file_report()
    assert report["exists"] is True
    assert report["mode"] == "0644"
    assert report["secure"] is False


def test_report_accepts_0600(onboarding_env):
    path = default_secrets_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"OPENAI_API_KEY": "x"}', encoding="utf-8")
    os.chmod(path, 0o600)
    report = secrets_file_report()
    assert report["mode"] == "0600"
    assert report["secure"] is True


# --- omni auth login ----------------------------------------------------------


def test_login_stores_the_key_and_never_prints_it(backend):
    lines: list[str] = []
    code = run_auth_command(
        ["login", "openai"],
        store=SecretStore(backend),
        secret_reader=lambda prompt: "sk-live-do-not-print",
        out=lines.append,
    )
    assert code == 0
    assert get_secret("openai") == "sk-live-do-not-print"
    joined = "\n".join(lines)
    assert "sk-live-do-not-print" not in joined
    assert "OPENAI_API_KEY" in joined
    assert backend.name in joined


def test_login_without_provider_asks_with_the_menu(backend):
    answers = iter(["2"])
    lines: list[str] = []
    code = run_auth_command(
        ["login"],
        store=SecretStore(backend),
        text_reader=lambda prompt: next(answers),
        secret_reader=lambda prompt: "deepseek-key",
        out=lines.append,
    )
    assert code == 0
    assert get_secret("deepseek") == "deepseek-key"
    assert "1) openai" in "\n".join(lines)


def test_login_accepts_a_provider_name_at_the_menu(backend):
    code = run_auth_command(
        ["login"],
        store=SecretStore(backend),
        text_reader=lambda prompt: "Anthropic",
        secret_reader=lambda prompt: "sk-ant-x",
        out=lambda line: None,
    )
    assert code == 0
    assert get_secret("anthropic") == "sk-ant-x"


def test_login_with_an_empty_value_does_not_write(backend):
    lines: list[str] = []
    code = run_auth_command(
        ["login", "gemini"],
        store=SecretStore(backend),
        secret_reader=lambda prompt: "   ",
        out=lines.append,
    )
    assert code == 1
    assert backend.names() == []
    assert "no se modificó" in "\n".join(lines)


def test_login_rejects_an_unknown_provider(backend):
    lines: list[str] = []
    code = run_auth_command(
        ["login", "bitwarden"],
        store=SecretStore(backend),
        secret_reader=lambda prompt: "x",
        out=lines.append,
    )
    assert code == 2
    assert "proveedor desconocido" in "\n".join(lines)
    assert backend.names() == []


def test_login_without_a_tty_and_without_provider_exits_2(backend):
    def no_stdin(prompt):
        raise EOFError

    lines: list[str] = []
    code = run_auth_command(
        ["login"],
        store=SecretStore(backend),
        text_reader=no_stdin,
        secret_reader=lambda prompt: "x",
        out=lines.append,
    )
    assert code == 2
    assert auth_cli.USAGE in "\n".join(lines)


def test_unknown_action_reports_usage(backend):
    code = run_auth_command(["frobnicate"], store=SecretStore(backend), out=lambda line: None)
    assert code == 2


# --- wiring: `omni auth login` end to end -------------------------------------


def test_omni_auth_login_writes_the_documented_file(tmp_path, monkeypatch, capsys):
    from nexus_core.cli.main import main

    root = tmp_path / "config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(root))
    monkeypatch.setattr(secrets_module, "select_backend", lambda **_: FileBackend())
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "sk-from-cli")

    assert main(["auth", "login", "openai"]) == 0

    path = root / "omni" / "secrets.json"
    assert path.is_file()
    assert mode_of(path) == 0o600
    assert get_secret("openai") == "sk-from-cli"
    output = capsys.readouterr().out
    assert "sk-from-cli" not in output


# --- /auth inside the TUI -----------------------------------------------------


class FakeSession:
    """The two input seams ``cmd_auth`` uses; ``input()`` would deadlock the TUI."""

    def __init__(self, *, answers=(), secret="sk-from-tui"):
        self.answers = list(answers)
        self.secret = secret
        self.visible_prompts: list[str] = []

    def visible_input(self, prompt):
        self.visible_prompts.append(prompt)
        return self.answers.pop(0) if self.answers else ""

    def secure_input(self, prompt):
        return self.secret


def test_visible_input_prefers_the_injected_reader():
    from nexus_core.cli.session import OmniSession

    seen: list[str] = []
    session = OmniSession(store=None, use_tui=False, input_reader=lambda p: seen.append(p) or "2")
    assert session.visible_input("p: ") == "2"
    assert seen == ["p: "]


def test_visible_input_falls_back_to_input(monkeypatch):
    from nexus_core.cli.session import OmniSession

    monkeypatch.setattr("builtins.input", lambda prompt="": "3")
    session = OmniSession(store=None, use_tui=False)
    assert session.visible_input("p: ") == "3"


def test_auth_slash_command_is_registered():
    from nexus_core.cli import commands

    assert "/auth" in commands.COMMANDS


def test_auth_command_asks_provider_then_hidden_key(backend, capsys):
    from nexus_core.cli import commands

    session = FakeSession(answers=["1"])
    commands.cmd_auth(session, [])
    out = capsys.readouterr().out
    assert session.visible_prompts and "Proveedor" in session.visible_prompts[0]
    assert get_secret("openai") == "sk-from-tui"
    assert "sk-from-tui" not in out
    assert "openai" in out


def test_auth_command_with_argument_skips_the_menu(backend):
    from nexus_core.cli import commands

    session = FakeSession()
    commands.cmd_auth(session, ["anthropic"])
    assert session.visible_prompts == []
    assert get_secret("anthropic") == "sk-from-tui"


# --- the factory consumes the store ------------------------------------------


def test_llm_factory_prefers_the_store_over_the_environment(backend, monkeypatch):
    from nexus_core.llm.abstraction import LLMFactory

    backend.set("OPENAI_API_KEY", "stored-key")
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")
    clients = LLMFactory.create_from_env()
    assert clients["openai"].config.api_key == "stored-key"


def test_llm_factory_builds_no_client_without_any_key(backend, monkeypatch):
    from nexus_core.llm.abstraction import LLMFactory

    for name in ("OPENAI_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    clients = LLMFactory.create_from_env()
    assert set(clients) <= {"fake"}


def test_omni_auth_without_action_defaults_to_login(tmp_path, monkeypatch):
    from nexus_core.cli.main import main

    root = tmp_path / "config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(root))
    monkeypatch.setattr(secrets_module, "select_backend", lambda **_: FileBackend())
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "sk-default-action")
    assert main(["auth", "login", "gemini"]) == 0
    assert get_secret("gemini") == "sk-default-action"
