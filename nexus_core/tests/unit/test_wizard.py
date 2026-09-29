from unittest.mock import patch
import pytest

from nexus_core.cli import wizard as w
from nexus_core.config.loader import ConfigError, load_config, save_config
from nexus_core.config.schema import OmniConfig

pytestmark = pytest.mark.usefixtures("onboarding_env")


def tty(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setattr(w.sys.stdin, "isatty", lambda: True)


def test_should_run_wizard_true_when_no_config(onboarding_env, monkeypatch):
    tty(monkeypatch)
    assert w.should_run_wizard(onboarding_env.paths)


def test_should_run_wizard_false_when_config_exists(onboarding_env, monkeypatch):
    tty(monkeypatch)
    save_config(OmniConfig(), onboarding_env.paths)
    assert not w.should_run_wizard(onboarding_env.paths)


def test_should_run_wizard_false_when_no_tty(onboarding_env, monkeypatch):
    tty(monkeypatch)
    monkeypatch.setattr(w.sys.stdin, "isatty", lambda: False)
    assert not w.should_run_wizard(onboarding_env.paths)


def test_should_run_wizard_false_when_flag_set(onboarding_env, monkeypatch):
    tty(monkeypatch)
    assert not w.should_run_wizard(onboarding_env.paths, force_no_wizard=True)


def test_run_wizard_creates_config_file(onboarding_env):
    with patch("builtins.input", side_effect=["n", "6", "", "n"]):
        config = w.run_wizard(onboarding_env.paths)
    assert load_config(onboarding_env.paths) == config


def test_run_wizard_respects_abort_with_keyboard_interrupt(onboarding_env):
    with patch("builtins.input", side_effect=KeyboardInterrupt), pytest.raises(w.WizardAborted):
        w.run_wizard(onboarding_env.paths)
    assert not onboarding_env.paths.config_file.exists()


def test_run_wizard_asks_for_provider(onboarding_env, capsys):
    with patch("builtins.input", side_effect=["n", "5", "local-model", "n"]):
        config = w.run_wizard(onboarding_env.paths)
    assert config.llm.default_provider == "ollama" and config.llm.default_model == "local-model"
    assert "Groq / 2 OpenAI" in capsys.readouterr().out


def test_run_wizard_saves_api_key(onboarding_env, capsys):
    with (
        patch("builtins.input", side_effect=["n", "1", "", "n"]),
        patch.object(w.getpass, "getpass", return_value="fixture-key"),
    ):
        w.run_wizard(onboarding_env.paths)
    assert load_config(onboarding_env.paths).llm.api_keys["groq"] == "fixture-key"
    assert "fixture-key" not in capsys.readouterr().out


def test_run_wizard_skips_tool_install_if_user_says_no(onboarding_env):
    with (
        patch("builtins.input", side_effect=["n", "6", "", "n"]),
        patch.object(w, "execute_install") as execute,
    ):
        w.run_wizard(onboarding_env.paths)
    execute.assert_not_called()
    onboarding_env.run.assert_not_called()


def test_run_wizard_atomic_write_on_failure(onboarding_env):
    with (
        patch("builtins.input", side_effect=["n", "6", "", "n"]),
        patch("nexus_core.config.loader.os.replace", side_effect=OSError),
        pytest.raises(ConfigError),
    ):
        w.run_wizard(onboarding_env.paths)
    assert not onboarding_env.paths.config_file.exists()
    assert not list(onboarding_env.paths.config_dir.glob("*.tmp"))


def test_existing_config_does_not_prompt(onboarding_env):
    save_config(OmniConfig(), onboarding_env.paths)
    with patch("builtins.input", side_effect=AssertionError):
        w.run_wizard(onboarding_env.paths)


def test_wizard_no_install_without_per_tool_yes(onboarding_env):
    onboarding_env.which.side_effect = lambda name: (
        "/bin/" + name if name in {"apt", "sudo"} else None
    )

    def answer(prompt):
        if "Revisar instalaciones" in prompt:
            return "y"
        return "6" if prompt.startswith("Proveedor [") else "n"

    with patch("builtins.input", side_effect=answer), patch.object(w, "execute_install") as execute:
        w.run_wizard(onboarding_env.paths)
    execute.assert_not_called()


def test_ci_never_runs_wizard(onboarding_env, monkeypatch):
    tty(monkeypatch)
    monkeypatch.setenv("CI", "true")
    assert not w.should_run_wizard(onboarding_env.paths)


def test_scope_creation_rolled_back_if_save_fails(onboarding_env):
    from nexus_core.kernel.store_factory import get_control_store
    from nexus_core.scope import EngagementStore

    answers = ["n", "6", "", "y", "test", "203.0.113.0/24", "y"]
    with (
        patch("builtins.input", side_effect=answers),
        patch.object(w, "save_config", side_effect=ConfigError),
        pytest.raises(ConfigError),
    ):
        w.run_wizard(onboarding_env.paths)
    store = get_control_store(onboarding_env.paths.db_file)
    assert EngagementStore(store).list_for_tenant("system") == []
    assert not onboarding_env.paths.config_file.exists()
