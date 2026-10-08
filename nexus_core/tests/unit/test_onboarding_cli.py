import asyncio
import json
from unittest.mock import patch

import httpx
import pytest

import omni

pytestmark = pytest.mark.usefixtures("onboarding_env")


def test_config_path_has_no_filesystem_side_effect(onboarding_env, capsys):
    with patch("dotenv.load_dotenv"):
        assert omni.main(["--config-path"]) == 0
    assert capsys.readouterr().out.strip() == str(onboarding_env.paths.config_file)
    assert not onboarding_env.paths.config_dir.exists()


def test_doctor_skips_wizard(onboarding_env, capsys):
    with (
        patch("dotenv.load_dotenv"),
        patch("nexus_core.cli.wizard.run_wizard", side_effect=AssertionError),
        patch("socket.create_connection", side_effect=OSError),
    ):
        assert omni.main(["--doctor", "--json", "--no-wizard"]) == 0
    assert json.loads(capsys.readouterr().out)["config"]["schema_version"] == 1


def test_no_tty_uses_xdg_db(onboarding_env):
    with (
        patch("dotenv.load_dotenv"),
        patch("sys.stdin.isatty", return_value=False),
        patch("nexus_core.cli.main.main", return_value=0) as cli,
    ):
        assert omni.main(["--no-wizard"]) == 0
    assert cli.call_args.kwargs["paths"].db_file == onboarding_env.paths.db_file


def test_editor_uses_argv_not_shell(onboarding_env, monkeypatch):
    monkeypatch.setenv("EDITOR", "editor --wait")
    with patch("dotenv.load_dotenv"):
        assert omni.main(["--config"]) == 0
    assert onboarding_env.run.call_args.args[0] == [
        "editor",
        "--wait",
        str(onboarding_env.paths.config_file),
    ]
    assert onboarding_env.run.call_args.kwargs["shell"] is False


def test_anthropic_uses_existing_httpx(monkeypatch):
    from nexus_core.llm.abstraction import LLMConfig, LLMFactory, LLMMessage, LLMProvider
    from nexus_core.llm import anthropic_client as module

    config = LLMConfig(LLMProvider.ANTHROPIC, "fixture-model", api_key="fixture-key")

    def handler(request):
        payload = json.loads(request.content)
        assert payload["system"] == "system"
        assert request.headers["x-api-key"] == "fixture-key"
        return httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "done"}],
                "usage": {"input_tokens": 1, "output_tokens": 2},
            },
        )

    factory = httpx.AsyncClient
    monkeypatch.setattr(
        module.httpx,
        "AsyncClient",
        lambda **kw: factory(transport=httpx.MockTransport(handler), **kw),
    )
    result = asyncio.run(
        LLMFactory.create(config).complete(
            [LLMMessage("system", "system"), LLMMessage("user", "hello")]
        )
    )
    assert result.content == "done" and result.total_tokens == 3

@pytest.mark.parametrize('explicit', [False, True])
def test_worker_uses_global_db_config(onboarding_env, monkeypatch, explicit):
    from unittest.mock import MagicMock, patch
    import os
    import nexus_worker
    from nexus_core.config.loader import save_config
    from nexus_core.config.schema import OmniConfig

    config = OmniConfig()
    config.db.path = str(onboarding_env.paths.data_dir / 'worker.db')
    config.llm.default_provider = 'fake'
    config.llm.default_model = 'nexus-fake-v1'
    save_config(config, onboarding_env.paths)
    expected = config.db.path
    if explicit:
        expected = str(onboarding_env.paths.data_dir / 'explicit.db')
        monkeypatch.setenv('NEXUS_DB_PATH', expected)
    monkeypatch.setattr('sys.argv', ['nexus_worker.py', '--once'])
    store = MagicMock()
    store.claim_task.return_value = None
    with patch('dotenv.load_dotenv'), patch.object(nexus_worker, 'get_control_store', return_value=store) as factory:
        nexus_worker.main()
    factory.assert_called_once_with()
    assert os.environ['NEXUS_DB_PATH'] == expected
    store.initialize.assert_called_once_with()
    store.complete_task.assert_not_called()
