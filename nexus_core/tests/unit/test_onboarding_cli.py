import asyncio
import json
from unittest.mock import patch

import httpx
import pytest

import omni

pytestmark = pytest.mark.usefixtures("onboarding_env")


def test_config_path_has_no_filesystem_side_effect(onboarding_env, capsys):
    with patch.object(omni, "load_dotenv"):
        assert omni.main(["--config-path"]) == 0
    assert capsys.readouterr().out.strip() == str(onboarding_env.paths.config_file)
    assert not onboarding_env.paths.config_dir.exists()


def test_doctor_skips_wizard(onboarding_env, capsys):
    with (
        patch.object(omni, "load_dotenv"),
        patch("nexus_core.cli.wizard.run_wizard", side_effect=AssertionError),
        patch("socket.create_connection", side_effect=OSError),
    ):
        assert omni.main(["--doctor", "--json", "--no-wizard"]) == 0
    assert json.loads(capsys.readouterr().out)["config"]["schema_version"] == 1


def test_no_tty_uses_xdg_db(onboarding_env):
    with (
        patch.object(omni, "load_dotenv"),
        patch("sys.stdin.isatty", return_value=False),
        patch("nexus_core.cli.main.main", return_value=0) as cli,
    ):
        assert omni.main(["--no-wizard"]) == 0
    assert cli.call_args.kwargs["paths"].db_file == onboarding_env.paths.db_file


def test_editor_uses_argv_not_shell(onboarding_env, monkeypatch):
    monkeypatch.setenv("EDITOR", "editor --wait")
    with patch.object(omni, "load_dotenv"):
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
