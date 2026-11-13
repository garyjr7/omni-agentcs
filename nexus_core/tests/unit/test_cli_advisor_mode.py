"""Free-text questions are consultations; only targets/actions open the engine."""

from __future__ import annotations

from unittest import mock

import pytest

from nexus_core.cli import commands as commands_module
from nexus_core.cli.session import OmniSession


class _Answer:
    def __init__(self, content: str = "Redis 2.8.24 tiene vectores conocidos.") -> None:
        self.content = content


class _FakeLLM:
    def __init__(self) -> None:
        self.calls: list[list] = []

    async def complete(self, messages, **kwargs):
        self.calls.append(list(messages))
        return _Answer()


def _session() -> OmniSession:
    return OmniSession(
        store=None,
        tenant_id="system",
        engagement=None,
        llm_client=_FakeLLM(),
        use_tui=False,
        operator_id="operator:tester",
    )


@pytest.mark.parametrize(
    "text",
    [
        "Tengo un Redis 2.8.24, ¿es vulnerable?",
        "¿Qué es un pivot?",
        "¿Cómo funciona Kerberoasting?",
        "Háblame de las diferencias entre nmap y masscan",
        "Hola",
    ],
)
def test_questions_are_advisor_mode(text):
    assert commands_module.is_advisor_question(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "Escanea 10.0.0.5",
        "Escanea los puertos 80 y 443",
        "Analiza scanme.nmap.org",
        "https://example.com/login",
        "Audita el engagement actual",
    ],
)
def test_targets_and_imperatives_use_the_engine(text):
    assert commands_module.is_advisor_question(text) is False


def test_advisor_question_does_not_create_a_run_or_call_a_tool():
    session = _session()
    with mock.patch.object(session, "run_objective") as run_objective:
        session.handle_text("Tengo un Redis 2.8.24, ¿es vulnerable?")
    run_objective.assert_not_called()
    assert session.run_id is None
    assert session.llm_client.calls, "the advisor should answer with the LLM"
    system = session.llm_client.calls[0][0]
    assert "MODO ASESOR" in system.content
    assert "No ejecutas herramientas" in system.content


def test_target_text_still_opens_the_governed_engine():
    session = _session()
    with (
        mock.patch.object(session, "run_objective", return_value="run") as run_objective,
        mock.patch.object(commands_module, "cmd_ask") as ask,
    ):
        session.handle_text("Escanea 10.0.0.5")
    run_objective.assert_called_once_with("Escanea 10.0.0.5")
    ask.assert_not_called()


def test_slash_commands_keep_their_dispatcher():
    session = _session()
    with mock.patch.object(commands_module, "run_command", return_value=True) as run_command:
        session.handle_text("/help")
    run_command.assert_called_once_with(session, "/help")
