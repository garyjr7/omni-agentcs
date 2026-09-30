"""``/ask`` must describe the real Omni CLI, not generic pentest theory."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from nexus_core.cli import commands as commands_module
from nexus_core.cli.main import PROGRAM_VERSION
from nexus_core.cli.session import OmniSession
from nexus_core.kernel.control_store import ControlStore
from nexus_core.scope import EngagementScope, EngagementStore

TENANT = "system"


class _Answer:
    def __init__(self, content: str = "usa /scope") -> None:
        self.content = content


class _FakeLLM:
    def __init__(self) -> None:
        self.calls: list[list] = []

    async def complete(self, messages, **kwargs):
        self.calls.append(list(messages))
        return _Answer()

    async def ask(self, system_prompt, user_message):
        return "usa /scope"


def _iso() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()


@pytest.fixture()
def session(tmp_path) -> OmniSession:
    store = ControlStore(tmp_path / "ask-context.db")
    store.initialize()
    scope = EngagementStore(store).create(
        EngagementScope(
            engagement_id="eng-scanme",
            tenant_id=TENANT,
            name="scanme-lab",
            client="NEXUS",
            owner_id="owner-1",
            valid_from=_iso(),
            valid_until=_iso(),
            cidrs=("10.10.0.0/24",),
            domains=("scanme.nmap.org",),
            urls=(),
            exclusions=(),
            created_at=_iso(),
        )
    )
    assert scope is not None
    return OmniSession(
        store=store, tenant_id=TENANT, engagement=scope, llm_client=_FakeLLM(),
        operator_id="operator:tester",
    )


def test_ask_prompt_includes_real_tools(session):
    prompt = commands_module._build_ask_system_prompt(session)
    assert "nexus.recon.nmap" in prompt
    assert "nexus.exploit.msf_exploit" in prompt
    assert "nexus.report.generate" in prompt


def test_ask_prompt_includes_engagement_and_scope(session):
    prompt = commands_module._build_ask_system_prompt(session)
    assert "scanme-lab" in prompt
    assert "eng-scanme" in prompt
    assert "scanme.nmap.org" in prompt
    assert "10.10.0.0/24" in prompt


def test_ask_prompt_lists_meta_commands(session):
    prompt = commands_module._build_ask_system_prompt(session)
    for name in ("/tools", "/scope", "/ask", "/help"):
        assert name in prompt


def test_ask_prompt_mentions_product_version_and_provider(session):
    prompt = commands_module._build_ask_system_prompt(session)
    assert PROGRAM_VERSION in prompt
    assert "Proveedor LLM resuelto:" in prompt


def test_ask_prompt_without_engagement_is_honest(tmp_path):
    store = ControlStore(tmp_path / "ask-empty.db")
    store.initialize()
    session = OmniSession(store=store, tenant_id=TENANT, engagement=None, llm_client=_FakeLLM())
    prompt = commands_module._build_ask_system_prompt(session)
    assert "Sin engagement activo" in prompt
    assert "/ask" in prompt


def test_cmd_ask_sends_the_contextual_prompt(session):
    commands_module.cmd_ask(session, ["qué", "puedes", "hacer"])
    system = session.llm_client.calls[0][0]
    assert system.role == "system"
    assert "nexus.recon.nmap" in system.content
    assert "/tools" in system.content
    # The base persona is preserved at the head of the prompt.
    assert system.content.startswith(commands_module.ASK_SYSTEM_PROMPT)
