"""``--trust-mode``: unattended high-risk authorization, never destructive.

Trust mode must still create a durable approval row and audit the automatic
authorization with ``trust_mode=true`` so a report can tell it apart.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from nexus_core.cli.approval import TRUST_MODE_ACTION, make_approval_callback, os_user
from nexus_core.cli.commands import cmd_trust
from nexus_core.cli.main import build_parser
from nexus_core.cli.session import OmniSession
from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import PolicyDecision, RiskLevel
from nexus_core.scope import EngagementScope, EngagementStore
from nexus_core.tools.handlers.system import system_status_definition

TENANT = "system"
#: A real HIGH-risk tool registered in the durable catalog.
HIGH_TOOL = "nexus.exploit.msf_exploit"
DESTRUCTIVE_TOOL = "nexus.test.destructive"
ACTION = f"execute:tool:{HIGH_TOOL}"


class Feed:
    """Deterministic ``input()`` that records prompts and replays answers."""

    def __init__(self, answers: list[str] | None = None, fallback: str = "n") -> None:
        self.answers = list(answers or [])
        self.fallback = fallback
        self.prompts: list[str] = []

    def __call__(self, prompt: str = "") -> str:
        self.prompts.append(prompt)
        return self.answers.pop(0) if self.answers else self.fallback


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


@pytest.fixture()
def session(tmp_path) -> OmniSession:
    store = ControlStore(tmp_path / "trust-mode.db")
    store.initialize()
    scope = EngagementStore(store).create(
        EngagementScope(
            engagement_id="eng-1",
            tenant_id=TENANT,
            name="engagement-1",
            client="acme",
            owner_id="owner-1",
            valid_from=_iso(-timedelta(days=1)),
            valid_until=_iso(timedelta(days=1)),
            cidrs=("10.0.0.0/24",),
            domains=(),
            urls=(),
            exclusions=(),
            created_at=_iso(timedelta(0)),
        )
    )
    run = store.create_run(TENANT, {})
    value = OmniSession(
        store=store,
        tenant_id=TENANT,
        engagement=scope,
        llm_client=None,
        max_iterations=3,
        operator_id="operator:tester",
    )
    value.run_id = str(run["id"])
    return value


def _decision() -> PolicyDecision:
    return PolicyDecision(
        True,
        "allowed after human approval",
        "risk-approval",
        requires_approval=True,
        obligations=("audit", "sandbox", "human-approval"),
    )


def _trust_events(session: OmniSession) -> list[dict]:
    return [
        event
        for event in AuditWriter(session.store).export(TENANT)
        if event["action"] == TRUST_MODE_ACTION
    ]


def _destructive_catalog() -> dict:
    definition = replace(
        system_status_definition(TENANT),
        tool_id=DESTRUCTIVE_TOOL,
        risk=RiskLevel.DESTRUCTIVE,
    )
    return {DESTRUCTIVE_TOOL: (definition, None)}


def test_trust_mode_flag_parsed():
    assert build_parser().parse_args(["--trust-mode"]).trust_mode is True
    args = build_parser().parse_args(["--trust-mode", "--engagement", "eng-1"])
    assert args.trust_mode is True and args.engagement == "eng-1"


def test_trust_mode_autо_approves_high_risk_and_audits(session, capsys):
    feed = Feed()
    session.input_reader = feed
    callback = make_approval_callback(
        session, session.store, TENANT, session.run_id, trust_mode=True
    )

    decision = callback(HIGH_TOOL, {"module": "exploit/x/y", "target": "10.0.0.5"}, _decision())

    assert decision.approved is True and decision.reason == "trust_mode"
    assert decision.approval_id and decision.approval_id.startswith("approval_")
    # No prompt was ever shown: the human was not asked.
    assert feed.prompts == []
    out = capsys.readouterr().out
    assert "TRUST MODE" in out and "aprobado automáticamente" in out
    # The durable approval is real and verifiable by the gateway.
    row = ApprovalService(session.store).get(decision.approval_id, TENANT)
    assert row["status"] == "approved"
    assert row["requested_by"] == session.agent_subject_id
    assert row["decided_by"] == session.operator_id
    assert (
        ApprovalService(session.store).verify(
            decision.approval_id, session.build_run_context(session.run_id), ACTION
        )
        is True
    )
    events = _trust_events(session)
    assert len(events) == 1
    payload = events[0]["payload"]
    assert payload["trust_mode"] is True
    assert payload["trusted_by"] == os_user()
    assert payload["approval_id"] == decision.approval_id
    assert payload["tool_id"] == HIGH_TOOL and payload["run_id"] == session.run_id
    assert events[0]["decision"] == "allow"


def test_trust_mode_does_not_auto_approve_destructive(session, monkeypatch, capsys):
    monkeypatch.setattr(
        "nexus_core.tools.registry.durable_tool_definitions",
        lambda tenant_id="system": _destructive_catalog(),
    )
    session.input_reader = Feed(["n"])
    callback = make_approval_callback(
        session, session.store, TENANT, session.run_id, trust_mode=True
    )

    decision = callback(DESTRUCTIVE_TOOL, {}, _decision())

    assert decision.approved is False and decision.reason == "user denied"
    assert "APROBACIÓN HUMANA REQUERIDA" in capsys.readouterr().out
    assert _trust_events(session) == []
    assert ApprovalService(session.store).list_pending(TENANT) == []


def test_trust_mode_off_by_default(tmp_path):
    assert build_parser().parse_args([]).trust_mode is False
    store = ControlStore(tmp_path / "default.db")
    store.initialize()
    assert OmniSession(store=store).trust_mode is False


def test_trust_mode_denied_when_operator_is_the_requester(session, capsys):
    """Separation of duties survives trust mode: no self-authorization."""
    session.operator_id = session.agent_subject_id
    callback = make_approval_callback(
        session, session.store, TENANT, session.run_id, trust_mode=True
    )

    decision = callback(HIGH_TOOL, {}, _decision())

    assert decision.approved is False
    assert "could not be registered" in decision.reason
    assert _trust_events(session) == []
    with session.store.connect() as conn:
        assert [row["status"] for row in conn.execute("SELECT status FROM kernel_approvals")] == [
            "pending"
        ]
    assert "no se pudo registrar la aprobación durable" in capsys.readouterr().out


def test_repl_prompt_shows_trust_mode(tmp_path):
    store = ControlStore(tmp_path / "prompt.db")
    store.initialize()
    session = OmniSession(store=store)
    assert "[TRUST MODE]" not in session.prompt
    session.trust_mode = True
    assert "[TRUST MODE]" in session.prompt
    assert session.prompt.endswith("> ")


def test_trust_command_toggles_at_runtime(tmp_path, capsys):
    store = ControlStore(tmp_path / "cmd.db")
    store.initialize()
    session = OmniSession(store=store)

    cmd_trust(session, [])
    assert "OFF" in capsys.readouterr().out
    cmd_trust(session, ["on"])
    assert session.trust_mode is True
    assert "se aplica al siguiente objetivo" in capsys.readouterr().out
    cmd_trust(session, ["off"])
    assert session.trust_mode is False
    cmd_trust(session, ["maybe"])
    assert session.trust_mode is False
    assert "valor inválido" in capsys.readouterr().out
