"""Create and switch engagements from the CLI/REPL: module + /engage command."""

from datetime import datetime, timedelta, timezone

import pytest

from nexus_core.cli import commands
from nexus_core.cli import engage as engage_module
from nexus_core.cli.session import OmniSession
from nexus_core.kernel.control_store import ControlStore
from nexus_core.scope import EngagementScope, EngagementStore, ScopeValidator

SECRET = "test-signing-secret"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-existing",
        tenant_id="system",
        name="lab-viejo",
        client="acme",
        owner_id="owner-1",
        valid_from=_iso(-timedelta(days=1)),
        valid_until=_iso(timedelta(days=1)),
        cidrs=("10.65.151.43/32",),
        domains=(),
        urls=(),
        exclusions=(),
        created_at=_iso(timedelta(0)),
    )


@pytest.fixture()
def session(tmp_path, monkeypatch):
    monkeypatch.setattr("nexus_core.cli.engage.signing_secret", lambda: SECRET)
    store = ControlStore(tmp_path / "engage.db")
    store.initialize()
    scope = EngagementStore(store).create(_scope())
    return OmniSession(
        store=store, tenant_id="system", engagement=scope, llm_client=None,
        operator_id="operator:tester", use_tui=False,
    )


def test_parse_scope_entries_cidr_only():
    cidrs, domains = engage_module.parse_scope_entries("203.0.113.0/24")
    assert cidrs == ("203.0.113.0/24",)
    assert domains == ()


def test_parse_scope_entries_domain_resolves(monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("203.0.113.10", 0))],
    )
    cidrs, domains = engage_module.parse_scope_entries("scanme.nmap.org")
    assert domains == ("scanme.nmap.org",)
    assert cidrs == ("203.0.113.10/32",)


def test_parse_scope_entries_rejects_garbage():
    with pytest.raises(ValueError):
        engage_module.parse_scope_entries("not a target!!")


def test_build_scope_is_signed_and_valid(session):
    scope = engage_module.build_scope("scanme", "203.0.113.0/24", SECRET)
    assert scope.signature
    loaded = EngagementStore(session.store).create(scope)
    # The signature survives persistence (created_at is signed, not filled later).
    result = ScopeValidator(loaded, signing_secret=SECRET).validate("203.0.113.10")
    assert result.ip == "203.0.113.10"


def test_create_engagement_persists(session):
    created = engage_module.create_engagement(
        session.store, "scanme-lab", "203.0.113.0/24", secret=SECRET
    )
    assert created.engagement_id.startswith("eng-")
    stored = EngagementStore(session.store).get("system", created.engagement_id)
    assert stored is not None and stored.name == "scanme-lab"


def test_cmd_engage_lists_created_engagement(session, capsys):
    engage_module.create_engagement(session.store, "scanme-lab", "203.0.113.0/24", secret=SECRET)
    commands.cmd_engage(session, ["list"])
    out = capsys.readouterr().out
    assert "eng-existing" in out and "lab-viejo" in out
    assert "scanme-lab" in out


def test_cmd_engage_create_persists_and_switches(session, capsys):
    commands.cmd_engage(session, ["create", "scanme-lab", "203.0.113.0/24"])
    # A successful state change is silent: the header badge and the status bar
    # already name the engagement.
    assert capsys.readouterr().out == ""
    assert session.engagement.name == "scanme-lab"
    assert session.engagement.cidrs == ("203.0.113.0/24",)
    assert len(EngagementStore(session.store).list_for_tenant("system")) == 2


def test_cmd_engage_create_requires_name_and_scope(session, capsys):
    commands.cmd_engage(session, ["create", "solo-nombre"])
    assert "uso: /engage_create" in capsys.readouterr().out
    assert session.engagement.name == "lab-viejo"


def test_top_level_engage_commands_registered():
    for name in ("/engage_list", "/engage_create", "/engage_use", "/engage_current"):
        assert name in commands.COMMANDS


def test_cmd_engage_list_top_level_lists(session, capsys):
    commands.cmd_engage_list(session, [])
    out = capsys.readouterr().out
    assert "eng-existing" in out and "lab-viejo" in out


def test_cmd_engage_create_top_level_persists_and_switches(session, capsys):
    commands.cmd_engage_create(session, ["scanme-lab", "203.0.113.0/24", "--hours", "48"])
    assert capsys.readouterr().out == ""
    assert session.engagement.name == "scanme-lab"
    assert session.engagement.cidrs == ("203.0.113.0/24",)


def test_cmd_engage_create_top_level_usage(session, capsys):
    commands.cmd_engage_create(session, ["solo-nombre"])
    assert "uso: /engage_create" in capsys.readouterr().out


def test_cmd_engage_use_top_level_switches(session, capsys):
    created = engage_module.create_engagement(
        session.store, "scanme-lab", "203.0.113.0/24", secret=SECRET
    )
    commands.cmd_engage_use(session, [created.engagement_id])
    assert session.engagement.engagement_id == created.engagement_id
    assert capsys.readouterr().out == ""


def test_cmd_engage_current_shows_active(session, capsys):
    commands.cmd_engage_current(session, [])
    assert "lab-viejo" in capsys.readouterr().out


def test_cmd_engage_use_switches_active(session, capsys):
    created = engage_module.create_engagement(
        session.store, "scanme-lab", "203.0.113.0/24", secret=SECRET
    )
    commands.cmd_engage(session, ["use", created.engagement_id])
    assert session.engagement.engagement_id == created.engagement_id
    assert capsys.readouterr().out == ""


def test_cmd_engage_use_unknown_id_errors(session, capsys):
    commands.cmd_engage(session, ["use", "eng-nope"])
    assert "no encontrado" in capsys.readouterr().out
    assert session.engagement.name == "lab-viejo"


def test_cmd_engage_bad_action_shows_usage(session, capsys):
    commands.cmd_engage(session, ["bogus"])
    assert "uso: /engage" in capsys.readouterr().out


def test_set_engagement_resets_the_work_session(session):
    session._work_session_id = "work:old"
    session.run_id = "run-old"
    session.conversation_id = "conv-old"
    created = engage_module.create_engagement(
        session.store, "scanme-lab", "203.0.113.0/24", secret=SECRET
    )
    session.set_engagement(created)
    assert session.engagement is created
    assert session._work_session_id is None
    assert session.run_id is None and session.conversation_id is None
    assert session.engagement_id == created.engagement_id


def test_parser_exposes_new_engagement_flags():
    from nexus_core.cli.main import build_parser

    args = build_parser().parse_args(
        ["--new-engagement", "scanme", "--scope", "203.0.113.0/24", "--valid-hours", "72"]
    )
    assert args.new_engagement == "scanme"
    assert args.scope == "203.0.113.0/24"
    assert args.valid_hours == 72
