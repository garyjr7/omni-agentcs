"""`/interview`, `/review`, `/plan` surface map and subagent specialization."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable, Iterator

import pytest

from nexus_core.agent import subagents
from nexus_core.agent.planner import attack_surface
from nexus_core.cli import commands
from nexus_core.cli.session import OmniSession
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.scope import EngagementScope, EngagementStore, load_roe

pytestmark = pytest.mark.usefixtures("lab_scope")


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-intake",
        tenant_id="system",
        name="intake-test",
        client="acme",
        owner_id="owner-1",
        valid_from=_iso(-timedelta(days=1)),
        valid_until=_iso(timedelta(days=1)),
        cidrs=("45.33.32.156/32",),
        domains=(),
        urls=(),
        exclusions=(),
        created_at=_iso(timedelta(0)),
    )


@pytest.fixture()
def session(tmp_path, monkeypatch) -> OmniSession:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    store = ControlStore(tmp_path / "cli.db")
    store.initialize()
    scope = EngagementStore(store).create(_scope())
    run = store.create_run("system", {"source": "test", "engagement_id": scope.engagement_id})
    value = OmniSession(
        store=store,
        tenant_id="system",
        engagement=scope,
        llm_client=None,
        max_iterations=5,
        operator_id="operator:tester",
        export_dir=tmp_path,
    )
    value.run_id = str(run["id"])
    return value


def _scripted(answers: list[str]) -> Callable[[str], str]:
    iterator: Iterator[str] = iter(answers)

    def reader(prompt: str) -> str:
        return next(iterator)

    return reader


def _eight(*answers: str) -> Callable[[str], str]:
    values = list(answers)
    while len(values) < 8:
        values.append("")
    return _scripted(values[:8])


# ---------------------------------------------------------------- /interview


def test_interview_records_brief_and_rejects_out_of_scope(session, capsys):
    from nexus_core.cli.interview import run_interview

    result = run_interview(
        session,
        reader=_eight(
            "Comprometer el AD y documentar rutas a DA",
            "ACME",
            "45.33.32.156 10.0.0.9",
            "sin DoS ni exfiltración de PII",
        ),
    )
    assert result.objectives.startswith("Comprometer")
    assert result.authorized_targets == ("45.33.32.156",)
    assert result.rejected_targets == ("10.0.0.9",)
    assert session.engagement_brief["objectives"].startswith("Comprometer")

    facts = Blackboard(session.store).list_facts("system", "eng-intake", fact_type="hint")
    brief = [fact for fact in facts if fact["key"] == "engagement-brief"]
    assert len(brief) == 1
    assert brief[0]["value"]["objectives"].startswith("Comprometer")


def test_interview_persists_roe_limits(session):
    from nexus_core.cli.interview import run_interview

    result = run_interview(
        session,
        reader=_eight(
            "Validar el perímetro",
            "ACME",
            "45.33.32.156",
            "",
            "09:00-18:00",
            "30",
            "2",
            "soc@acme.test",
        ),
    )
    assert result.roe_saved is True
    roe = load_roe("eng-intake")
    assert roe is not None
    assert roe.max_actions_per_minute == 30
    assert roe.max_concurrent_actions == 2
    assert [window.to_dict() for window in roe.windows] == [
        {"start": "09:00", "end": "18:00", "days": []}
    ]
    assert roe.emergency_contact == "soc@acme.test"


def test_interview_cancels_on_empty_answers(session, capsys):
    session.input_reader = _eight()
    commands.cmd_interview(session, [])
    out = capsys.readouterr().out
    assert "cancelada" in out
    assert not Blackboard(session.store).list_facts(
        "system", "eng-intake", fact_type="hint"
    )


def test_command_interview_show_prints_brief(session, capsys):
    from nexus_core.cli.interview import run_interview

    run_interview(session, reader=_eight("Objetivo uno", "ACME", "45.33.32.156"))
    commands.cmd_interview(session, ["show"])
    out = capsys.readouterr().out
    assert "Objetivo uno" in out


def test_command_interview_requires_engagement(session, capsys):
    session.engagement = None
    commands.cmd_interview(session, [])
    assert "no hay engagement activo" in capsys.readouterr().out


def test_command_interview_rejects_bad_subcommand(session, capsys):
    commands.cmd_interview(session, ["bogus"])
    assert "uso: /interview" in capsys.readouterr().out


# ------------------------------------------------------------------- /review


def test_review_reports_integrity_and_cleanup(session, capsys):
    commands.cmd_review(session, [])
    out = capsys.readouterr().out
    assert "REVISIÓN DEL ENGAGEMENT eng-intake" in out
    assert "cadena de auditoría válida" in out
    assert "sin jobs durables abiertos" in out
    assert "sin sesión adjunta" in out


def test_review_flags_open_jobs(session, capsys):
    session.store.enqueue_task(
        tenant_id="system",
        run_id=str(session.run_id),
        task_type="tool.invoke",
        payload={"tool_id": "nexus.recon.nmap"},
    )
    commands.cmd_review(session, [])
    out = capsys.readouterr().out
    assert "sin cerrar" in out or "job" in out
    assert "REVISAR ANTES DE CERRAR" in out


def test_review_deliverable_is_rendered(session, capsys, monkeypatch):
    monkeypatch.setattr(
        commands,
        "_run_report_tool",
        lambda session, arguments: {
            "output": {
                "directory": "/tmp/report",
                "report_sha256": "deadbeef",
                "markdown_size_bytes": 10,
                "html_size_bytes": 20,
            }
        },
    )
    commands.cmd_review(session, ["--deliver"])
    out = capsys.readouterr().out
    assert "Entregables" in out
    assert "deadbeef" in out


def test_review_rejects_unknown_format(session, capsys):
    commands.cmd_review(session, ["--format", "pdf"])
    assert "uso: /review" in capsys.readouterr().out


def test_review_without_engagement_is_an_error(session, capsys):
    session.engagement = None
    commands.cmd_review(session, [])
    assert "no hay engagement activo" in capsys.readouterr().out


# ------------------------------------------------------- /plan attack surface


def _verified_fact(fact_type: str, key: str) -> dict:
    return {
        "fact_type": fact_type,
        "key": key,
        "value": {},
        "verified": True,
        "asserted_by": "verifier",
        "verification_method": "test",
        "invocation_id": "inv-1",
    }


def test_attack_surface_lists_only_verified_facts():
    surface = attack_surface(
        [
            _verified_fact("host", "10.0.0.5"),
            _verified_fact("service", "10.0.0.5:80/tcp"),
            {"fact_type": "host", "key": "10.0.0.9", "verified": False},
        ]
    )
    assert surface.hosts == ("10.0.0.5",)
    assert surface.services == ("10.0.0.5:80/tcp",)
    assert surface.verified_facts == 2
    assert surface.unverified_facts == 1


def test_cmd_plan_includes_surface_and_tactical_profile(session, capsys):
    commands.cmd_plan(session, [])
    out = capsys.readouterr().out
    assert "PLAN DE ENGAGEMENT" in out
    assert "SUPERFICIE DE ATAQUE" in out
    assert "ESTRATEGIA OPERATIVA" in out


# -------------------------------------------- subagent specialization routing


def test_alias_resolution_maps_to_canonical_profiles():
    assert subagents.resolve_subagent_id("target-mapper") == "recon"
    assert subagents.resolve_subagent_id("exploit-scripter") == "exploit"
    assert subagents.resolve_subagent_id("c2-operator") == "postexploit"
    assert subagents.resolve_subagent_id("stealth-validator") == "reporter"
    assert subagents.resolve_subagent_id("recon") == "recon"
    assert subagents.resolve_subagent_id("does-not-exist") is None
    assert subagents.resolve_subagent_id(None) is None


def test_select_subagent_accepts_an_alias_override():
    profile = subagents.select_subagent(override="deep-reasoning")
    assert profile.id == "recon"


def test_select_subagent_rejects_an_unknown_override():
    with pytest.raises(ValueError):
        subagents.select_subagent(override="not-a-profile")


def test_capability_boundary_is_enforced_per_profile():
    recon = subagents.SUBAGENTS_BY_ID["recon"]
    assert subagents.permits(recon, "nexus.recon.nmap") is True
    # A tool from another phase is refused even though it exists in the catalog.
    assert subagents.permits(recon, "nexus.exploit.msf_exploit") is False


def test_cmd_subagent_accepts_alias_and_sets_override(session, capsys):
    commands.cmd_subagent(session, ["exploit-scripter"])
    out = capsys.readouterr().out
    assert session.subagent_override == "exploit"
    assert "exploit" in out


def test_cmd_subagent_lists_aliases(session, capsys):
    commands.cmd_subagent(session, [])
    out = capsys.readouterr().out
    assert "target-mapper→recon" in out
