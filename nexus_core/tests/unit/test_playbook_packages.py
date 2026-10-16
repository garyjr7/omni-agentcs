"""Declarative playbook packages: strict schema, registration, reachability.

``red_team_base.yaml`` is the foundational assessment chain. These tests pin the
three properties that make it *usable* rather than decorative:

* it is a valid document (strict JSON Schema, no unknown keys, no invented
  vocabulary);
* every phase it declares is reachable by the capability profile declared for it
  (a chain the active subagent cannot execute is guidance into a denial);
* its gates are pure functions of the blackboard, so the ReAct prompt and
  ``nexus.orchestrator.playbook`` agree on the next gated step.
"""

from __future__ import annotations

from pathlib import Path
from nexus_core.playbooks.loader import LoadedPackage


import asyncio
from typing import Any

import pytest
import yaml

from nexus_core.agent.playbooks import (
    PLAYBOOKS,
    gate_for,
    is_applicable,
    packaged_playbooks,
    playbook_by_id,
    registered_playbooks,
    render_playbook_matches,
    select_playbooks,
)
from nexus_core.agent.turn_telemetry import TURN_TELEMETRY_SIGNALS
from nexus_core.playbooks.loader import (
    PACKAGE_DIR,
    PlaybookSchemaError,
    load_package,
    load_package_text,
    load_packages,
    validate_against_catalog,
)
from nexus_core.tests.sliver_support import owned_context
from nexus_core.tools import registry as registry_module

BASE = "red_team_base"


def _package() -> LoadedPackage:
    return load_package(PACKAGE_DIR / f"{BASE}.yaml")


def _raw_base_document() -> dict[str, Any]:
    return dict(yaml.safe_load((PACKAGE_DIR / f"{BASE}.yaml").read_text(encoding="utf-8")))


def _phase(**overrides: Any) -> dict[str, Any]:
    phase = {
        "phase_id": "one",
        "title": "Fase uno",
        "planner_phase": "recon",
        "subagent": "recon",
        "noise": "low",
        "objective": "objetivo",
        "gate": {"always": True},
        "steps": [
            {
                "step_id": "s1",
                "title": "Paso",
                "tool_id": "nexus.recon.nmap",
                "produces": "service",
                "rationale": "razón",
                "verification": "cómo se verifica",
            }
        ],
    }
    phase.update(overrides)
    return phase


def _document(**overrides: Any) -> str:
    document = {
        "schema_version": 1,
        "playbook_id": "pkg",
        "version": "1.0.0",
        "title": "Paquete",
        "description": "descripción",
        "phases": [_phase()],
    }
    document.update(overrides)
    return yaml.safe_dump(document, allow_unicode=True)


# ------------------------------------------------------------------ the package
def test_base_package_declares_the_four_ordered_phases() -> None:
    package = _package()
    assert package.playbook_id == BASE
    assert [phase.phase_id for phase in package.phases] == [
        "stealth_recon",
        "staging_and_interaction",
        "command_execution",
        "local_elevation_heuristics",
    ]
    assert [phase.planner_phase for phase in package.phases] == [
        "recon",
        "enumeration",
        "privilege_escalation",
        "privilege_escalation",
    ]


def test_base_package_covers_the_requested_tactical_tools() -> None:
    tools = {
        step.tool_id
        for phase in _package().phases
        for step in phase.playbook.steps
    }
    # The four tactics the playbook exists to encode.
    assert {
        "nexus.recon.nmap",
        "nexus.web.upload",
        "nexus.post.shell_exec",
        "nexus.post.enum_system",
    } <= tools


def test_every_declared_telemetry_signal_exists_in_the_loop_vocabulary() -> None:
    declared = {
        signal
        for phase in _raw_base_document()["phases"]
        for signal in phase.get("telemetry", [])
    }
    assert declared  # the package declares what it needs to be measurable
    assert declared <= set(TURN_TELEMETRY_SIGNALS)


def test_every_step_is_reachable_by_the_profile_declared_for_its_phase() -> None:
    catalog = registry_module.durable_tool_definitions("system")
    assert validate_against_catalog(load_packages(strict=True), catalog) == []


def test_every_step_tool_exists_in_the_durable_catalog() -> None:
    catalog = registry_module.durable_tool_definitions("system")
    for phase in _package().phases:
        for step in phase.playbook.steps:
            assert step.tool_id in catalog, step.tool_id


# ------------------------------------------------------------------ registration
def test_registry_merges_hand_written_and_packaged_playbooks() -> None:
    ids = [item.playbook_id for item in registered_playbooks()]
    packaged = [item.playbook_id for item in packaged_playbooks()]
    for hand_written in PLAYBOOKS:
        assert hand_written.playbook_id in ids
    assert packaged and set(packaged) <= set(ids)
    assert all(item.startswith(f"{BASE}.") for item in packaged)


def test_packaged_phase_is_looked_up_and_gated_like_a_hand_written_one() -> None:
    assert playbook_by_id("red_team_base.stealth_recon") is not None
    assert playbook_by_id("red_team_base.nope") is None
    assert gate_for("red_team_base.stealth_recon") is not None
    assert gate_for("nope") is None
    assert is_applicable("red_team_base.stealth_recon", []) is True
    assert is_applicable("nope", []) is False


def _facts(*entries: tuple[str, str, dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"fact_type": kind, "key": key, "value": value, "verified": True,
         "asserted_by": "verifier", "verification_method": "fixture", "invocation_id": "fixture"}
        for kind, key, value in entries
    ]


def test_gates_follow_the_blackboard() -> None:
    base = f"{BASE}."
    empty = [match.playbook.playbook_id for match in select_playbooks([])]
    assert empty == [f"{base}stealth_recon"]

    with_service = [
        match.playbook.playbook_id
        for match in select_playbooks(_facts(("service", "10.0.0.5:80", {"port": 80})))
    ]
    assert f"{base}staging_and_interaction" in with_service
    assert f"{base}command_execution" not in with_service

    with_access = [
        match.playbook.playbook_id
        for match in select_playbooks(_facts(("access", "10.0.0.5", {"transport": "ssh"})))
    ]
    assert f"{base}command_execution" in with_access
    assert f"{base}local_elevation_heuristics" in with_access


def test_completion_requires_execution_proof_even_with_verified_global_facts() -> None:
    matches = {item.playbook.playbook_id: item for item in select_playbooks(
        _facts(("service", "10.0.0.5:80", {"port": 80}),
               ("endpoint", "http://10.0.0.5/", {"status_code": 200}))) }
    stealth = matches[f"{BASE}.stealth_recon"]
    assert stealth.next_step is not None
    assert stealth.next_step.step_id == "passive_footprint"
    assert stealth.completed == ()


def test_prompt_guidance_names_the_packaged_next_step() -> None:
    rendered = render_playbook_matches(select_playbooks([]))
    assert "[red_team_base.stealth_recon]" in rendered
    assert "nexus.recon.subfinder" in rendered


# --------------------------------------------------------------------- the tool
def test_orchestrator_tool_exposes_the_declarative_metadata(tmp_path: Path) -> None:
    from nexus_core.tools.handlers import playbook as playbook_handler

    context, _store = owned_context(tmp_path)
    result = asyncio.run(
        playbook_handler.playbook_handler(
            {"action": "show", "playbook_id": f"{BASE}.command_execution"}, context
        )
    )
    assert result.success
    assert result.output["applicable"] is False  # no access fact on the board yet
    assert result.output["declarative"]["subagent"] == "privesc"
    assert result.output["declarative"]["planner_phase"] == "privilege_escalation"
    assert [step["tool_id"] for step in result.output["playbook"]["steps"]][1] == (
        "nexus.post.shell_exec"
    )


def test_orchestrator_tool_next_lists_the_packaged_phase(tmp_path: Path) -> None:
    from nexus_core.tools.handlers import playbook as playbook_handler

    context, _store = owned_context(tmp_path)
    result = asyncio.run(playbook_handler.playbook_handler({"action": "next"}, context))
    ids = [item["playbook_id"] for item in result.output["playbooks"]]
    assert f"{BASE}.stealth_recon" in ids


# ------------------------------------------------------------------ strictness
def test_unknown_key_is_rejected() -> None:
    document = yaml.safe_load(_document())
    document["surprise"] = True
    with pytest.raises(PlaybookSchemaError):
        load_package_text(yaml.safe_dump(document))


def test_unknown_fact_type_is_rejected() -> None:
    document = yaml.safe_load(_document())
    document["phases"][0]["steps"][0]["produces"] = "made_up_fact"
    with pytest.raises(PlaybookSchemaError):
        load_package_text(yaml.safe_dump(document))


def test_unknown_telemetry_signal_is_rejected() -> None:
    document = yaml.safe_load(_document())
    document["phases"][0]["telemetry"] = ["vibes"]
    with pytest.raises(PlaybookSchemaError):
        load_package_text(yaml.safe_dump(document))


def test_unknown_subagent_profile_is_rejected() -> None:
    document = yaml.safe_load(_document())
    document["phases"][0]["subagent"] = "ninja"
    with pytest.raises(PlaybookSchemaError):
        load_package_text(yaml.safe_dump(document))


def test_phase_without_produced_facts_can_use_verified_execution_proof() -> None:
    document = yaml.safe_load(_document())
    document["phases"][0]["steps"][0]["produces"] = None
    assert load_package_text(yaml.safe_dump(document)).phases[0].playbook.steps[0].produces is None


def test_duplicate_phase_ids_are_rejected() -> None:
    document = yaml.safe_load(_document())
    document["phases"] = [document["phases"][0], dict(document["phases"][0])]
    with pytest.raises(PlaybookSchemaError) as excinfo:
        load_package_text(yaml.safe_dump(document))
    assert "phase_id duplicado" in str(excinfo.value) or "aliases" in str(excinfo.value)


def test_gate_requires_a_condition() -> None:
    document = yaml.safe_load(_document())
    document["phases"][0]["gate"] = {"min_count": 2}
    with pytest.raises(PlaybookSchemaError):
        load_package_text(yaml.safe_dump(document))


def test_invalid_yaml_is_reported_as_a_schema_error() -> None:
    with pytest.raises(PlaybookSchemaError):
        load_package_text("phases: [ {unbalanced")


def test_load_packages_degrades_softly_outside_strict_mode(tmp_path: Path) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text("schema_version: 1\n", encoding="utf-8")
    assert load_packages(tmp_path) == ()
    with pytest.raises(PlaybookSchemaError):
        load_packages(tmp_path, strict=True)
