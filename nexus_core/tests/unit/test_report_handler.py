"""``nexus.report.generate``: durable artifacts, chain of custody and audit."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.tests import report_support as support
from nexus_core.tools.handlers import report_generate as module
from nexus_core.tools.registry import register_durable_tools

TOOL = "nexus.report.generate"


def _context(store: object, scope: object = None) -> RunContext:
    """Agent identity with the store the handler reads (scope optional)."""
    return RunContext(
        tenant_id=support.TENANT,
        identity=Identity("agent:omni", support.TENANT, kind="agent", roles=("operator",)),
        scope=scope,
        store=store,
    )


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """A seeded store, a registered gateway and an isolated XDG data dir."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    store, engagement, run_id = support.seed_full_engagement(tmp_path)
    gateway = ToolGateway(PolicyEngine(), AuditWriter(store))
    register_durable_tools(gateway)
    return store, engagement, run_id, gateway


def _invoke(gateway, arguments, store):
    return asyncio.run(gateway.invoke(TOOL, arguments, _context(store)))


def _execute(arguments, store=None):
    return asyncio.run(module.report_generate_handler(arguments, _context(store)))


def test_report_validates_arguments(env):
    store, _engagement, _run_id, gateway = env
    with pytest.raises(ValueError):
        _invoke(gateway, {"engagement_id": ""}, store)
    with pytest.raises(ValueError):
        _invoke(gateway, {"engagement_id": "eng-lab", "format": "pdf"}, store)
    with pytest.raises(ValueError):
        _invoke(gateway, {"engagement_id": "eng-lab", "unexpected": 1}, store)


def test_report_inherits_active_engagement(env):
    """H2: with no ``engagement_id`` argument, the active scope is used."""
    store, engagement, _run_id, _gateway = env
    result = asyncio.run(
        module.report_generate_handler({}, _context(store, engagement))
    )
    assert result.verified is True
    assert result.output["engagement_id"] == engagement.engagement_id
    assert result.output["findings_count"] >= 6


def test_report_without_engagement_is_not_verified(env):
    store, _engagement, _run_id, _gateway = env
    result = _execute({"format": "both"}, store)
    assert result.verified is False
    assert result.verification_method == "report_missing_engagement"
    assert result.output["status"] == "missing_engagement"


def test_report_unknown_engagement_is_not_verified(env):
    store, _engagement, _run_id, _gateway = env
    result = _execute({"engagement_id": "eng-missing"}, store)
    assert result.verified is False
    assert result.verification_method == "report_unknown_engagement"
    assert result.output["status"] == "unknown_engagement"


def test_report_generates_markdown_only(env):
    store, engagement, _run_id, gateway = env
    result = _invoke(
        gateway, {"engagement_id": engagement.engagement_id, "format": "markdown"}, store
    )
    output = result["output"]
    assert output["report_path_md"].endswith("report.md")
    assert output["report_path_html"] == ""
    assert output["report_path_json"].endswith("report.json")
    assert Path(output["report_path_md"]).is_file()
    assert not Path(output["directory"], "report.html").exists()
    assert "# Reporte de Pentesting" in Path(output["report_path_md"]).read_text()


def test_report_generates_html_only(env):
    store, engagement, _run_id, gateway = env
    result = _invoke(
        gateway, {"engagement_id": engagement.engagement_id, "format": "html"}, store
    )
    output = result["output"]
    assert output["report_path_html"].endswith("report.html")
    assert output["report_path_md"] == ""
    text = Path(output["report_path_html"]).read_text()
    assert text.startswith("<!DOCTYPE html>")
    assert "<script" not in text.lower()


def test_report_generates_both(env):
    store, engagement, _run_id, gateway = env
    result = _invoke(
        gateway, {"engagement_id": engagement.engagement_id, "format": "both"}, store
    )
    output = result["output"]
    assert result["verified"] is True
    assert result["verification_method"] == "report_generated_from_audit"
    assert output["findings_count"] >= 6
    assert output["severity_breakdown"]["critical"] >= 1
    assert output["severity_breakdown"]["info"] >= 1
    assert output["failed_attempts"] == 2
    assert output["sessions_opened"] == 1
    assert "nexus.recon.nmap" in output["tools_used"]
    assert Path(output["report_path_md"]).is_file()
    assert Path(output["report_path_html"]).is_file()
    assert Path(output["report_path_json"]).is_file()
    assert output["markdown_size_bytes"] > 1000
    assert output["html_size_bytes"] > 1000
    assert json.loads(Path(output["report_path_json"]).read_text())["engagement_id"] == (
        engagement.engagement_id
    )


def test_report_writes_to_output_dir(env, tmp_path):
    store, engagement, _run_id, gateway = env
    target = tmp_path / "client-deliverable"
    result = _invoke(
        gateway,
        {"engagement_id": engagement.engagement_id, "output_dir": str(target)},
        store,
    )
    assert result["verified"] is True
    assert (target / "report.md").is_file()
    assert (target / "report.html").is_file()
    assert (target / "report.json").is_file()
    assert result["output"]["directory"] == str(target)


def test_report_registers_artifact_with_sha256(env):
    import hashlib

    store, engagement, _run_id, gateway = env
    result = _invoke(gateway, {"engagement_id": engagement.engagement_id}, store)
    evidence = result["evidence"]
    assert len(evidence["artifacts"]) == 3
    assert set(evidence["artifact_sha256"]) == {"report.md", "report.html", "report.json"}
    for name, digest in evidence["artifact_sha256"].items():
        body = Path(result["output"]["directory"], name).read_bytes()
        assert len(digest) == 64
        assert digest == hashlib.sha256(body).hexdigest()
    with store.connect() as conn:
        rows = conn.execute(
            # Scope to the report's own deliverables: since P2-D4 the same
            # store also holds content-addressed invocation results.
            "SELECT id, sha256, media_type FROM kernel_artifacts "
            "WHERE tenant_id=? AND metadata LIKE '%engagement_report%'",
            (support.TENANT,),
        ).fetchall()
    assert len(rows) == 3
    by_id = {row["id"]: row for row in rows}
    for artifact_id in evidence["artifacts"]:
        assert artifact_id in by_id
        assert len(by_id[artifact_id]["sha256"]) == 64
    # The report itself is content-addressed too.
    assert len(result["output"]["report_sha256"]) == 64
    assert result["evidence"]["report_sha256"] == result["output"]["report_sha256"]


def test_report_audits_its_own_generation(env):
    store, engagement, _run_id, gateway = env
    _invoke(
        gateway,
        {"engagement_id": engagement.engagement_id, "format": "markdown"},
        store,
    )
    events = AuditWriter(store).export(support.TENANT)
    generated = [event for event in events if event["action"] == module.REPORT_AUDIT_ACTION]
    assert len(generated) == 1
    payload = generated[0]["payload"]
    assert payload["format"] == "markdown"
    assert payload["findings_count"] >= 6
    assert payload["audit_chain_valid"] is True
    assert generated[0]["resource_type"] == "engagement"
    assert generated[0]["resource_id"] == engagement.engagement_id
    # The gateway also recorded the invocation itself.
    assert any(
        event["action"] == "tool.complete" and event["resource_id"] == TOOL for event in events
    )


def test_report_flags_broken_audit_chain(env):
    store, engagement, _run_id, gateway = env
    with store.connect() as conn:
        conn.execute("UPDATE kernel_audit_events SET event_hash='deadbeef' WHERE sequence=1")
    result = _invoke(gateway, {"engagement_id": engagement.engagement_id}, store)
    # Generating the report still succeeds (fail-safe): the tool post-condition
    # is that the deliverables were produced from the durable record.
    assert result["verified"] is True
    # ... but the broken chain is surfaced in evidence and in the report body.
    assert result["evidence"]["audit_chain_valid"] is False
    assert result["evidence"]["findings"] >= 6  # the report is still produced
    markdown = Path(result["output"]["report_path_md"]).read_text()
    assert "NO VERIFICADA" in markdown
    assert "NO VERIFICADA" in Path(result["output"]["report_path_html"]).read_text()


def test_report_never_executes_shell(env):
    store, engagement, _run_id, gateway = env
    with (
        patch("subprocess.Popen", side_effect=AssertionError("no subprocess")),
        patch("asyncio.create_subprocess_exec", side_effect=AssertionError("no process")),
    ):
        result = _invoke(gateway, {"engagement_id": engagement.engagement_id}, store)
    assert result["verified"] is True


def test_report_llm_cvss_degrades_without_provider(env, monkeypatch):
    store, engagement, _run_id, gateway = env
    monkeypatch.setenv("NEXUS_LLM_DEFAULT_PROVIDER", "fake")
    result = _invoke(
        gateway,
        {"engagement_id": engagement.engagement_id, "llm_cvss": True},
        store,
    )
    assert result["verified"] is True
    assert result["evidence"]["llm_cvss"] is True
    payload = json.loads(Path(result["output"]["report_path_json"]).read_text())
    assert all(finding["cvss_source"] in {"heuristic", "llm", "tool"} for finding in payload["findings"])


def test_report_default_directory_is_under_xdg_data(env, tmp_path):
    store, engagement, _run_id, gateway = env
    result = _invoke(gateway, {"engagement_id": engagement.engagement_id}, store)
    directory = Path(result["output"]["directory"])
    assert directory.parent == tmp_path / "xdg" / "omni" / "reports"
    assert directory.name.startswith(engagement.name)


def test_report_direct_handler_requires_store():
    result = _execute({"engagement_id": "eng-lab"})
    assert result.verified is False
    assert result.verification_method == "report_store_missing"


def test_report_artifact_store_is_content_addressed(env, tmp_path):
    """Two runs of the same report reuse one storage path per digest."""
    from nexus_core.kernel.artifacts import LocalArtifactStore

    store, engagement, _run_id, gateway = env
    first = _invoke(
        gateway,
        {"engagement_id": engagement.engagement_id, "output_dir": str(tmp_path / "a")},
        store,
    )
    second = _invoke(
        gateway,
        {"engagement_id": engagement.engagement_id, "output_dir": str(tmp_path / "b")},
        store,
    )
    assert first["verified"] is True and second["verified"] is True
    # The JSON carries the generation timestamp, so only identical bytes are
    # deduplicated: addresses are portable and blobs remain tenant-scoped.
    roots = {item["sha256"] for item in [{"sha256": s} for s in first["evidence"]["artifact_sha256"].values()]}
    assert roots
    digest = next(iter(roots))
    with store.connect() as conn:
        rows = conn.execute(
            "SELECT storage_uri FROM kernel_artifacts WHERE tenant_id=? AND sha256=?",
            (support.TENANT, digest),
        ).fetchall()
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM kernel_artifacts WHERE tenant_id=? "
            "AND metadata LIKE '%engagement_report%'",
            (support.TENANT,),
        ).fetchone()["n"]
    assert count == 6  # three deliverables per generation, both recorded
    assert rows
    root = LocalArtifactStore(store, module.default_artifact_root()).root
    for row in rows:
        assert row["storage_uri"] == f"cas:v1/{support.TENANT}/{digest}"
        assert (root / support.TENANT / digest[:2] / digest).is_file()


def test_report_sarif_format_writes_sarif(env):
    """``format=sarif`` emits a valid SARIF 2.1.0 document and nothing else."""
    from nexus_core.report.sarif import validate_sarif

    store, engagement, _run_id, gateway = env
    result = _invoke(
        gateway, {"engagement_id": engagement.engagement_id, "format": "sarif"}, store
    )
    output = result["output"]
    assert output["report_path_sarif"].endswith("report.sarif")
    assert output["report_path_md"] == ""
    assert not Path(output["directory"], "report.md").exists()
    document = json.loads(Path(output["report_path_sarif"]).read_text())
    assert document["version"] == "2.1.0"
    assert validate_sarif(document) == []
    assert len(document["runs"][0]["results"]) == output["findings_count"]
    assert output["sarif_size_bytes"] > 0


def test_report_json_carries_dual_cvss_and_frameworks(env):
    store, engagement, _run_id, gateway = env
    result = _invoke(gateway, {"engagement_id": engagement.engagement_id}, store)
    payload = json.loads(Path(result["output"]["report_path_json"]).read_text())
    assert payload["findings"]
    for finding in payload["findings"]:
        assert finding["cvss4_source"] in {"tool", "llm", "heuristic", "nvd", "none"}
        assert isinstance(finding["frameworks"], list)
        assert finding["frameworks"]
    markdown = Path(result["output"]["report_path_md"]).read_text()
    assert "CVSS v3.1" in markdown and "CVSS v4.0" in markdown
    assert "Mapeo de marcos" in markdown
    assert "Cobertura de marcos" in markdown
