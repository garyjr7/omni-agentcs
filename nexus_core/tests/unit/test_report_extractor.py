"""``nexus_core.report.extractor``: findings, failed attempts and attribution."""

from __future__ import annotations

from datetime import timedelta

import pytest

from nexus_core.report.extractor import (
    extract_engagement_metadata,
    extract_findings,
    extract_findings_sync,
    matches_scope,
    summarize_scope,
)
from nexus_core.tests import report_support as support


def _extract(store, engagement_id="eng-lab", run_ids=None):
    import asyncio

    return asyncio.run(extract_findings(store, support.TENANT, engagement_id, run_ids))


def _setup(tmp_path):
    store = support.make_store(tmp_path)
    support.seed_engagement(store)
    run_id = support.add_run(store)
    return store, run_id


def test_extract_nmap_finding(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.recon.nmap",
        {"target": support.LAB_TARGET, "ports": "22,80"},
        support.result(
            support.nmap_output(),
            verification_method="nmap_xml_parsed",
            evidence={"hosts_up": 1, "ports_open_total": 2, "raw_xml_sha256": "a" * 64},
        ),
    )
    findings, failed = _extract(store)

    assert failed == []
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "info"          # ssh + http are routine exposure
    assert finding.kind == "open_ports"
    assert finding.discovered_by_tool == "nexus.recon.nmap"
    assert support.LAB_TARGET + ":22" in finding.affected_targets
    assert "T1046" in finding.mitre_techniques  # enriched from the tool map
    assert any(item.sha256 for item in finding.evidence)


def test_extract_nmap_legacy_port_is_medium(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.recon.nmap",
        {"target": support.LAB_TARGET},
        support.result(
            support.nmap_output(ports=(("23", "telnet"), ("22", "ssh"))),
            verification_method="nmap_xml_parsed",
            evidence={"hosts_up": 1, "raw_xml_sha256": "a" * 64},
        ),
    )
    findings, _ = _extract(store)
    assert findings[0].severity == "medium"


def test_extract_nuclei_multiple_findings(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.web.nuclei",
        {"targets": [support.LAB_TARGET], "severity": ["low", "medium", "high"]},
        support.result(
            support.nuclei_output(
                (
                    support.nuclei_finding(),
                    support.nuclei_finding(
                        template_id="exposed-git-config",
                        name="Exposed .git/config",
                        severity_value="medium",
                        tags=("exposure", "git"),
                    ),
                )
            ),
            verification_method="nuclei_jsonl_parsed",
            evidence={"count": 2, "raw_sha256": "d" * 64},
        ),
    )
    findings, _ = _extract(store)

    assert len(findings) == 2
    apache = next(item for item in findings if "Apache" in item.title)
    assert apache.severity == "high"
    assert apache.cve == "CVE-2021-41773"
    assert apache.mitre_techniques == ("T1190",)  # enriched from the tool map
    git_config = next(item for item in findings if "git" in item.title.lower())
    assert git_config.severity == "medium"
    assert git_config.cve is None


def test_extract_subfinder_count_finding(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.recon.subfinder",
        {"domain": support.LAB_DOMAIN},
        support.result(
            support.subfinder_output(),
            verification_method="subfinder_jsonl_parsed",
            evidence={"count": 3, "raw_sha256": "e" * 64},
        ),
    )
    findings, _ = _extract(store)

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "3" in findings[0].title
    assert len(findings[0].affected_targets) == 3
    assert "T1595" in findings[0].mitre_techniques


def test_extract_ffuf_hits_finding(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.web.ffuf",
        {"url": f"http://{support.LAB_TARGET}/FUZZ"},
        support.result(
            support.ffuf_output(),
            verification_method="ffuf_json_parsed",
            evidence={"count": 2, "raw_sha256": "f" * 64},
        ),
    )
    findings, _ = _extract(store)

    by_kind = {finding.kind: finding for finding in findings}
    assert set(by_kind) == {"http_surface", "endpoint_protected"}
    assert by_kind["http_surface"].severity == "info"
    assert by_kind["endpoint_protected"].severity == "low"
    assert "403" in by_kind["endpoint_protected"].affected_targets[0]
    assert by_kind["endpoint_protected"].owasp_category == "A01:2021-Broken Access Control"


def test_extract_msf_exploit_success_critical(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.exploit.msf_exploit",
        {"module": "exploit/linux/http/apache_mod_cgi_bash_env_exec", "target": support.LAB_TARGET},
        support.result(
            support.exploit_output(),
            verification_method="msf_exploit_session_opened",
            evidence={"module": "m", "target": support.LAB_TARGET, "session_uuid": "abc12345"},
        ),
    )
    findings, failed = _extract(store)

    assert failed == []
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "critical"
    assert finding.kind == "session_opened"
    assert support.LAB_TARGET in finding.affected_targets
    assert "T1190" in finding.mitre_techniques and "T1210" in finding.mitre_techniques
    assert "nexus.session.list" in " ".join(finding.reproduction_steps)


def test_extract_msf_exploit_failure_as_failed_attempt(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.exploit.msf_exploit",
        {"module": "exploit/multi/handler", "target": support.LAB_TARGET},
        support.result(
            support.exploit_output("timeout"),
            verification_method="msf_exploit_timeout",
            evidence={"module": "exploit/multi/handler", "target": support.LAB_TARGET},
        ),
    )
    findings, failed = _extract(store)

    assert findings == []
    assert len(failed) == 1
    assert failed[0].tool_id == "nexus.exploit.msf_exploit"
    assert failed[0].target == support.LAB_TARGET
    assert "sin abrir sesión" in failed[0].reason


def test_extract_session_interact_hashdump_critical(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.session.interact",
        {"session_uuid": "abc12345", "command": "hashdump"},
        support.result(
            support.session_output("hashdump", text="Administrator:500:aad3b435b51404ee...\n"),
            verification_method="msf_session_interact_ok",
        ),
        engagement_id="eng-lab",  # the REPL stamps the live engagement
    )
    findings, _ = _extract(store)

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].kind == "session_command"
    # The command contributes T1003 and the tool itself T1059 (union, deduped).
    assert findings[0].mitre_techniques == ("T1003", "T1059")
    assert "abc12345" in findings[0].affected_targets


def test_extract_session_interact_id_is_info(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.session.interact",
        {"session_uuid": "abc12345", "command": "id"},
        support.result(support.session_output("id"), verification_method="msf_session_interact_ok"),
        engagement_id="eng-lab",
    )
    findings, _ = _extract(store)
    assert findings[0].severity == "info"
    assert "uid=33" in findings[0].description
    assert findings[0].mitre_techniques == ("T1033", "T1059")


def test_extract_scope_denied_not_a_finding(tmp_path):
    store, run_id = _setup(tmp_path)
    # A real run mixes an authorized call with a refused one.
    support.record(
        store,
        run_id,
        "nexus.recon.nmap",
        {"target": support.LAB_TARGET},
        support.result(support.nmap_output(), verification_method="nmap_xml_parsed"),
    )
    support.audit(
        store,
        run_id=run_id,
        action="scope.denied",
        tool_id="nexus.recon.nmap",
        payload={
            "target_keys": ["target"],
            "reason": "ScopeViolation(example.com): target is outside the engagement",
        },
        decision="deny",
    )
    findings, failed = _extract(store)

    assert [finding.kind for finding in findings] == ["open_ports"]
    assert len(failed) == 1
    assert failed[0].tool_id == "nexus.recon.nmap"
    assert "denegado por scope" in failed[0].reason
    assert "example.com" in failed[0].reason  # the refused target survives
    assert failed[0].evidence[0].kind == "audit_event"
    assert failed[0].evidence[0].sha256  # chained event hash


def test_extract_tool_failed_is_failed_attempt(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.web.nuclei",
        {"targets": [support.LAB_TARGET]},
        support.result({}, verified=False, verification_method="nuclei_templates_missing"),
    )
    findings, failed = _extract(store)

    assert findings == []
    assert len(failed) == 1
    assert "no verificó su post-condition" in failed[0].reason


def test_extract_deduplication_within_5_minutes(tmp_path):
    store, run_id = _setup(tmp_path)
    for offset in (0, 60, 120):
        support.record(
            store,
            run_id,
            "nexus.recon.subfinder",
            {"domain": support.LAB_DOMAIN},
            support.result(
                support.subfinder_output(),
                verification_method="subfinder_jsonl_parsed",
                evidence={"count": 3, "raw_sha256": "e" * 64},
            ),
            at=support.iso(timedelta(seconds=offset)),
        )
    findings, _ = _extract(store)

    assert len(findings) == 1
    assert findings[0].reproductions == 3
    # Every ToolResult is kept, each paired with its own completion event.
    tool_results = [item for item in findings[0].evidence if item.kind == "tool_result"]
    audit_events = [item for item in findings[0].evidence if item.kind == "audit_event"]
    assert len(tool_results) == 3
    assert len(audit_events) == 3


def test_extract_no_deduplication_outside_window(tmp_path):
    store, run_id = _setup(tmp_path)
    for offset in (0, 3600):
        support.record(
            store,
            run_id,
            "nexus.recon.subfinder",
            {"domain": support.LAB_DOMAIN},
            support.result(
                support.subfinder_output(),
                verification_method="subfinder_jsonl_parsed",
                evidence={"count": 3, "raw_sha256": "e" * 64},
            ),
            at=support.iso(timedelta(seconds=offset)),
        )
    findings, _ = _extract(store)
    assert len(findings) == 2
    assert {finding.reproductions for finding in findings} == {1}


def test_extract_empty_audit_returns_empty(tmp_path):
    store, _ = _setup(tmp_path)
    findings, failed = _extract(store)
    assert findings == []
    assert failed == []


def test_extract_engagement_metadata(tmp_path):
    import asyncio

    store = support.make_store(tmp_path)
    support.seed_engagement(store, support.lab_scope(exclusions=("203.0.113.250",)))
    metadata = asyncio.run(
        extract_engagement_metadata(store, support.TENANT, "eng-lab")
    )

    assert metadata["engagement_name"] == "lab-engagement"
    assert metadata["client"] == "ACME"
    assert metadata["operator"] == "operator-1"
    assert metadata["scope_summary"] == "1 CIDR, 1 dominio, 0 URLs, 1 exclusión"
    assert metadata["scope_full"]["cidrs"] == ["203.0.113.0/24"]
    assert metadata["scope_full"]["exclusions"] == ["203.0.113.250"]
    assert metadata["audit_chain_valid"] is True


def test_extract_unknown_engagement_raises(tmp_path):
    store = support.make_store(tmp_path)
    with pytest.raises(KeyError):
        extract_findings_sync(store, support.TENANT, "eng-missing")


def test_extract_preserves_evidence_sha256(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.web.nuclei",
        {"targets": [support.LAB_TARGET]},
        support.result(
            support.nuclei_output((support.nuclei_finding(),)),
            verification_method="nuclei_jsonl_parsed",
            evidence={"count": 1, "raw_sha256": "9" * 64},
        ),
    )
    findings, _ = _extract(store)

    kinds = {item.kind for item in findings[0].evidence}
    assert {"tool_result", "audit_event"} <= kinds
    tool_evidence = next(item for item in findings[0].evidence if item.kind == "tool_result")
    assert tool_evidence.sha256 == "9" * 64
    event_evidence = next(item for item in findings[0].evidence if item.kind == "audit_event")
    assert event_evidence.sha256  # the chained event hash


def test_extract_out_of_scope_tool_call_is_not_attributed(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.recon.nmap",
        {"target": "198.51.100.7"},  # outside the signed engagement
        support.result(
            support.nmap_output("198.51.100.7"),
            verification_method="nmap_xml_parsed",
            evidence={"hosts_up": 1, "raw_xml_sha256": "a" * 64},
        ),
    )
    findings, _ = _extract(store)
    assert findings == []


def test_extract_handles_malformed_event_payload(tmp_path):
    from nexus_core.agent import memory

    store, run_id = _setup(tmp_path)
    conversation_id = memory.ensure_conversation(store, support.TENANT, run_id, "omni")
    # A truncated observation body must degrade, never raise.
    memory.append_step(
        store,
        support.TENANT,
        conversation_id,
        "user",
        '{"tool_id": "nexus.recon.nmap", "output": {"scan": {"hosts": [{"ip":',
        {"kind": "react.observation", "tool_id": "nexus.recon.nmap", "run_id": run_id},
    )
    findings, failed = _extract(store)
    assert findings == [] and failed == []


def test_matches_scope_offline(tmp_path):
    scope = support.lab_scope()
    assert matches_scope(support.LAB_TARGET, scope) is True
    assert matches_scope("203.0.113.10:8080", scope) is True
    assert matches_scope(f"http://{support.LAB_TARGET}/admin", scope) is True
    assert matches_scope(f"https://{support.LAB_DOMAIN}/", scope) is True
    assert matches_scope(f"sub.{support.LAB_DOMAIN}", scope) is True
    assert matches_scope("198.51.100.7", scope) is False
    assert matches_scope("example.com", scope) is False
    assert matches_scope("", scope) is False


def test_matches_scope_exclusions_win():
    scope = support.lab_scope(exclusions=("203.0.113.10", "banned.scanme.example"))
    assert matches_scope("203.0.113.10", scope) is False
    assert matches_scope("banned.scanme.example", scope) is False
    assert matches_scope("203.0.113.11", scope) is True


def test_summarize_scope_pluralization():
    scope = support.lab_scope(cidrs=("10.0.0.0/8", "10.1.0.0/16"), domains=("a.example",))
    summary = summarize_scope(scope)
    assert "2 CIDRs" in summary
    assert "1 dominio," in summary
