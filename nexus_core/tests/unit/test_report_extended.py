"""The report represents every one of the 10 new tools (audit finding #6).

Not every tool yields a vulnerability. Each tool has a faithful representation:
findings for sqlmap/dalfox/secretsdump/getuserspns/psexec, inventories for
gobuster/whatweb, references for searchsploit, surfaces for netexec and evidence
for BloodHound.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from nexus_core.kernel.blackboard import Blackboard
from nexus_core.report import markdown as markdown_module
from nexus_core.report.extractor import (
    build_report,
    extract_findings,
    extract_report_items,
)
from nexus_core.tests import report_support as support

pytestmark = pytest.mark.unit


def _setup(tmp_path):
    store = support.make_store(tmp_path)
    support.seed_engagement(store)
    run_id = support.add_run(store)
    return store, run_id


def _extract_findings(store, run_id):
    return asyncio.run(
        extract_findings(store, support.TENANT, "eng-lab", [run_id])
    )


def _items(store, run_id):
    return asyncio.run(
        extract_report_items(store, support.TENANT, "eng-lab", [run_id])
    )


def _report(store, run_id):
    return asyncio.run(build_report(store, support.TENANT, "eng-lab", run_ids=[run_id]))


# -------------------------------------------------------------------- findings


def test_extract_sqlmap_finding(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.web.sqlmap",
        {"url": f"http://{support.LAB_TARGET}/?id=1", "flags": ["--batch"]},
        support.result(
            {
                "url": f"http://{support.LAB_TARGET}/?id=1",
                "noise_level": "high",
                "vulnerable": True,
                "findings": [
                    {
                        "parameter": "id",
                        "method": "GET",
                        "dbms": "MySQL",
                        "injection_type": "boolean-based blind",
                        "payload": "id=1 AND 1=1",
                        "title": "SQL injection en `id`",
                        "severity": "high",
                    }
                ],
            },
            verification_method="sqlmap_stdout_parsed",
        ),
    )
    findings, failed = _extract_findings(store, run_id)
    assert failed == []
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind == "sqli"
    assert finding.severity == "high"
    assert finding.cwe == "CWE-89"
    assert "T1190" in finding.mitre_techniques


def test_extract_dalfox_finding(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.web.dalfox",
        {"target": f"http://{support.LAB_TARGET}/"},
        support.result(
            {
                "target": f"http://{support.LAB_TARGET}/",
                "noise_level": "medium",
                "count": 1,
                "findings": [
                    {
                        "method": "GET",
                        "url": f"http://{support.LAB_TARGET}/?q=1",
                        "param": "q",
                        "payload": "<script>alert(1)</script>",
                        "evidence": "reflected in body",
                        "inject_type": "reflected",
                        "cwe": "CWE-79",
                        "severity": "medium",
                        "message": "Reflected XSS",
                    }
                ],
            },
            verification_method="dalfox_json_parsed",
        ),
    )
    findings, _ = _extract_findings(store, run_id)
    assert len(findings) == 1
    assert findings[0].kind == "xss"
    assert findings[0].severity == "medium"
    assert findings[0].cwe == "CWE-79"
    assert "T1059.007" in findings[0].mitre_techniques


def test_extract_secretsdump_critical(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.attack.impacket_secretsdump",
        {"target": support.LAB_TARGET, "username": "Administrator"},
        support.result(
            {
                "target": support.LAB_TARGET,
                "method": "smbexec",
                "count": 1,
                "secret_count": 0,
                "sources": ["SAM"],
                "entries": [
                    {
                        "username": "Administrator",
                        "rid": "500",
                        "lm_hash": "",
                        "ntlm_hash": "a" * 32,
                        "source": "SAM",
                    }
                ],
                "secrets": [],
                "raw_sha256": "z" * 64,
            },
            verification_method="secretsdump_files_parsed",
        ),
    )
    findings, _ = _extract_findings(store, run_id)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].kind == "credentials"
    assert "T1003.003" in findings[0].mitre_techniques


def test_extract_getuserspns_high(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.attack.impacket_getuserspns",
        {"dc_ip": support.LAB_TARGET, "domain": "SCANME.EXAMPLE"},
        support.result(
            {
                "dc_ip": support.LAB_TARGET,
                "domain": "SCANME.EXAMPLE",
                "spn_count": 1,
                "hash_count": 1,
                "service_principals": [
                    {
                        "service_principal_name": "MSSQLSvc/db:1433",
                        "name": "svc_sql",
                        "member_of": "",
                        "password_last_set": "",
                        "last_logon": "",
                    }
                ],
                "hashes": [
                    {
                        "username": "svc_sql",
                        "domain": "SCANME",
                        "service_principal_name": "MSSQLSvc/db:1433",
                        "ticket_hash": "$krb5tgs$23$...",
                    }
                ],
                "raw_sha256": "y" * 64,
            },
            verification_method="getuserspns_text_parsed",
        ),
    )
    findings, _ = _extract_findings(store, run_id)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].kind == "kerberoast"
    assert "T1558.003" in findings[0].mitre_techniques


def test_extract_psexec_critical(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.attack.impacket_psexec",
        {"target": support.LAB_TARGET, "command": "whoami"},
        support.result(
            {
                "target": support.LAB_TARGET,
                "command": "whoami",
                "line_count": 1,
                "connected": True,
                "lines": ["nt authority\\system"],
                "raw_output_sha256": "x" * 64,
            },
            verification_method="psexec_output_parsed",
        ),
    )
    findings, _ = _extract_findings(store, run_id)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].kind == "remote_exec"
    assert "T1021.002" in findings[0].mitre_techniques


# --------------------------------------------------- inventories / references


def test_extract_gobuster_inventory(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.recon.gobuster",
        {"target": f"http://{support.LAB_TARGET}", "mode": "dir"},
        support.result(
            {
                "target": f"http://{support.LAB_TARGET}",
                "mode": "dir",
                "noise_level": "low",
                "count": 2,
                "hits": [
                    {"path": "/admin", "status": 200, "size": 120, "redirect": None},
                    {"path": "/login", "status": 302, "size": 0, "redirect": "/auth"},
                ],
            },
            verification_method="gobuster_text_parsed",
        ),
    )
    inventories, references, surfaces, evidences = _items(store, run_id)
    assert references == () and surfaces == () and evidences == ()
    assert len(inventories) == 1
    item = inventories[0]
    assert item.kind == "inventory"
    assert "2" in item.title
    assert {hit["path"] for hit in item.detail["hits"]} == {"/admin", "/login"}
    assert "T1595" in item.mitre_techniques


def test_extract_whatweb_inventory(tmp_path):
    store, run_id = _setup(tmp_path)
    url = f"http://{support.LAB_TARGET}/"
    support.record(
        store,
        run_id,
        "nexus.recon.whatweb",
        {"targets": [url]},
        support.result(
            {
                "noise_level": "low",
                "targets": [url],
                "count": 1,
                "fingerprints": [
                    {
                        "url": url,
                        "http_status": 200,
                        "fingerprints": [
                            {"name": "Apache", "version": "2.4.49", "confidence": 100.0, "details": ""},
                            {"name": "PHP", "version": "8.1", "confidence": 100.0, "details": ""},
                        ],
                    }
                ],
            },
            verification_method="whatweb_json_parsed",
        ),
    )
    inventories, _, _, _ = _items(store, run_id)
    assert len(inventories) == 1
    item = inventories[0]
    assert item.kind == "inventory"
    tech = {entry["name"] for entry in item.detail["targets"][0]["technologies"]}
    assert tech == {"Apache", "PHP"}
    assert "T1592" in item.mitre_techniques


def test_extract_searchsploit_reference(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.exploit.searchsploit",
        {"query": "apache 2.4.49"},
        support.result(
            {
                "query": "apache 2.4.49",
                "total": 1,
                "exploits": [
                    {
                        "title": "Apache 2.4.49 Path Traversal",
                        "edb_id": "50383",
                        "date": "2021-10-05",
                        "author": "x",
                        "type": "remote",
                        "platform": "linux",
                        "path": "/opt/exploitdb/exploits/linux/remote/50383.py",
                    }
                ],
                "shellcodes": [],
            },
            verification_method="searchsploit_json_parsed",
        ),
    )
    _, references, _, _ = _items(store, run_id)
    assert len(references) == 1
    item = references[0]
    assert item.kind == "reference"
    assert item.detail["exploits"][0]["edb_id"] == "50383"
    assert "T1588.005" in item.mitre_techniques


# ---------------------------------------------------------------- surface/evidence


def test_extract_netexec_surface(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.recon.netexec",
        {"target": support.LAB_TARGET, "protocol": "smb", "operation": "shares"},
        support.result(
            {
                "protocol": "smb",
                "target": support.LAB_TARGET,
                "operation": "shares",
                "noise_level": "medium",
                "count": 2,
                "targets": [support.LAB_TARGET],
                "entries": [
                    {
                        "protocol": "SMB",
                        "target": support.LAB_TARGET,
                        "port": 445,
                        "host": support.LAB_TARGET,
                        "kind": "share",
                        "mark": "READ",
                        "text": "Public READ",
                    },
                    {
                        "protocol": "SMB",
                        "target": support.LAB_TARGET,
                        "port": 445,
                        "host": support.LAB_TARGET,
                        "kind": "signing",
                        "mark": "False",
                        "text": "signing:False",
                    },
                ],
                "raw_output_sha256": "w" * 64,
            },
            verification_method="netexec_text_parsed",
        ),
    )
    _, _, surfaces, _ = _items(store, run_id)
    assert len(surfaces) == 1
    item = surfaces[0]
    assert item.kind == "surface"
    assert item.detail["protocol"] == "smb"
    assert len(item.detail["entries"]) == 2
    assert "T1046" in item.mitre_techniques


def test_extract_bloodhound_evidence(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.recon.bloodhound_python",
        {"domain": "SCANME.EXAMPLE", "dc": support.LAB_TARGET},
        support.result(
            {
                "domain": "SCANME.EXAMPLE",
                "dc": support.LAB_TARGET,
                "file_count": 1,
                "total_records": 47,
                "files": [
                    {
                        "name": "users.json",
                        "collection": "users",
                        "record_count": 47,
                        "sha256": "b" * 64,
                    }
                ],
                "raw_json_sha256": "c" * 64,
            },
            verification_method="bloodhound_json_parsed",
        ),
    )
    _, _, _, evidences = _items(store, run_id)
    assert len(evidences) == 1
    item = evidences[0]
    assert item.kind == "evidence"
    assert item.detail["total_records"] == 47
    assert item.detail["files"][0]["sha256"] == "b" * 64
    assert "T1482" in item.mitre_techniques


# ------------------------------------------------------------------- rendering


def test_report_carries_all_collections(tmp_path):
    store, run_id = _setup(tmp_path)
    report = _report(store, run_id)
    assert report.inventories == ()
    assert report.references == ()
    assert report.surfaces == ()
    assert report.evidences == ()
    payload = report.to_dict()
    assert payload["inventories"] == []


def test_markdown_renders_new_sections(tmp_path):
    store, run_id = _setup(tmp_path)
    support.record(
        store,
        run_id,
        "nexus.recon.gobuster",
        {"target": f"http://{support.LAB_TARGET}", "mode": "dir"},
        support.result(
            {
                "target": f"http://{support.LAB_TARGET}",
                "mode": "dir",
                "count": 1,
                "hits": [{"path": "/admin", "status": 200, "size": 1, "redirect": None}],
            },
            verification_method="gobuster_text_parsed",
        ),
    )
    report = _report(store, run_id)
    text = markdown_module.render_markdown(report)
    for section in ("## Inventario", "## Referencias", "## Superficie expuesta", "## Evidencia adicional"):
        assert section in text
    assert "Rutas descubiertas" in text
    assert json.loads(markdown_module.render_markdown_json(report))["schema"] == "nexus.engagement_report/2"


# ------------------------------------------------------- blackboard facts (H3)
#: The 8 facts the operator logged during RUN7 (Bounty Hacker).
RUN7_FACTS = (
    ("service", "10.67.155.239:21/tcp", {"product": "vsftpd 3.0.5", "anonymous": True}),
    ("service", "10.67.155.239:22/tcp", {"product": "OpenSSH 8.2p1"}),
    ("service", "10.67.155.239:80/tcp", {"product": "Apache httpd 2.4.41"}),
    ("vulnerability", "vsftpd-3.0.5-backdoor", {"severity": "high", "service": "ftp"}),
    ("user", "lin", {"username": "lin", "shell": "/bin/bash"}),
    ("credential", "lin:ssh", {"username": "lin", "service": "ssh"}),
    ("access", "lin@10.67.155.239", {"user": "lin", "method": "ssh"}),
    ("privilege", "lin->root", {"vector": "sudo tar", "sudo": "(root) /bin/tar"}),
)


def _seed_facts(store, engagement_id: str = "eng-lab") -> None:
    board = Blackboard(store)
    for fact_type, key, value in RUN7_FACTS:
        board.record(
            tenant_id=support.TENANT,
            engagement_id=engagement_id,
            fact_type=fact_type,
            key=key,
            value=value,
            source="nexus.recon.nmap",
            created_by="operator-1",
        )


def test_facts_become_findings_and_inventory(tmp_path):
    store, run_id = _setup(tmp_path)
    _seed_facts(store)
    report = _report(store, run_id)
    # The 8 facts of RUN7 are 8 findings, none dropped.
    assert len(report.findings) == 8
    assert len({finding.finding_id for finding in report.findings}) == 8
    by_kind = {finding.kind: finding for finding in report.findings}
    assert {
        "fact_service",
        "fact_vulnerability",
        "fact_user",
        "fact_credential",
        "fact_access",
        "fact_privilege",
    } <= set(by_kind)
    assert by_kind["fact_privilege"].severity == "critical"
    assert by_kind["fact_credential"].severity == "high"
    assert by_kind["fact_service"].severity == "info"
    # The inventory is populated from the facts.
    assert report.inventories
    inventory = report.inventories[0]
    assert inventory.kind == "inventory"
    assert inventory.detail["total"] == 8
    assert inventory.detail["counts"]["service"] == 3
    # ... and it reaches the deliverable.
    text = markdown_module.render_markdown(report)
    assert "Inventario del engagement (8 hecho(s))" in text
    assert "no registró inventario" not in text


def test_no_facts_means_no_inventory(tmp_path):
    store, run_id = _setup(tmp_path)
    report = _report(store, run_id)
    assert report.inventories == ()
    assert all(not finding.kind.startswith("fact_") for finding in report.findings)
