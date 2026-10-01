"""E2E: a report built from all ten new tools has all five representations.

Deterministic and offline: the durable records are written through the same
store path the toolkit uses, then the report is extracted and rendered.
"""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.report import html as html_module
from nexus_core.report import markdown as markdown_module
from nexus_core.report.extractor import build_report
from nexus_core.tests import report_support as support

pytestmark = pytest.mark.integration

TARGET = support.LAB_TARGET
URL = f"http://{TARGET}/"


def _record_all(store, run_id):
    record = support.record
    result = support.result

    record(
        store, run_id, "nexus.web.sqlmap",
        {"url": f"{URL}?id=1"},
        result(
            {
                "url": f"{URL}?id=1",
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
    record(
        store, run_id, "nexus.web.dalfox",
        {"target": URL},
        result(
            {
                "target": URL,
                "count": 1,
                "findings": [
                    {
                        "method": "GET",
                        "url": f"{URL}?q=1",
                        "param": "q",
                        "payload": "<script>alert(1)</script>",
                        "evidence": "reflected",
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
    record(
        store, run_id, "nexus.recon.gobuster",
        {"target": URL, "mode": "dir"},
        result(
            {
                "target": URL,
                "mode": "dir",
                "count": 1,
                "hits": [{"path": "/admin", "status": 200, "size": 1, "redirect": None}],
            },
            verification_method="gobuster_text_parsed",
        ),
    )
    record(
        store, run_id, "nexus.recon.whatweb",
        {"targets": [URL]},
        result(
            {
                "targets": [URL],
                "count": 1,
                "fingerprints": [
                    {
                        "url": URL,
                        "http_status": 200,
                        "fingerprints": [
                            {"name": "Apache", "version": "2.4.49", "confidence": 100.0}
                        ],
                    }
                ],
            },
            verification_method="whatweb_json_parsed",
        ),
    )
    record(
        store, run_id, "nexus.exploit.searchsploit",
        {"query": "apache 2.4.49"},
        result(
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
                        "path": "/opt/exploitdb/50383.py",
                    }
                ],
                "shellcodes": [],
            },
            verification_method="searchsploit_json_parsed",
        ),
    )
    record(
        store, run_id, "nexus.recon.netexec",
        {"target": TARGET, "protocol": "smb", "operation": "shares"},
        result(
            {
                "protocol": "smb",
                "target": TARGET,
                "count": 1,
                "targets": [TARGET],
                "entries": [
                    {
                        "protocol": "SMB",
                        "target": TARGET,
                        "port": 445,
                        "host": TARGET,
                        "kind": "share",
                        "mark": "READ",
                        "text": "Public READ",
                    }
                ],
            },
            verification_method="netexec_text_parsed",
        ),
    )
    record(
        store, run_id, "nexus.recon.bloodhound_python",
        {"domain": "SCANME.EXAMPLE", "dc": TARGET},
        result(
            {
                "domain": "SCANME.EXAMPLE",
                "dc": TARGET,
                "file_count": 1,
                "total_records": 47,
                "files": [
                    {"name": "users.json", "collection": "users", "record_count": 47, "sha256": "b" * 64}
                ],
            },
            verification_method="bloodhound_json_parsed",
        ),
    )
    record(
        store, run_id, "nexus.attack.impacket_secretsdump",
        {"target": TARGET},
        result(
            {
                "target": TARGET,
                "method": "smbexec",
                "count": 1,
                "secret_count": 0,
                "sources": ["SAM"],
                "entries": [
                    {"username": "Administrator", "rid": "500", "lm_hash": "", "ntlm_hash": "a" * 32, "source": "SAM"}
                ],
                "secrets": [],
            },
            verification_method="secretsdump_files_parsed",
        ),
    )
    record(
        store, run_id, "nexus.attack.impacket_getuserspns",
        {"dc_ip": TARGET, "domain": "SCANME.EXAMPLE"},
        result(
            {
                "dc_ip": TARGET,
                "domain": "SCANME.EXAMPLE",
                "spn_count": 1,
                "hash_count": 0,
                "service_principals": [
                    {
                        "service_principal_name": "MSSQLSvc/db:1433",
                        "name": "svc_sql",
                        "member_of": "",
                        "password_last_set": "",
                        "last_logon": "",
                    }
                ],
                "hashes": [],
            },
            verification_method="getuserspns_text_parsed",
        ),
    )
    record(
        store, run_id, "nexus.attack.impacket_psexec",
        {"target": TARGET, "command": "whoami"},
        result(
            {
                "target": TARGET,
                "command": "whoami",
                "line_count": 1,
                "connected": True,
                "lines": ["nt authority\\system"],
            },
            verification_method="psexec_output_parsed",
        ),
    )


def test_full_report_covers_all_tool_types(tmp_path):
    store = support.make_store(tmp_path)
    support.seed_engagement(store)
    run_id = support.add_run(store)
    _record_all(store, run_id)

    report = asyncio.run(
        build_report(store, support.TENANT, "eng-lab", run_ids=[run_id])
    )

    # Findings from the five vulnerability-producing tools.
    finding_kinds = {finding.kind for finding in report.findings}
    assert {"sqli", "xss", "credentials", "kerberoast", "remote_exec"} <= finding_kinds
    assert next(f for f in report.findings if f.kind == "credentials").severity == "critical"

    # The other representations.
    assert {item.kind for item in report.inventories} == {"inventory"}
    assert len(report.inventories) == 2
    assert {item.kind for item in report.references} == {"reference"}
    assert {item.kind for item in report.surfaces} == {"surface"}
    assert {item.kind for item in report.evidences} == {"evidence"}

    markdown = markdown_module.render_markdown(report)
    for section in (
        "## Hallazgos",
        "## Inventario",
        "## Referencias",
        "## Superficie expuesta",
        "## Evidencia adicional",
    ):
        assert section in markdown
    assert "Rutas descubiertas" in markdown
    assert "Stack tecnológico identificado" in markdown
    assert "Exploits disponibles" in markdown
    assert "Superficie smb observada" in markdown
    assert "Mapa de Active Directory recolectado" in markdown

    html = html_module.render_html(report)
    for anchor in ("hallazgos", "inventario", "referencias", "superficie", "evidencia"):
        assert f"id='{anchor}'" in html
