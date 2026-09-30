"""Opt-in end-to-end tests for the five new web/recon durable tools.

Gated behind ``NEXUS_E2E=1``. They drive the real handlers through the real
local sandbox against the authorised ``scanme.nmap.org`` target (plus a local
Exploit-DB lookup), so they need the binaries installed and network access.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.tools.handlers.dalfox import dalfox_handler
from nexus_core.tools.handlers.gobuster import gobuster_handler
from nexus_core.tools.handlers.searchsploit import searchsploit_handler
from nexus_core.tools.handlers.sqlmap import sqlmap_handler
from nexus_core.tools.handlers.whatweb import whatweb_handler

ENABLED = os.getenv("NEXUS_E2E") == "1"

pytestmark = pytest.mark.skipif(
    not ENABLED, reason="set NEXUS_E2E=1 to run the live web/recon tests"
)

SCANME = "http://scanme.nmap.org/"
SCANME_PARAM = "http://scanme.nmap.org/?id=1"


def _context(run_id: str) -> RunContext:
    return RunContext(
        "system",
        Identity("operator:e2e", "system", roles=("operator",)),
        run_id=run_id,
    )


def _run(handler, arguments: dict, run_id: str):
    return asyncio.run(handler(arguments, _context(run_id)))


@pytest.fixture(autouse=True)
def _workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    return tmp_path


@pytest.mark.skipif(shutil.which("searchsploit") is None, reason="searchsploit missing")
def test_e2e_searchsploit_local_lookup():
    result = _run(searchsploit_handler, {"query": "apache"}, "e2e-searchsploit")
    assert result.verified is True
    assert result.output["total"] >= 1
    assert result.evidence["exploits"] >= 1


@pytest.mark.skipif(shutil.which("whatweb") is None, reason="whatweb missing")
def test_e2e_whatweb_fingerprints_scanme():
    result = _run(whatweb_handler, {"targets": [SCANME], "aggression": 1}, "e2e-whatweb")
    assert result.verified is True
    assert result.evidence["target_count"] >= 1
    assert result.evidence["fingerprint_count"] >= 1


@pytest.mark.skipif(shutil.which("gobuster") is None, reason="gobuster missing")
def test_e2e_gobuster_dir_against_scanme(_workspace):
    wordlist = Path(_workspace) / "words.txt"
    wordlist.write_text("index.html\nrobots.txt\nshared\n", encoding="utf-8")
    result = _run(
        gobuster_handler,
        {"mode": "dir", "target": SCANME, "wordlist": str(wordlist), "threads": 5},
        "e2e-gobuster",
    )
    assert result.verified is True
    assert result.evidence["mode"] == "dir"


@pytest.mark.skipif(shutil.which("sqlmap") is None, reason="sqlmap missing")
def test_e2e_sqlmap_detection_only():
    result = _run(
        sqlmap_handler,
        {"url": SCANME_PARAM, "level": 1, "risk": 1, "timeout_seconds": 300},
        "e2e-sqlmap",
    )
    assert result.verified is True
    assert "vulnerable" in result.output


@pytest.mark.skipif(shutil.which("dalfox") is None, reason="dalfox missing")
def test_e2e_dalfox_handles_zero_findings():
    result = _run(
        dalfox_handler,
        {"target": SCANME_PARAM, "workers": 3, "timeout_seconds": 300},
        "e2e-dalfox",
    )
    assert result.verified is True
    assert result.output["count"] >= 0
