"""End-to-end tests for the recon/web toolkit. Opt-in via NEXUS_E2E=1.

Every test needs live network access and its own binary, so each one carries a
``skipif``. The nuclei test is additionally skipped when no template directory
is installed (``nuclei -update-templates``).
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext, build_default_registry
from nexus_core.scope import EngagementScope, EngagementStore, ScopeViolation

E2E_ENABLED = os.getenv("NEXUS_E2E") == "1"
SKIP_UNLESS_E2E = pytest.mark.skipif(
    not E2E_ENABLED, reason="set NEXUS_E2E=1 to run live network tools"
)


def _requires(binary: str):
    return pytest.mark.skipif(
        shutil.which(binary) is None, reason=f"{binary} binary is not installed"
    )


def _nuclei_templates_present() -> bool:
    """True only when a template directory with at least one template exists.

    nuclei creates an empty ``~/nuclei-templates`` even when it then fails to
    download anything, so an existence check is not enough.
    """
    override = os.getenv("NEXUS_NUCLEI_TEMPLATES")
    candidates = [Path.home() / "nuclei-templates", Path.home() / ".local" / "nuclei-templates"]
    if override:
        candidates.insert(0, Path(override))
    for path in candidates:
        if not path.is_dir():
            continue
        if next(iter(path.rglob("*.yaml")), None) is not None:
            return True
    return False


SKIP_WITHOUT_NUCLEI_TEMPLATES = pytest.mark.skipif(
    not _nuclei_templates_present(),
    reason="nuclei templates are not installed (run 'nuclei -update-templates')",
)

SCANME_HOST = "scanme.nmap.org"
SCANME_IPV4 = "45.33.32.156"
SCANME_IPV6 = "2600:3c01::f03c:91ff:fe18:bb2f"
#: scanme only serves plain HTTP; port 443 is closed.
SCANME_HTTP_URL = "http://scanme.nmap.org"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _cidr_for(address: str) -> str:
    return f"{address}/128" if ":" in address else f"{address}/32"


def _scope(engagement_id: str, domains: tuple[str, ...], addresses: tuple[str, ...]):
    return EngagementScope(
        engagement_id=engagement_id,
        tenant_id="system",
        name=engagement_id,
        client="nexus-e2e",
        owner_id="owner-1",
        valid_from=_iso(-timedelta(days=1)),
        valid_until=_iso(timedelta(days=1)),
        cidrs=tuple(_cidr_for(address) for address in addresses),
        domains=domains,
        urls=(),
        exclusions=(),
        created_at=_iso(timedelta(0)),
    )


def _scanme_scope() -> EngagementScope:
    # scanme.nmap.org resolves to both an A and an AAAA record; the validator
    # requires every resolved address to fall inside the scope.
    return _scope("eng-scanme", (SCANME_HOST,), (SCANME_IPV4, SCANME_IPV6))


def _resolved_scope(engagement_id: str, host: str) -> EngagementScope:
    try:
        infos = socket.getaddrinfo(host, 80, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:  # pragma: no cover - depends on live DNS
        pytest.skip(f"cannot resolve {host}: {exc}")
    addresses = tuple(sorted({str(info[4][0]) for info in infos}))
    return _scope(engagement_id, (host,), addresses)


def _run_tool(store: ControlStore, payload: dict) -> dict:
    run = store.create_run("system", {})
    store.enqueue_task(
        tenant_id="system", run_id=run["id"], task_type="tool.invoke", payload=payload
    )
    claimed = store.claim_task("worker-test")
    assert claimed is not None
    return asyncio.run(
        build_default_registry().execute(claimed, ExecutionContext(store, claimed, "worker-test"))
    )


def _operator() -> dict:
    return {"subject_id": "operator-1", "roles": ["operator"]}


@SKIP_UNLESS_E2E
@_requires("subfinder")
def test_e2e_subfinder_against_nmap_org_in_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    EngagementStore(store).create(_resolved_scope("eng-nmaporg", "nmap.org"))

    result = _run_tool(
        store,
        {
            "tool_id": "nexus.recon.subfinder",
            "arguments": {"domain": "nmap.org", "timeout_seconds": 120},
            "engagement_id": "eng-nmaporg",
            "identity": _operator(),
        },
    )

    output = result["output"]
    assert output["verified"] is True
    assert output["evidence"]["noise_level"] == "low"
    assert output["evidence"]["passive"] is True
    assert output["evidence"]["count"] >= 1
    assert all(domain.endswith("nmap.org") for domain in output["output"]["subdomains"])


@SKIP_UNLESS_E2E
@_requires("httpx")
def test_e2e_httpx_against_scanme_in_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    EngagementStore(store).create(_scanme_scope())

    result = _run_tool(
        store,
        {
            "tool_id": "nexus.recon.httpx",
            "arguments": {"targets": [SCANME_HTTP_URL], "tech_detect": True},
            "engagement_id": "eng-scanme",
            "identity": _operator(),
        },
    )

    output = result["output"]
    assert output["verified"] is True
    assert output["evidence"]["hosts_alive"] >= 1
    assert "200" in output["evidence"]["status_counts"]
    assert output["output"]["probes"][0]["url"].startswith("http://scanme")


@SKIP_UNLESS_E2E
@_requires("nuclei")
@SKIP_WITHOUT_NUCLEI_TEMPLATES
def test_e2e_nuclei_against_scanme_in_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    EngagementStore(store).create(_scanme_scope())

    result = _run_tool(
        store,
        {
            "tool_id": "nexus.web.nuclei",
            "arguments": {
                "targets": [SCANME_HTTP_URL],
                "flags": ["-severity", "info"],
                "timeout_seconds": 180,
            },
            "engagement_id": "eng-scanme",
            "identity": _operator(),
        },
    )

    output = result["output"]
    # A non-intrusive scan with no findings is still a completed, verified scan.
    assert output["verified"] is True
    assert output["evidence"]["noise_level"] == "low"
    assert output["evidence"]["interactsh"] is False
    assert "-no-interactsh" in output["evidence"]["flags"]


@SKIP_UNLESS_E2E
@_requires("ffuf")
def test_e2e_ffuf_against_scanme_denied_when_out_of_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nlogin\n", encoding="utf-8")
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    EngagementStore(store).create(_scanme_scope())

    with pytest.raises(ScopeViolation):
        _run_tool(
            store,
            {
                "tool_id": "nexus.web.ffuf",
                "arguments": {
                    "url": "http://example.com/FUZZ",
                    "wordlist": str(wordlist),
                    "threads": 2,
                },
                "engagement_id": "eng-scanme",
                "identity": _operator(),
            },
        )

    events = AuditWriter(store).export("system")
    denials = [event for event in events if event["action"] == "scope.denied"]
    assert len(denials) == 1
    assert denials[0]["decision"] == "deny"
    assert denials[0]["resource_id"] == "nexus.web.ffuf"
