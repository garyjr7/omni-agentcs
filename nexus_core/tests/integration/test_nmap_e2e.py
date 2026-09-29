"""End-to-end nmap tests. Opt-in via NEXUS_E2E=1 (live network).

The in-scope scan also requires the ``nmap`` binary; it is skipped otherwise.
The out-of-scope denial runs without nmap because scope gating fires first.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from datetime import datetime, timedelta, timezone

import pytest

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext, build_default_registry
from nexus_core.scope import EngagementScope, EngagementStore, ScopeViolation

E2E_ENABLED = os.getenv("NEXUS_E2E") == "1"
SKIP_UNLESS_E2E = pytest.mark.skipif(
    not E2E_ENABLED, reason="set NEXUS_E2E=1 to run live network scans"
)
SKIP_WITHOUT_NMAP = pytest.mark.skipif(
    shutil.which("nmap") is None, reason="nmap binary is not installed"
)

SCANME_IPV4 = "45.33.32.156"
SCANME_IPV6 = "2600:3c01::f03c:91ff:fe18:bb2f"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scanme_scope() -> EngagementScope:
    # scanme.nmap.org resolves to both an A and an AAAA record; the validator
    # requires every resolved address to fall inside the scope.
    return EngagementScope(
        engagement_id="eng-scanme",
        tenant_id="system",
        name="test-scanme",
        client="nmap",
        owner_id="owner-1",
        valid_from=_iso(-timedelta(days=1)),
        valid_until=_iso(timedelta(days=1)),
        cidrs=(f"{SCANME_IPV4}/32", f"{SCANME_IPV6}/128"),
        domains=(),
        urls=(),
        exclusions=(),
        created_at=_iso(timedelta(0)),
    )


def _run_tool(store: ControlStore, payload: dict) -> dict:
    run = store.create_run("system", {})
    store.enqueue_task(tenant_id="system", run_id=run["id"],
                       task_type="tool.invoke", payload=payload)
    claimed = store.claim_task("worker-test")
    assert claimed is not None
    return asyncio.run(build_default_registry().execute(
        claimed, ExecutionContext(store, claimed, "worker-test")
    ))


def _operator() -> dict:
    return {"subject_id": "operator-1", "roles": ["operator"]}


@SKIP_UNLESS_E2E
@SKIP_WITHOUT_NMAP
def test_e2e_nmap_against_scanme_in_scope(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    EngagementStore(store).create(_scanme_scope())

    result = _run_tool(store, {
        "tool_id": "nexus.recon.nmap",
        "arguments": {"target": "scanme.nmap.org", "flags": ["-Pn", "-p", "22,80"]},
        "engagement_id": "eng-scanme",
        "identity": _operator(),
    })

    output = result["output"]
    assert output["verified"] is True
    assert output["evidence"]["hosts_up"] >= 1
    assert output["evidence"]["raw_xml_sha256"]


@SKIP_UNLESS_E2E
def test_e2e_nmap_denied_when_target_out_of_scope(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    EngagementStore(store).create(_scanme_scope())

    with pytest.raises(ScopeViolation):
        _run_tool(store, {
            "tool_id": "nexus.recon.nmap",
            "arguments": {"target": "example.com"},
            "engagement_id": "eng-scanme",
            "identity": _operator(),
        })

    events = AuditWriter(store).export("system")
    denials = [event for event in events if event["action"] == "scope.denied"]
    assert len(denials) == 1
    assert denials[0]["decision"] == "deny"
    assert denials[0]["resource_id"] == "nexus.recon.nmap"
