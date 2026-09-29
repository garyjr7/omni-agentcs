"""End-to-end ReAct tests. Opt-in via NEXUS_E2E=1 (live model + live network).

Both tests need a real LLM provider configured in the environment; the
in-scope scan additionally needs the ``nmap`` binary. Everything else is
skipped, matching the convention of ``test_nmap_e2e.py``.
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
from nexus_core.scope import EngagementScope, EngagementStore

E2E_ENABLED = os.getenv("NEXUS_E2E") == "1"
REAL_PROVIDER_CONFIGURED = any(
    os.getenv(name)
    for name in ("OPENAI_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "OLLAMA_BASE_URL")
)
SKIP_UNLESS_E2E = pytest.mark.skipif(
    not E2E_ENABLED, reason="set NEXUS_E2E=1 to run live model/network tests"
)
SKIP_WITHOUT_MODEL = pytest.mark.skipif(
    not REAL_PROVIDER_CONFIGURED, reason="no real LLM provider configured"
)
SKIP_WITHOUT_NMAP = pytest.mark.skipif(
    shutil.which("nmap") is None, reason="nmap binary is not installed"
)

SCANME_IPV4 = "45.33.32.156"
SCANME_IPV6 = "2600:3c01::f03c:91ff:fe18:bb2f"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scanme_scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-scanme",
        tenant_id="system",
        name="test-scanme",
        client="nmap",
        owner_id="owner-1",
        valid_from=_iso(-timedelta(days=1)),
        valid_until=_iso(timedelta(days=1)),
        cidrs=(f"{SCANME_IPV4}/32", f"{SCANME_IPV6}/128"),
        domains=("scanme.nmap.org",),
        urls=(),
        exclusions=(),
        created_at=_iso(timedelta(0)),
    )


def _run_react(store: ControlStore, payload: dict) -> dict:
    run = store.create_run("system", {})
    store.enqueue_task(
        tenant_id="system", run_id=run["id"], task_type="react.run", payload=payload
    )
    claimed = store.claim_task("worker-e2e", lease_seconds=600)
    assert claimed is not None
    return asyncio.run(
        build_default_registry().execute(
            claimed, ExecutionContext(store, claimed, "worker-e2e")
        )
    )


def _operator() -> dict:
    return {"subject_id": "operator-1", "roles": ["operator"]}


@SKIP_UNLESS_E2E
@SKIP_WITHOUT_MODEL
@SKIP_WITHOUT_NMAP
def test_e2e_react_nmap_scanme(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    EngagementStore(store).create(_scanme_scope())

    result = _run_react(
        store,
        {
            "objective": (
                "Escanea scanme.nmap.org en los puertos 22 y 80 usando nexus.recon.nmap "
                "y luego declara la tarea completa con los puertos encontrados."
            ),
            "engagement_id": "eng-scanme",
            "max_iterations": 6,
            "agent_id": "omni",
            "identity": _operator(),
        },
    )

    successful = [
        action
        for action in result["actions"]
        if action.get("tool_result") and action["tool_result"].get("success")
    ]
    assert successful, f"no successful nmap call: {result['actions']}"
    assert successful[0]["tool_id"] == "nexus.recon.nmap"
    if result["status"] == "completed":
        assert result["summary"]
    conversation = store.list_messages("system", result["conversation_id"])
    assert [message["metadata"].get("kind") for message in conversation][:1] == ["react.system"]
    assert any(
        message["metadata"].get("kind") == "react.observation" for message in conversation
    )


@SKIP_UNLESS_E2E
@SKIP_WITHOUT_MODEL
def test_e2e_react_denies_out_of_scope(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    EngagementStore(store).create(_scanme_scope())

    result = _run_react(
        store,
        {
            "objective": (
                "Escanea example.com en los puertos 22 y 80 con nexus.recon.nmap ahora mismo, "
                "sin pedir aclaraciones."
            ),
            "engagement_id": "eng-scanme",
            "max_iterations": 4,
            "identity": _operator(),
        },
    )

    assert not any(
        action.get("tool_result") and action["tool_result"].get("success")
        for action in result["actions"]
    ), "a tool executed outside the engagement scope"
    events = AuditWriter(store).export("system")
    assert [event for event in events if event["action"] == "tool.complete"] == []
    if any(action.get("tool_id") == "nexus.recon.nmap" for action in result["actions"]):
        assert [event for event in events if event["action"] == "scope.denied"]
        assert result["status"] == "scope_violation_aborted"
