"""V1-6: value-based redaction at the HTTP and owned-session boundaries."""

from __future__ import annotations

import asyncio
import json

import pytest

from nexus_core.cli.engage import build_scope
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext, ToolResult
from nexus_core.kernel.secret_store import default_secret_store
from nexus_core.kernel.redaction import secrets_for_redaction
from nexus_core.scope import EngagementStore
from nexus_core.tools.handlers import http_request as http_module
from nexus_core.tools.handlers import shell_exec as shell_module

SIGNING = "test-signing-secret"
TARGET = "10.10.10.5"
VAULT_SECRET = "Sup3rS3cret!2026"


@pytest.fixture()
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_SCOPE_SIGNING_SECRET", SIGNING)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(workspace))
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    scope = EngagementStore(store).create(build_scope("bench", f"{TARGET}/32", SIGNING))
    ref = default_secret_store().put(
        VAULT_SECRET, kind="credential", tenant_id="system"
    )
    Blackboard(store).record(
        tenant_id="system",
        engagement_id=scope.engagement_id,
        fact_type="credential",
        key=f"cred:ssh:lin@{TARGET}",
        value={"username": "lin", "secret_ref": ref, "service": "ssh"},
        source="test",
        created_by="test",
        verified=True,
        asserted_by="verifier",
        verification_method="test_verifier",
        invocation_id="inv-1",
    )
    return RunContext(
        "system",
        Identity("operator-1", "system", roles=("operator",)),
        store=store,
        scope=scope,
        project_root=str(workspace),
        run_id="run_redaction",
    )


def test_secrets_for_redaction_reads_only_verified_credential_facts(context):
    assert VAULT_SECRET in secrets_for_redaction(context)
    # An unverified credential is a hypothesis, not something we may leak.
    Blackboard(context.store).record(
        tenant_id="system",
        engagement_id=context.scope.engagement_id,
        fact_type="credential",
        key="cred:agent",
        value={"username": "agent", "secret_ref": "vault:not-a-real-ref"},
        source="agent",
        created_by="agent",
        verified=False,
    )
    assert "vault:not-a-real-ref" not in secrets_for_redaction(context)


def test_http_handler_redacts_a_vault_secret_echoed_by_the_server(context, monkeypatch):
    async def fake_handler(arguments, run_context):
        return ToolResult(
            output={"body_preview": f"login failed for lin:{VAULT_SECRET}"},
            verified=True,
            verification_method="http_response_received",
            evidence={"note": f"echo {VAULT_SECRET}"},
            stdout=f"body={VAULT_SECRET}",
        )

    monkeypatch.setattr(http_module, "_http_request_handler", fake_handler)
    result = asyncio.run(
        http_module.http_request_handler({"url": f"http://{TARGET}/login"}, context)
    )
    encoded = json.dumps(result.output) + json.dumps(result.evidence) + result.stdout
    assert VAULT_SECRET not in encoded
    assert "[REDACTED]" in result.output["body_preview"]


def test_shell_exec_handler_redacts_the_remote_session_echo(context, monkeypatch):
    async def fake_handler(arguments, run_context):
        return ToolResult(
            output={"stdout": f"password: {VAULT_SECRET}"},
            verified=True,
            verification_method="session_command_executed",
            evidence={"command": "cat notes.txt"},
            stdout=f"password: {VAULT_SECRET}",
        )

    monkeypatch.setattr(shell_module, "_shell_exec_handler", fake_handler)
    result = asyncio.run(
        shell_module.shell_exec_handler(
            {"transport": "metasploit", "session_id": "s-1", "command": "cat notes.txt"},
            context,
        )
    )
    encoded = json.dumps(result.output) + json.dumps(result.evidence) + result.stdout
    assert VAULT_SECRET not in encoded
    assert "[REDACTED]" in result.output["stdout"]
