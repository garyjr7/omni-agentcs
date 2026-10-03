"""V4.5 Sliver tools: implant build, lateral deploy and loot custody."""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.integrations.sliver.client import SliverUnavailable
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.tests.sliver_support import (
    context,
    fake_client,
    gateway,
    gateway_with_approvals,
    owned_context,
)
from nexus_core.tools.handlers import sliver_deploy, sliver_generate, sliver_loot
from nexus_core.tools.parsers.sliver import parse_sliver_loot

GENERATE_TOOL = "nexus.c2.sliver_generate"
DEPLOY_TOOL = "nexus.c2.sliver_deploy"
LOOT_TOOL = "nexus.c2.sliver_loot"


# --------------------------------------------------------------- generate
def test_generate_requires_approval(tmp_path, monkeypatch):
    fake_client(monkeypatch)
    gw, _ = gateway(tmp_path)
    with pytest.raises(PermissionError, match="approval"):
        asyncio.run(
            gw.invoke(GENERATE_TOOL, {"os": "linux", "arch": "amd64"}, context())
        )


def test_generate_success_hides_bytes(monkeypatch):
    client = fake_client(monkeypatch)
    result = asyncio.run(
        sliver_generate.sliver_generate_handler(
            {"os": "linux", "arch": "amd64"}, context()
        )
    )
    assert result.success and result.verified
    assert result.verification_method == "sliver_implant_generated"
    assert result.output["implant"]["sha256"] == "d34db33f"
    assert result.output["bytes_returned"] is False
    assert "data" not in result.output["implant"]
    assert result.evidence["persistent"] is False
    client.generate_implant.assert_awaited_once()


def test_generate_persistent_maps_to_service(monkeypatch):
    client = fake_client(monkeypatch)
    asyncio.run(
        sliver_generate.sliver_generate_handler(
            {"os": "windows", "arch": "amd64", "format": "service", "persistent": True},
            context(),
        )
    )
    _, kwargs = client.generate_implant.call_args
    assert kwargs["persistent"] is True
    assert kwargs["format"] == "service"


@pytest.mark.parametrize(
    "arguments",
    [
        {"os": "plan9", "arch": "amd64"},
        {"os": "linux", "arch": "sparc"},
        {"os": "linux", "arch": "amd64", "format": "zip"},
        {"os": "linux", "arch": "amd64", "interval": 0},
        {"os": "linux", "arch": "amd64", "jitter": 101},
    ],
)
def test_generate_rejects_invalid_arguments(monkeypatch, arguments):
    client = fake_client(monkeypatch)
    with pytest.raises(ValueError):
        asyncio.run(sliver_generate.sliver_generate_handler(arguments, context()))
    client.generate_implant.assert_not_awaited()


def test_generate_fail_closed_when_unavailable(monkeypatch):
    client = fake_client(monkeypatch)
    client.connect.side_effect = SliverUnavailable("down")
    result = asyncio.run(
        sliver_generate.sliver_generate_handler({"os": "linux", "arch": "amd64"}, context())
    )
    assert not result.success
    assert result.verification_method == "sliver_unavailable"


# --------------------------------------------------------------- deploy
def test_deploy_is_destructive():
    assert sliver_deploy.sliver_deploy_definition().risk.value == "destructive"


def test_deploy_requires_approval(tmp_path, monkeypatch):
    fake_client(monkeypatch)
    gw, _ = gateway(tmp_path)
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    with pytest.raises(PermissionError, match="approval"):
        asyncio.run(
            gw.invoke(
                DEPLOY_TOOL,
                {"session_id": "sess-1", "remote_path": "/tmp/i", "os": "linux", "arch": "amd64"},
                run_context,
            )
        )


def test_deploy_rejects_unowned_session(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    run_context, _ = owned_context(tmp_path)
    result = asyncio.run(
        sliver_deploy.sliver_deploy_handler(
            {"session_id": "ghost", "remote_path": "/tmp/i", "os": "linux", "arch": "amd64"},
            run_context,
        )
    )
    assert not result.success
    assert result.verification_method == "session_not_registered"
    client.generate_implant.assert_not_awaited()


def test_deploy_success_uploads_and_runs(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    result = asyncio.run(
        sliver_deploy.sliver_deploy_handler(
            {
                "session_id": "sess-1",
                "remote_path": "/tmp/implant",
                "os": "linux",
                "arch": "amd64",
                "persistent": True,
            },
            run_context,
        )
    )
    assert result.success
    assert result.verification_method == "sliver_implant_deployed"
    assert result.output["executed"] is True
    assert result.evidence["ran"] is True and result.evidence["pid"] == 123
    client.upload_file.assert_awaited_once()
    client.execute_path.assert_awaited_once()
    upload_args, upload_kwargs = client.upload_file.call_args
    assert upload_args[:2] == ("sess-1", "/tmp/implant")
    assert upload_kwargs["kind"] == "session"


def test_deploy_can_skip_execution(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    result = asyncio.run(
        sliver_deploy.sliver_deploy_handler(
            {
                "session_id": "sess-1",
                "remote_path": "/tmp/implant",
                "os": "linux",
                "arch": "amd64",
                "run": False,
            },
            run_context,
        )
    )
    assert result.success and result.output["executed"] is False
    client.execute_path.assert_not_awaited()


@pytest.mark.parametrize("bad_arg", ["a;b", "a|b", "$(id)"])
def test_deploy_rejects_shell_metacharacters(tmp_path, monkeypatch, bad_arg):
    client = fake_client(monkeypatch)
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    with pytest.raises(ValueError):
        asyncio.run(
            sliver_deploy.sliver_deploy_handler(
                {
                    "session_id": "sess-1",
                    "remote_path": "/tmp/implant",
                    "os": "linux",
                    "arch": "amd64",
                    "args": [bad_arg],
                },
                run_context,
            )
        )
    client.generate_implant.assert_not_awaited()


def test_deploy_rejects_empty_implant(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    client.generate_implant.return_value = ({"name": "x", "sha256": "", "size": 0}, b"")
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    result = asyncio.run(
        sliver_deploy.sliver_deploy_handler(
            {"session_id": "sess-1", "remote_path": "/tmp/i", "os": "linux", "arch": "amd64"},
            run_context,
        )
    )
    assert result.verification_method == "sliver_implant_empty"
    client.upload_file.assert_not_awaited()


def test_deploy_runs_through_gateway_with_approval(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    gw, _audit, approvals, _store = gateway_with_approvals(tmp_path)
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    approval = approvals.request(run_context, f"execute:tool:{DEPLOY_TOOL}")
    approvals.decide(approval["id"], "system", "operator-test", True, "test")
    result = asyncio.run(
        gw.invoke(
            DEPLOY_TOOL,
            {"session_id": "sess-1", "remote_path": "/tmp/i", "os": "linux", "arch": "amd64"},
            run_context,
            approval_id=approval["id"],
        )
    )
    assert result["success"] is True
    client.upload_file.assert_awaited_once()


# --------------------------------------------------------------- loot
def _loot_record(**overrides):
    record = {
        "Type": "LOOT_FILE",
        "LootID": "loot-1",
        "Name": "creds.txt",
        "FileType": "BINARY",
        "File": {"Name": "creds.txt", "Data": "aGVsbG8="},  # base64("hello")
    }
    record.update(overrides)
    return record


def test_parse_loot_hashes_file_content():
    import hashlib

    (entry,) = parse_sliver_loot([_loot_record()])
    assert entry.name == "creds.txt" and entry.kind == "file"
    assert entry.sha256 == hashlib.sha256(b"hello").hexdigest()
    assert entry.size == 5 and entry.has_content is True


def test_loot_list_returns_entries(monkeypatch):
    client = fake_client(monkeypatch)
    client.loot_list.return_value = [_loot_record()]
    result = asyncio.run(sliver_loot.sliver_loot_handler({"action": "list"}, context()))
    assert result.success
    assert result.verification_method == "sliver_loot_listed"
    assert result.output["count"] == 1
    assert result.output["loot"][0]["sha256"]


def test_loot_get_requires_selector(monkeypatch):
    fake_client(monkeypatch)
    with pytest.raises(ValueError):
        asyncio.run(sliver_loot.sliver_loot_handler({"action": "get"}, context()))


def test_loot_get_not_found(monkeypatch):
    fake_client(monkeypatch)
    result = asyncio.run(
        sliver_loot.sliver_loot_handler({"action": "get", "name": "nope"}, context())
    )
    assert result.verification_method == "sliver_loot_not_found"


def test_loot_record_writes_blackboard_fact(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    client.loot_list.return_value = [_loot_record()]
    run_context, store = owned_context(tmp_path)
    result = asyncio.run(
        sliver_loot.sliver_loot_handler(
            {"action": "record", "name": "creds.txt"}, run_context
        )
    )
    assert result.success
    assert result.verification_method == "sliver_loot_recorded"
    facts = Blackboard(store).list_facts(
        "system", run_context.scope.engagement_id, fact_type="loot"
    )
    assert len(facts) == 1
    assert facts[0]["key"] == "creds.txt"
    assert facts[0]["value"]["sha256"] == result.evidence["sha256"]
    assert facts[0]["verified"] is True
