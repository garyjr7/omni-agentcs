"""``omni tool``: invoke one governed tool without the agent/repl.

Two layers are exercised: the pure helpers (``parse_arguments``/``list_tools``)
and ``run_tool_command``, which must route through ``OmniSession.invoke_tool``
(scope, approval and audit) exactly like the agent does.
"""

from __future__ import annotations

from unittest.mock import patch

import omni
import pytest

from nexus_core.cli import tool as tool_module
from nexus_core.cli.main import build_parser
from nexus_core.cli.session import OmniSession
from nexus_core.tests import report_support as support

pytestmark = pytest.mark.usefixtures("onboarding_env")


# ------------------------------------------------------------------- parsing
def test_parse_arguments_object():
    assert tool_module.parse_arguments(['{"target": "10.0.0.1"}']) == {"target": "10.0.0.1"}


def test_parse_arguments_joins_split_tokens():
    assert tool_module.parse_arguments(['{"target":', '"10.0.0.1"}']) == {"target": "10.0.0.1"}


def test_parse_arguments_defaults_to_empty_object():
    assert tool_module.parse_arguments([]) == {}


def test_parse_arguments_rejects_invalid_json():
    with pytest.raises(ValueError):
        tool_module.parse_arguments(["not json"])


def test_parse_arguments_rejects_non_object():
    with pytest.raises(ValueError):
        tool_module.parse_arguments(["[1, 2]"])


# --------------------------------------------------------------------- parser
def test_parser_accepts_tool_list():
    args = build_parser().parse_args(["tool", "--list"])
    assert args.command == ["tool"]
    assert args.list is True


def test_parser_keeps_tool_id_and_json_in_command():
    args = build_parser().parse_args(["tool", "nexus.recon.nmap", '{"target": "x"}'])
    assert args.command == ["tool", "nexus.recon.nmap", '{"target": "x"}']


# ------------------------------------------------------------------ listing
def test_list_tools_prints_the_catalog(capsys):
    assert tool_module.list_tools(support.TENANT) == 0
    out = capsys.readouterr().out
    assert "nexus.recon.nmap" in out
    assert "nexus.report.generate" in out


# ---------------------------------------------------------------- invocation
def _verified(tool_id: str) -> dict:
    return {"tool_id": tool_id, "output": {"success": True, "verified": True, "output": {"ok": 1}}}


def test_run_tool_command_invokes_and_prints(tmp_path, monkeypatch, capsys):
    store = support.make_store(tmp_path)
    engagement = support.seed_engagement(store)
    seen: dict = {}

    def fake(self, tool_id, arguments):
        seen["tool_id"] = tool_id
        seen["arguments"] = arguments
        return _verified(tool_id)

    monkeypatch.setattr(OmniSession, "invoke_tool", fake)
    code = tool_module.run_tool_command(
        store, support.TENANT, engagement, "nexus.knowledge.query_facts",
        ['{"limit": 5}'], trust_mode=True,
    )
    assert code == 0
    assert seen == {"tool_id": "nexus.knowledge.query_facts", "arguments": {"limit": 5}}
    assert '"ok": 1' in capsys.readouterr().out


def test_run_tool_command_forwards_trust_mode_and_engagement(tmp_path, monkeypatch):
    store = support.make_store(tmp_path)
    engagement = support.seed_engagement(store)
    seen: dict = {}

    def fake(self, tool_id, arguments):
        seen["trust_mode"] = self.trust_mode
        seen["engagement"] = self.engagement
        return _verified(tool_id)

    monkeypatch.setattr(OmniSession, "invoke_tool", fake)
    tool_module.run_tool_command(
        store, support.TENANT, engagement, "nexus.recon.nmap", ["{}"], trust_mode=True
    )
    assert seen["trust_mode"] is True
    assert seen["engagement"] is engagement


def test_run_tool_command_returns_two_on_bad_json(tmp_path, capsys):
    store = support.make_store(tmp_path)
    engagement = support.seed_engagement(store)
    code = tool_module.run_tool_command(
        store, support.TENANT, engagement, "nexus.recon.nmap", ["not-json"], trust_mode=True
    )
    assert code == 2
    assert "JSON" in capsys.readouterr().out


def test_run_tool_command_returns_one_when_denied(tmp_path, monkeypatch):
    store = support.make_store(tmp_path)
    engagement = support.seed_engagement(store)
    monkeypatch.setattr(OmniSession, "invoke_tool", lambda self, tid, args: None)
    code = tool_module.run_tool_command(
        store, support.TENANT, engagement, "nexus.recon.nmap", ["{}"], trust_mode=True
    )
    assert code == 1


# -------------------------------------------------------------------- scope
def test_run_tool_command_blocks_out_of_scope_target(tmp_path, capsys):
    """H7 + H4: a target outside the signed scope is refused fail-closed."""
    store = support.make_store(tmp_path)
    engagement = support.seed_engagement(store)  # scope 203.0.113.0/24
    code = tool_module.run_tool_command(
        store, support.TENANT, engagement, "nexus.recon.nmap",
        ['{"target": "10.0.0.1"}'], trust_mode=True,
    )
    captured = capsys.readouterr()
    assert code == 1
    assert "bloqueado por scope" in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err


# --------------------------------------------------- H7 ScopeViolation render
def test_invoke_tool_renders_scope_violation_without_traceback(tmp_path, monkeypatch, capsys):
    from nexus_core.kernel import runtime as runtime_module
    from nexus_core.scope import ScopeViolation

    store = support.make_store(tmp_path)
    engagement = support.seed_engagement(store)
    session = OmniSession(
        store=store,
        tenant_id=support.TENANT,
        engagement=engagement,
        use_tui=False,
        input_reader=lambda _prompt="": "n",
    )

    async def boom(payload, context):
        raise ScopeViolation(
            "10.0.0.1", "target is outside the engagement", engagement.engagement_id
        )

    monkeypatch.setattr(runtime_module, "execute_tool", boom)
    result = session.invoke_tool("nexus.recon.nmap", {"target": "10.0.0.1"})
    captured = capsys.readouterr()
    assert result is None
    assert "bloqueado por scope" in captured.out
    assert "10.0.0.1" in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err


# --------------------------------------------------------------- approval
def test_run_tool_command_denies_high_risk_without_trust_mode(tmp_path, capsys):
    store = support.make_store(tmp_path)
    engagement = support.seed_engagement(store)
    code = tool_module.run_tool_command(
        store, support.TENANT, engagement, "nexus.post.ssh_exec",
        ['{"target": "203.0.113.10", "username": "lin", "password": "x", "command": "id"}'],
        trust_mode=False,
    )
    assert code == 1
    assert "denegado" in capsys.readouterr().out


# ------------------------------------------------------------- main dispatch
def test_main_tool_list_routes_without_selecting_an_engagement(
    onboarding_env, monkeypatch, capsys
):
    import importlib
    import sys

    importlib.import_module("nexus_core.cli.main")
    main_module = sys.modules["nexus_core.cli.main"]

    def _fail(*args, **kwargs):  # pragma: no cover - asserts it is never called
        raise AssertionError("tool --list must not require an engagement")

    monkeypatch.setattr(main_module, "select_engagement", _fail)
    with patch("dotenv.load_dotenv"):
        code = omni.main(["tool", "--list", "--no-wizard"])
    assert code == 0
    assert "nexus.recon.nmap" in capsys.readouterr().out


def test_main_tool_invokes_through_the_session(onboarding_env, monkeypatch):
    seen: dict = {}

    def fake(self, tool_id, arguments):
        seen["tool_id"] = tool_id
        seen["arguments"] = arguments
        return _verified(tool_id)

    monkeypatch.setattr(OmniSession, "invoke_tool", fake)
    with patch("dotenv.load_dotenv"):
        code = omni.main(
            ["tool", "nexus.knowledge.query_facts", '{"limit": 5}', "--no-wizard"]
        )
    assert code == 0
    assert seen == {"tool_id": "nexus.knowledge.query_facts", "arguments": {"limit": 5}}


# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))
