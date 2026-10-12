"""Unit tests for the durable BloodHound handler and parser (sandbox mocked)."""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import bloodhound as bloodhound_module
from nexus_core.tools.handlers.bloodhound import (
    BLOODHOUND_FORBIDDEN_FLAGS,
    bloodhound_definition,
    bloodhound_handler,
)
from nexus_core.tools.parsers.bloodhound import parse_bloodhound_outputs


class FakeSandbox:
    def __init__(self, result: SandboxResult):
        self.result = result
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append(list(argv))
        return self.result


@contextlib.contextmanager
def _fake_sandbox(result: SandboxResult):
    sandbox = FakeSandbox(result)

    def factory(workspace_root, resolved=None, *extra):
        return sandbox

    with mock.patch.object(bloodhound_module, "ad_sandbox", factory):
        with mock.patch.object(
            bloodhound_module,
            "resolve_ad_binary",
            return_value="/home/u/.local/bin/bloodhound-python",
        ):
            yield sandbox


def _context(run_id: str = "run_bh_test") -> RunContext:
    return RunContext(
        "system", Identity("op", "system", roles=("operator",)), run_id=run_id
    )


def _run(arguments: dict, context: RunContext | None = None) -> object:
    return asyncio.run(bloodhound_handler(arguments, context or _context()))


def test_definition_is_medium_scoped_on_dc():
    definition = bloodhound_definition()
    assert definition.tool_id == "nexus.recon.bloodhound_python"
    assert definition.risk is RiskLevel.MEDIUM
    assert definition.scope_target_field == "dc"
    assert definition.scope_required is True


def test_handler_builds_ntlm_command(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        _run(
            {
                "domain": "corp.local",
                "dc": "dc01.corp.local",
                "username": "svc",
                "password": "Passw0rd",
                "collection": ["Group", "LocalAdmin"],
            }
        )
    argv = sandbox.calls[0]
    assert argv[0].endswith("bloodhound-python")
    assert argv[argv.index("-d") + 1] == "corp.local"
    assert argv[argv.index("-dc") + 1] == "dc01.corp.local"
    assert argv[argv.index("--auth-method") + 1] == "ntlm"
    assert argv[argv.index("-c") + 1] == "Group,LocalAdmin"
    assert "-op" in argv


def test_handler_uses_nameserver_flag_not_unsupported_computeronly():
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        _run(
            {
                "domain": "corp.local",
                "dc": "10.0.0.10",
                "flags": ["-ns", "10.0.0.10", "--disable-pooling"],
            }
        )
    argv = sandbox.calls[0]
    assert argv[argv.index("-ns") + 1] == "10.0.0.10"
    assert "ComputerOnly" not in argv


def test_handler_rejects_unknown_collection():
    with _fake_sandbox(SandboxResult(0, "", "")):
        with pytest.raises(ValueError):
            _run({"domain": "corp.local", "dc": "10.0.0.10", "collection": ["Nope"]})


def test_handler_rejects_a_model_managed_flag():
    # The handler owns -d/-dc/-op; a model copy is refused (fail closed).
    with _fake_sandbox(SandboxResult(0, "", "")):
        with pytest.raises(ValueError):
            _run(
                {
                    "domain": "corp.local",
                    "dc": "10.0.0.10",
                    "flags": ["-d", "attacker.local"],
                }
            )


def test_handler_rejects_forbidden_flags():
    for flag in ("--computerfile", "--cachefile"):
        assert flag in BLOODHOUND_FORBIDDEN_FLAGS
        with _fake_sandbox(SandboxResult(0, "", "")):
            with pytest.raises(ValueError):
                _run({"domain": "corp.local", "dc": "10.0.0.10", "flags": [flag]})


def test_handler_reads_output_files(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / "bh_run_bh_test_users.json").write_text(
        '[{"name": "a"}, {"name": "b"}]', encoding="utf-8"
    )
    (tmp_path / "bh_run_bh_test_computers.json").write_text(
        '[{"name": "dc01"}]', encoding="utf-8"
    )
    with _fake_sandbox(SandboxResult(0, "", "")):
        result = _run({"domain": "corp.local", "dc": "10.0.0.10"})
    assert result.verified is True
    assert result.output["file_count"] == 2
    assert result.output["total_records"] == 3
    assert result.verification_method == "bloodhound_json_parsed"


def test_handler_returns_unverified_without_output(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "", "")):
        result = _run({"domain": "corp.local", "dc": "10.0.0.10"})
    assert result.success is False
    assert result.verification_method == "bloodhound_no_output"
    # Nothing to collect is an answer about the target (V0-22).
    assert result.outcome == "negative"


def test_handler_uses_sandbox_and_no_subprocess(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / "bh_run_bh_test_users.json").write_text("[]", encoding="utf-8")
    with _fake_sandbox(SandboxResult(0, "", "")):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses"),
        ):
            _run({"domain": "corp.local", "dc": "10.0.0.10"})


def test_parser_counts_and_labels_files():
    parsed = parse_bloodhound_outputs(
        {"20260101_users.json": '[{"a":1},{"b":2}]', "20260101_groups.json": "[]"}
    )
    assert parsed.total_records == 2
    labels = {item.collection for item in parsed.files}
    assert labels == {"users", "groups"}


def test_parser_rejects_invalid_json():
    with pytest.raises(ValueError):
        parse_bloodhound_outputs({"x_users.json": "not json"})
