"""Unit tests for the durable secretsdump handler and parser (sandbox mocked)."""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import impacket_secretsdump as sd_module
from nexus_core.tools.handlers.impacket_secretsdump import (
    build_impacket_target,
    impacket_secretsdump_definition,
    impacket_secretsdump_handler,
    secretsdump_method_flags,
)
from nexus_core.tools.parsers.impacket_secretsdump import parse_secretsdump_files

SAM = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
SECRETS = "dpapi_machinekey:0x1234\nNL$KM:0xdeadbeef\n"


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

    with mock.patch.object(sd_module, "ad_sandbox", factory):
        with mock.patch.object(
            sd_module,
            "resolve_impacket_binary",
            return_value="/home/u/.local/bin/secretsdump.py",
        ):
            yield sandbox


def _context(run_id: str = "run_sd_test") -> RunContext:
    return RunContext(
        "system", Identity("op", "system", roles=("operator",)), run_id=run_id
    )


def _run(arguments: dict, context: RunContext | None = None) -> object:
    return asyncio.run(impacket_secretsdump_handler(arguments, context or _context()))


def test_definition_is_high_scoped():
    definition = impacket_secretsdump_definition()
    assert definition.tool_id == "nexus.attack.impacket_secretsdump"
    assert definition.risk is RiskLevel.HIGH
    assert definition.scope_required is True
    assert definition.scope_target_field == "target"


def test_build_target_includes_domain_user_host():
    assert (
        build_impacket_target(
            target="10.0.0.5", domain="corp.local", username="svc", password="Pw"
        )
        == "corp.local/svc:Pw@10.0.0.5"
    )
    assert build_impacket_target(target="10.0.0.5", domain="", username="", password=None) == "10.0.0.5"


def test_method_flags_use_just_dc_not_sam_mode():
    assert secretsdump_method_flags("all") == []
    assert secretsdump_method_flags("ntds") == ["-just-dc"]
    assert secretsdump_method_flags("ntds_ntlm") == ["-just-dc-ntlm"]


def test_handler_builds_outputfile_prefix(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / "sd_run_sd_test.sam").write_text(SAM, encoding="utf-8")
    (tmp_path / "sd_run_sd_test.secrets").write_text(SECRETS, encoding="utf-8")
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        result = _run(
            {
                "target": "10.0.0.5",
                "domain": "corp.local",
                "username": "svc",
                "password": "Pw",
                "method": "ntds",
            }
        )
    argv = sandbox.calls[0]
    assert argv[0].endswith("secretsdump.py")
    assert argv[argv.index("-outputfile") + 1] == str(tmp_path / "sd_run_sd_test")
    assert "-just-dc" in argv
    assert argv[-1] == "corp.local/svc:Pw@10.0.0.5"
    assert result.output["count"] == 1
    assert result.output["secret_count"] == 2
    assert result.verified is True


def test_handler_passes_hash_without_password(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / "sd_run_sd_test.sam").write_text(SAM, encoding="utf-8")
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        _run(
            {
                "target": "10.0.0.5",
                "domain": "corp.local",
                "username": "svc",
                "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            }
        )
    argv = sandbox.calls[0]
    assert argv[argv.index("-hashes") + 1].startswith("aad3b")
    assert "-no-pass" not in argv


def test_handler_rejects_forbidden_flags():
    with _fake_sandbox(SandboxResult(0, "", "")):
        with pytest.raises(ValueError):
            _run({"target": "10.0.0.5", "flags": ["-system", "/tmp/system"]})


def test_handler_rejects_bad_method():
    with _fake_sandbox(SandboxResult(0, "", "")):
        with pytest.raises(ValueError):
            _run({"target": "10.0.0.5", "method": "sam"})


def test_handler_unverified_without_output(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "", "")):
        result = _run({"target": "10.0.0.5"})
    assert result.success is False
    assert result.verification_method == "secretsdump_no_output"


def test_handler_no_subprocess(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / "sd_run_sd_test.sam").write_text(SAM, encoding="utf-8")
    with _fake_sandbox(SandboxResult(0, "", "")):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses"),
        ):
            _run({"target": "10.0.0.5"})


def test_parser_reads_sam_and_secrets():
    parsed = parse_secretsdump_files({"sam": SAM, "secrets": SECRETS})
    assert parsed.entries[0].username == "Administrator"
    assert parsed.entries[0].rid == "500"
    assert parsed.entries[0].source == "sam"
    assert {secret.key for secret in parsed.secrets} == {"dpapi_machinekey", "NL$KM"}
