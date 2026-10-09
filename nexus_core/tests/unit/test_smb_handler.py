"""Unit tests for the durable SMB handlers (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import smb as smb_module
from nexus_core.tools.handlers.smb import (
    smb_definition,
    smb_handler,
    smb_upload_definition,
    smb_upload_handler,
)


class FakeSandbox:
    def __init__(self, result: SandboxResult, *, on_run=None):
        self.result = result
        self.calls: list[tuple[list[str], float]] = []
        self._on_run = on_run

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append((list(argv), timeout_seconds))
        if self._on_run is not None:
            self._on_run(list(argv))
        return self.result


@contextlib.contextmanager
def _fake_sandbox(result: SandboxResult, *, on_run=None):
    sandbox = FakeSandbox(result, on_run=on_run)
    with mock.patch.object(smb_module, "ad_sandbox", lambda *args, **kwargs: sandbox):
        with mock.patch.object(
            smb_module, "resolve_ad_binary", lambda *args, **kwargs: "/usr/bin/smbclient"
        ):
            yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(smb_handler(arguments, _context()))


def _run_upload(arguments: dict) -> object:
    return asyncio.run(smb_upload_handler(arguments, _context()))


def _result(stdout: str = "", exit_code: int = 0, stderr: str = "") -> SandboxResult:
    return SandboxResult(exit_code, stdout, stderr)


SHARES_OUTPUT = "\n".join(
    [
        "\tSharename       Type      Comment",
        "\t---------       ----      -------",
        "\tADMIN$          Disk      Remote Admin",
        "\tC$              Disk      Default share",
        "\tIPC$            IPC       Remote IPC",
        "\tnt4wrksv        Disk      ",
    ]
)

LIST_OUTPUT = "\n".join(
    [
        "  .                                   D        0  Sat Jul 25 16:46:04 2020",
        "  ..                                  D        0  Sat Jul 25 16:46:04 2020",
        "  passwords.txt                       A       98  Sat Jul 25 10:15:33 2020",
    ]
)


# ------------------------------------------------------------------ definition
def test_definitions_declare_scope_and_actions():
    definition = smb_definition()
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True
    assert set(definition.input_schema["properties"]["action"]["enum"]) == {"shares", "list", "get"}
    upload = smb_upload_definition()
    assert upload.scope_target_field == "target"
    assert upload.effect == "exploit"
    assert set(upload.input_schema["required"]) == {"target", "share", "local_path", "remote_path"}


# --------------------------------------------------------------------- handler
def test_shares_action_parses_share_list():
    with _fake_sandbox(_result(SHARES_OUTPUT)) as sandbox:
        result = _run({"target": "203.0.113.10", "action": "shares"})
    argv = sandbox.calls[0][0]
    assert argv[0] == "/usr/bin/smbclient"
    assert "-N" in argv and f"//203.0.113.10" in argv
    assert result.verified is True
    assert result.verification_method == "smb_shares_parsed"
    names = {share["name"] for share in result.output["shares"]}
    assert {"ADMIN$", "C$", "IPC$", "nt4wrksv"} <= names


def test_list_action_parses_directory_entries():
    with _fake_sandbox(_result(LIST_OUTPUT)) as sandbox:
        result = _run({"target": "203.0.113.10", "share": "nt4wrksv", "action": "list"})
    assert sandbox.calls[0][0][-2:] == ["-c", "ls"]
    assert result.verified is True
    assert result.output["count"] == 1
    assert result.output["entries"][0]["name"] == "passwords.txt"


def test_list_action_reports_nt_status_failure():
    with _fake_sandbox(_result("NT_STATUS_ACCESS_DENIED listing \\\\*\n")):
        result = _run({"target": "203.0.113.10", "share": "nt4wrksv", "action": "list"})
    assert result.verified is False
    assert result.verification_method == "smb_listing_failed"
    assert result.output["error"] == "NT_STATUS_ACCESS_DENIED"


def test_authenticated_request_passes_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_result(SHARES_OUTPUT)) as sandbox:
        _run({"target": "203.0.113.10", "username": "Bob", "password": "s3cret"})
    argv = sandbox.calls[0][0]
    assert "-N" not in argv
    assert "Bob%s3cret" in argv


def test_get_download_reports_size_and_sha256(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / "passwords.txt").write_text("hello\n")

    def _touch(argv):
        # The sandbox mock "downloads" into the workspace.
        (tmp_path / "passwords.txt").write_text("hello\n")

    with _fake_sandbox(_result("getting file \\passwords.txt\n"), on_run=_touch):
        result = _run({"target": "203.0.113.10", "share": "nt4wrksv", "action": "get", "remote_path": "passwords.txt"})
    assert result.verified is True
    assert result.verification_method == "smb_download_verified"
    assert result.output["size"] == 6
    assert len(result.output["sha256"]) == 64
    assert result.output["preview"] == "hello\n"


def test_get_rejects_local_path_escape(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_result("")):
        with pytest.raises(ValueError):
            _run(
                {
                    "target": "203.0.113.10",
                    "share": "nt4wrksv",
                    "action": "get",
                    "remote_path": "passwords.txt",
                    "local_path": "../../etc/passwd",
                }
            )


def test_upload_writes_workspace_file(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / "shell.aspx").write_text("<%@ Page %>")

    with _fake_sandbox(_result("putting file shell.aspx as \\shell.aspx\n")) as sandbox:
        result = _run_upload(
            {
                "target": "203.0.113.10",
                "share": "nt4wrksv",
                "local_path": "shell.aspx",
                "remote_path": "shell.aspx",
            }
        )
    argv = sandbox.calls[0][0]
    assert argv[-2] == "-c"
    assert "put" in argv[-1] and "shell.aspx" in argv[-1]
    assert result.verified is True
    assert result.verification_method == "smb_upload_done"
    assert result.output["uploaded_bytes"] == len("<%@ Page %>")


def test_upload_requires_existing_source(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_result("")):
        with pytest.raises(ValueError):
            _run_upload(
                {
                    "target": "203.0.113.10",
                    "share": "nt4wrksv",
                    "local_path": "missing.bin",
                    "remote_path": "missing.bin",
                }
            )


def test_unsupported_action_is_rejected():
    with pytest.raises(ValueError):
        _run({"target": "203.0.113.10", "action": "delete"})


def test_control_characters_in_remote_path_are_rejected():
    with pytest.raises(ValueError):
        _run({"target": "203.0.113.10", "share": "s", "action": "list", "remote_path": "ok\nINJECT"})


def test_share_with_separators_is_rejected():
    with pytest.raises(ValueError):
        _run({"target": "203.0.113.10", "share": "a/b", "action": "list"})


def test_timeout_is_not_verified():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"target": "203.0.113.10", "action": "shares"})
    assert result.verified is False
    assert result.verification_method == "smb_timeout"


def test_handlers_never_spawn_subprocess_directly(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / "x.bin").write_text("data")
    with _fake_sandbox(_result(SHARES_OUTPUT)):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"target": "203.0.113.10", "action": "shares"})
            _run_upload(
                {"target": "203.0.113.10", "share": "s", "local_path": "x.bin", "remote_path": "x.bin"}
            )
