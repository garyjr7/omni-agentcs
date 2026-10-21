"""``nexus.recon.nfs``: exports and unprivileged reads (sandbox mocked)."""

from __future__ import annotations

import asyncio
import shutil
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import nfs as nfs_module
from nexus_core.tools.handlers.nfs import (
    NFS_INSTALL_GUIDANCE,
    NFS_MOUNT_GUIDANCE,
    nfs_definition,
    nfs_handler,
    parse_exports,
)

#: The unpatched resolver, for the test that exercises path resolution itself.
REAL_RESOLVE = nfs_module.resolve_program

EXPORTS_STDOUT = (
    "Export list for 203.0.113.10: \n"
    "/srv/nfs  *\n"
    "/home     10.0.0.0/24 203.0.113.11\n"
)


@pytest.fixture(autouse=True)
def _bare_programs(monkeypatch):
    """Keep the tests host-independent: argv[0] is the bare program name.

    ``_sandbox`` resolves ``/usr/sbin/showmount`` on a real Kali host; the queue
    below is keyed by the program the handler asks for, not by its path.
    """
    monkeypatch.setattr(nfs_module, "resolve_program", lambda program: program)


class FakeSandbox:
    """Queue of results keyed by program; a missing program raises like the OS."""

    def __init__(self, results: dict[str, object]):
        self.results = results
        self.calls: list[list[str]] = []

    async def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        outcome = self.results.get(argv[0])
        if outcome is None:
            raise FileNotFoundError(argv[0])
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(nfs_handler(arguments, _context()))


def _sandbox(results: dict[str, object]) -> FakeSandbox:
    sandbox = FakeSandbox(results)
    with mock.patch.object(
        nfs_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        return sandbox


def _result(stdout: str = "", stderr: str = "", exit_code: int = 0) -> SandboxResult:
    return SandboxResult(exit_code, stdout, stderr)


# ------------------------------------------------------------------ definition
def test_resolution_finds_sbin_binaries_the_sandbox_path_hides():
    extra = "/usr/sbin:/sbin:/usr/local/sbin"
    expected = shutil.which("showmount", path=extra)
    if expected is None:
        pytest.skip("showmount is not installed on this host")
    assert REAL_RESOLVE("showmount") == expected


def test_unknown_program_keeps_its_name():
    assert REAL_RESOLVE("not-a-real-nfs-binary") == "not-a-real-nfs-binary"


def test_definition_is_read_only_and_scoped_to_the_target():
    definition = nfs_definition()
    assert definition.effect == "read_only"
    assert definition.scope_required is True
    assert definition.scope_target_field == "target"
    assert set(definition.input_schema["properties"]["action"]["enum"]) == {
        "exports",
        "list",
        "read",
    }


# --------------------------------------------------------------------- parsing
def test_parse_exports_reads_paths_and_clients():
    assert parse_exports(EXPORTS_STDOUT) == [
        {"path": "/srv/nfs", "clients": ["*"]},
        {"path": "/home", "clients": ["10.0.0.0/24", "203.0.113.11"]},
    ]


def test_parse_exports_ignores_warnings_before_the_table():
    stdout = "rpc mount export: RPC: Timed out\n" + EXPORTS_STDOUT
    assert [entry["path"] for entry in parse_exports(stdout)] == ["/srv/nfs", "/home"]


# --------------------------------------------------------------------- handler
def test_exports_uses_showmount_without_mounting():
    sandbox = FakeSandbox({"showmount": _result(EXPORTS_STDOUT)})
    with mock.patch.object(
        nfs_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        result = _run({"target": "203.0.113.10"})
    assert sandbox.calls[0] == ["showmount", "-e", "203.0.113.10"]
    assert result.verified is True
    assert result.verification_method == "nfs_exports_parsed"
    assert result.evidence["exports_total"] == 2


def test_empty_export_table_is_a_negative_not_a_failure():
    with mock.patch.object(
        nfs_module,
        "sandbox_for_environment",
        lambda *args, **kwargs: FakeSandbox({"showmount": _result("Export list for x:\n")}),
    ):
        result = _run({"target": "203.0.113.10"})
    assert result.verified is True
    assert result.output["count"] == 0
    assert result.outcome in ("", None)


def test_an_unreachable_rpcbind_is_unavailable_not_an_empty_table():
    stdout = ""
    stderr = "clnt_create: RPC: Unable to receive"
    with mock.patch.object(
        nfs_module,
        "sandbox_for_environment",
        lambda *args, **kwargs: FakeSandbox(
            {"showmount": _result(stdout, stderr, 1)}
        ),
    ):
        result = _run({"target": "203.0.113.10"})
    assert result.outcome == "unavailable"
    assert result.verification_method == "nfs_exports_unavailable"
    assert result.evidence["reachable"] is False


def test_missing_showmount_is_unavailable_with_the_install_hint():
    with mock.patch.object(
        nfs_module, "sandbox_for_environment", lambda *args, **kwargs: FakeSandbox({})
    ):
        result = _run({"target": "203.0.113.10"})
    assert result.outcome == "unavailable"
    assert result.verification_method == "nfs_showmount_unavailable"
    assert "nfs-common" in result.output["guidance"]


def test_list_without_nfs_ls_returns_partial_with_the_exports():
    sandbox = FakeSandbox({"showmount": _result(EXPORTS_STDOUT)})
    with mock.patch.object(
        nfs_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        result = _run({"target": "203.0.113.10", "action": "list", "path": "/srv/nfs"})
    assert result.outcome == "partial"
    assert result.verification_method == "nfs_nfs_ls_missing"
    assert result.output["message"] == NFS_MOUNT_GUIDANCE
    assert [entry["path"] for entry in result.output["exports"]] == ["/srv/nfs", "/home"]
    assert result.output["guidance"] == NFS_INSTALL_GUIDANCE["nfs-ls"]


def test_list_reads_the_export_with_the_userland_client():
    sandbox = FakeSandbox(
        {"nfs-ls": _result("notes.txt\nid_rsa\n"), "showmount": _result(EXPORTS_STDOUT)}
    )
    with mock.patch.object(
        nfs_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        result = _run({"target": "203.0.113.10", "action": "list", "path": "/srv/nfs"})
    assert sandbox.calls[0] == ["nfs-ls", "nfs://203.0.113.10/srv/nfs"]
    assert result.verified is True
    assert result.verification_method == "nfs_listing_parsed"
    assert result.output["entries"] == ["notes.txt", "id_rsa"]


def test_read_returns_the_file_without_a_kernel_mount():
    sandbox = FakeSandbox(
        {"nfs-cat": _result("user.txt: flag{fake_flag}\n"), "showmount": _result(EXPORTS_STDOUT)}
    )
    with mock.patch.object(
        nfs_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        result = _run(
            {
                "target": "203.0.113.10",
                "action": "read",
                "path": "/srv/nfs",
                "file": "user.txt",
            }
        )
    assert sandbox.calls[0] == ["nfs-cat", "nfs://203.0.113.10/srv/nfs/user.txt"]
    assert result.verified is True
    assert result.verification_method == "nfs_file_read"
    assert "flag{fake_flag}" in result.output["preview"]


def test_restricted_export_stays_partial_and_shows_what_is_visible():
    sandbox = FakeSandbox(
        {
            "nfs-ls": _result("", "RPC: Mount failure: access denied", 13),
            "showmount": _result(EXPORTS_STDOUT),
        }
    )
    with mock.patch.object(
        nfs_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        result = _run({"target": "203.0.113.10", "action": "list", "path": "/srv/nfs"})
    assert result.outcome == "partial"
    assert result.verification_method == "nfs_nfs_ls_failed"
    assert result.output["message"] == NFS_MOUNT_GUIDANCE
    assert result.evidence["exit_code"] == 13


def test_read_requires_file_and_list_requires_path():
    with pytest.raises(ValueError):
        _run({"target": "203.0.113.10", "action": "list"})
    with pytest.raises(ValueError):
        _run({"target": "203.0.113.10", "action": "read", "path": "/srv/nfs"})
