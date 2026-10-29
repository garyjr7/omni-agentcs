"""FIX 2.1b: ``nexus.recon.nfs`` dice exactamente qué pasó y qué hacer.

Medido en ``run_3a188d2c2bd440f8bca8d88ad922a024`` (Hijack v3): ``nfs-ls`` no
estaba instalado (``dpkg.log``: ``libnfs-utils`` se instaló 6 minutos después de
que el run terminara), el handler contestó ``partial`` y el modelo gastó 23
llamadas a ``pyNfsClient`` por ``shell.exec`` en vez de instalar el cliente. El
veredicto era correcto; lo que faltaba era un ``error`` legible por máquina y un
``hint`` con la acción concreta, y que el éxito de ``exports`` no se confundiera
con «NFS enumerado».
"""

from __future__ import annotations

import asyncio
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import nfs as nfs_module
from nexus_core.tools.handlers.nfs import nfs_handler

EXPORTS_STDOUT = "Export list for 10.0.0.5: \n/mnt/share *\n"


@pytest.fixture(autouse=True)
def _bare_programs(monkeypatch):
    monkeypatch.setattr(nfs_module, "resolve_program", lambda program: program)


class FakeSandbox:
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


def _result(stdout: str = "", stderr: str = "", exit_code: int = 0) -> SandboxResult:
    return SandboxResult(exit_code, stdout, stderr)


def _run(arguments: dict, results: dict[str, object]):
    sandbox = FakeSandbox(results)
    with mock.patch.object(
        nfs_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        result = asyncio.run(
            nfs_handler(
                arguments,
                RunContext("system", Identity("operator-1", "system", roles=("operator",))),
            )
        )
    return result, sandbox


def test_userland_missing_returns_partial_with_hint():
    result, _ = _run(
        {"target": "10.0.0.5", "action": "list", "path": "/mnt/share"},
        {"showmount": _result(EXPORTS_STDOUT), "nfs-ls": FileNotFoundError("nfs-ls")},
    )

    assert result.success is False
    assert result.outcome == "partial"
    assert result.output["error"] == "userland_client_missing"
    assert "libnfs-utils" in result.output["hint"]
    assert result.output["exports"] == [{"path": "/mnt/share", "clients": ["*"]}]


def test_failed_client_returns_stderr_and_error_code():
    result, _ = _run(
        {"target": "10.0.0.5", "action": "list", "path": "/mnt/share"},
        {
            "showmount": _result(EXPORTS_STDOUT),
            "nfs-ls": _result(stdout="", stderr="mount: permission denied", exit_code=1),
        },
    )

    assert result.success is False
    assert result.outcome == "partial"
    assert result.output["error"] == "mount_failed"
    assert "permission denied" in result.output["stderr"]
    assert "hint" in result.output


def test_success_lists_files():
    result, _ = _run(
        {"target": "10.0.0.5", "action": "list", "path": "/mnt/share"},
        {"showmount": _result(EXPORTS_STDOUT), "nfs-ls": _result("notes.txt\nbackup.tar\n")},
    )

    assert result.success is True
    assert result.outcome == ""
    assert result.output["entries"] == ["notes.txt", "backup.tar"]
    assert result.output["count"] == 2


def test_empty_listing_is_reported_as_negative_not_as_an_empty_success():
    result, _ = _run(
        {"target": "10.0.0.5", "action": "list", "path": "/mnt/share"},
        {"showmount": _result(EXPORTS_STDOUT), "nfs-ls": _result("")},
    )

    assert result.outcome == "negative"
    assert result.output["entries"] == []
    assert "vacío" in result.output["message"]


def test_exports_success_tells_the_model_how_to_list():
    result, _ = _run({"target": "10.0.0.5"}, {"showmount": _result(EXPORTS_STDOUT)})

    assert result.success is True
    steps = " ".join(result.output["next_steps"])
    assert "action=list" in steps
    assert "libnfs-utils" in steps


pytestmark = pytest.mark.unit
