"""FIX 2.3: ``nexus.cred.bruteforce`` enseña la invocación válida y no bloquea 30 min.

Medido en ``run_3a188d2c2bd440f8bca8d88ad922a024`` (Hijack v3): la iteración 7
recibió ``"$: 'form_url' is a required property"`` sin ejemplo y gastó la
iteración 8 adivinando; la iteración 35 ejecutó hydra durante 1 785 174 ms y el
run leyó ``unavailable``. El rechazo de schema ocurre en el gateway (antes del
handler), así que el ejemplo viaja declarado en la definición.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.tools.handlers import cred_bruteforce as module
from nexus_core.tools.handlers.cred_bruteforce import (
    CRED_DEFAULT_TIMEOUT_SECONDS,
    cred_bruteforce_definition,
    cred_bruteforce_handler,
)

TARGET = "10.0.0.5"


class FakeSandbox:
    def __init__(self, result: SandboxResult):
        self.result = result
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30, **kwargs):
        self.calls.append((list(argv), timeout_seconds))
        return self.result


@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch) -> Path:
    (tmp_path / "locks.txt").write_text("\n".join(f"pw{i}" for i in range(5)) + "\n")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    return tmp_path


def _ssh(**overrides) -> dict:
    arguments = {
        "target": TARGET,
        "service": "ssh",
        "username": "lin",
        "password_file": "locks.txt",
    }
    arguments.update(overrides)
    return arguments


def _run(arguments: dict, result: SandboxResult):
    sandbox = FakeSandbox(result)
    with mock.patch.object(
        module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        output = asyncio.run(
            cred_bruteforce_handler(
                arguments,
                RunContext("system", Identity("operator-1", "system", roles=("operator",))),
            )
        )
    return output, sandbox


# ------------------------------------------------------------------- schema example
def test_missing_form_url_returns_example(tmp_path: Path) -> None:
    store = ControlStore(tmp_path / "gateway.db")
    store.initialize()
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store), ApprovalService(store))
    gateway.register(cred_bruteforce_definition(), cred_bruteforce_handler)
    context = RunContext("system", Identity("operator-1", "system", roles=("operator",)))

    with pytest.raises(Exception) as excinfo:
        asyncio.run(
            gateway.invoke(
                "nexus.cred.bruteforce",
                {
                    "target": TARGET,
                    "service": "http-post-form",
                    "username": "admin",
                    "password_file": "/usr/share/wordlists/rockyou.txt",
                },
                context,
            )
        )

    message = str(excinfo.value)
    assert "'form_url' is a required property" in message
    assert "ejemplo" in message
    # The example is a valid invocation, not a paraphrase of the error.
    assert "form_params" in message and "^USER^" in message
    assert "failure_string" in message


def test_the_declared_example_is_a_valid_invocation() -> None:
    from nexus_core.kernel.schema_validation import validate

    definition = cred_bruteforce_definition()
    validate(dict(definition.input_example), definition.input_schema)


# ------------------------------------------------------------------------- timeout
def test_hydra_timeout_default_is_300(workspace: Path) -> None:
    _result, sandbox = _run(_ssh(), SandboxResult(0, "0 valid password found", ""))
    assert sandbox.calls[0][0][0] == "hydra"
    assert sandbox.calls[0][1] == CRED_DEFAULT_TIMEOUT_SECONDS == 300


def test_hydra_timeout_respected_when_provided(workspace: Path) -> None:
    _result, sandbox = _run(
        _ssh(timeout_seconds=900), SandboxResult(0, "0 valid password found", "")
    )
    assert sandbox.calls[0][1] == 900


def test_a_timed_out_sweep_is_a_timeout_even_with_a_missing_binary_marker(
    workspace: Path,
) -> None:
    # hydra killed at the ceiling; a truncated stderr that happens to carry a
    # "not found" marker must not turn the sweep into ``unavailable``.
    result, _sandbox_calls = _run(
        _ssh(), SandboxResult(127, "", "hydra: not found", timed_out=True)
    )

    assert result.outcome == "timeout"
    assert result.verification_method == "cred_bruteforce_timeout"
    assert result.timed_out is True


pytestmark = pytest.mark.unit
