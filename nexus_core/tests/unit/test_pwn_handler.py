"""Unit tests for the durable pwn handlers (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
import json
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import pwn as pwn_module
from nexus_core.tools.handlers.pwn import (
    PWN_RESULT_MARKER,
    pwn_analyze_definition,
    pwn_analyze_handler,
    ret2libc_definition,
    ret2libc_handler,
)

EXPLICIT = {
    "offset": 18, "pop_rdi": 0x400683, "gets_plt": 0x4004C0, "puts_plt": 0x4004A0,
    "puts_got": 0x601018, "main": 0x4005C7, "puts_off": 0x84420,
    "system_off": 0x52290, "binsh_off": 0x1B45BD, "writable": 0x601100,
}

ANALYSIS = {
    "ok": True, "mode": "analyze", "connected": True,
    "analysis": {
        "path": "/home/andy/exploit_me", "size": 8392, "sha256": "c" * 64,
        "pie": False, "nx": True, "relro": "partial", "canary": False,
        "plt": {"gets": 0x4004C0, "puts": 0x4004A0},
        "got": {"puts": 0x601018},
        "gadgets": {"pop_rdi": [0x400683], "ret": [0x400684]},
        "overflow": {"buffer_displacement": 10, "offset_to_rip": 18, "gets_plt": 0x4004C0, "site": 0x4005EA},
        "writable": 0x601100,
        "symbols": {"main": 0x4005C7, "setuid": 0x400520},
    },
    "libc": {"path": "/lib/x86_64-linux-gnu/libc.so.6", "sha256": "d" * 64,
             "puts": 0x84420, "system": 0x52290, "binsh": 0x1B45BD},
}


class FakeSandbox:
    def __init__(self, results: list[SandboxResult]):
        self.results = results
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append(list(argv))
        return self.results[min(len(self.calls) - 1, len(self.results) - 1)]


@contextlib.contextmanager
def _fake_sandbox(results: list[SandboxResult]):
    sandbox = FakeSandbox(results)
    with mock.patch.object(
        pwn_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _client(payload: dict) -> SandboxResult:
    return SandboxResult(0, json.dumps(payload) + "\n", "")


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(coro):
    return asyncio.run(coro)


BASE_ARGS = {"target": "10.65.169.187", "username": "andy", "password": "ret2libc!",
             "remote_path": "/home/andy/exploit_me"}


# ------------------------------------------------------------------ definitions
def test_definitions_are_scoped_and_risky():
    analyze = pwn_analyze_definition()
    ret2libc = ret2libc_definition()
    assert analyze.scope_target_field == "target" and analyze.scope_required is True
    assert ret2libc.scope_target_field == "target" and ret2libc.scope_required is True
    assert ret2libc.risk == RiskLevel.HIGH
    assert "command" in ret2libc.input_schema["properties"]


# ------------------------------------------------------------------- analyze
def test_analyze_is_verified_and_trims_symbols():
    with _fake_sandbox([_client(ANALYSIS)]):
        result = _run(pwn_analyze_handler(dict(BASE_ARGS), _context()))
    assert result.verified is True
    assert result.verification_method == "pwn_binary_analyzed"
    assert result.evidence["pie"] is False and result.evidence["nx"] is True
    binary = result.output["binary"]
    assert "symbols" not in binary and binary["symbols_total"] == 2
    assert binary["symbols_of_interest"]["main"] == 0x4005C7
    assert result.output["libc"]["system"] == 0x52290


def test_analyze_unparseable_output_is_not_verified():
    with _fake_sandbox([SandboxResult(0, "garbage\n", "")]):
        result = _run(pwn_analyze_handler(dict(BASE_ARGS), _context()))
    assert result.verified is False
    assert result.verification_method == "pwn_analyze_parse_failed"


def test_analyze_client_error_is_not_verified():
    with _fake_sandbox([_client({"ok": False, "error": "ssh_connect_failed: nope"})]):
        result = _run(pwn_analyze_handler(dict(BASE_ARGS), _context()))
    assert result.verified is False
    assert result.verification_method == "pwn_analyze_failed"


# ------------------------------------------------------------------ ret2libc
def _exploit_client(*, uid_root: bool, base: int = 0x7F0000000000) -> SandboxResult:
    marker = {
        "leak": base + 0x84420, "libc_base": base if uid_root else base + 1,
        "output": "uid=0(root) gid=0" if uid_root else "uid=1002(andy)",
        "uid_root": uid_root, "flag": "thm{abc}" if uid_root else None, "error": None,
    }
    return _client({"ok": True, "mode": "exploit", "connected": True,
                    "stdout": "noise\n" + PWN_RESULT_MARKER + json.dumps(marker) + "\n",
                    "stderr": "", "exit_status": 0})


def test_ret2libc_verified_when_root_and_aligned():
    args = dict(BASE_ARGS, command="id; cat /root/root.txt", **EXPLICIT)
    with _fake_sandbox([_exploit_client(uid_root=True)]):
        result = _run(ret2libc_handler(args, _context()))
    assert result.verified is True
    assert result.verification_method == "ret2libc_root_command"
    assert result.output["ui"] == "root"
    assert result.output["flag"] == "thm{abc}"
    assert result.evidence["libc_base_aligned"] is True


def test_ret2libc_not_verified_without_root():
    args = dict(BASE_ARGS, command="id", **EXPLICIT)
    with _fake_sandbox([_exploit_client(uid_root=False)]):
        result = _run(ret2libc_handler(args, _context()))
    assert result.verified is False
    assert result.verification_method == "ret2libc_no_root"
    assert result.evidence["libc_base_aligned"] is False


def test_ret2libc_resolves_constants_via_analyzer():
    args = dict(BASE_ARGS, command="id")
    with _fake_sandbox([_client(ANALYSIS), _exploit_client(uid_root=True)]) as sandbox:
        result = _run(ret2libc_handler(args, _context()))
    assert result.verified is True
    # First call resolved constants (analyze), second ran the exploit.
    assert len(sandbox.calls) == 2
    assert sandbox.calls[0][3] == "analyze" and sandbox.calls[1][3] == "exploit"
    assert result.evidence["constants"]["offset"] == 18


def test_ret2libc_rejects_pie_binaries():
    analysis = json.loads(json.dumps(ANALYSIS))
    analysis["analysis"]["pie"] = True
    args = dict(BASE_ARGS, command="id")
    with _fake_sandbox([_client(analysis)]):
        result = _run(ret2libc_handler(args, _context()))
    assert result.verified is False
    assert result.verification_method == "ret2libc_resolve_failed"
    assert "PIE" in result.output["error"]


def test_ret2libc_rejects_control_characters_in_command():
    args = dict(BASE_ARGS, command="id\nrm -rf /", **EXPLICIT)
    with pytest.raises(ValueError):
        _run(ret2libc_handler(args, _context()))


def test_ret2libc_transport_error_is_not_verified():
    args = dict(BASE_ARGS, command="id", **EXPLICIT)
    with _fake_sandbox([_client({"ok": False, "error": "ssh_unavailable"})]):
        result = _run(ret2libc_handler(args, _context()))
    assert result.verified is False
    assert result.verification_method == "ret2libc_transport_failed"
