"""Unit tests for ``nexus.post.pwnkit`` (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import pwnkit as pwnkit_module
from nexus_core.tools.handlers.pwnkit import (
    PWNKIT_GCONV_MODULES,
    _c_string,
    pwnkit_definition,
    pwnkit_handler,
)

NONCE_RE = re.compile(r"nexus[0-9a-f]{12}")
BASE_ARGS = {"target": "10.71.235.159", "username": "entrance", "password": "Knossos"}


class FakeSandbox:
    def __init__(self, responder) -> None:
        self.responder = responder
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append(list(argv))
        # argv = python3 -c <script> mode host port user password payload
        payload = json.loads(argv[8])
        return self.responder(argv[3], payload)


@contextlib.contextmanager
def _sandbox(responder):
    sandbox = FakeSandbox(responder)
    with mock.patch.object(
        pwnkit_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(pwnkit_handler(arguments, _context()))


def _client(payload: dict) -> SandboxResult:
    return SandboxResult(0, json.dumps(payload) + "\n", "")


def _exploit_responder(*, uid_root: bool = True, module_output: str | None = None):
    """Answer the exploit run with the block the module would have produced."""

    def respond(mode: str, payload: dict) -> SandboxResult:
        nonce = NONCE_RE.search(payload["module_source"])
        assert nonce, "the module source must carry the nonce markers"
        output = module_output
        if output is None:
            output = (
                "uid=0(root) gid=0(root) groups=0(root)\n"
                "flag{fake_flag}"
                if uid_root
                else "Usage: pkexec [--version]"
            )
        stdout = (
            "Starting...\n"
            f"{nonce.group(0)}\n{output}\n__NEXUS_RC=0\n{nonce.group(0)}\n"
        )
        return _client(
            {
                "ok": True,
                "mode": mode,
                "connected": True,
                "compile": {"exit_status": 0, "stdout": "", "stderr": ""},
                "stdout": stdout,
                "stderr": "",
                "exit_status": 0,
            }
        )

    return respond


def test_definition_is_high_risk_and_scoped_to_the_target():
    definition = pwnkit_definition()
    assert definition.risk == RiskLevel.HIGH
    assert definition.scope_required is True
    assert definition.scope_target_field == "target"
    assert definition.effect == "exploit"
    assert {"jump_host", "jump_username", "jump_password", "command"} <= set(
        definition.input_schema["properties"]
    )


def test_c_string_escapes_quotes_and_backslashes():
    assert _c_string('id; echo "x"') == 'id; echo \\"x\\"'
    assert _c_string("a\\b") == "a\\\\b"


def test_module_source_carries_the_escaped_command():
    seen: dict = {}

    def respond(mode: str, payload: dict) -> SandboxResult:
        seen.update(payload)
        return _exploit_responder()(mode, payload)

    with _sandbox(respond):
        result = _run(dict(BASE_ARGS, command='id; echo "hi"'))
    assert result.verified is True
    source = seen["module_source"]
    assert 'system("' in source and 'echo \\"hi\\"' in source
    assert "setuid(0)" in source and "setgid(0)" in source
    assert seen["gconv_modules"] == PWNKIT_GCONV_MODULES
    assert 'execve("/usr/bin/pkexec"' in seen["driver_source"]
    assert "(char *)0" in seen["driver_source"]
    assert seen["dir"].startswith("/tmp/.omni_pwnkit_")


def test_exploit_is_verified_only_with_uid_zero():
    with _sandbox(_exploit_responder(uid_root=True)):
        result = _run(dict(BASE_ARGS))
    assert result.verified is True
    assert result.verification_method == "pwnkit_root_command"
    assert result.output["ui"] == "root"
    assert result.output["returncode"] == 0
    assert result.output["flag"] == "flag{fake_flag}"


def test_a_patched_pkexec_is_not_verified():
    with _sandbox(_exploit_responder(uid_root=False)):
        result = _run(dict(BASE_ARGS))
    assert result.verified is False
    assert result.verification_method == "pwnkit_no_root"
    assert "parcheado" in result.output["next_steps"][0]


def test_a_target_without_gcc_returns_the_alternatives():
    def respond(mode: str, payload: dict) -> SandboxResult:
        return _client(
            {
                "ok": False,
                "error": "no_gcc",
                "detail": "the target has no gcc",
                "compile": {"exit_status": 90, "stdout": "NEXUS_NO_GCC\n", "stderr": ""},
            }
        )

    with _sandbox(respond):
        result = _run(dict(BASE_ARGS))
    assert result.verified is False
    assert result.verification_method == "pwnkit_no_gcc"
    assert "Metasploit" in result.output["next_steps"][0]


def test_the_jump_host_travels_in_the_payload():
    seen: dict = {}

    def respond(mode: str, payload: dict) -> SandboxResult:
        seen.update(payload)
        return _exploit_responder()(mode, payload)

    args = dict(
        BASE_ARGS,
        jump_host="10.10.10.122",
        jump_username="root",
        jump_password="cracked",
        command="id",
    )
    with _sandbox(respond):
        result = _run(args)
    assert result.verified is True
    assert seen["jump"] == {
        "host": "10.10.10.122", "port": 22, "username": "root", "password": "cracked",
    }


def test_check_reads_the_surface_without_exploiting():
    def respond(mode: str, payload: dict) -> SandboxResult:
        assert mode == "check"
        return _client(
            {
                "ok": True,
                "mode": "check",
                "connected": True,
                "stdout": (
                    "-rwsr-xr-x 1 root root 146K /usr/bin/pkexec\n"
                    "pkexec version 0.105\nUbuntu 18.04.4 LTS\nx86_64\n"
                ),
                "stderr": "",
                "exit_status": 0,
            }
        )

    with _sandbox(respond):
        result = _run(dict(BASE_ARGS, action="check"))
    assert result.verified is False
    assert result.verification_method == "pwnkit_surface"
    assert result.output["surface"]["assessment"] == "likely_vulnerable"
    assert result.output["surface"]["version"] == "0.105"


def test_jump_password_is_required_with_a_jump_host():
    with pytest.raises(ValueError):
        _run(dict(BASE_ARGS, jump_host="10.10.10.122", jump_username="root"))


def test_command_with_control_characters_is_rejected():
    with pytest.raises(ValueError):
        _run(dict(BASE_ARGS, command="id\nrm -rf /"))


def test_missing_password_is_rejected():
    with pytest.raises(ValueError):
        _run({"target": "10.71.235.159", "username": "entrance"})
