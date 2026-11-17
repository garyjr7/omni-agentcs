"""Unit tests for ``nexus.web.ssti`` (sandbox mocked, no network).

The fake sandbox *is* a tiny Flask app: it evaluates the canary and the exec
payloads for the parameter the payload names, so the assertions describe what
the target would answer instead of what the client happened to send.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import re
from urllib.parse import parse_qsl, urlsplit

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import web_ssti as ssti_module
from nexus_core.tools.handlers.web_ssti import (
    SSTI_CANARY_VALUE,
    SSTI_REPEAT_VALUE,
    ssti_definition,
    ssti_handler,
)

PAGE = "<html><body><pre>King Minos ... MAKE USE OF THE KEY</pre></body></html>"
NONCE_RE = re.compile(r"nexus[0-9a-f]{12}")
COMMAND_RE = re.compile(r"\( (.*?) \); echo __NEXUS_RC")


class FakeTarget:
    """A page that renders ``param`` with a template engine (Jinja2 by default)."""

    def __init__(self, *, param: str = "key", engine: str = "jinja2",
                 command: str = "", sends: bool = True) -> None:
        self.param = param
        self.engine = engine
        self.command = command
        self.sends = sends
        self.requests: list[str] = []

    def _evaluates(self, value: str) -> list[str]:
        rendered: list[str] = []
        if not self.sends:
            return rendered
        if "7351*3" in value and "{{" in value and self.engine in {"jinja2", "twig"}:
            rendered.append(SSTI_CANARY_VALUE)
        if "7351*3" in value and "${" in value and self.engine == "freemarker":
            rendered.append(SSTI_CANARY_VALUE)
        if "7351*3" in value and "<%=" in value and self.engine == "erb":
            rendered.append(SSTI_CANARY_VALUE)
        if "7*'7'" in value and self.engine == "jinja2":
            rendered.append(SSTI_REPEAT_VALUE)
        return rendered

    def _execution(self, value: str) -> str:
        if not self.sends:
            return ""
        match = re.search(r"echo ([A-Za-z0-9+/=]+)\|base64 -d\|sh", value)
        if not match:
            return ""
        decoded = base64.b64decode(match.group(1)).decode("utf-8")
        nonce = NONCE_RE.search(decoded)
        command = COMMAND_RE.search(decoded)
        if not nonce or not command:
            return ""
        output = self.command or self._run(command.group(1))
        return f"\n{nonce.group(0)}\n{output}\n__NEXUS_RC=0\n{nonce.group(0)}\n"

    def _run(self, command: str) -> str:
        if command.strip() == "id":
            return "uid=0(root) gid=0(root) groups=0(root)"
        if command.startswith("cat ") and "Minos_Flag" in command:
            return "flag{fake_flag}"
        if command.startswith("cat ") and "Crete_Shores" in command:
            return "Username: entrance Password: Knossos"
        return ""

    def respond(self, payload: dict) -> SandboxResult:
        responses: list[dict] = []
        for spec in payload["requests"]:
            self.requests.append(spec["url"])
            parts = urlsplit(spec["url"])
            query = dict(parse_qsl(parts.query, keep_blank_values=True))
            if spec.get("method") == "POST":
                query.update(dict(parse_qsl(spec.get("body") or "", keep_blank_values=True)))
            value = query.get(self.param, "")
            text = PAGE
            if value:
                rendered = self._evaluates(value)
                if rendered:
                    text = PAGE + "".join(rendered)
                execution = self._execution(value)
                if execution:
                    text = PAGE + execution
            responses.append(
                {
                    "url": spec["url"],
                    "status": 200,
                    "length": len(text),
                    "elapsed": 0.01,
                    "body": text[: int(spec.get("keep") or 4000)],
                    "tokens": {token: token in text for token in spec.get("tokens") or []},
                }
            )
        return SandboxResult(0, json.dumps({"ok": True, "responses": responses}) + "\n", "")


@contextlib.contextmanager
def _target(target: FakeTarget):
    class Sandbox:
        async def run(self, argv, *, timeout_seconds: float = 30):
            return target.respond(json.loads(argv[3]))

    with _patch_sandbox(Sandbox()):
        yield target


@contextlib.contextmanager
def _patch_sandbox(sandbox):
    from unittest import mock

    with mock.patch.object(
        ssti_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(ssti_handler(arguments, _context()))


def test_definition_is_high_risk_and_scoped_to_the_url():
    definition = ssti_definition()
    assert definition.risk == RiskLevel.HIGH
    assert definition.scope_required is True
    assert definition.scope_target_field == "url"
    assert definition.effect == "exploit"
    assert "param" in definition.input_schema["properties"]


def test_discovery_names_the_parameter_the_page_evaluates():
    target = FakeTarget()
    with _target(target):
        result = _run({"url": "http://10.10.57.61:8080/"})
    assert result.verified is True
    assert result.verification_method == "ssti_engine_evaluated"
    assert result.output["parameter"] == "key"
    assert result.output["engine"] == "jinja2"
    assert result.output["discovered"] is True
    # A bounded pass over the built-in names, not an endless fuzz.
    assert len(target.requests) <= 62


def test_discovery_reports_twig_when_the_repeat_canary_does_not_evaluate():
    with _target(FakeTarget(engine="twig")):
        result = _run({"url": "http://10.10.57.61:8080/"})
    assert result.verified is True
    assert result.output["engine"] == "twig"


@pytest.mark.parametrize(("engine", "payload"), [
    ("freemarker", "${7351*3}"),
    ("erb", "<%= 7351*3 %>"),
])
def test_discovery_recognises_the_dollar_and_erb_syntaxes(engine, payload):
    target = FakeTarget(engine=engine, param="name")
    with _target(target):
        result = _run({"url": "http://10.10.57.61:8080/?name=hi"})
    assert result.verified is True
    assert result.output["engine"] == engine
    assert result.output["parameter"] == "name"


def test_detection_without_a_hit_is_not_verified_and_offers_the_next_probe():
    with _target(FakeTarget(sends=False)):
        result = _run({"url": "http://10.10.57.61:8080/"})
    assert result.verified is False
    assert result.verification_method == "ssti_not_detected"
    assert "params=[" in result.output["next_steps"][0]


def test_exec_runs_the_command_through_the_detected_engine():
    with _target(FakeTarget()):
        result = _run({"url": "http://10.10.57.61:8080/", "action": "exec",
                       "engine": "jinja2", "param": "key", "command": "id"})
    assert result.verified is True
    assert result.verification_method == "ssti_command_output"
    assert "uid=0(root)" in result.output["output"]
    assert result.output["returncode"] == 0
    assert result.evidence["engine"] == "jinja2"


def test_read_file_extracts_the_flag_and_credentials():
    with _target(FakeTarget()):
        flag = _run({"url": "http://10.10.57.61:8080/", "action": "read_file",
                     "engine": "jinja2", "param": "key",
                     "path": "/home/minos/Minos_Flag"})
    assert flag.verified is True
    assert flag.output["flag"] == "flag{fake_flag}"

    with _target(FakeTarget()):
        notes = _run({"url": "http://10.10.57.61:8080/", "action": "read_file",
                      "engine": "jinja2", "param": "key",
                      "path": "/home/minos/Crete_Shores"})
    assert notes.output["credentials"] == [
        {"username": "entrance", "password": "Knossos", "source": "http://10.10.57.61:8080/?key"}
    ]


def test_an_empty_output_still_counts_as_execution_when_the_markers_arrive():
    """``id`` on a host that prints nothing is still a proven RCE: the markers
    are what prove execution, not the command's text."""
    with _target(FakeTarget(command="")):
        result = _run({"url": "http://10.10.57.61:8080/", "action": "exec",
                       "engine": "jinja2", "param": "key", "command": "whoami"})
    assert result.verified is True
    assert result.output["output"] == ""


def test_a_payload_that_is_never_evaluated_is_not_verified():
    with _target(FakeTarget(sends=False)):
        result = _run({"url": "http://10.10.57.61:8080/", "action": "exec",
                       "engine": "jinja2", "param": "key", "command": "id"})
    assert result.verified is False
    assert result.verification_method == "ssti_no_output"


def test_command_with_control_characters_is_rejected():
    with pytest.raises(ValueError):
        _run({"url": "http://10.10.57.61:8080/", "action": "exec", "param": "key",
              "command": "id\nrm -rf /"})


def test_read_file_requires_a_path():
    with pytest.raises(ValueError):
        _run({"url": "http://10.10.57.61:8080/", "action": "read_file", "param": "key"})


def test_url_must_be_http():
    with pytest.raises(ValueError):
        _run({"url": "ftp://10.10.57.61/etc/passwd"})
