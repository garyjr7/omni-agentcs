"""Unit tests for the durable HTTP request handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
import json
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import http_request as http_module
from nexus_core.tools.handlers.http_request import (
    http_request_definition,
    http_request_handler,
)


class FakeSandbox:
    def __init__(self, result: SandboxResult):
        self.result = result
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append((list(argv), timeout_seconds))
        return self.result


@contextlib.contextmanager
def _fake_sandbox(result: SandboxResult):
    sandbox = FakeSandbox(result)
    with mock.patch.object(
        http_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(http_request_handler(arguments, _context()))


def _sandbox_for(payload: dict, exit_code: int = 0) -> SandboxResult:
    return SandboxResult(exit_code, json.dumps(payload) + "\n", "")


def _ok_payload(**overrides) -> dict:
    payload = {
        "ok": True,
        "url": "http://203.0.113.10/",
        "method": "GET",
        "status": 200,
        "reason": "OK",
        "headers": {"content-type": "text/html"},
        "content_type": "text/html",
        "body_bytes": 12,
        "body_sha256": "a" * 64,
        "body_preview": "<html></html>",
        "preview_truncated": False,
        "elapsed_ms": 5,
        "uploaded": None,
    }
    payload.update(overrides)
    return payload


# ------------------------------------------------------------------ definition
def test_definition_declares_scope_and_methods():
    definition = http_request_definition()
    assert definition.scope_target_field == "url"
    assert definition.scope_required is True
    assert set(definition.input_schema["properties"]["method"]["enum"]) == {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
    }


# --------------------------------------------------------------------- handler
def test_handler_runs_python_client_in_sandbox():
    with _fake_sandbox(_sandbox_for(_ok_payload())) as sandbox:
        result = _run({"url": "http://203.0.113.10/"})
    argv = sandbox.calls[0][0]
    assert argv[0] == "python3" and argv[1] == "-c"
    assert argv[3] == "GET"
    assert argv[4] == "http://203.0.113.10/"
    assert result.verified is True
    assert result.verification_method == "http_response_received"
    assert result.output["status"] == 200


def test_handler_never_spawns_subprocess_directly():
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"url": "http://203.0.113.10/"})


def test_upload_builds_spec_and_marks_noise_medium(tmp_path, monkeypatch):
    shell = tmp_path / "shell.phtml"
    shell.write_text("<?php system($_GET['cmd']); ?>", encoding="utf-8")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    payload = _ok_payload(
        method="POST",
        status=200,
        uploaded={"field": "fileUpload", "filename": "shell.phtml", "size": 34},
    )
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run(
            {
                "url": "http://203.0.113.10/panel/",
                "method": "POST",
                "upload": {
                    "field": "fileUpload",
                    "filename": "shell.phtml",
                    "path": "shell.phtml",
                },
            }
        )
    argv = sandbox.calls[0][0]
    upload_spec = json.loads(argv[7])
    assert upload_spec["field"] == "fileUpload"
    assert upload_spec["path"] == str(shell.resolve())
    assert result.verified is True
    assert result.evidence["upload"] is True
    assert result.evidence["noise_level"] == "medium"


def test_upload_extra_form_fields_are_carried(tmp_path, monkeypatch):
    shell = tmp_path / "shell.phtml"
    shell.write_text("<?php system($_GET['cmd']); ?>", encoding="utf-8")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(_sandbox_for(_ok_payload(method="POST", uploaded=None))) as sandbox:
        _run(
            {
                "url": "http://203.0.113.10/panel/",
                "method": "POST",
                "upload": {
                    "field": "fileUpload",
                    "filename": "shell.phtml",
                    "path": "shell.phtml",
                    "fields": {"submit": "Upload"},
                },
            }
        )
    upload_spec = json.loads(sandbox.calls[0][0][7])
    assert upload_spec["fields"] == {"submit": "Upload"}


def test_upload_path_outside_workspace_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path / "ws"))
    (tmp_path / "ws").mkdir()
    outsider = tmp_path / "outside.txt"
    outsider.write_text("x", encoding="utf-8")
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with pytest.raises(ValueError):
            _run(
                {
                    "url": "http://203.0.113.10/panel/",
                    "upload": {"field": "f", "path": str(outsider)},
                }
            )


def test_non_http_url_is_rejected():
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with pytest.raises(ValueError):
            _run({"url": "ftp://203.0.113.10/file"})


def test_data_and_data_base64_are_mutually_exclusive():
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with pytest.raises(ValueError):
            _run({"url": "http://203.0.113.10/", "data": "a", "data_base64": "YQ=="})


def test_invalid_base64_is_rejected():
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with pytest.raises(ValueError):
            _run({"url": "http://203.0.113.10/", "data_base64": "not base64!!"})


def test_control_characters_in_headers_are_rejected():
    with _fake_sandbox(_sandbox_for(_ok_payload())):
        with pytest.raises(ValueError):
            _run({"url": "http://203.0.113.10/", "headers": {"X-Test": "ok\r\nInjected: 1"}})


def test_client_error_payload_is_not_verified():
    payload = {"ok": False, "url": "http://203.0.113.10/", "error": "URLError: refused"}
    with _fake_sandbox(_sandbox_for(payload, exit_code=0)):
        result = _run({"url": "http://203.0.113.10/"})
    assert result.verified is False
    assert result.verification_method == "http_request_failed"


def test_unparseable_output_is_not_verified():
    with _fake_sandbox(SandboxResult(0, "not json at all\n", "")):
        result = _run({"url": "http://203.0.113.10/"})
    assert result.verified is False
    assert result.verification_method == "http_parse_failed"


def test_timeout_is_not_verified():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"url": "http://203.0.113.10/"})
    assert result.verified is False
    assert result.verification_method == "http_timeout"
