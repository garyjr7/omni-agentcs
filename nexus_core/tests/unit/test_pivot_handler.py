"""Unit tests for the SSH-pivot credential attack (sandbox mocked, no network).

The handler must never talk to the pivoted service itself: it drives a sandboxed
client that owns the SSH connection, so these tests assert the *transport
contract* (argv shape, wordlist slice, artefact paths) and the *interpretation*
of the client's JSON, including the refusal to report an unverified hit.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import pivot as pivot_module
from nexus_core.tools.handlers._pivot import (
    PIVOT_CLIENT_SCRIPT,
    PIVOT_HTTP_REMOTE_SCRIPT,
    PIVOT_REMOTE_SCRIPT,
)
from nexus_core.tools.handlers.pivot import (
    pivot_bruteforce_definition,
    pivot_bruteforce_handler,
    pivot_http_definition,
    pivot_http_handler,
)

pytestmark = pytest.mark.unit


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
    allowlists: list[tuple[str, ...]] = []

    def factory(workspace_root, allowed_programs=None):
        allowlists.append(tuple(allowed_programs or ()))
        return sandbox

    with mock.patch.object(pivot_module, "sandbox_for_environment", factory):
        yield sandbox, allowlists


def _context() -> RunContext:
    return RunContext("system", Identity("op", "system", roles=("operator",)))


def _payload(**overrides) -> dict:
    payload = {
        "form_url": "http://127.0.0.1:8080/j_spring_security_check",
        "form_username": "admin",
        "password": "bubb13guM!@#123",
        "failure_marker": "Invalid username or password",
    }
    payload.update(overrides)
    return payload


def _run(arguments: dict):
    return asyncio.run(pivot_bruteforce_handler(arguments, _context()))


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("\n".join(f"pw{index}" for index in range(30)) + "\n", encoding="utf-8")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    return tmp_path, wordlist


def _argv(payload: dict, **extra) -> dict:
    return _payload(**{**payload, **extra})


# ------------------------------------------------------------------ definition
def test_definition_is_high_risk_and_scope_gated_on_the_ssh_host():
    definition = pivot_bruteforce_definition()
    assert definition.risk.value == "high"
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True
    assert "target" in definition.input_schema["required"]
    assert "form_url" in definition.input_schema["required"]


# -------------------------------------------------------------- validation
def test_form_url_must_be_http(workspace):
    _, wordlist = workspace
    arguments = _argv(
        {"form_url": "file:///etc/passwd"},
        target="10.0.0.1",
        username="aubreanna",
        password_file=str(wordlist),
    )
    with pytest.raises(ValueError, match="http"):
        _run(arguments)


def test_missing_failure_marker_is_rejected(workspace):
    _, wordlist = workspace
    arguments = {
        "target": "10.0.0.1",
        "username": "aubreanna",
        "password": "x",
        "form_url": "http://127.0.0.1:8080/j_spring_security_check",
        "form_username": "admin",
        "password_file": str(wordlist),
    }
    with pytest.raises(ValueError, match="failure_marker"):
        _run(arguments)


def test_offset_past_the_wordlist_is_rejected(workspace):
    _, wordlist = workspace
    arguments = _argv(
        {},
        target="10.0.0.1",
        username="aubreanna",
        password_file=str(wordlist),
        offset=5000,
    )
    with pytest.raises(ValueError, match="no usable entries"):
        _run(arguments)


def test_wordlist_outside_the_workspace_is_rejected(workspace):
    _, _wordlist = workspace
    arguments = _argv(
        {},
        target="10.0.0.1",
        username="aubreanna",
        password_file="/etc/shadow",
    )
    with pytest.raises(ValueError):
        _run(arguments)


# ---------------------------------------------------------------- transport
def test_client_runs_through_the_sandbox_with_the_slice_on_disk(workspace):
    root, wordlist = workspace
    outcome = {"ok": True, "password": "pw7", "tested": 8, "total": 30,
               "verification": {"ok": True}, "preflight": {"ok": True}}
    with _fake_sandbox(SandboxResult(0, json.dumps(outcome) + "\n", "")) as (sandbox, allowlists):
        result = _run(_argv(
            {},
            target="10.66.156.56",
            username="aubreanna",
            password_file=str(wordlist),
            max_attempts=5,
            offset=2,
        ))

    (argv, timeout), = sandbox.calls
    assert argv[0] == "python3"
    assert argv[1] == "-c"
    assert argv[2] == PIVOT_CLIENT_SCRIPT
    assert argv[3:5] == ["10.66.156.56", "22"]
    assert argv[5] == "aubreanna"
    assert argv[6] == "bubb13guM!@#123"
    payload = json.loads(argv[7])
    assert payload["failure_marker"] == "Invalid username or password"
    assert payload["session_url"] is None
    assert argv[8] == PIVOT_REMOTE_SCRIPT
    # The slice is materialized inside the workspace for the client to upload
    # over SFTP, and nowhere else.
    assert Path(payload["wordlist_path"]).parent.parent == root
    sliced = Path(payload["wordlist_path"]).read_text(encoding="utf-8").splitlines()
    assert sliced == ["pw2", "pw3", "pw4", "pw5", "pw6"]
    assert "python3" in allowlists[0]
    assert timeout >= 30
    assert result.verified is True


def test_verified_hit_is_reported_with_the_credential(workspace):
    _, wordlist = workspace
    outcome = {
        "ok": True,
        "password": "bubb13guM!@#123",
        "tested": 3913,
        "total": 14344391,
        "rate_per_second": 82.1,
        "elapsed_seconds": 47.6,
        "preflight": {"ok": True, "status": 200},
        "verification": {"ok": True, "status": 302, "control_status": 200},
    }
    with _fake_sandbox(SandboxResult(0, json.dumps(outcome) + "\n", "")):
        result = _run(_argv(
            {},
            target="10.66.156.56",
            username="aubreanna",
            password_file=str(wordlist),
        ))
    assert result.verified is True
    assert result.verification_method == "pivot_credential_validated"
    assert result.output["valid_credentials"] == [
        {"username": "admin", "password": "bubb13guM!@#123", "service": "http-pivot"}
    ]
    assert result.evidence["reachable_from"] == "target"


def test_hit_without_remote_verification_is_not_promoted(workspace):
    _, wordlist = workspace
    outcome = {
        "ok": True,
        "password": "maybe",
        "tested": 10,
        "total": 30,
        "preflight": {"ok": True},
        "verification": {"ok": False, "detail": "second attempt failed"},
    }
    with _fake_sandbox(SandboxResult(0, json.dumps(outcome) + "\n", "")):
        result = _run(_argv(
            {},
            target="10.66.156.56",
            username="aubreanna",
            password_file=str(wordlist),
        ))
    # The candidate was not reproducible, so no credential exists and the run is
    # a plain (completed) negative — never a promoted credential.
    assert result.verified is True
    assert result.verification_method == "pivot_bruteforce_completed"
    assert result.output["valid_credentials"] == []
    assert result.output["verification"]["ok"] is False


def test_completed_sweep_without_a_hit_is_a_trustworthy_negative(workspace):
    _, wordlist = workspace
    outcome = {
        "ok": True,
        "tested": 30,
        "total": 30,
        "statuses": {"302": 30},
        "preflight": {"ok": True, "status": 302},
        "errors": [],
    }
    with _fake_sandbox(SandboxResult(0, json.dumps(outcome) + "\n", "")):
        result = _run(_argv(
            {},
            target="10.66.156.56",
            username="aubreanna",
            password_file=str(wordlist),
        ))
    assert result.verified is True
    assert result.verification_method == "pivot_bruteforce_completed"
    assert result.output["valid_credentials"] == []


def test_transport_wall_is_reported_as_unavailable(workspace):
    _, wordlist = workspace
    outcome = {
        "ok": True,
        "tested": 30,
        "total": 30,
        "statuses": {"403": 30},
        "preflight": {"ok": True, "status": 403},
        "errors": [
            (
                "every attempt returned HTTP 403: the request was rejected before "
                "reaching the credential check"
            )
        ],
    }
    with _fake_sandbox(SandboxResult(0, json.dumps(outcome) + "\n", "")):
        result = _run(_argv(
            {},
            target="10.66.156.56",
            username="aubreanna",
            password_file=str(wordlist),
        ))
    assert result.verified is False
    assert result.verification_method == "pivot_bruteforce_unavailable"
    assert result.output["transport_rejected_every_attempt"] is True


def test_failed_preflight_is_surfaced_to_the_operator(workspace):
    _, wordlist = workspace
    outcome = {
        "ok": True,
        "tested": 0,
        "total": 30,
        "preflight": {"ok": False, "detail": "a random password was accepted"},
        "errors": [],
    }
    with _fake_sandbox(SandboxResult(0, json.dumps(outcome) + "\n", "")):
        result = _run(_argv(
            {},
            target="10.66.156.56",
            username="aubreanna",
            password_file=str(wordlist),
        ))
    assert result.verified is False
    assert result.verification_method == "pivot_bruteforce_unavailable"
    assert result.output["preflight"]["ok"] is False


def test_client_without_result_yields_an_unverified_failure(workspace):
    _, wordlist = workspace
    with _fake_sandbox(SandboxResult(0, "no json here\n", "")):
        result = _run(_argv(
            {},
            target="10.66.156.56",
            username="aubreanna",
            password_file=str(wordlist),
        ))
    assert result.verified is False
    assert result.verification_method == "pivot_bruteforce_unavailable"


# ------------------------------------------------------------------- scripts
def test_remote_harness_never_invents_success():
    # No failure marker in the body is only a *candidate*: the harness re-runs
    # the hit and a control attempt before it will name a password.
    assert "verification" in PIVOT_REMOTE_SCRIPT
    assert "control_status" in PIVOT_REMOTE_SCRIPT
    assert '"password"' in PIVOT_REMOTE_SCRIPT


def test_remote_harness_warm_up_keeps_a_session():
    # Measured on the Jenkins box: without the session cookie every POST is 403,
    # which a naive per-request client would report as "no credential found".
    assert "warm_up" in PIVOT_REMOTE_SCRIPT
    assert "http.cookiejar" in PIVOT_REMOTE_SCRIPT
    assert 'headers["Cookie"] = cookie' in PIVOT_REMOTE_SCRIPT
    assert "parse_hidden_fields" in PIVOT_REMOTE_SCRIPT


def test_remote_harness_matches_markers_against_the_redirect_target():
    # A rejected login is a 302 to /loginError: the answer is in Location.
    assert "getheader(\"Location\")" in PIVOT_REMOTE_SCRIPT or 'getheader("Location")' in PIVOT_REMOTE_SCRIPT


def test_remote_harness_reports_a_transport_level_wall():
    assert "rejected before" in PIVOT_REMOTE_SCRIPT
    assert "statuses" in PIVOT_REMOTE_SCRIPT


def test_client_cleans_up_remote_artefacts():
    assert "omni-pivot-" in PIVOT_CLIENT_SCRIPT
    assert "remote_cleanup" in PIVOT_CLIENT_SCRIPT
    assert 'sftp.put(config["wordlist_path"]' in PIVOT_CLIENT_SCRIPT
    # Single-request mode uploads no wordlist and must not create one either.
    assert 'if config.get("wordlist_path")' in PIVOT_CLIENT_SCRIPT


def test_scripts_are_stdlib_only():
    for script in (PIVOT_CLIENT_SCRIPT, PIVOT_REMOTE_SCRIPT, PIVOT_HTTP_REMOTE_SCRIPT):
        assert "subprocess" not in script
        assert "os.system" not in script


# ------------------------------------------------------------- pivot_http

def _run_http(arguments: dict):
    return asyncio.run(pivot_http_handler(arguments, _context()))


def _http_args(**overrides) -> dict:
    arguments = {
        "target": "10.66.156.56",
        "username": "aubreanna",
        "password": "bubb13guM!@#123",
        "url": "http://127.0.0.1:8080/scriptText",
        "method": "POST",
        "body": "script=println(1)",
    }
    arguments.update(overrides)
    return arguments


def test_pivot_http_definition_is_high_risk_and_scope_gated():
    definition = pivot_http_definition()
    assert definition.risk.value == "high"
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True


def test_pivot_http_rejects_a_non_http_url(workspace):
    with pytest.raises(ValueError, match="http"):
        _run_http(_http_args(url="gopher://127.0.0.1:8080/") )


def test_pivot_http_rejects_header_injection():
    with pytest.raises(ValueError, match="invalid header"):
        _run_http(_http_args(headers={"X-Test": "value\r\nJenkins-Crumb: forged"}))


def test_pivot_http_rejects_a_bad_method():
    with pytest.raises(ValueError, match="method"):
        _run_http(_http_args(method="DELETE"))


def test_pivot_http_drives_a_logged_in_request(workspace):
    outcome = {
        "status": 200,
        "location": "",
        "body": "note.txt: root credentials",
        "body_length": 28,
        "session": {"ok": True, "cookies": True},
        "login": {"ok": True, "status": 302},
        "errors": [],
    }
    with _fake_sandbox(SandboxResult(0, json.dumps(outcome) + "\n", "")) as (sandbox, _allow):
        result = _run_http(
            _http_args(
                session_url="http://127.0.0.1:8080/login",
                login_url="http://127.0.0.1:8080/j_acegi_security_check",
                login_username="admin",
                login_password="spongebob",
                login_failure_marker="loginError",
                token_url="http://127.0.0.1:8080/crumbIssuer/api/json",
            )
        )
    (argv, _timeout), = sandbox.calls
    assert argv[2] == PIVOT_CLIENT_SCRIPT
    assert argv[8] == PIVOT_HTTP_REMOTE_SCRIPT
    config = json.loads(argv[7])
    assert config["login_username"] == "admin"
    assert config["token_field"] == ""  # default applied inside the harness
    # A single request uploads nothing: no local scaffold, no remote artefact.
    assert config["wordlist_path"] is None
    assert result.verified is True
    assert result.verification_method == "pivot_http_response_received"
    assert result.output["status"] == 200
    assert "root credentials" in result.output["body"]


def test_pivot_http_reports_a_failed_login_as_unavailable(workspace):
    outcome = {
        "session": {"ok": True},
        "login": {"ok": False, "status": 302, "rejected": True},
        "errors": ["login rejected (status=302)"],
    }
    with _fake_sandbox(SandboxResult(0, json.dumps(outcome) + "\n", "")):
        result = _run_http(
            _http_args(
                login_url="http://127.0.0.1:8080/j_acegi_security_check",
                login_username="admin",
                login_password="wrong",
                login_failure_marker="loginError",
            )
        )
    assert result.verified is False
    assert result.verification_method == "pivot_http_unavailable"
    assert result.output["errors"]


def test_pivot_http_without_a_result_is_unavailable():
    with _fake_sandbox(SandboxResult(0, "garbage\n", "")):
        result = _run_http(_http_args())
    assert result.verified is False
    assert result.verification_method == "pivot_http_unavailable"


def test_http_harness_fetches_a_token_from_the_session():
    # The crumb is bound to the *authenticated* session: the harness fetches it
    # with the same cookies it will send on the request.
    assert "token_header" in PIVOT_HTTP_REMOTE_SCRIPT
    assert "token_url" in PIVOT_HTTP_REMOTE_SCRIPT
    assert "Jenkins-Crumb" in PIVOT_HTTP_REMOTE_SCRIPT
