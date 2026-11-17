"""Unit tests for the credential-testing handler (sandbox mocked, no network)."""

from __future__ import annotations

import asyncio
import contextlib
import http.server
import json
import subprocess
import sys
import threading
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import cred_bruteforce as module
from nexus_core.tools.handlers.cred_bruteforce import (
    CRED_DEFAULT_MAX_ATTEMPTS,
    cred_bruteforce_definition,
    cred_bruteforce_handler,
    parse_hydra_credentials,
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
        module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(arguments: dict) -> object:
    return asyncio.run(cred_bruteforce_handler(arguments, _context()))


def _workspace(tmp_path: Path) -> None:
    (tmp_path / "locks.txt").write_text("\n".join(f"pw{i}" for i in range(5)) + "\n", encoding="utf-8")


# ------------------------------------------------------------------ definition
def test_definition_declares_scope_and_services():
    definition = cred_bruteforce_definition()
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True
    # The web-form modules are part of the contract: Brute It (2026-10-20) is an
    # HTTP login and the run could only brute-force SSH.
    assert set(definition.input_schema["properties"]["service"]["enum"]) == {
        "ssh", "ftp", "tcp", "telnet", "http-post-form", "http-get-form"
    }


# ----------------------------------------------------------- http form modules
def _form_arguments(**overrides) -> dict:
    arguments = {
        "target": "10.0.0.1",
        "service": "http-post-form",
        "port": 80,
        "username": "admin",
        "password_file": "locks.txt",
        "form_url": "/admin/index.php",
        "form_params": "user=^USER^&pass=^PASS^&submit=Login",
        "failure_string": "Invalid username or password",
    }
    arguments.update(overrides)
    return arguments


def test_a_full_login_url_is_reduced_to_its_route(tmp_path, monkeypatch):
    """Brute It v5 (iteration 12): ``http://host/admin/`` cost the model a turn.

    The URL already says the route and the host, so the handler takes them
    instead of answering ``form_url must be the login path``.
    """
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    # ``probe=False``: this test is about hydra's argv, and the probe is its own
    # call. The default (probe on) is covered by the probe tests below.
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        result = _run(
            _form_arguments(form_url="http://10.0.0.1/admin/", probe=False)
        )
    argv = sandbox.calls[0][0]
    assert argv[-3:] == [
        "10.0.0.1",
        "http-post-form",
        "/admin/:user=^USER^&pass=^PASS^&submit=Login:F=Invalid username or password",
    ]
    assert "-S" not in argv
    # The evidence names the route that actually ran, not the raw argument.
    assert result.evidence["form_url"] == "/admin/"


def test_an_https_login_url_sets_the_port_and_the_ssl_switch(tmp_path, monkeypatch):
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    arguments = _form_arguments(form_url="https://10.0.0.1/login", probe=False)
    arguments.pop("port")
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        _run(arguments)
    argv = sandbox.calls[0][0]
    assert argv[5:7] == ["-s", "443"]
    assert "-S" in argv
    assert argv[-3:] == [
        "10.0.0.1",
        "http-post-form",
        "/login:user=^USER^&pass=^PASS^&submit=Login:F=Invalid username or password",
    ]


def test_a_url_for_another_host_keeps_the_scoped_targets_defaults(tmp_path, monkeypatch):
    """The scope-gated ``target`` always wins: the URL's host/port are not used."""
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        result = _run(_form_arguments(form_url="http://otro-host:8080/admin/", probe=False))
    argv = sandbox.calls[0][0]
    assert argv[5:7] == ["-s", "80"]
    assert argv[-3] == "10.0.0.1"
    assert result.evidence["form_url"] == "/admin/"


def test_a_form_url_with_a_query_is_normalized_to_its_route(tmp_path, monkeypatch):
    """Run V13 (HackPark, 2026-10-21): the query was refused and the run left.

    ``/Account/login.aspx?ReturnURL=/admin/`` is what an ASP.NET panel hands the
    model. ``?`` is structural in hydra's single argv token and the login does
    not need the return URL to authenticate, so the handler drops it and sweeps
    the route instead of spending a turn on an error -which is how the run ended
    up hand-rolling hydra through ``nexus.shell.exec``-.
    """
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        result = _run(
            _form_arguments(
                form_url="http://10.0.0.1/login.aspx?ReturnURL=/admin/",
                probe=False,
            )
        )
    spec = sandbox.calls[0][0][-1]
    assert spec.split(":", 1)[0] == "/login.aspx"
    assert "/login.aspx:user=^USER^&pass=^PASS^&submit=Login:" in spec
    assert result.evidence["form_url"] == "/login.aspx"
    # The dropped query is reported, so the run can see which route ran.
    assert result.evidence["form_query_dropped"] == "ReturnURL=/admin/"


def test_a_bare_form_path_with_a_query_is_normalized_too(tmp_path, monkeypatch):
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        result = _run(
            _form_arguments(
                form_url="/Account/login.aspx?ReturnURL=/admin/", probe=False
            )
        )
    assert sandbox.calls[0][0][-1].startswith("/Account/login.aspx:user=")
    assert "?" not in result.evidence["form_url"]


def test_a_missing_pass_placeholder_is_filled_in_the_password_field(
    tmp_path, monkeypatch
):
    """V13, iteration 52: the WebForms fields were right, ``^PASS^`` was missing.

    The handler used to refuse the sweep, so the run improvised with hydra. Hydra
    cannot test a wordlist without ``^PASS^``, so the empty password field is
    filled instead of refused, and the substitution is reported in the evidence.
    """
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    params = (
        "ctl00$MainContent$LoginUser$UserName=^USER^"
        "&ctl00$MainContent$LoginUser$Password="
        "&ctl00$MainContent$LoginUser$LoginButton=Log in"
    )
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        result = _run(
            _form_arguments(
                form_url="/Account/login.aspx",
                form_params=params,
                failure_string="Login failed",
                probe=False,
            )
        )
    spec = sandbox.calls[0][0][-1]
    assert "ctl00$MainContent$LoginUser$Password=^PASS^" in spec
    assert result.evidence["form_params_autofill"] == (
        "ctl00$MainContent$LoginUser$Password=^PASS^"
    )


def test_http_post_form_builds_the_hydra_spec(tmp_path, monkeypatch):
    """Hydra's form module is one argv token: ``path:params:F=failure``."""
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        result = _run(_form_arguments(probe=False))
    argv = sandbox.calls[0][0]
    assert argv[:9] == ["hydra", "-l", "admin", "-P", argv[4], "-s", "80", "-t", "4"]
    assert argv[9:12] == ["-f", "-I", "-o"]
    assert argv[13:] == [
        "10.0.0.1",
        "http-post-form",
        "/admin/index.php:user=^USER^&pass=^PASS^&submit=Login:F=Invalid username or password",
    ]
    # The form modules take a bare host: ``http-post-form://host`` is not hydra.
    assert not argv[13].startswith("http-post-form://")
    assert result.evidence["form_url"] == "/admin/index.php"
    assert result.evidence["service"] == "http-post-form"


def test_https_forms_get_hydras_ssl_switch(tmp_path, monkeypatch):
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        _run(_form_arguments(port=443, service="http-get-form", probe=False))
    argv = sandbox.calls[0][0]
    assert "-S" in argv
    assert argv[-3:] == [
        "10.0.0.1",
        "http-get-form",
        "/admin/index.php:user=^USER^&pass=^PASS^&submit=Login:F=Invalid username or password",
    ]


def test_a_form_spec_cannot_smuggle_a_hydra_condition(tmp_path, monkeypatch):
    """A colon in any part would become ``C=``/``H=``: rejected, not escaped."""
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    for overrides in (
        {"form_url": "/login.php:C=/etc/passwd"},
        {"form_params": "user=^USER^&pass=^PASS^:H=X-Foo: 1"},
        {"failure_string": "Invalid:F=ok"},
    ):
        with pytest.raises(ValueError, match=r":"):
            _run(_form_arguments(**overrides))


def test_aspnet_field_names_are_accepted_verbatim(tmp_path, monkeypatch):
    """Run V11 (HackPark): a real WebForms login posts names hydra can carry.

    ``ctl00$MainContent$LoginUser$UserName`` was rejected with *"form_params
    must not contain ':' or whitespace"* while the run already had the form, the
    user and the wordlist. ``$``, ``_`` and spaces are ordinary body characters:
    hydra only parses ``:`` and ``?``, so the sweep must run.
    """
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    params = (
        "ctl00$MainContent$LoginUser$UserName=^USER^"
        "&ctl00$MainContent$LoginUser$Password=^PASS^"
    )
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        result = _run(
            _form_arguments(
                form_url="/Account/login.aspx",
                form_params=params,
                failure_string="Login failed",
                probe=False,
            )
        )
    spec = sandbox.calls[0][0][-1]
    assert spec == f"/Account/login.aspx:{params}:F=Login failed"
    assert result.evidence["form_url"] == "/Account/login.aspx"


def test_a_form_param_pair_without_a_name_is_rejected(tmp_path, monkeypatch):
    """``&&`` and ``=value`` would post a nameless field: refused, not escaped."""
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    for params in (
        "user=^USER^&&pass=^PASS^",
        "user=^USER^&=^PASS^",
        "user=^USER^&pass=^PASS^&submit",
        "user=^USER^&pass=^PASS^?x=1",
    ):
        with pytest.raises(ValueError, match="form_params"):
            _run(_form_arguments(form_params=params, probe=False))


def test_a_form_spec_requires_the_placeholders(tmp_path, monkeypatch):
    """Without ``^USER^``/``^PASS^`` hydra sends the same request N times."""
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(ValueError, match="placeholders"):
        _run(_form_arguments(form_params="user=admin&pass=fixed"))


def test_form_services_require_the_three_fields_at_the_schema_boundary():
    from nexus_core.kernel.schema_validation import SchemaValidationError, validate

    schema = cred_bruteforce_definition().input_schema
    validate(_form_arguments(), schema)
    for field in ("form_url", "form_params", "failure_string"):
        arguments = _form_arguments()
        arguments.pop(field)
        with pytest.raises(SchemaValidationError) as excinfo:
            validate(arguments, schema)
        assert field in str(excinfo.value)


# -------------------------------------------------------------------- parser
def test_parse_hydra_credentials_extracts_login_and_password():
    text = "[22][ssh] host: 10.0.0.1   login: lin   password: synthetic-password\n"
    found = parse_hydra_credentials(text)
    assert found == [
        {"host": "10.0.0.1", "username": "lin", "password": "synthetic-password"}
    ]


def test_parse_hydra_credentials_tolerates_extra_fields():
    # hydra injects ``misc: (null)`` between host and login on ssh.
    text = "[22][ssh] host: 10.0.0.1   misc: (null)   login: lin   password: synthetic-password\n"
    found = parse_hydra_credentials(text)
    assert found[0]["username"] == "lin"
    assert found[0]["password"] == "synthetic-password"


def test_parse_hydra_credentials_empty_on_no_match():
    assert parse_hydra_credentials("0 valid password found") == []


# ------------------------------------------------------------------- handler
def test_handler_runs_hydra_with_expected_flags(tmp_path, monkeypatch):
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
        _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "lin",
                "password_file": "locks.txt",
            }
        )
    argv = sandbox.calls[0][0]
    assert argv[0] == "hydra"
    assert ["-l", "lin"] == argv[1:3]
    assert "-f" in argv and "-I" in argv
    assert argv[-1] == "ssh://10.0.0.1"
    assert "-s" in argv and "22" in argv


def test_handler_truncates_wordlist_to_max_attempts(tmp_path, monkeypatch):
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "", "")):
        result = _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "lin",
                "password_file": "locks.txt",
                "max_attempts": 2,
            }
        )
    assert result.evidence["attempts"] == 2
    wordlists = list(tmp_path.glob("cred_*/wordlist.txt"))
    assert wordlists and len(wordlists[0].read_text().splitlines()) == 2


def test_a_wordlist_larger_than_the_old_cap_is_still_usable(tmp_path, monkeypatch):
    """Measured: ``rockyou.txt`` (134 MB) was refused, and the branch died.

    The list is streamed and cut at ``max_attempts``, so total size is not work.
    """
    _workspace(tmp_path)
    big = tmp_path / "rockyou.txt"
    line = "x" * 63
    with big.open("w", encoding="utf-8") as handle:
        for _ in range(300_000):  # ~19 MB: over the old 16 MB ceiling
            handle.write(line + "\n")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "", "")):
        result = _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "lin",
                "password_file": "rockyou.txt",
                "max_attempts": 3,
            }
        )
    assert result.evidence["attempts"] == 3


def test_ssh_requires_a_username_at_the_schema_boundary():
    """The catalog is the contract: a missing login is rejected before the turn."""
    from nexus_core.kernel.schema_validation import SchemaValidationError, validate

    schema = cred_bruteforce_definition().input_schema
    validate(
        {"target": "10.0.0.1", "service": "ssh", "username": "lin",
         "password_file": "locks.txt"},
        schema,
    )
    with pytest.raises(SchemaValidationError) as excinfo:
        validate(
            {"target": "10.0.0.1", "service": "ssh", "password_file": "locks.txt"},
            schema,
        )
    assert "username" in str(excinfo.value)
    # ``tcp`` keeps it optional: the script drives whatever prompt the service has.
    validate(
        {"target": "10.0.0.1", "service": "tcp", "port": 9001,
         "password_file": "locks.txt", "success_marker": "OK"},
        schema,
    )


def test_handler_returns_valid_credential_from_output(tmp_path, monkeypatch):
    """A validated credential travels as a handle, never as plaintext (V1-29)."""
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    stdout = "[22][ssh] host: 10.0.0.1   login: lin   password: synthetic-password\n"
    with _fake_sandbox(SandboxResult(0, stdout, "")):
        result = _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "lin",
                "password_file": "locks.txt",
            }
        )
    assert result.verified is True
    assert result.evidence["found_count"] == 1
    credential = result.output["valid_credentials"][0]
    assert "password" not in credential
    assert credential["secret_ref"].startswith("vault:")
    assert credential["username"] == "lin"
    from nexus_core.kernel.secret_store import default_secret_store

    assert default_secret_store().get(credential["secret_ref"]) == b"synthetic-password"


def test_timeout_is_not_verified(tmp_path, monkeypatch):
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "lin",
                "password_file": "locks.txt",
            }
        )
    assert result.verified is False
    assert result.verification_method == "cred_bruteforce_timeout"


def test_unsupported_service_is_rejected(tmp_path, monkeypatch):
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(ValueError):
        _run(
            {
                "target": "10.0.0.1",
                "service": "rdp",
                "username": "lin",
                "password_file": "locks.txt",
            }
        )


def test_password_file_escaping_workspace_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(ValueError):
        _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "lin",
                "password_file": "../../etc/passwd",
            }
        )


def test_wordlist_can_live_in_a_configured_system_root(tmp_path, monkeypatch):
    """``rockyou.txt`` must work without copying it into every workspace.

    Measured in run_1052d63f9bba4838902b3aa21bd27d21 (2026-10-19): the SQLi was
    closed and the only branch left was SSH, but ``/usr/share/wordlists/rockyou.txt``
    was rejected twice as escaping the workspace; the run then exhausted its
    budget without ever testing a credential.
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    roots = tmp_path / "wordlists"
    roots.mkdir()
    (roots / "rockyou.txt").write_text("root\nadmin\n", encoding="utf-8")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("NEXUS_WORDLIST_ROOTS", str(roots))

    for password_file in (str(roots / "rockyou.txt"), "rockyou.txt"):
        with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
            result = _run(
                {
                    "target": "10.0.0.1",
                    "service": "ssh",
                    "username": "root",
                    "password_file": password_file,
                }
            )
        assert result.evidence["attempts"] == 2
        assert sandbox.calls[0][0][-1] == "ssh://10.0.0.1"


def test_omitting_the_wordlist_uses_the_installed_one(tmp_path, monkeypatch):
    """hijack_v7 invented ``path/to/your/wordlist.txt``; no path is now needed."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    roots = tmp_path / "wordlists"
    roots.mkdir()
    (roots / "rockyou.txt").write_text("root\nadmin\n", encoding="utf-8")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("NEXUS_WORDLIST_ROOTS", str(roots))

    with _fake_sandbox(SandboxResult(0, "", "")):
        result = _run(
            {"target": "10.0.0.1", "service": "ssh", "username": "root"}
        )

    assert result.output["attempts"] == 2
    assert result.output["wordlist"] == str(roots / "rockyou.txt")


def test_wordlist_outside_the_allowed_roots_is_still_rejected(tmp_path, monkeypatch):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    roots = tmp_path / "wordlists"
    roots.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("hunter2\n", encoding="utf-8")
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("NEXUS_WORDLIST_ROOTS", str(roots))
    # The message names *why*: the file exists, it is just not ours to read.
    with pytest.raises(ValueError, match="forbidden path"):
        _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "root",
                "password_file": str(outside),
            }
        )


def test_the_handler_slices_by_default_and_publishes_no_ceiling(tmp_path, monkeypatch):
    """The default is a bounded slice; the contract still has no ``maximum``.

    Measured in Brute It v5 (iteration 13): the handler killed hydra at 60.08 s
    and answered ``unavailable``, so the run read a budget cut as a broken tool.
    Measured again in v7 (iteration 16): with no attempt default at all, a
    ``rockyou`` sweep ran 890 s until the loop killed it. The handler now tests
    ``CRED_DEFAULT_MAX_ATTEMPTS`` by default and reports ``next_start_at`` when
    the list has more, while the *ceiling* stays out of the schema: containment
    is the signed scope, the RoE, ``ToolDefinition`` and the run budget.
    """
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "0 valid password found\n", "")) as sandbox:
        result = _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "lin",
                "password_file": "locks.txt",
            }
        )
    _, timeout_seconds = sandbox.calls[0]
    # The contract's 1800 s stays as the ceiling for an explicit request, but the
    # default is the bounded slice: Hijack v3 (run_3a188d2c2bd440f8bca8d88ad922a024)
    # spent 1 785 174 ms on a 5 000-entry ssh slice that decided nothing, because
    # the old default was the ceiling minus the reporting margin.
    assert cred_bruteforce_definition().timeout_seconds == 1800
    assert timeout_seconds == 300
    assert result.evidence["timeout_seconds"] == 300
    # The five-line file fits in the default slice, so this is a completed sweep
    # (``negative``), not a ``partial`` with a next offset.
    assert result.evidence["max_attempts"] == CRED_DEFAULT_MAX_ATTEMPTS
    assert result.evidence["attempts"] == 5
    assert result.evidence["wordlist_completed"] is True
    assert result.outcome == "negative"
    schema = cred_bruteforce_definition().input_schema
    assert "maximum" not in schema["properties"]["max_attempts"]


def test_an_explicit_timeout_and_attempt_cap_are_respected(tmp_path, monkeypatch):
    """When the caller asks for a bound, the handler uses exactly that bound."""
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "0 valid password found\n", "")) as sandbox:
        result = _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "lin",
                "password_file": "locks.txt",
                "max_attempts": 2000,  # over the old 500 attempt ceiling
                "timeout_seconds": 120,
            }
        )
    _, timeout_seconds = sandbox.calls[0]
    assert timeout_seconds == 120
    assert result.evidence["max_attempts"] == 2000
    assert result.evidence["attempts"] == 5
    assert cred_bruteforce_definition().input_schema["properties"]["timeout_seconds"][
        "maximum"
    ] == 1800


def test_a_long_sweep_budget_is_accepted(tmp_path, monkeypatch):
    """V13 asked for 1200 s and the contract refused it: the ceiling is now 1800."""
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(0, "0 valid password found\n", "")) as sandbox:
        result = _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "lin",
                "password_file": "locks.txt",
                "timeout_seconds": 1800,
            }
        )
    _, timeout_seconds = sandbox.calls[0]
    assert timeout_seconds == 1800
    assert result.evidence["timeout_seconds"] == 1800
    # The loop ceiling leaves room for the handler to answer first (V12 test).
    from nexus_core.agent.react_types import ReActConfig

    assert ReActConfig().timeout_per_tool_seconds > 1800


def test_a_sweep_without_a_hit_is_a_negative_that_closes_the_branch(tmp_path, monkeypatch):
    """The instruction: no hit in the cap -> abort, ``barrier``, next branch.

    The barrier is the point: without it the next turn repeated the same sweep
    three times (``/tmp/bruteit-run-v2.ndjson``, iterations 19-21) while the web
    login was the vector.
    """
    from nexus_core.kernel.blackboard import Blackboard
    from nexus_core.kernel.control_store import ControlStore

    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    store = ControlStore(tmp_path / "facts.db")
    store.initialize()

    class _Scope:
        engagement_id = "eng-1"

    context = RunContext(
        "system", Identity("operator-1", "system", roles=("operator",)),
        store=store, scope=_Scope(),
    )
    with _fake_sandbox(SandboxResult(0, "0 valid password found\n", "")):
        result = asyncio.run(
            cred_bruteforce_handler(
                {
                    "target": "10.0.0.1",
                    "service": "ssh",
                    "username": "lin",
                    "password_file": "locks.txt",
                },
                context,
            )
        )
    # A sweep that ran and found nothing is an observation, not a tool defect.
    assert result.verified is False
    assert result.outcome == "negative"
    assert result.completed is True
    assert result.evidence["barrier_recorded"] is True
    barriers = [
        fact for fact in Blackboard(store).list_facts("system", "eng-1")
        if fact.get("fact_type") == "barrier"
    ]
    assert len(barriers) == 1
    assert barriers[0]["key"] == "10.0.0.1:22"
    assert "sin credencial válida" in barriers[0]["value"]["reason"]
    # Unverified and attributed: the operator can tell it from a proof.
    assert barriers[0]["verified"] is False
    assert barriers[0]["source"] == "nexus.cred.bruteforce"


def test_a_sweep_cut_by_the_budget_does_not_close_the_branch(tmp_path, monkeypatch):
    """A timeout is a budget cut, not a verdict: it must not record a barrier.

    The wordlist did not finish, so nothing about the target was disproved; the
    route stays open for a longer sweep, a sliced list or a bigger budget. The
    loop still counts the ``timeout`` and retires the tool after repeats.
    """
    from nexus_core.kernel.blackboard import Blackboard
    from nexus_core.kernel.control_store import ControlStore

    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    store = ControlStore(tmp_path / "facts.db")
    store.initialize()

    class _Scope:
        engagement_id = "eng-1"

    context = RunContext(
        "system", Identity("operator-1", "system", roles=("operator",)),
        store=store, scope=_Scope(),
    )
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = asyncio.run(
            cred_bruteforce_handler(
                {
                    "target": "10.0.0.1",
                    "service": "http-post-form",
                    "username": "admin",
                    "password_file": "locks.txt",
                    "form_url": "/admin/",
                    "form_params": "user=^USER^&pass=^PASS^",
                    "failure_string": "Incorrect",
                },
                context,
            )
        )
    assert result.output["aborted"] == "time_cap"
    assert result.outcome == "timeout" and result.timed_out is True
    assert result.verified is False
    assert result.evidence["wordlist_completed"] is False
    assert "no terminó" in result.output["message"]
    assert [
        fact for fact in Blackboard(store).list_facts("system", "eng-1")
        if fact.get("fact_type") == "barrier"
    ] == []


def test_a_finished_sweep_is_negative_even_when_hydra_exits_non_zero(
    tmp_path, monkeypatch
):
    """hydra closes a fruitless sweep with ``0 valid password found`` and 255.

    The sweep ran to the end, so the verdict is ``negative`` (the credentials
    were disproved), never ``unavailable`` (the tool is broken). Measured in
    Brute It v5, iterations 15 and 20: the model read ``unavailable`` and went
    back to hand-written SQLi.
    """
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(255, "0 valid password found\n", "")):
        result = _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "lin",
                "password_file": "locks.txt",
            }
        )
    assert result.outcome == "negative"
    assert result.completed is True
    assert result.verified is False
    assert result.output["message"] == (
        "Hydra completó el ataque sin encontrar credenciales válidas"
    )
    assert result.output["hydra_verdict"] == "0 valid password found"
    assert result.evidence["wordlist_completed"] is True


def test_a_missing_hydra_binary_is_unavailable(tmp_path, monkeypatch):
    """The only ``unavailable`` case: hydra never started, the target was untouched."""
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _fake_sandbox(SandboxResult(127, "", "sh: 1: hydra: not found\n")):
        result = _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "lin",
                "password_file": "locks.txt",
            }
        )
    assert result.outcome == "unavailable"
    assert result.completed is True
    assert result.verified is False
    assert result.verification_method == "cred_bruteforce_unavailable"
    assert "no está instalado" in result.output["message"]
    assert "barrier_recorded" not in result.evidence


def test_missing_password_file_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(ValueError):
        _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "lin",
                "password_file": "nope.txt",
            }
        )


# ------------------------------------------------- failure_string probe (FIX 1)
class _ProbeSandbox:
    """Answers the probe script and hydra differently, in call order."""

    def __init__(self, probe_stdout: str, sweep: SandboxResult | None = None):
        self.probe_stdout = probe_stdout
        self.sweep = sweep or SandboxResult(0, "0 valid password found\n", "")
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append((list(argv), timeout_seconds))
        if argv and argv[0] == "python3":
            return SandboxResult(0, self.probe_stdout, "")
        return self.sweep


@contextlib.contextmanager
def _probe_sandbox(probe_stdout: str, sweep: SandboxResult | None = None):
    sandbox = _ProbeSandbox(probe_stdout, sweep)
    with mock.patch.object(
        module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _probe_stdout(**overrides) -> str:
    payload = {
        "ok": True, "baseline_status": 200, "failure_status": 200,
        "in_baseline": False, "in_failure": True,
        "baseline_len": 900, "failure_len": 950,
    }
    payload.update(overrides)
    return json.dumps(payload) + "\n"


def test_definition_declares_the_probe_switch():
    properties = cred_bruteforce_definition().input_schema["properties"]
    assert properties["probe"] == {"type": "boolean"}


def test_probe_rejects_a_marker_the_login_page_already_carries(tmp_path, monkeypatch):
    """Brute It v6, iteration 8: ``F=LOGIN`` and the button says ``Login``.

    The marker is in the anonymous page, so it cannot separate a failed login
    from a good one: the sweep would run the whole list and could never report
    the credential it walked past.
    """
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    stdout = _probe_stdout(in_baseline=True, in_failure=True)
    with _probe_sandbox(stdout) as sandbox:
        result = _run(_form_arguments(failure_string="LOGIN"))
    assert result.outcome == "invalid_failure_string"
    assert result.completed is True
    assert result.verified is False
    assert result.output["reason"] == "present_in_baseline"
    assert result.output["sweep_attempted"] is False
    assert result.evidence["attempts"] == 0
    assert result.verification_method == "cred_bruteforce_failure_string_invalid"
    # Two requests, no hydra: the wordlist is never spent on a dead marker.
    assert [call[0][0] for call in sandbox.calls] == ["python3"]
    assert "nexus.web.request" in result.output["message"]


def test_probe_rejects_a_marker_absent_from_the_failure_response(tmp_path, monkeypatch):
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _probe_sandbox(_probe_stdout(in_failure=False)) as sandbox:
        result = _run(_form_arguments())
    assert result.outcome == "invalid_failure_string"
    assert result.output["reason"] == "missing_in_failure_response"
    assert len(sandbox.calls) == 1


def test_a_discriminating_marker_lets_the_sweep_run(tmp_path, monkeypatch):
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _probe_sandbox(_probe_stdout()) as sandbox:
        result = _run(_form_arguments())
    assert len(sandbox.calls) == 2
    assert sandbox.calls[1][0][0] == "hydra"
    assert sandbox.calls[1][0][-1].endswith("F=Invalid username or password")
    assert result.evidence["failure_string_probe"] == "ok"
    assert result.evidence["failure_string_probe_reason"] == "discriminating"


def test_a_probe_that_cannot_run_never_blocks_the_sweep(tmp_path, monkeypatch):
    """Infrastructure is not a verdict: an empty probe answer proceeds."""
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _probe_sandbox("") as sandbox:
        result = _run(_form_arguments())
    assert len(sandbox.calls) == 2
    assert sandbox.calls[1][0][0] == "hydra"
    assert result.evidence["failure_string_probe"] == "skipped"
    assert result.outcome == "negative"


def test_the_probe_switch_can_be_turned_off(tmp_path, monkeypatch):
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with _probe_sandbox(_probe_stdout(in_baseline=True)) as sandbox:
        result = _run(_form_arguments(probe=False))
    assert [call[0][0] for call in sandbox.calls] == ["hydra"]
    assert result.evidence["failure_string_probe"] == "disabled"


class _LoginFormHandler(http.server.BaseHTTPRequestHandler):
    """A panel that says ``Login`` in the button and fails in a div."""

    def do_GET(self):  # noqa: N802 - stdlib naming
        self._send(b"<form><input type='submit' name='submit' value='Login'></form>")

    def do_POST(self):  # noqa: N802 - stdlib naming
        self._send(
            b"<form><input type='submit' name='submit' value='Login'></form>"
            b"<div>Invalid credentials</div>"
        )

    def _send(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # noqa: ARG002 - silence the server
        return


def _run_probe_script(url: str, *, needle: str) -> dict:
    """Execute the *shipped* probe exactly like the handler does, no mocks."""
    body = "user=admin&pass=invalid_probe_12345&submit=Login"
    argv = [
        sys.executable, "-c", module.CRED_PROBE_SCRIPT,
        url, "POST", url, body, needle, "10",
    ]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    payloads = [line for line in proc.stdout.splitlines() if line.startswith("{")]
    assert payloads, proc.stdout + proc.stderr
    return json.loads(payloads[-1])


def test_the_probe_finds_the_failure_string_of_a_live_form():
    """The user's case: ``Login`` in the button, ``Invalid credentials`` in a div.

    The button's own label is in the anonymous page, so it is not a marker; the
    div only appears after a bad credential, so it is the one hydra needs.
    """
    server = http.server.HTTPServer(("127.0.0.1", 0), _LoginFormHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/admin/"
        wrong = _run_probe_script(url, needle="Login")
        right = _run_probe_script(url, needle="Invalid credentials")
    finally:
        server.shutdown()
        server.server_close()
    assert wrong["ok"] is True
    # ``Login`` is rendered before any credential is sent: it cannot discriminate.
    assert wrong["in_baseline"] is True
    assert module._probe_verdict(wrong).status == "invalid"
    # ``Invalid credentials`` is only in the response to the wrong password.
    assert right["in_failure"] is True and right["in_baseline"] is False
    assert module._probe_verdict(right).status == "ok"


# ------------------------------------------------ wordlist resolution (FIX 2)
def test_a_symlink_inside_a_system_root_is_accepted(tmp_path, monkeypatch):
    """Kali ships ``fasttrack.txt`` as a symlink pointing outside the root.

    Measured in Brute It v6, iteration 11: the path *is* inside
    ``/usr/share/wordlists``, but ``realpath`` was applied before the containment
    check, so the handler refused it as path traversal.
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    roots = tmp_path / "wordlists"
    roots.mkdir()
    target = tmp_path / "set" / "wordlist.txt"
    target.parent.mkdir()
    target.write_text("alpha\nbeta\n", encoding="utf-8")
    (roots / "fasttrack.txt").symlink_to(target)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("NEXUS_WORDLIST_ROOTS", str(roots))

    for password_file in (str(roots / "fasttrack.txt"), "fasttrack.txt"):
        with _fake_sandbox(SandboxResult(0, "", "")) as sandbox:
            result = _run(
                {
                    "target": "10.0.0.1",
                    "service": "ssh",
                    "username": "root",
                    "password_file": password_file,
                }
            )
        assert result.evidence["attempts"] == 2
        assert sandbox.calls[0][0][0] == "hydra"


def test_a_workspace_symlink_that_escapes_is_forbidden(tmp_path, monkeypatch):
    """The model can create symlinks with ``nexus.shell.exec``: no free reads."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("hunter2\n", encoding="utf-8")
    (workspace / "words.txt").symlink_to(secret)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("NEXUS_WORDLIST_ROOTS", str(tmp_path / "none"))

    with pytest.raises(ValueError, match="forbidden path"):
        _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "root",
                "password_file": "words.txt",
            }
        )


def test_a_wordlist_that_is_not_installed_says_so(tmp_path, monkeypatch):
    """Brute It v6, iteration 12: ``/usr/share/seclists`` does not exist there.

    The answer must be "does not exist", not "forbidden": one reaction is to pick
    another list, the other is to stop trying. The generic message made the model
    retry the same path in iteration 17.
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("NEXUS_WORDLIST_ROOTS", raising=False)

    with pytest.raises(ValueError, match="file does not exist"):
        _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "root",
                "password_file": "/usr/share/seclists/Passwords/Common-Credentials/absent.txt",
            }
        )


# ---------------------------------------------------------- csrf form sweep
def test_definition_exposes_csrf_mode_for_forms():
    properties = cred_bruteforce_definition().input_schema["properties"]
    assert properties["csrf_mode"]["type"] == "boolean"
    assert properties["csrf_form_url"]["type"] == "string"


def test_csrf_mode_requires_a_form_service(tmp_path, monkeypatch):
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(ValueError):
        _run(
            {
                "target": "10.0.0.1",
                "service": "ssh",
                "username": "lin",
                "password_file": "locks.txt",
                "csrf_mode": True,
            }
        )


def test_csrf_form_url_requires_csrf_mode(tmp_path, monkeypatch):
    _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(ValueError):
        _run(_form_arguments(csrf_form_url="/Account/login.aspx"))


def test_csrf_mode_sweeps_a_real_aspnet_form(tmp_path, monkeypatch):
    """The wall of run_93546320…: a login that rejects every POST without tokens.

    Hydra cannot fetch the page again per attempt, so before this mode the whole
    branch was unreachable: the engine had the username, the wordlist and the
    URL, and every single attempt was answered "invalid token" instead of
    "invalid password".
    """
    server = http.server.HTTPServer(("127.0.0.1", 0), _CsrfLoginHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        (tmp_path / "passwords.txt").write_text("wrong\nhackpark\n", encoding="utf-8")
        monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
        monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
        result = _run(
            {
                "target": "127.0.0.1",
                "port": server.server_address[1],
                "service": "http-post-form",
                "username": "admin",
                "password_file": "passwords.txt",
                "form_url": "/Account/login.aspx",
                "form_params": (
                    "ctl00$MainContent$LoginUser$UserName=^USER^"
                    "&ctl00$MainContent$LoginUser$Password=^PASS^"
                ),
                "failure_string": "Login failed",
                "csrf_mode": True,
            }
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.verified is True
    assert result.verification_method == "cred_bruteforce_csrf_completed"
    assert result.output["engine"] == "csrf-form-sweep"
    assert result.evidence["csrf_mode"] is True
    assert "__VIEWSTATE" in result.evidence["csrf_fields"]
    credential = result.output["valid_credentials"][0]
    assert credential["username"] == "admin"
    assert credential["secret_ref"].startswith("vault:")
    assert result.output["session"]["session_ref"].startswith("vault:")
    from nexus_core.kernel.secret_store import default_secret_store

    assert default_secret_store().get(credential["secret_ref"]) == b"hackpark"
    assert "ASP.NET_SessionId" in default_secret_store().get(
        result.output["session"]["session_ref"]
    ).decode()


def test_csrf_mode_rejects_a_failure_marker_that_the_form_already_shows(tmp_path, monkeypatch):
    server = http.server.HTTPServer(("127.0.0.1", 0), _CsrfLoginHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        (tmp_path / "passwords.txt").write_text("wrong\n", encoding="utf-8")
        monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
        result = _run(
            {
                "target": "127.0.0.1",
                "port": server.server_address[1],
                "service": "http-post-form",
                "username": "admin",
                "password_file": "passwords.txt",
                "form_url": "/Account/login.aspx",
                "form_params": (
                    "ctl00$MainContent$LoginUser$UserName=^USER^"
                    "&ctl00$MainContent$LoginUser$Password=^PASS^"
                ),
                "failure_string": "Password",
                "csrf_mode": True,
            }
        )
    finally:
        server.shutdown()
        server.server_close()
    assert result.success is False
    assert result.outcome == "invalid_failure_string"
    assert result.output["sweep_attempted"] is False


class _CsrfLoginHandler(http.server.BaseHTTPRequestHandler):
    """Minimal ASP.NET-shaped login: hidden tokens + session cookie required."""

    viewstate = "VS-csrf/123=="
    eventvalidation = "EV-csrf/456=="

    def _send(self, status: int, body: str, *, cookie: str | None = None) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):  # noqa: N802 - stdlib naming
        if not self.path.startswith("/Account/login.aspx"):
            self._send(404, "not found")
            return
        self._send(
            200,
            (
                '<form method="post" action="/Account/login.aspx">'
                f'<input type="hidden" name="__VIEWSTATE" value="{self.viewstate}">'
                f'<input type="hidden" name="__EVENTVALIDATION" value="{self.eventvalidation}">'
                "</form>"
            ),
            cookie="ASP.NET_SessionId=csrf-session; path=/; HttpOnly",
        )

    def do_POST(self):  # noqa: N802 - stdlib naming
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        from urllib.parse import parse_qs

        fields = parse_qs(body)
        cookie = self.headers.get("Cookie") or ""
        tokens_ok = (
            fields.get("__VIEWSTATE") == [self.viewstate]
            and fields.get("__EVENTVALIDATION") == [self.eventvalidation]
        )
        password = (fields.get("ctl00$MainContent$LoginUser$Password") or [""])[0]
        if tokens_ok and "ASP.NET_SessionId=csrf-session" in cookie and password == "hackpark":
            self._send(200, "Welcome admin")
        else:
            self._send(200, "Login failed")

    def log_message(self, *args):  # noqa: ARG002 - silence the server
        return


def test_a_token_protected_form_switches_to_the_csrf_sweep_by_itself(tmp_path, monkeypatch):
    """The model does not have to know: the page's hidden inputs are the signal.

    V10 asked for the credential and never got it because every POST was answered
    "invalid token". A probe that sees __VIEWSTATE in the form must not hand the
    wordlist to Hydra: it switches engine and says so in the evidence.
    """
    server = http.server.HTTPServer(("127.0.0.1", 0), _CsrfLoginHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        (tmp_path / "passwords.txt").write_text("wrong\nhackpark\n", encoding="utf-8")
        monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
        monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
        result = _run(
            {
                "target": "127.0.0.1",
                "port": server.server_address[1],
                "service": "http-post-form",
                "username": "admin",
                "password_file": "passwords.txt",
                "form_url": "/Account/login.aspx",
                "form_params": (
                    "ctl00$MainContent$LoginUser$UserName=^USER^"
                    "&ctl00$MainContent$LoginUser$Password=^PASS^"
                ),
                "failure_string": "Login failed",
            }
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.verified is True
    assert result.output["engine"] == "csrf-form-sweep"
    assert result.evidence["csrf_auto"] is True
