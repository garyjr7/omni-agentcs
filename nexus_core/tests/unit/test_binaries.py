"""Regression tests for the binary-identity preflight (B1 of the E2E report).

The original failure: `/usr/bin/httpx` is the Python HTTP client, not
ProjectDiscovery's scanner. Presence alone (`shutil.which`) cannot tell them
apart, so the run started, burned tokens and died with an opaque
post-condition error.
"""

from __future__ import annotations

from nexus_core.agent.preflight import (
    DEGRADED_TOOLS_ENV,
    preflight_binaries,
    unavailable_tools_from_env,
)
from nexus_core.provisioner.binaries import (
    BINARY_IDENTITIES_BY_NAME,
    check_binary_identities,
    check_binary_identity,
    classify_identity,
    identity_problems,
)
from nexus_core.provisioner.runtime_deps import missing_python_modules
from nexus_core.provisioner.readiness import assess_environment

PYTHON_HTTPX = "Usage: httpx [OPTIONS] URL\n\nError: No such option: -e\n"
PD_HTTPX = "ProjectDiscovery's HTTP toolkit\nCurrent Version: v1.7.0\n"
WHATWEB = "WhatWeb version 0.6.4 ( https://morningstarsecurity.com/research/whatweb/ )\n"
NMAP = "Nmap version 7.99 ( https://nmap.org )\n"
RIPGREP = "ripgrep 14.1.0 (rev e50df40a19)\n"


def _runner(outputs):
    def run(argv):
        return outputs.get(argv[0].rsplit("/", 1)[-1], (127, ""))

    return run


def test_classify_identity_detects_the_python_httpx():
    identity = BINARY_IDENTITIES_BY_NAME["httpx"]
    check = classify_identity(identity, path="/usr/bin/httpx", present=True, output=PYTHON_HTTPX)
    assert check.ok is False
    assert "equivocado" in check.detail
    assert check.install.startswith("go install")


def test_classify_identity_accepts_projectdiscovery():
    identity = BINARY_IDENTITIES_BY_NAME["httpx"]
    check = classify_identity(identity, path="/usr/local/bin/httpx", present=True, output=PD_HTTPX)
    assert check.ok is True
    assert check.install == ""


def test_classify_identity_missing_binary():
    identity = BINARY_IDENTITIES_BY_NAME["nmap"]
    check = classify_identity(identity, path="", present=False, output="")
    assert check.present is False and check.ok is False


def test_check_binary_identities_reports_only_wrong_present_binaries():
    which = lambda name: f"/usr/bin/{name}"  # noqa: E731
    run = _runner(
        {
            "httpx": (2, PYTHON_HTTPX),
            "whatweb": (0, WHATWEB),
            "nmap": (0, NMAP),
            "rg": (0, RIPGREP),
        }
    )
    checks = check_binary_identities(which=which, run=run)
    problems = identity_problems(checks)
    assert [item.name for item in problems] == ["httpx"]
    assert all(item.ok for item in checks if item.name != "httpx")


def test_check_binary_identity_is_fail_closed_on_unknown_output():
    identity = BINARY_IDENTITIES_BY_NAME["whatweb"]
    check = check_binary_identity(
        identity, which=lambda name: "/usr/bin/whatweb", run=lambda argv: (0, "something else")
    )
    assert check.ok is False
    assert "identidad" in check.detail


def test_assess_environment_flags_a_wrong_binary_as_not_ready():
    def which(name):
        return f"/usr/bin/{name}"

    probe = lambda identity: classify_identity(  # noqa: E731
        identity,
        path=f"/usr/bin/{identity.name}",
        present=True,
        output=PYTHON_HTTPX if identity.name == "httpx" else WHATWEB,
    )
    report = assess_environment(probe_binary=probe, which=which, port_open=lambda *a: False)
    httpx = next(c for c in report.components if c.component_id == "httpx")
    assert httpx.ready is False
    assert httpx.identity_ok is False
    assert "go install" in httpx.setup
    assert "binario equivocado" in httpx.detail


def test_assess_environment_without_probe_keeps_presence_semantics():
    report = assess_environment(
        which=lambda name: f"/usr/bin/{name}", port_open=lambda *a: False
    )
    httpx = next(c for c in report.components if c.component_id == "httpx")
    assert httpx.ready is True
    assert httpx.identity_ok is None


def test_preflight_aborts_on_a_wrong_binary_by_default():
    which = lambda name: f"/usr/bin/{name}"  # noqa: E731
    run = _runner(
        {
            "httpx": (2, PYTHON_HTTPX),
            "whatweb": (0, WHATWEB),
            "nmap": (0, NMAP),
            "rg": (0, RIPGREP),
        }
    )
    verdict = preflight_binaries(which=which, run=run, env={})
    assert verdict.ok is False
    assert [p.name for p in verdict.problems] == ["httpx"]
    assert DEGRADED_TOOLS_ENV in verdict.message()


def test_preflight_allows_degraded_mode_with_the_operator_flag():
    which = lambda name: f"/usr/bin/{name}"  # noqa: E731
    run = _runner(
        {
            "httpx": (2, PYTHON_HTTPX),
            "whatweb": (0, WHATWEB),
            "nmap": (0, NMAP),
            "rg": (0, RIPGREP),
        }
    )
    verdict = preflight_binaries(which=which, run=run, env={DEGRADED_TOOLS_ENV: "1"})
    assert verdict.degraded is True
    assert verdict.ok is True


def test_preflight_passes_when_all_binaries_are_correct():
    which = lambda name: f"/usr/bin/{name}"  # noqa: E731
    run = _runner(
        {
            "httpx": (0, PD_HTTPX),
            "whatweb": (0, WHATWEB),
            "nmap": (0, NMAP),
            "rg": (0, RIPGREP),
        }
    )
    # Pin the module probe so this stays a binary-only assertion (H5 adds a
    # runtime-module check that would otherwise depend on the test venv).
    verdict = preflight_binaries(which=which, run=run, env={}, module_finder=lambda name: object())
    assert verdict.ok is True
    assert verdict.problems == ()
    assert verdict.unavailable_tools == ()


def test_missing_binary_retires_its_tool_without_blocking_the_run():
    """B6: a missing ``rg`` must not fail the preflight, just retire the tool."""
    which = lambda name: None if name == "rg" else f"/usr/bin/{name}"  # noqa: E731
    run = _runner({"httpx": (0, PD_HTTPX), "whatweb": (0, WHATWEB), "nmap": (0, NMAP)})
    verdict = preflight_binaries(which=which, run=run, env={}, module_finder=lambda name: object())
    assert verdict.ok is True
    assert verdict.unavailable_tools == ("nexus.workspace.search",)


# ------------------------------------------------- H5 runtime Python modules
def test_missing_python_module_retires_its_tools():
    """Without paramiko, the SSH post-exploitation tools are retired (H5)."""
    assert missing_python_modules(find_spec=lambda name: None) == (
        "nexus.post.enum_system",
        "nexus.post.ssh_exec",
    )
    present = missing_python_modules(find_spec=lambda name: object())
    assert present == ()


def test_preflight_retires_ssh_tools_without_paramiko():
    which = lambda name: f"/usr/bin/{name}"  # noqa: E731
    run = _runner(
        {"httpx": (0, PD_HTTPX), "whatweb": (0, WHATWEB), "nmap": (0, NMAP), "rg": (0, RIPGREP)}
    )
    verdict = preflight_binaries(which=which, run=run, env={}, module_finder=lambda name: None)
    # A missing runtime module never blocks the run; it only retires tools.
    assert verdict.ok is True
    assert "nexus.post.ssh_exec" in verdict.unavailable_tools
    assert "nexus.post.enum_system" in verdict.unavailable_tools


def test_unavailable_tools_from_env_includes_missing_modules():
    retired = unavailable_tools_from_env(
        which=lambda name: f"/usr/bin/{name}", env={}, module_finder=lambda name: None
    )
    assert {"nexus.post.ssh_exec", "nexus.post.enum_system"} <= retired
    # Missing binaries and missing modules compose.
    composed = unavailable_tools_from_env(
        which=lambda name: None if name == "rg" else f"/usr/bin/{name}",
        env={},
        module_finder=lambda name: None,
    )
    assert {"nexus.workspace.search", "nexus.post.ssh_exec"} <= composed


def test_helper_retires_a_tool_whose_binary_is_absent():
    from nexus_core.provisioner.binaries import missing_tool_binaries

    missing = missing_tool_binaries(
        which=lambda name: None if name in {"rg", "httpx"} else f"/usr/bin/{name}"
    )
    assert missing == ("nexus.recon.httpx", "nexus.workspace.search")
