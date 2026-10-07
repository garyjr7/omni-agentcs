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
)
from nexus_core.provisioner.binaries import (
    BINARY_IDENTITIES_BY_NAME,
    check_binary_identities,
    check_binary_identity,
    classify_identity,
    identity_problems,
)
from nexus_core.provisioner.readiness import assess_environment

PYTHON_HTTPX = "Usage: httpx [OPTIONS] URL\n\nError: No such option: -e\n"
PD_HTTPX = "ProjectDiscovery's HTTP toolkit\nCurrent Version: v1.7.0\n"
WHATWEB = "WhatWeb version 0.6.4 ( https://morningstarsecurity.com/research/whatweb/ )\n"
NMAP = "Nmap version 7.99 ( https://nmap.org )\n"


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
    run = _runner({"httpx": (2, PYTHON_HTTPX), "whatweb": (0, WHATWEB), "nmap": (0, NMAP)})
    verdict = preflight_binaries(which=which, run=run, env={})
    assert verdict.ok is False
    assert [p.name for p in verdict.problems] == ["httpx"]
    assert DEGRADED_TOOLS_ENV in verdict.message()


def test_preflight_allows_degraded_mode_with_the_operator_flag():
    which = lambda name: f"/usr/bin/{name}"  # noqa: E731
    run = _runner({"httpx": (2, PYTHON_HTTPX), "whatweb": (0, WHATWEB), "nmap": (0, NMAP)})
    verdict = preflight_binaries(which=which, run=run, env={DEGRADED_TOOLS_ENV: "1"})
    assert verdict.degraded is True
    assert verdict.ok is True


def test_preflight_passes_when_all_binaries_are_correct():
    which = lambda name: f"/usr/bin/{name}"  # noqa: E731
    run = _runner({"httpx": (0, PD_HTTPX), "whatweb": (0, WHATWEB), "nmap": (0, NMAP)})
    verdict = preflight_binaries(which=which, run=run, env={})
    assert verdict.ok is True
    assert verdict.problems == ()
