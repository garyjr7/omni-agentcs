"""``nexus_core.report.severity``: the deterministic severity heuristic."""

from __future__ import annotations

import pytest

from nexus_core.report.severity import (
    highest_severity,
    infer_severity,
    normalize_severity,
    severity_for_command,
    severity_for_ffuf,
    severity_for_port,
    severity_from_nuclei,
)

ALL_LEVELS = ("critical", "high", "medium", "low", "info")


def test_severity_critical_for_session_opened():
    assert infer_severity({"kind": "session_opened"}) == "critical"


def test_severity_from_nuclei_template():
    assert infer_severity({"kind": "nuclei", "template_severity": "critical"}) == "critical"
    assert infer_severity({"kind": "nuclei", "template_severity": "HIGH"}) == "high"
    assert infer_severity({"kind": "nuclei", "template_severity": "medium"}) == "medium"
    # An unknown template severity degrades to informational, never to a guess.
    assert infer_severity({"kind": "nuclei", "template_severity": "unknown"}) == "info"
    assert severity_from_nuclei(None) == "info"


def test_severity_low_for_401_endpoint():
    assert infer_severity({"kind": "endpoint_protected"}) == "low"
    assert severity_for_ffuf(401) == "low"
    assert severity_for_ffuf(403) == "low"
    assert severity_for_ffuf(200) == "info"
    assert severity_for_ffuf(302) == "info"


def test_severity_medium_for_legacy_service():
    assert severity_for_port({"port": "23", "service": "telnet"}) == "medium"
    assert severity_for_port({"port": "21", "service": "ftp"}) == "medium"
    assert severity_for_port({"port": "445", "service": "microsoft-ds"}) == "medium"
    # A bare legacy port number is enough, even without a service banner.
    assert infer_severity({"kind": "open_ports", "port": {"port": 5900}}) == "medium"


def test_severity_info_for_normal_port():
    assert severity_for_port({"port": "22", "service": "ssh"}) == "info"
    assert severity_for_port({"port": "443", "service": "https"}) == "info"
    assert infer_severity({"kind": "open_ports", "port": {"port": 8080}}) == "info"
    assert infer_severity({"kind": "subdomains"}) == "info"
    assert infer_severity({"kind": "http_surface"}) == "info"
    assert infer_severity({}) == "info"


def test_severity_deterministic_no_llm():
    """The heuristic is a pure function: same input, same output, no model."""
    context = {"kind": "session_command", "command": "hashdump", "status": "ok"}
    results = {infer_severity(context) for _ in range(20)}
    assert results == {"critical"}
    assert severity_for_command("hashdump") == "critical"
    assert severity_for_command("getsystem") == "critical"
    assert severity_for_command("migrate") == "high"
    assert severity_for_command("id") == "info"
    assert severity_for_command("ls -la /etc") == "info"
    assert severity_for_command("some-unknown-tool") == "low"
    # A command that never ran is context, not compromise.
    assert severity_for_command("hashdump", "session_dead") == "info"


def test_severity_helpers_are_total():
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("bogus") == "info"
    assert normalize_severity(None) == "info"
    assert highest_severity([]) == "info"
    assert highest_severity(["low", "medium", "info"]) == "medium"
    assert highest_severity(["info", "critical"]) == "critical"
    for level in ALL_LEVELS:
        assert infer_severity({"kind": "nuclei", "template_severity": level}) == level


@pytest.mark.parametrize("port", [{"port": "not-a-port"}, {"port": None}, {}])
def test_severity_tolerates_malformed_ports(port):
    assert severity_for_port(port) == "info"
