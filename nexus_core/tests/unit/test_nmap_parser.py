"""Unit tests for nexus_core.tools.parsers.nmap (no network, no nmap)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from nexus_core.tools.parsers.nmap import parse_nmap_xml

FIXTURES = Path(__file__).parents[1] / "fixtures" / "nmap"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_parse_single_host_returns_one_host():
    scan = parse_nmap_xml(_read("scan_single_host.xml"))
    assert len(scan.hosts) == 1
    assert scan.hosts_up == 1
    host = scan.hosts[0]
    assert host.ip == "203.0.113.10"
    assert host.hostname == "scanme.example"
    assert host.state == "up"


def test_parse_multi_host_returns_two_hosts():
    scan = parse_nmap_xml(_read("scan_multi_host.xml"))
    assert len(scan.hosts) == 2
    assert scan.hosts_up == 1
    assert scan.hosts_down == 1
    assert scan.hosts[1].state == "down"


def test_parse_no_hosts_returns_zero():
    scan = parse_nmap_xml(_read("scan_no_hosts.xml"))
    assert scan.hosts == ()
    assert scan.hosts_up == 0
    assert scan.hosts_down == 0


def test_parse_with_os_extracts_osmatch():
    scan = parse_nmap_xml(_read("scan_with_os.xml"))
    matches = scan.hosts[0].os_matches
    assert len(matches) == 2
    assert matches[0]["name"] == "Linux 5.4 - 5.15"
    assert matches[0]["accuracy"] == "98"


def test_parse_malformed_xml_raises_value_error():
    with pytest.raises(ValueError):
        parse_nmap_xml(_read("scan_malformed.xml"))


def test_parse_wrong_root_raises_value_error():
    with pytest.raises(ValueError):
        parse_nmap_xml("<notnmap><host/></notnmap>")


def test_parse_extracts_open_ports_correctly():
    scan = parse_nmap_xml(_read("scan_single_host.xml"))
    ports = {port["port"]: port for port in scan.hosts[0].ports}
    assert set(ports) == {"22", "80"}
    assert ports["22"]["state"] == "open"
    assert ports["22"]["service"] == "ssh"
    assert ports["22"]["version"] == "8.2p1"
    assert ports["80"]["service"] == "http"


def test_parse_calculates_sha256_of_raw_xml():
    xml_text = _read("scan_single_host.xml")
    scan = parse_nmap_xml(xml_text)
    assert scan.raw_xml_sha256 == hashlib.sha256(xml_text.encode("utf-8")).hexdigest()


def test_parse_handles_namespaced_xml():
    scan = parse_nmap_xml(_read("scan_namespaced.xml"))
    assert len(scan.hosts) == 1
    host = scan.hosts[0]
    assert host.ip == "203.0.113.10"
    assert host.hostname == "secure.example"
    assert host.ports[0]["port"] == "443"
    assert host.ports[0]["state"] == "open"


def test_parse_extraports_are_captured():
    scan = parse_nmap_xml(_read("scan_single_host.xml"))
    assert scan.hosts[0].extraports == {"closed": 998}
