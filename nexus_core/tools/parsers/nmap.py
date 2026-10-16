"""Parser de nmap XML → JSON estructurado.

nmap emite XML con el flag `-oX -`. Este parser transforma ese XML en un
dict serializable y estable, sin regex sobre stdout.
"""

from __future__ import annotations

import hashlib
import math
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any


def _local_name(tag: str) -> str:
    """Return the tag without an optional ``{namespace}`` prefix."""
    return tag.rsplit("}", 1)[-1]


def _children(element: ET.Element | None, name: str) -> list[ET.Element]:
    if element is None:
        return []
    return [child for child in element if _local_name(child.tag) == name]


def _child(element: ET.Element | None, name: str) -> ET.Element | None:
    matches = _children(element, name)
    return matches[0] if matches else None


@dataclass(frozen=True)
class NmapHost:
    """A single scanned host with its ports and OS guesses."""

    ip: str
    hostname: str
    state: str
    ports: tuple[dict[str, Any], ...]
    os_matches: tuple[dict[str, Any], ...]
    extraports: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the host."""
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state,
            "ports": [dict(port) for port in self.ports],
            "os_matches": [dict(match) for match in self.os_matches],
            "extraports": dict(self.extraports),
        }


@dataclass(frozen=True)
class NmapScan:
    """A full nmap run normalized into stable structured data."""

    scanner: str
    args: str
    started_at: str
    ended_at: str
    elapsed_seconds: float
    hosts_up: int
    hosts_down: int
    hosts: tuple[NmapHost, ...]
    warnings: tuple[str, ...]
    raw_xml_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the scan."""
        return {
            "scanner": self.scanner,
            "args": self.args,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "elapsed_seconds": self.elapsed_seconds,
            "hosts_up": self.hosts_up,
            "hosts_down": self.hosts_down,
            "hosts": [host.to_dict() for host in self.hosts],
            "warnings": list(self.warnings),
            "raw_xml_sha256": self.raw_xml_sha256,
        }


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
        return number if math.isfinite(number) else default
    except (TypeError, ValueError, OverflowError):
        return default


def _parse_host(host_element: ET.Element) -> NmapHost:
    status = _child(host_element, "status")
    state = (status.get("state", "") if status is not None else "")

    address = ""
    for address_element in _children(host_element, "address"):
        candidate = address_element.get("addr", "")
        if address_element.get("addrtype") in {"ipv4", "ip"}:
            address = candidate
            break
        if not address:
            address = candidate

    hostname = ""
    for hostname_element in _children(_child(host_element, "hostnames"), "hostname"):
        if hostname_element.get("name"):
            hostname = hostname_element.get("name", "")
            break

    ports: list[dict[str, Any]] = []
    extraports: dict[str, int] = {}
    ports_element = _child(host_element, "ports")
    for port_element in _children(ports_element, "port"):
        state_element = _child(port_element, "state")
        service_element = _child(port_element, "service")
        ports.append({
            "port": port_element.get("portid", ""),
            "protocol": port_element.get("protocol", ""),
            "state": state_element.get("state", "") if state_element is not None else "",
            "service": service_element.get("name", "") if service_element is not None else "",
            "product": service_element.get("product", "") if service_element is not None else "",
            "version": service_element.get("version", "") if service_element is not None else "",
            "extra_info": service_element.get("extrainfo", "") if service_element is not None else "",
        })
    for extra_element in _children(ports_element, "extraports"):
        extra_state = extra_element.get("state", "")
        extraports[extra_state] = extraports.get(extra_state, 0) + _to_int(
            extra_element.get("count")
        )

    os_matches: list[dict[str, Any]] = []
    for osmatch_element in _children(_child(host_element, "os"), "osmatch"):
        os_matches.append({
            "name": osmatch_element.get("name", ""),
            "accuracy": osmatch_element.get("accuracy", ""),
        })

    return NmapHost(
        ip=address,
        hostname=hostname,
        state=state,
        ports=tuple(ports),
        os_matches=tuple(os_matches),
        extraports=extraports,
    )


def parse_nmap_xml(xml_text: str) -> NmapScan:
    """Parse the XML emitted by nmap into an :class:`NmapScan`.

    Raises ``ValueError`` when the XML is invalid or the root is not
    ``<nmaprun>``. Namespaces added by some nmap builds are tolerated.
    """
    if not isinstance(xml_text, str) or not xml_text.strip():
        raise ValueError("nmap xml is empty")
    if "<!ENTITY" in xml_text.upper():
        raise ValueError("XML entity declarations are not supported")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid nmap xml: {exc}") from exc
    if _local_name(root.tag) != "nmaprun":
        raise ValueError("nmap xml root must be <nmaprun>")

    hosts = tuple(_parse_host(host_element) for host_element in _children(root, "host"))

    runstats = _child(root, "runstats")
    finished = _child(runstats, "finished")
    hosts_stats = _child(runstats, "hosts")
    if hosts_stats is not None:
        hosts_up = _to_int(hosts_stats.get("up"))
        hosts_down = _to_int(hosts_stats.get("down"))
    else:
        hosts_up = sum(1 for host in hosts if host.state == "up")
        hosts_down = sum(1 for host in hosts if host.state == "down")

    warnings = tuple(
        (warning.text or "").strip()
        for warning in _children(root, "warning")
        if (warning.text or "").strip()
    )

    return NmapScan(
        scanner=root.get("scanner", "nmap"),
        args=root.get("args", ""),
        started_at=root.get("startstr", "") or root.get("start", ""),
        ended_at=(finished.get("timestr", "") if finished is not None else "")
        or (finished.get("time", "") if finished is not None else ""),
        elapsed_seconds=_to_float(finished.get("elapsed") if finished is not None else None),
        hosts_up=hosts_up,
        hosts_down=hosts_down,
        hosts=hosts,
        warnings=warnings,
        raw_xml_sha256=hashlib.sha256(xml_text.encode("utf-8")).hexdigest(),
    )


def empty_scan(reason: str) -> NmapScan:
    """Devuelve un NmapScan vacío con warning. Útil si nmap falló."""
    return NmapScan(
        scanner="nmap",
        args="",
        started_at="",
        ended_at="",
        elapsed_seconds=0.0,
        hosts_up=0,
        hosts_down=0,
        hosts=(),
        warnings=(str(reason),),
        raw_xml_sha256=hashlib.sha256(b"").hexdigest(),
    )
