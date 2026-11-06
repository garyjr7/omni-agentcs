"""Parser ``nmap`` de ``nexus.system.execute_and_parse``.

Reutiliza el parser XML que ya usa ``nexus.recon.nmap`` (``-oX -``), de modo que
un nmap lanzado por el shell universal produce exactamente el mismo dato
estructurado que la tool dedicada. La única diferencia es la entrada: aquí el
XML llega del stdout capturado, no de un fichero de salida.
"""

from __future__ import annotations

from typing import Any

from nexus_core.tools.parsers.nmap import parse_nmap_xml

PARSER_NAME = "nmap"


def open_ports(scan: dict[str, Any]) -> list[str]:
    """Puertos abiertos del scan como ``["21", "22", "80/tcp"]``.

    Se conservan el orden y el protocolo: un ``udp`` abierto no es lo mismo que
    un ``tcp`` y la línea del TUI no debe insinuarlo.
    """
    ports: list[str] = []
    for host in scan.get("hosts") or []:
        if not isinstance(host, dict):
            continue
        for port in host.get("ports") or []:
            if not isinstance(port, dict):
                continue
            if str(port.get("state") or "open").lower() != "open":
                continue
            number = port.get("port", port.get("portid"))
            if number in (None, ""):
                continue
            protocol = str(port.get("protocol") or "tcp").lower()
            label = str(number) if protocol == "tcp" else f"{number}/{protocol}"
            if label not in ports:
                ports.append(label)
    return ports


def parse(raw: str) -> dict[str, Any]:
    """Parse the nmap XML in *raw*; raises ``ValueError`` when it is not XML."""
    scan = parse_nmap_xml(raw)
    payload = scan.to_dict()
    ports = open_ports(payload)
    return {
        "parser": PARSER_NAME,
        "scan": payload,
        "hosts_up": scan.hosts_up,
        "hosts_down": scan.hosts_down,
        "ports_open_total": len(ports),
        "open_ports": ports,
    }


def summary(parsed: dict[str, Any]) -> str:
    """``3 puertos abiertos (21, 22, 80)`` — the one line the operator reads."""
    ports = [str(port) for port in parsed.get("open_ports") or []]
    total = int(parsed.get("ports_open_total") or len(ports))
    hosts = int(parsed.get("hosts_up") or 0)
    body = f"{total} puerto(s) abierto(s)"
    if ports:
        shown = ", ".join(ports[:12])
        if len(ports) > 12:
            shown += f" y {len(ports) - 12} más"
        body += f" ({shown})"
    if hosts:
        body += f" · {hosts} host(s) up"
    return body


__all__ = ["PARSER_NAME", "open_ports", "parse", "summary"]
