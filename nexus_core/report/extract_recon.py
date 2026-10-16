"""Pure recon and inventory extractors; no storage access."""

from __future__ import annotations


from . import severity
from .models import (
    Finding,
    ReportItem,
)

from .extraction_support import (
    Observation,
    _Context,
    _evidence_for,
    _finding_id,
    _as_dict,
    _as_list,
    _report_item,
    _dict_list,
)


def _nmap_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    scan = _as_dict(output.get("scan"))
    hosts = _as_list(scan.get("hosts"))
    open_entries: list[str] = []
    severities: list[str] = []
    for host in hosts:
        if not isinstance(host, dict):
            continue
        address = str(host.get("ip") or host.get("hostname") or "")
        for port in host.get("ports") or ():
            if not isinstance(port, dict) or str(port.get("state")) != "open":
                continue
            number = str(port.get("port") or "")
            open_entries.append(f"{address}:{number}" if address else number)
            severities.append(severity.severity_for_port(port))
    if not open_entries:
        return []
    level = severity.highest_severity(severities)
    target = str(output.get("target") or "")
    hosts_up = int((observation.tool_evidence or {}).get("hosts_up") or 0)
    return [
        Finding(
            finding_id=_finding_id("open_ports", observation),
            title=f"Superficie expuesta: {len(open_entries)} puertos abiertos",
            description=(
                f"El escaneo de {target or 'el objetivo'} encontró {len(open_entries)} "
                f"puertos abiertos en {hosts_up} host(s) alcanzable(s): "
                f"{', '.join(open_entries[:20])}"
                + (" (truncado)" if len(open_entries) > 20 else "")
                + ". Es superficie de ataque confirmada, no una vulnerabilidad explotada."
            ),
            severity=level,
            cvss_score=None,
            cvss_vector=None,
            cwe=None,
            cve=None,
            mitre_techniques=(),
            owasp_category=None,
            affected_targets=tuple(open_entries),
            evidence=_evidence_for(observation, context, excerpt=output),
            discovered_by_tool=observation.tool_id,
            discovered_at=observation.created_at,
            reproduction_steps=(
                f"nmap {str(scan.get('args') or '')}".strip(),
                f"Revisar el XML (sha256 {scan.get('raw_xml_sha256') or 'n/d'})",
            ),
            kind="open_ports",
        )
    ]


def _subfinder_findings(observation: Observation, context: _Context) -> list[Finding]:
    output = observation.output or {}
    subdomains = [str(item) for item in (output.get("subdomains") or ()) if item]
    domain = str(output.get("domain") or "")
    if not domain:
        return []
    return [
        Finding(
            finding_id=_finding_id("subdomains", observation),
            title=f"Subdominios enumerados ({len(subdomains)})",
            description=(
                f"La enumeración pasiva de {domain} devolvió {len(subdomains)} "
                f"subdominio(s). Es superficie de ataque, no una vulnerabilidad; "
                f"amplía el alcance revisable del engagement."
                + (f" Muestra: {', '.join(subdomains[:10])}" if subdomains else "")
            ),
            severity="info",
            cvss_score=None,
            cvss_vector=None,
            cwe=None,
            cve=None,
            mitre_techniques=(),
            owasp_category=None,
            affected_targets=tuple(subdomains[:50]) or (domain,),
            evidence=_evidence_for(observation, context, excerpt=output),
            discovered_by_tool=observation.tool_id,
            discovered_at=observation.created_at,
            reproduction_steps=(
                f"subfinder -d {domain} -silent",
                "Verificar cada subdominio antes de escanearlo",
            ),
            kind="subdomains",
        )
    ]


def _gobuster_inventory(observation: Observation, context: _Context) -> list[ReportItem]:
    output = observation.output or {}
    hits = _dict_list(output.get("hits"))
    if not hits:
        return []
    target = str(output.get("target") or "")
    entries = [
        {
            "path": str(hit.get("path") or ""),
            "status": hit.get("status"),
            "size": hit.get("size"),
            "redirect": hit.get("redirect"),
        }
        for hit in hits
    ]
    return [
        _report_item(
            kind="inventory",
            title=f"Rutas descubiertas ({len(entries)})",
            detail={
                "mode": str(output.get("mode") or ""),
                "target": target,
                "hits": entries,
            },
            observation=observation,
            context=context,
            targets=(str(hit.get("path") or "") for hit in entries),
        )
    ]


def _whatweb_inventory(observation: Observation, context: _Context) -> list[ReportItem]:
    output = observation.output or {}
    targets = _dict_list(output.get("fingerprints"))
    if not targets:
        return []
    entries = []
    urls: list[str] = []
    for target in targets:
        url = str(target.get("url") or "")
        if url:
            urls.append(url)
        entries.append(
            {
                "url": url,
                "http_status": target.get("http_status"),
                "technologies": [
                    {
                        "name": str(fp.get("name") or ""),
                        "version": fp.get("version"),
                        "confidence": fp.get("confidence"),
                    }
                    for fp in _dict_list(target.get("fingerprints"))
                ],
            }
        )
    return [
        _report_item(
            kind="inventory",
            title=f"Stack tecnológico identificado ({len(entries)} target(s))",
            detail={"targets": entries},
            observation=observation,
            context=context,
            targets=urls,
        )
    ]
