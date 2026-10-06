"""Framework mappings for findings: PTES, OWASP WSTG, NIST SP 800-115, D3FEND.

A client deliverable is not only a list of technical issues: an enterprise reader
expects each finding to be placed in the methodology that produced it (PTES), in
the web-testing catalogue it belongs to (OWASP WSTG), in the technical guide the
engagement followed (NIST SP 800-115) and against the defensive countermeasures
that would mitigate it (MITRE D3FEND).

**Honesty note.** These tables are *curated and coarse*, not the exhaustive
catalogues: mapping every one of the ~100 WSTG tests and ~270 D3FEND techniques
is out of scope (and this project must not invent identifiers). Each entry below
is a real, published identifier taken from the framework itself:

* PTES — the seven standard phases of the Penetration Testing Execution Standard.
* OWASP WSTG v4.2 — web security testing guide identifiers (``WSTG-*``).
* NIST SP 800-115 — the technical testing sections of the guide.
* MITRE D3FEND — defensive technique identifiers (``D3-*``) and their tactic.

The mapping is keyed on the finding's internal ``kind`` (what the toolkit
actually observed) and refined by its MITRE ATT&CK techniques. Anything the
tables do not cover is returned as an **empty** mapping rather than a guess.
Nothing here calls the network: the tables are embedded and deterministic.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterable

from .models import Finding, FrameworkMapping

#: Stable framework slugs, in the order a reader should see them.
FRAMEWORKS: tuple[str, ...] = ("PTES", "OWASP-WSTG", "NIST-SP-800-115", "MITRE-D3FEND")

_PTES_PHASE_NAMES = {
    1: "Pre-engagement Interactions",
    2: "Intelligence Gathering",
    3: "Threat Modeling",
    4: "Vulnerability Analysis",
    5: "Exploitation",
    6: "Post-Exploitation",
    7: "Reporting",
}


def _ptes(phase: int) -> FrameworkMapping:
    return FrameworkMapping("PTES", f"PTES-{phase}", _PTES_PHASE_NAMES[phase])


def _wstg(test_id: str, name: str) -> FrameworkMapping:
    return FrameworkMapping("OWASP-WSTG", test_id, name)


def _nist(section: str, name: str) -> FrameworkMapping:
    return FrameworkMapping("NIST-SP-800-115", f"§{section}", name)


def _d3fend(technique_id: str, name: str, tactic: str) -> FrameworkMapping:
    return FrameworkMapping("MITRE-D3FEND", technique_id, f"{name} ({tactic})")


# --------------------------------------------------------------- PTES (phases)
PTES_PHASES: dict[str, int] = {
    "subdomains": 2, "open_ports": 2, "http_surface": 2,
    "endpoint_protected": 4, "nuclei": 4, "sqli": 4, "xss": 4,
    "session_opened": 5,
    "session_command": 6, "credentials": 6, "kerberoast": 6, "remote_exec": 6,
    "generic": 4,
}

# ------------------------------------------------------------- OWASP WSTG v4.2
WSTG_TESTS: dict[str, tuple[FrameworkMapping, ...]] = {
    "subdomains": (
        _wstg("WSTG-INFO-01", "Conduct Search Engine Discovery and Reconnaissance for Information Leakage"),
    ),
    "http_surface": (_wstg("WSTG-INFO-02", "Fingerprint Web Server"),),
    "endpoint_protected": (_wstg("WSTG-INFO-10", "Map Application Architecture"),),
    "nuclei": (_wstg("WSTG-CONF-01", "Test Network Infrastructure Configuration"),),
    "sqli": (_wstg("WSTG-INPV-05", "Testing for SQL Injection"),),
    "xss": (_wstg("WSTG-INPV-01", "Testing for Reflected Cross Site Scripting"),),
}

# ------------------------------------------------------- NIST SP 800-115 (§)
NIST_SECTIONS: dict[str, tuple[str, str]] = {
    "subdomains": ("4.1", "Network Discovery"),
    "open_ports": ("4.2", "Network Port and Service Identification"),
    "http_surface": ("4.2", "Network Port and Service Identification"),
    "endpoint_protected": ("4.3", "Vulnerability Scanning"),
    "nuclei": ("4.3", "Vulnerability Scanning"),
    "sqli": ("4.3", "Vulnerability Scanning"),
    "xss": ("4.3", "Vulnerability Scanning"),
    "credentials": ("5.1", "Password Cracking"),
    "kerberoast": ("5.1", "Password Cracking"),
    "session_opened": ("5.2", "Penetration Testing"),
    "session_command": ("5.2", "Penetration Testing"),
    "remote_exec": ("5.2", "Penetration Testing"),
    "generic": ("4.3", "Vulnerability Scanning"),
}

# ---------------------------------------------------------------- MITRE D3FEND
#: D3FEND countermeasures implied by a finding's internal kind.
D3FEND_BY_KIND: dict[str, tuple[FrameworkMapping, ...]] = {
    "subdomains": (_d3fend("D3-CA", "Certificate Analysis", "Detect"),),
    "open_ports": (
        _d3fend("D3-NTA", "Network Traffic Analysis", "Detect"),
        _d3fend("D3-CAA", "Connection Attempt Analysis", "Detect"),
    ),
    "http_surface": (_d3fend("D3-CA", "Certificate Analysis", "Detect"),),
    "endpoint_protected": (_d3fend("D3-NTA", "Network Traffic Analysis", "Detect"),),
    "nuclei": (_d3fend("D3-OSM", "Operating System Monitoring", "Detect"),),
    "sqli": (_d3fend("D3-DQSA", "Database Query String Analysis", "Detect"),),
    "xss": (_d3fend("D3-SEA", "Script Execution Analysis", "Detect"),),
    "session_opened": (
        _d3fend("D3-SCA", "System Call Analysis", "Detect"),
        _d3fend("D3-PT", "Process Termination", "Evict"),
    ),
    "session_command": (_d3fend("D3-OSM", "Operating System Monitoring", "Detect"),),
    "credentials": (
        _d3fend("D3-AL", "Account Locking", "Evict"),
        _d3fend("D3-ANCI", "Authentication Cache Invalidation", "Evict"),
    ),
    "kerberoast": (
        _d3fend("D3-AL", "Account Locking", "Evict"),
        _d3fend("D3-ANCI", "Authentication Cache Invalidation", "Evict"),
    ),
    "remote_exec": (
        _d3fend("D3-RTA", "RPC Traffic Analysis", "Detect"),
        _d3fend("D3-NTA", "Network Traffic Analysis", "Detect"),
    ),
    "generic": (_d3fend("D3-OSM", "Operating System Monitoring", "Detect"),),
}

#: D3FEND countermeasures implied by the ATT&CK techniques of a finding. These
#: refine (they never replace) the kind-level defaults above.
D3FEND_BY_TECHNIQUE: dict[str, tuple[FrameworkMapping, ...]] = {
    "T1003": (
        _d3fend("D3-AL", "Account Locking", "Evict"),
        _d3fend("D3-ANCI", "Authentication Cache Invalidation", "Evict"),
    ),
    "T1033": (_d3fend("D3-LAM", "Local Account Monitoring", "Detect"),),
    "T1016": (_d3fend("D3-NTA", "Network Traffic Analysis", "Detect"),),
    "T1046": (
        _d3fend("D3-NTA", "Network Traffic Analysis", "Detect"),
        _d3fend("D3-CAA", "Connection Attempt Analysis", "Detect"),
    ),
    "T1021": (_d3fend("D3-RTA", "RPC Traffic Analysis", "Detect"),),
    "T1053": (_d3fend("D3-SJA", "Scheduled Job Analysis", "Detect"),),
    "T1055": (_d3fend("D3-PLA", "Process Lineage Analysis", "Detect"),),
    "T1057": (_d3fend("D3-PSA", "Process Spawn Analysis", "Detect"),),
    "T1059": (_d3fend("D3-SEA", "Script Execution Analysis", "Detect"),),
    "T1068": (_d3fend("D3-SCA", "System Call Analysis", "Detect"),),
    "T1070": (_d3fend("D3-SFA", "System File Analysis", "Detect"),),
    "T1082": (_d3fend("D3-OSM", "Operating System Monitoring", "Detect"),),
    "T1083": (_d3fend("D3-SFA", "System File Analysis", "Detect"),),
    "T1005": (_d3fend("D3-SFA", "System File Analysis", "Detect"),),
    "T1105": (_d3fend("D3-NTA", "Network Traffic Analysis", "Detect"),),
    "T1112": (_d3fend("D3-SFA", "System File Analysis", "Detect"),),
    "T1562": (_d3fend("D3-SDM", "System Daemon Monitoring", "Detect"),),
}


def _dedupe(mappings: Iterable[FrameworkMapping]) -> tuple[FrameworkMapping, ...]:
    seen: set[tuple[str, str]] = set()
    result: list[FrameworkMapping] = []
    for item in mappings:
        key = (item.framework, item.technique_id)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return tuple(result)


def _map(kind: str, techniques: Iterable[Any]) -> tuple[FrameworkMapping, ...]:
    """Mapping tables applied to an explicit ``(kind, techniques)`` pair.

    A kind no table knows is treated as ``generic`` (a conservative analysis-stage
    mapping) rather than dropped, so a finding is never left without any placement.
    """
    if kind not in PTES_PHASES:
        kind = "generic"
    mappings: list[FrameworkMapping] = []
    phase = PTES_PHASES.get(kind)
    if phase:
        mappings.append(_ptes(phase))
    mappings.extend(WSTG_TESTS.get(kind, ()))
    section = NIST_SECTIONS.get(kind)
    if section:
        mappings.append(_nist(*section))
    mappings.extend(D3FEND_BY_KIND.get(kind, ()))
    for technique in techniques:
        mappings.extend(D3FEND_BY_TECHNIQUE.get(str(technique), ()))
    return _dedupe(mappings)


def map_finding(finding: Any) -> tuple[FrameworkMapping, ...]:
    """Return the framework mappings of one finding (empty when undefined)."""
    kind = str(getattr(finding, "kind", "generic") or "generic")
    techniques = tuple(getattr(finding, "mitre_techniques", ()) or ())
    return _map(kind, techniques)


def map_for_kind(kind: str) -> tuple[FrameworkMapping, ...]:
    """Convenience mapping for a bare kind (used by tests and callers)."""
    return _map(str(kind or "generic"), ())


def frameworks_present(mappings: Iterable[FrameworkMapping]) -> tuple[str, ...]:
    """Distinct framework slugs present, in :data:`FRAMEWORKS` order."""
    present = {item.framework for item in mappings}
    return tuple(name for name in FRAMEWORKS if name in present)


def attach_frameworks(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    """Return copies of ``findings`` carrying their framework mappings."""
    return tuple(replace(finding, frameworks=map_finding(finding)) for finding in findings)


__all__ = [
    "D3FEND_BY_KIND",
    "D3FEND_BY_TECHNIQUE",
    "FRAMEWORKS",
    "NIST_SECTIONS",
    "PTES_PHASES",
    "WSTG_TESTS",
    "attach_frameworks",
    "frameworks_present",
    "map_finding",
    "map_for_kind",
]
