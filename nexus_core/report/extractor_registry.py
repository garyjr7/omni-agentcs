"""Explicit capability registry; extractors consume snapshots, never a DB."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from .extraction_support import Observation, _Context
from .models import Finding, FailedAttempt, ReportItem


@dataclass
class Extraction:
    findings: list[Finding] = field(default_factory=list)
    failed: list[FailedAttempt] = field(default_factory=list)
    inventories: list[ReportItem] = field(default_factory=list)
    references: list[ReportItem] = field(default_factory=list)
    surfaces: list[ReportItem] = field(default_factory=list)
    evidences: list[ReportItem] = field(default_factory=list)


Extractor = Callable[[Observation, _Context], Extraction]


class ExtractorRegistry:
    def __init__(self) -> None:
        self._extractors: dict[str, Extractor] = {}
        self._kinds: dict[str, Literal["findings", "items"]] = {}

    def register(
        self, tool_id: str, extractor: Extractor, *, kind: Literal["findings", "items"] = "findings"
    ) -> None:
        if tool_id in self._extractors:
            raise ValueError(f"duplicate report extractor: {tool_id}")
        self._extractors[tool_id] = extractor
        self._kinds[tool_id] = kind

    def extract(
        self,
        observation: Observation,
        context: _Context,
        *,
        kind: Literal["findings", "items"] | None = None,
    ) -> Extraction:
        if kind is not None and self._kinds.get(observation.tool_id) != kind:
            return Extraction()
        extractor = self._extractors.get(observation.tool_id)
        return extractor(observation, context) if extractor is not None else Extraction()


def _findings(parser: Callable[[Observation, _Context], list[Finding]]) -> Extractor:
    def extract(observation: Observation, context: _Context) -> Extraction:
        return Extraction(findings=parser(observation, context))

    return extract


def default_registry() -> ExtractorRegistry:
    from . import extract_access as access, extract_recon as recon, extract_web as web

    registry = ExtractorRegistry()
    for tool, parser in {
        "nexus.recon.nmap": recon._nmap_findings,
        "nexus.recon.subfinder": recon._subfinder_findings,
        "nexus.web.nuclei": web._nuclei_findings,
        "nexus.web.ffuf": web._ffuf_findings,
        "nexus.web.sqlmap": web._sqlmap_findings,
        "nexus.web.dalfox": web._dalfox_findings,
        "nexus.attack.impacket_secretsdump": access._secretsdump_findings,
        "nexus.attack.impacket_getuserspns": access._getuserspns_findings,
        "nexus.attack.impacket_psexec": access._psexec_findings,
        "nexus.session.interact": access._session_findings,
    }.items():
        registry.register(tool, _findings(parser))

    def exploit(observation: Observation, context: _Context) -> Extraction:
        findings, failed = access._exploit_findings(observation, context)
        return Extraction(findings=findings, failed=failed)

    registry.register("nexus.exploit.msf_exploit", exploit)
    registry.register(
        "nexus.recon.gobuster",
        lambda o, c: Extraction(inventories=recon._gobuster_inventory(o, c)),
        kind="items",
    )
    registry.register(
        "nexus.recon.whatweb",
        lambda o, c: Extraction(inventories=recon._whatweb_inventory(o, c)),
        kind="items",
    )
    registry.register(
        "nexus.exploit.searchsploit",
        lambda o, c: Extraction(references=access._searchsploit_reference(o, c)),
        kind="items",
    )
    registry.register(
        "nexus.recon.netexec",
        lambda o, c: Extraction(surfaces=access._netexec_surface(o, c)),
        kind="items",
    )
    registry.register(
        "nexus.recon.bloodhound_python",
        lambda o, c: Extraction(evidences=access._bloodhound_evidence(o, c)),
        kind="items",
    )
    return registry
