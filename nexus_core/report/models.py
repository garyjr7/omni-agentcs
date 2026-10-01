"""Frozen models of an engagement report (JSON-serializable, hashable)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

#: Severity levels, most severe first. The index is the ranking.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


def severity_rank(severity: str) -> int:
    """Return the rank of ``severity`` (0 = critical); unknown sorts last."""
    try:
        return SEVERITY_ORDER.index(str(severity).lower())
    except ValueError:
        return len(SEVERITY_ORDER)


@dataclass(frozen=True)
class Evidence:
    """One durable pointer backing a finding (chain of custody).

    ``kind`` is one of ``"audit_event"``, ``"artifact"``, ``"tool_result"`` or
    ``"message"``; ``ref_id`` is the durable identifier (event id, artifact id,
    message id) and ``sha256`` the digest when the source exposes one.
    """

    kind: str
    ref_id: str
    sha256: str | None
    excerpt: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the evidence."""
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    """A verified observation worth reporting, with its chain of custody."""

    finding_id: str
    title: str
    description: str
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    cwe: str | None
    cve: str | None
    mitre_techniques: tuple[str, ...]
    owasp_category: str | None
    affected_targets: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    discovered_by_tool: str
    discovered_at: str
    reproduction_steps: tuple[str, ...]
    #: Internal classification used for deduplication (never rendered as-is).
    kind: str = "generic"
    #: How many times the same observation was reproduced inside the window.
    reproductions: int = 1
    #: Whether CVSS came from the tool, the LLM or the deterministic heuristic.
    cvss_source: str = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the finding."""
        value = asdict(self)
        value["mitre_techniques"] = list(self.mitre_techniques)
        value["affected_targets"] = list(self.affected_targets)
        value["reproduction_steps"] = list(self.reproduction_steps)
        return value


@dataclass(frozen=True)
class ReportItem:
    """A non-finding observation worth reporting (inventory/reference/surface).

    Not every tool produces a vulnerability: an inventory lists what was
    discovered (endpoints, stack), a reference points at available material
    (Exploit-DB entries, an AD map) and a surface describes reachable services.
    ``kind`` is one of ``"inventory"``, ``"reference"``, ``"surface"`` or
    ``"evidence"``.
    """

    kind: str
    title: str
    detail: dict[str, Any]
    discovered_by_tool: str
    discovered_at: str
    affected_targets: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the item."""
        value = asdict(self)
        value["affected_targets"] = list(self.affected_targets)
        value["mitre_techniques"] = list(self.mitre_techniques)
        value["evidence"] = [item.to_dict() for item in self.evidence]
        return value


@dataclass(frozen=True)
class FailedAttempt:
    """Something the toolkit tried that produced no finding (never a finding).

    Kept in the report so a reader can tell "we tried and it did not work" from
    "we never looked", which is the difference between a scope gap and a
    negative result.
    """

    tool_id: str
    target: str
    reason: str
    attempted_at: str
    evidence: tuple[Evidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the attempt."""
        value = asdict(self)
        value["evidence"] = [item.to_dict() for item in self.evidence]
        return value


@dataclass(frozen=True)
class TimelineEntry:
    """One row of the engagement chronology, straight from the audit trail."""

    occurred_at: str
    action: str
    tool_id: str
    target: str
    decision: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the entry."""
        return asdict(self)


@dataclass(frozen=True)
class EngagementReport:
    """Everything the client deliverable contains, already extracted."""

    engagement_id: str
    engagement_name: str
    client: str
    operator: str
    started_at: str
    ended_at: str
    scope_summary: str
    scope_full: dict[str, Any]
    findings: tuple[Finding, ...]
    failed_attempts: tuple[FailedAttempt, ...]
    tools_used: tuple[str, ...]
    sessions_opened: int
    audit_events_total: int
    audit_chain_valid: bool
    generated_at: str
    report_sha256: str = ""
    timeline: tuple[TimelineEntry, ...] = ()
    run_ids: tuple[str, ...] = ()
    scope_signature: str = ""
    notes: str = ""
    #: Non-finding observations, grouped so every renderer can surface them.
    inventories: tuple[ReportItem, ...] = ()
    references: tuple[ReportItem, ...] = ()
    surfaces: tuple[ReportItem, ...] = ()
    evidences: tuple[ReportItem, ...] = ()

    @property
    def findings_by_severity(self) -> dict[str, int]:
        """Count findings per severity, always including the four real levels."""
        counts = {level: 0 for level in SEVERITY_ORDER}
        for finding in self.findings:
            key = str(finding.severity).lower()
            counts[key] = counts.get(key, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the whole report."""
        return {
            "engagement_id": self.engagement_id,
            "engagement_name": self.engagement_name,
            "client": self.client,
            "operator": self.operator,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "scope_summary": self.scope_summary,
            "scope_full": self.scope_full,
            "scope_signature": self.scope_signature,
            "findings": [item.to_dict() for item in self.findings],
            "failed_attempts": [item.to_dict() for item in self.failed_attempts],
            "tools_used": list(self.tools_used),
            "sessions_opened": self.sessions_opened,
            "audit_events_total": self.audit_events_total,
            "audit_chain_valid": self.audit_chain_valid,
            "generated_at": self.generated_at,
            "report_sha256": self.report_sha256,
            "timeline": [item.to_dict() for item in self.timeline],
            "run_ids": list(self.run_ids),
            "findings_by_severity": self.findings_by_severity,
            "notes": self.notes,
            "inventories": [item.to_dict() for item in self.inventories],
            "references": [item.to_dict() for item in self.references],
            "surfaces": [item.to_dict() for item in self.surfaces],
            "evidences": [item.to_dict() for item in self.evidences],
        }


def canonical_body(report: EngagementReport) -> str:
    """Return the deterministic byte string hashed by :func:`report_digest`.

    ``report_sha256`` is excluded so the digest can be recomputed after the fact
    without mutating the report.
    """
    value = report.to_dict()
    value.pop("report_sha256", None)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def report_digest(report: EngagementReport) -> str:
    """Return the SHA-256 digest of :func:`canonical_body`."""
    return hashlib.sha256(canonical_body(report).encode("utf-8")).hexdigest()


def with_digest(report: EngagementReport) -> EngagementReport:
    """Return a copy of ``report`` carrying its own content digest."""
    from dataclasses import replace

    return replace(report, report_sha256=report_digest(report))


def verify_report_digest(report: EngagementReport) -> bool:
    """Whether ``report.report_sha256`` matches the recomputed digest."""
    return bool(report.report_sha256) and report.report_sha256 == report_digest(report)


__all__ = [
    "SEVERITY_ORDER",
    "EngagementReport",
    "Evidence",
    "FailedAttempt",
    "Finding",
    "ReportItem",
    "TimelineEntry",
    "canonical_body",
    "report_digest",
    "severity_rank",
    "verify_report_digest",
    "with_digest",
]
