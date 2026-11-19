"""Report assembly facade; query snapshots, registered capabilities and enrichment."""

from __future__ import annotations

_TIMELINE_ACTIONS = frozenset(
    {
        "tool.invoke",
        "tool.complete",
        "tool.failed",
        "scope.denied",
        "session.command",
        "approval.trust_mode",
        "react.step",
    }
)
_TIMELINE_OPENERS = frozenset({"tool.invoke", "react.step", "session.command"})


from dataclasses import replace
from typing import Any, Iterable

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.models import utc_now
from nexus_core.scope import EngagementStore

from . import cve_enrichment as cve_module
from . import cvss as cvss_module
from . import cvss4 as cvss4_module
from . import frameworks as frameworks_module
from . import mitre
from .attack_chain import build_attack_chains
from .models import (
    EngagementReport,
    Evidence,
    FailedAttempt,
    Finding,
    ReportItem,
    TimelineEntry,
    severity_rank,
    with_digest,
)

from .extraction_support import (
    Observation as Observation,
    matches_scope as matches_scope,
    summarize_scope as summarize_scope,
    target_field_for as target_field_for,
    targets_for_arguments as targets_for_arguments,
    _target_from_reason,
    _event_target,
    _excerpt,
    _evidence_for,
    _as_dict,
    _deduplicate,
    _Collection,
    _collect,
    MAX_EXCERPT_CHARS as MAX_EXCERPT_CHARS,
    DEDUP_WINDOW_SECONDS as DEDUP_WINDOW_SECONDS,
    AUDIT_EVENT,
    _NON_FINDING_TOOLS,
)
from .repository import ReportRepository
from .extractor_registry import default_registry, ExtractorRegistry
from .extract_facts import _fact_findings, _fact_inventory


async def extract_engagement_metadata(
    store: Any,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    """Load the signed scope plus the operator recorded in the audit trail.

    Raises ``KeyError`` when the engagement does not exist for this tenant: the
    report must never be generated against an unknown authorization envelope.
    """
    scope = EngagementStore(store).get(tenant_id, engagement_id)
    if scope is None:
        raise KeyError(f"engagement not found: {engagement_id}")
    events = ReportRepository(store).events(tenant_id)
    actor = ""
    for event in events:
        candidate = str(event.get("actor_id") or "")
        if candidate and not candidate.startswith("agent:"):
            actor = candidate
            break
    operator = scope.owner_id or actor
    return {
        "engagement_id": scope.engagement_id,
        "engagement_name": scope.name,
        "client": scope.client,
        "operator": operator,
        "valid_from": scope.valid_from,
        "valid_until": scope.valid_until,
        "scope_summary": summarize_scope(scope),
        "scope_full": scope.to_dict(),
        "scope_signature": scope.signature,
        "notes": scope.notes,
        "run_ids": [],
        "audit_events_total": len(events),
        "audit_chain_valid": bool(AuditWriter(store).verify_chain()[0]),
    }


async def extract_findings(
    store: Any,
    tenant_id: str,
    engagement_id: str,
    run_ids: list[str] | None = None,
) -> tuple[list[Finding], list[FailedAttempt]]:
    """Return every finding and failed attempt attributable to the engagement.

    Findings carry no CVSS yet: :func:`build_report` resolves it (explicit,
    LLM-assisted or heuristic) so the extractor stays fully deterministic.
    """
    collection = _collect(store, tenant_id, engagement_id, run_ids)
    return findings_from_collection(
        collection, ReportRepository(store).facts(tenant_id, engagement_id)
    )


def findings_from_collection(
    collection: _Collection,
    facts: list[dict[str, Any]],
    *,
    registry: ExtractorRegistry | None = None,
) -> tuple[list[Finding], list[FailedAttempt]]:
    registry = registry or default_registry()
    observations = collection.observations
    selected = collection.selected
    scoped_events = collection.scoped_events
    context = collection.context

    findings: list[Finding] = []
    failed: list[FailedAttempt] = []
    observed_failures: set[tuple[str, str]] = set()
    for observation in observations:
        if observation.run_id not in selected:
            continue
        if observation.tool_id in _NON_FINDING_TOOLS:
            continue
        if not observation.success:
            observed_failures.add((observation.run_id, observation.tool_id))
            failed.append(
                FailedAttempt(
                    tool_id=observation.tool_id,
                    target=", ".join(
                        targets_for_arguments(observation.tool_id, observation.arguments)
                    ),
                    reason=(
                        f"el tool no verificó su post-condition "
                        f"({observation.verification_method or 'sin método'})"
                    ),
                    attempted_at=observation.created_at,
                    evidence=_evidence_for(observation, context),
                )
            )
            continue
        extracted = registry.extract(observation, context, kind="findings")
        # V0-32: keep the run that contributed to each finding. The renderer
        # shows a bounded list per finding instead of every id of the engagement.
        findings.extend(
            replace(finding, run_ids=(observation.run_id,))
            for finding in extracted.findings
        )
        failed.extend(extracted.failed)

    # Denied/aborted work is context, never a finding.
    for event in scoped_events:
        action = str(event.get("action") or "")
        payload = event.get("payload") or {}
        if action == "scope.denied":
            failed.append(
                FailedAttempt(
                    tool_id=str(event.get("resource_id") or ""),
                    target=_event_target(event),
                    reason=f"denegado por scope: {payload.get('reason') or 'fuera del alcance'}",
                    attempted_at=str(event.get("created_at") or ""),
                    evidence=(
                        Evidence(
                            kind=AUDIT_EVENT,
                            ref_id=str(event.get("event_id") or ""),
                            sha256=str(event.get("event_hash") or "") or None,
                            excerpt=_excerpt(payload, 1000),
                            created_at=str(event.get("created_at") or ""),
                        ),
                    ),
                )
            )
        elif action == "tool.failed":
            # The observation already reported this failure in detail.
            if (
                str(event.get("trace_id") or ""),
                str(event.get("resource_id") or ""),
            ) in observed_failures:
                continue
            failed.append(
                FailedAttempt(
                    tool_id=str(event.get("resource_id") or ""),
                    target=_event_target(event),
                    reason=f"fallo de ejecución: {payload.get('error_type') or 'error'}",
                    attempted_at=str(event.get("created_at") or ""),
                    evidence=(
                        Evidence(
                            kind=AUDIT_EVENT,
                            ref_id=str(event.get("event_id") or ""),
                            sha256=str(event.get("event_hash") or "") or None,
                            excerpt=_excerpt(payload, 1000),
                            created_at=str(event.get("created_at") or ""),
                        ),
                    ),
                )
            )

    # The blackboard is part of the durable record too: a fact the operator
    # logged (credential, access, privilege, vulnerability...) must show up as a
    # finding, not be dropped just because it came from a bookkeeping tool (H3).
    findings.extend(_fact_findings(facts, scope=collection.scope))
    findings = [mitre.enrich_finding_with_mitre(finding) for finding in _deduplicate(findings)]
    findings.sort(key=lambda item: (severity_rank(item.severity), item.discovered_at))
    failed.sort(key=lambda item: item.attempted_at)
    return findings, failed


def extract_findings_sync(
    store: Any,
    tenant_id: str,
    engagement_id: str,
    run_ids: list[str] | None = None,
) -> tuple[list[Finding], list[FailedAttempt]]:
    """Blocking convenience wrapper around :func:`extract_findings`.

    The extraction only touches SQLite, so running it in its own event loop is
    safe and keeps the CLI able to call it from a synchronous context.
    """
    import asyncio

    return asyncio.run(extract_findings(store, tenant_id, engagement_id, run_ids))


async def extract_report_items(
    store: Any,
    tenant_id: str,
    engagement_id: str,
    run_ids: list[str] | None = None,
) -> tuple[
    tuple[ReportItem, ...], tuple[ReportItem, ...], tuple[ReportItem, ...], tuple[ReportItem, ...]
]:
    """Return inventories, references, surfaces and evidence for the engagement.

    Not every tool produces a vulnerability. Inventories (gobuster, whatweb),
    references (searchsploit), surfaces (netexec) and evidence (BloodHound) are
    represented faithfully instead of being forced into a finding.
    """
    collection = _collect(store, tenant_id, engagement_id, run_ids)
    return items_from_collection(
        collection, ReportRepository(store).facts(tenant_id, engagement_id)
    )


def items_from_collection(
    collection: _Collection,
    facts: list[dict[str, Any]],
    *,
    registry: ExtractorRegistry | None = None,
) -> tuple[
    tuple[ReportItem, ...], tuple[ReportItem, ...], tuple[ReportItem, ...], tuple[ReportItem, ...]
]:
    registry = registry or default_registry()
    inventories: list[ReportItem] = []
    references: list[ReportItem] = []
    surfaces: list[ReportItem] = []
    evidences: list[ReportItem] = []
    for observation in collection.observations:
        if observation.run_id not in collection.selected or not observation.success:
            continue
        extracted = registry.extract(observation, collection.context, kind="items")
        inventories.extend(extracted.inventories)
        references.extend(extracted.references)
        surfaces.extend(extracted.surfaces)
        evidences.extend(extracted.evidences)
    # Facts are discoveries: render them as an explicit inventory so the report
    # can show "Inventario" populated even without an inventory-producing tool
    # (H3 of the RUN7 report).
    inventories.extend(_fact_inventory(facts))
    return (
        tuple(inventories),
        tuple(references),
        tuple(surfaces),
        tuple(evidences),
    )


def extract_report_items_sync(
    store: Any,
    tenant_id: str,
    engagement_id: str,
    run_ids: list[str] | None = None,
) -> tuple[
    tuple[ReportItem, ...], tuple[ReportItem, ...], tuple[ReportItem, ...], tuple[ReportItem, ...]
]:
    """Blocking wrapper around :func:`extract_report_items`."""
    import asyncio

    return asyncio.run(extract_report_items(store, tenant_id, engagement_id, run_ids))


def _sessions_opened(observations: Iterable[Observation], selected: set[str]) -> int:
    uuids: set[str] = set()
    for observation in observations:
        if observation.run_id not in selected or observation.tool_id != "nexus.exploit.msf_exploit":
            continue
        output = observation.output or {}
        if str(output.get("status")) != "session_opened":
            continue
        session = _as_dict(output.get("session"))
        uuids.add(str((session or {}).get("uuid") or observation.message_id))
    return len(uuids)


def timeline_for(
    store: Any,
    tenant_id: str,
    engagement_id: str,
    run_ids: list[str] | None = None,
) -> tuple[TimelineEntry, ...]:
    """Chronology of one engagement (runs selected exactly like a report)."""
    collection = _collect(store, tenant_id, engagement_id, run_ids)
    return build_timeline(collection.scoped_events, collection.observations)


def _targets_by_key(observations: Iterable[Observation]) -> dict[tuple[str, str], list[str]]:
    """``(run_id, tool_id) -> [target of each call]`` in trail order."""
    grouped: dict[tuple[str, str], list[str]] = {}
    for observation in observations:
        targets = targets_for_arguments(observation.tool_id, observation.arguments)
        text = ", ".join(targets)
        grouped.setdefault((observation.run_id, observation.tool_id), []).append(text)
    return grouped


def build_timeline(
    events: Iterable[dict[str, Any]],
    observations: Iterable[Observation] = (),
) -> tuple[TimelineEntry, ...]:
    """Chronology of the engagement, straight from the audit trail.

    The trail records which arguments were *used* but not their values, so the
    target of each entry is recovered from the matching persisted ToolResult.
    """
    targets = _targets_by_key(observations)
    opened: dict[tuple[str, str], int] = {}
    entries: list[TimelineEntry] = []
    for event in events:
        action = str(event.get("action") or "")
        if action not in _TIMELINE_ACTIONS:
            continue
        payload = event.get("payload") or {}
        run_id = str(event.get("trace_id") or "")
        tool_id = str(event.get("resource_id") or "")
        key = (run_id, tool_id)
        if action in _TIMELINE_OPENERS:
            index = opened.get(key, 0)
            opened[key] = index + 1
        else:
            # ``tool.complete``/``session.command`` close the newest call.
            index = max(0, opened.get(key, 1) - 1)
        candidates = targets.get(key) or []
        target = _event_target(event)
        if not target and action == "scope.denied":
            # A refused call has no ToolResult; the violation carries the target.
            target = _target_from_reason(payload.get("reason"))
        if not target and index < len(candidates):
            target = candidates[index]
        entries.append(
            TimelineEntry(
                occurred_at=str(event.get("created_at") or ""),
                action=action,
                tool_id=tool_id,
                target=target,
                decision=str(event.get("decision") or ""),
                detail=str(
                    payload.get("reason")
                    or payload.get("command")
                    or payload.get("error_type")
                    or ""
                )[:200],
            )
        )
    entries.sort(key=lambda item: item.occurred_at)
    return tuple(entries)


def attach_cvss(
    findings: Iterable[Finding],
    llm_client: Any = None,
) -> tuple[Finding, ...]:
    """Resolve the CVSS of every finding (explicit, LLM-assisted or heuristic).

    Both CVSS v3.1 and v4.0 are computed: the score is always recomputed locally
    from the resulting vector, so a model can never inject a number into the
    report. ``llm_client`` is only used when it is callable and may return either
    a 3.1 or a 4.0 vector (each scorer extracts the vector of its own version).
    """
    from dataclasses import replace

    def _ask(prompt: str) -> str | None:
        if not callable(llm_client):
            return None
        answer = llm_client(prompt)
        return answer if isinstance(answer, str) else None

    ask = _ask if callable(llm_client) else None
    resolved: list[Finding] = []
    for finding in findings:
        score, vector, source = cvss_module.estimate_cvss_with_source(finding, ask)
        score4, vector4, source4 = cvss4_module.estimate_cvss4_with_source(finding, ask)
        resolved.append(
            replace(
                finding,
                cvss_score=score,
                cvss_vector=vector,
                cvss_source=source,
                cvss4_score=score4,
                cvss4_vector=vector4,
                cvss4_source=source4,
            )
        )
    return tuple(resolved)


async def build_report(
    store: Any,
    tenant_id: str,
    engagement_id: str,
    *,
    run_ids: list[str] | None = None,
    llm_client: Any = None,
    llm_cvss: bool = False,
    include_failed_attempts: bool = True,
    enrich_cves: bool = True,
    cve_cache_dir: Any = None,
) -> EngagementReport:
    """Assemble a complete, content-addressed :class:`EngagementReport`.

    ``llm_cvss`` asks the model for a CVSS vector per finding; the *score* is
    always recomputed locally and any failure degrades to the deterministic
    heuristic, so the report is produced either way. ``enrich_cves`` merges the
    **cached** CVE intelligence (never the network) and the framework mappings;
    both are pipeline steps that can never fail the report.
    """
    metadata = await extract_engagement_metadata(store, tenant_id, engagement_id)
    collection = _collect(store, tenant_id, engagement_id, run_ids)
    repository = ReportRepository(store)
    facts = repository.facts(tenant_id, engagement_id)
    edges = repository.edges(tenant_id, engagement_id)
    findings, failed = findings_from_collection(collection, facts)
    if enrich_cves:
        findings = list(cve_module.enrich_findings(findings, root=cve_cache_dir))
    inventories, references, surfaces, evidences = items_from_collection(collection, facts)
    scored = attach_cvss(findings, llm_client if llm_cvss else None)
    scored = frameworks_module.attach_frameworks(scored)

    tools_used: list[str] = []
    for observation in collection.observations:
        if observation.run_id in collection.selected and observation.tool_id not in tools_used:
            tools_used.append(observation.tool_id)

    times = [str(event.get("created_at") or "") for event in collection.scoped_events]
    times = [item for item in times if item]
    notes = ""
    if collection.undecodable:
        notes = (
            f"{collection.undecodable} observación(es) truncadas en el almacén de "
            "mensajes: su hallazgo puede faltar en este reporte (la evidencia sigue "
            "en la auditoría)."
        )
    if not metadata["audit_chain_valid"]:
        notes = (notes + " " if notes else "") + (
            "La cadena de auditoría NO se pudo verificar: trátese como no confiable."
        )
    if not mitre.dataset_available():
        # Measured in Bounty Hacker v2 (2026-10-31): the pipx install shipped
        # without ``report/data/*.json`` and report generation died. The report
        # must be produced from the durable record even then, and say what it
        # could not enrich.
        notes = (notes + " " if notes else "") + (
            "El catálogo MITRE ATT&CK no está instalado en este entorno: el "
            "reporte omite ese enriquecimiento (los hallazgos y su evidencia "
            "siguen completos)."
        )

    report = EngagementReport(
        engagement_id=str(metadata["engagement_id"]),
        engagement_name=str(metadata["engagement_name"]),
        client=str(metadata["client"]),
        operator=str(metadata["operator"]),
        # V1-42: the engagement started when its first run started. Falling back
        # to the earliest event of the tenant is what dated the rerun 11 report
        # two hours before the engagement existed (an untagged run of another
        # engagement had written the earliest event).
        started_at=(
            collection.first_run_at
            or (min(times) if times else str(metadata["valid_from"]))
        ),
        ended_at=max(times) if times else utc_now(),
        scope_summary=str(metadata["scope_summary"]),
        scope_full=dict(metadata["scope_full"]),
        findings=scored,
        failed_attempts=tuple(failed) if include_failed_attempts else (),
        tools_used=tuple(tools_used),
        sessions_opened=_sessions_opened(collection.observations, collection.selected),
        audit_events_total=len(collection.scoped_events),
        audit_chain_valid=bool(metadata["audit_chain_valid"]),
        generated_at=utc_now(),
        timeline=build_timeline(collection.scoped_events),
        run_ids=tuple(sorted(collection.selected)),
        scope_signature=str(metadata.get("scope_signature") or ""),
        notes=notes,
        inventories=inventories,
        references=references,
        surfaces=surfaces,
        evidences=evidences,
        attack_chain=build_attack_chains(
            facts, edges, engagement_id=engagement_id
        ),
    )
    return with_digest(report)


__all__ = [
    "DEDUP_WINDOW_SECONDS",
    "MAX_EXCERPT_CHARS",
    "Observation",
    "attach_cvss",
    "build_report",
    "build_timeline",
    "extract_engagement_metadata",
    "extract_findings",
    "extract_findings_sync",
    "extract_report_items",
    "extract_report_items_sync",
    "matches_scope",
    "summarize_scope",
    "target_field_for",
    "targets_for_arguments",
    "timeline_for",
]
