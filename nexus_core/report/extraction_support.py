"""Shared scope, provenance and observation adapters for historical reports."""

from __future__ import annotations
import re

_COMPLETION_ACTIONS = frozenset({"tool.complete", "tool.failed", "session.command"})
_VIOLATION_TARGET = re.compile(r"ScopeViolation\(([^)]+)\)")


import ipaddress
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from nexus_core.scope import EngagementScope, EngagementStore

from . import mitre
from .models import (
    Evidence,
    Finding,
    ReportItem,
)

from .repository import ReportRepository

#: Excerpt kept per evidence pointer.
MAX_EXCERPT_CHARS = 2000
#: Two identical observations closer than this are one finding + reproductions.
DEDUP_WINDOW_SECONDS = 300

TOOL_RESULT = "tool_result"
AUDIT_EVENT = "audit_event"
ARTIFACT = "artifact"

#: Target field per tool, used when the catalog cannot be consulted.
_FALLBACK_TARGET_FIELDS: dict[str, str] = {
    "nexus.recon.nmap": "target",
    "nexus.recon.dns": "target",
    "nexus.post.dns_update": "target",
    "nexus.attack.impacket_changepasswd": "target",
    "nexus.recon.subfinder": "domain",
    "nexus.recon.httpx": "targets",
    "nexus.web.nuclei": "targets",
    "nexus.web.ffuf": "url",
    "nexus.exploit.msf_exploit": "target",
    "nexus.exploit.msf_auxiliary": "target",
    "nexus.web.sqlmap": "url",
    "nexus.web.dalfox": "target",
    "nexus.recon.gobuster": "target",
    "nexus.recon.whatweb": "targets",
    "nexus.recon.netexec": "target",
    "nexus.recon.bloodhound_python": "dc",
    "nexus.exploit.searchsploit": "query",
    "nexus.attack.impacket_secretsdump": "target",
    "nexus.attack.impacket_getuserspns": "dc_ip",
    "nexus.attack.impacket_psexec": "target",
}

#: Tools that never produce a finding on their own (bookkeeping only).
_NON_FINDING_TOOLS = frozenset(
    {
        "nexus.system.status",
        "nexus.system.check_env",
        "nexus.system.install_tool",
        "nexus.workspace.search",
        "nexus.exploit.msf_search",
        "nexus.session.list",
        "nexus.session.kill",
        "nexus.report.generate",
    }
)

#: Blackboard fact type -> the severity of the finding it maps to. Every recorded
#: fact becomes exactly one finding, so the compromise chain the operator logged
#: (credentials, access, privilege, loot...) is reflected in the deliverable
#: instead of being silently dropped (H3 of the RUN7 report).
_FACT_SEVERITY: dict[str, str] = {
    "vulnerability": "high",
    "credential": "high",
    "access": "high",
    "session": "high",
    "loot": "high",
    "privilege": "critical",
}

#: Fact type -> ``(kind, cwe, owasp, mitre_techniques)``. Unknown types fall back
#: to an informational ``fact_<type>`` finding.
_FACT_META: dict[str, tuple[str, str | None, str | None, tuple[str, ...]]] = {
    "vulnerability": ("fact_vulnerability", None, None, ()),
    "credential": (
        "fact_credential",
        "CWE-522",
        "A07:2021-Identification and Authentication Failures",
        ("T1078",),
    ),
    "access": ("fact_access", "CWE-284", "A01:2021-Broken Access Control", ("T1078",)),
    "privilege": ("fact_privilege", "CWE-269", "A04:2021-Insecure Design", ("T1068",)),
    "session": ("fact_session", "CWE-284", None, ("T1021",)),
    "loot": ("fact_loot", "CWE-522", None, ("T1005",)),
    "host": ("fact_host", None, None, ()),
    "service": ("fact_service", None, None, ()),
    "endpoint": ("fact_endpoint", None, None, ()),
    "user": ("fact_user", None, None, ()),
    "email": ("fact_email", None, None, ()),
    "artifact": ("fact_artifact", None, None, ()),
    "hint": ("fact_hint", None, None, ()),
}

FACT_RECORD_TOOL = "nexus.knowledge.record_fact"


@dataclass(frozen=True)
class Observation:
    """One persisted tool invocation (the durable ToolResult)."""

    run_id: str
    tool_id: str
    arguments: dict[str, Any]
    success: bool
    verification_method: str
    output: dict[str, Any] | None
    tool_evidence: dict[str, Any] | None
    created_at: str
    message_id: str
    raw_output_sha256: str | None = None
    #: Position of this observation within its ``(run, tool)`` group.
    ordinal: int = 0

    @property
    def status(self) -> str:
        """``status`` declared by the tool output, when it has one."""
        output = self.output or {}
        return str(output.get("status") or "")


@dataclass
class _Context:
    """Everything the per-tool builders need."""

    scope: EngagementScope
    event_by_run: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    artifact_refs: list[dict[str, Any]] = field(default_factory=list)
    #: ``(run_id, tool_id) -> [completion events]`` in trail order, so the Nth
    #: observation of a tool is tied to the Nth completion of that tool.
    completion_by_key: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)

    def completion_event(self, observation: Observation) -> dict[str, Any] | None:
        """The audit event that closed this exact observation, when known."""
        events = self.completion_by_key.get((observation.run_id, observation.tool_id)) or []
        if observation.ordinal < len(events):
            return events[observation.ordinal]
        return None


def _network(value: str):
    try:
        return ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return None


def matches_scope(target: str, scope: EngagementScope) -> bool:
    """Offline scope check of one target (no DNS, no network).

    Accepts an IP against the engagement CIDRs, or a domain/URL whose host is the
    engagement domain or a subdomain of it. Exclusions always win.
    """
    text = str(target or "").strip()
    if not text:
        return False
    host = text
    if "://" in text:
        host = text.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if host.startswith("["):  # bracketed IPv6 URL, e.g. http://[::1]:80/
        host = host.split("]", 1)[0].lstrip("[")
    elif host.count(":") == 1:  # host:port (a bare IPv6 has more colons)
        candidate, _, port = host.partition(":")
        if port.isdigit():
            host = candidate
    host = host.strip().lower().rstrip(".")

    for exclusion in scope.exclusions:
        excluded = str(exclusion).strip().lower()
        if not excluded:
            continue
        if excluded == host or host.endswith("." + excluded):
            return False
        network = _network(excluded)
        address = _address(host)
        if network is not None and address is not None and address in network:
            return False

    for cidr in scope.cidrs:
        network = _network(str(cidr))
        address = _address(host)
        if network is not None and address is not None and address in network:
            return True
    for domain in scope.domains:
        candidate = str(domain).strip().lower().rstrip(".")
        if candidate and (host == candidate or host.endswith("." + candidate)):
            return True
    return False


def _address(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def summarize_scope(scope: EngagementScope) -> str:
    """``"2 CIDRs, 1 dominio, 0 URLs, 1 exclusión"`` style one-liner."""
    parts = [
        f"{len(scope.cidrs)} CIDR{'s' if len(scope.cidrs) != 1 else ''}",
        f"{len(scope.domains)} dominio{'s' if len(scope.domains) != 1 else ''}",
        f"{len(scope.urls)} URL{'s' if len(scope.urls) != 1 else ''}",
        f"{len(scope.exclusions)} exclusi{'ones' if len(scope.exclusions) != 1 else 'ón'}",
    ]
    return ", ".join(parts)


def _decode_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        decoded = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def target_field_for(tool_id: str) -> str | None:
    """Declared ``scope_target_field`` of a tool (falls back to a static map)."""
    try:
        from nexus_core.tools.registry import durable_tool_definitions

        entry = durable_tool_definitions().get(tool_id)
        if entry is not None:
            definition = entry[0] if isinstance(entry, tuple) else entry
            field_name = getattr(definition, "scope_target_field", None)
            if field_name:
                return str(field_name)
    except Exception:  # noqa: BLE001 - the catalog is optional for extraction
        pass
    return _FALLBACK_TARGET_FIELDS.get(tool_id)


def targets_for_arguments(tool_id: str, arguments: dict[str, Any]) -> tuple[str, ...]:
    """Targets declared by a tool call, read from its schema-driven field."""
    field_name = target_field_for(tool_id)
    if not field_name:
        return ()
    value = (arguments or {}).get(field_name)
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value if str(item or "").strip())
    return ()


def _observations(
    messages: list[dict[str, Any]],
) -> tuple[list[Observation], int]:
    """Rebuild the ToolResults persisted by the loop and the REPL.

    Returns the observations plus the number of bodies that could not be decoded
    (a truncated observation body is not a reason to fail the report).
    """
    actions: dict[tuple[str, Any], dict[str, Any]] = {}
    for message in messages:
        metadata = message.get("metadata") or {}
        if metadata.get("kind") == "react.action":
            actions[(str(message.get("run_id") or ""), metadata.get("iteration"))] = metadata

    counters: dict[tuple[str, str], int] = {}
    observations: list[Observation] = []
    undecodable = 0
    for message in messages:
        metadata = message.get("metadata") or {}
        if metadata.get("kind") != "react.observation":
            continue
        run_id = str(message.get("run_id") or "")
        body = None
        try:
            decoded = json.loads(str(message.get("content") or ""))
            body = decoded if isinstance(decoded, dict) else None
        except (TypeError, ValueError):
            body = None
        if body is None:
            undecodable += 1
        action = actions.get((run_id, metadata.get("iteration"))) or {}
        # A REPL-invoked tool has no paired ``react.action``: it records its own
        # arguments in the observation metadata instead.
        arguments = _decode_payload(action.get("arguments") or metadata.get("arguments"))
        output = body.get("output") if body else None
        tool_evidence = body.get("evidence") if body else None
        raw_sha = None
        for candidate in (
            (tool_evidence or {}).get("raw_sha256"),
            (tool_evidence or {}).get("raw_xml_sha256"),
            (output or {}).get("raw_sha256") if isinstance(output, dict) else None,
        ):
            if isinstance(candidate, str) and candidate:
                raw_sha = candidate
                break
        tool_id = str(metadata.get("tool_id") or (body or {}).get("tool_id") or "")
        key = (run_id, tool_id)
        ordinal = counters.get(key, 0)
        counters[key] = ordinal + 1
        observations.append(
            Observation(
                run_id=run_id,
                tool_id=tool_id,
                arguments=arguments,
                success=bool(
                    metadata.get("success")
                    if metadata.get("success") is not None
                    else (body or {}).get("success")
                ),
                verification_method=str(
                    (body or {}).get("verification_method")
                    or metadata.get("verification_method")
                    or ""
                ),
                output=output if isinstance(output, dict) else None,
                tool_evidence=tool_evidence if isinstance(tool_evidence, dict) else None,
                created_at=str(message.get("created_at") or ""),
                message_id=str(message.get("id") or ""),
                raw_output_sha256=raw_sha,
                ordinal=ordinal,
            )
        )
    return observations, undecodable


def _target_from_reason(reason: Any) -> str:
    """Recover the refused target from the scope validator's message."""
    match = _VIOLATION_TARGET.search(str(reason or ""))
    return match.group(1) if match else ""


def _event_target(event: dict[str, Any]) -> str:
    payload = event.get("payload") or {}
    for key in ("target", "targets", "url", "domain", "host", "session_uuid"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, (list, tuple)) and value:
            return str(value[0])
    return ""


def _run_targets(observations: Iterable[Observation], scope: EngagementScope) -> set[str]:
    attributed: set[str] = set()
    for observation in observations:
        for target in targets_for_arguments(observation.tool_id, observation.arguments):
            if matches_scope(target, scope):
                attributed.add(observation.run_id)
                break
    return attributed


def engagement_runs(
    runs: Iterable[dict[str, Any]] | None,
    events: Iterable[dict[str, Any]] | None,
    engagement_id: str,
) -> set[str]:
    """Run ids the durable record attributes to ``engagement_id`` (V1-42).

    Two sources, both explicit statements of *which engagement* a run worked on:
    the engagement the CLI recorded in the run context, and the engagement the
    audit trail carries in the payload of an event (the REPL records
    ``session.command`` with the live engagement, and such a run may well have
    been created without one).
    """
    wanted = str(engagement_id or "")
    if not wanted:
        return set()
    selected: set[str] = set()
    for run in runs or ():
        if not isinstance(run, Mapping):
            continue
        context = run.get("context")
        if isinstance(context, str):
            try:
                context = json.loads(context or "{}")
            except (TypeError, ValueError):
                context = {}
        if not isinstance(context, Mapping):
            context = {}
        if str(context.get("engagement_id") or "") == wanted:
            selected.add(str(run.get("id") or run.get("run_id") or ""))
    for event in events or ():
        payload = event.get("payload") or {}
        if str(payload.get("engagement_id") or "") == wanted:
            selected.add(str(event.get("trace_id") or ""))
    selected.discard("")
    return selected


def _foreign_runs(
    runs: Iterable[dict[str, Any]] | None,
    events: Iterable[dict[str, Any]] | None,
    engagement_id: str,
) -> set[str]:
    """Run ids the durable record attributes to a *different* engagement.

    Only a run that *states* another engagement is foreign. An unattributed run
    is not: it says nothing about which engagement it worked on, so excluding it
    would silently empty the report of every engagement whose runs predate the
    engagement tag in the run context.
    """
    wanted = str(engagement_id or "")
    foreign: set[str] = set()
    for run in runs or ():
        if not isinstance(run, Mapping):
            continue
        context = run.get("context")
        if isinstance(context, str):
            try:
                context = json.loads(context or "{}")
            except (TypeError, ValueError):
                context = {}
        if not isinstance(context, Mapping):
            context = {}
        tag = str(context.get("engagement_id") or "")
        if tag and tag != wanted:
            foreign.add(str(run.get("id") or run.get("run_id") or ""))
    for event in events or ():
        payload = event.get("payload") or {}
        tag = str(payload.get("engagement_id") or "")
        if tag and tag != wanted:
            foreign.add(str(event.get("trace_id") or ""))
    foreign.discard("")
    return foreign


def _select_runs(
    events: list[dict[str, Any]],
    observations: list[Observation],
    scope: EngagementScope,
    run_ids: list[str] | None,
    runs: list[dict[str, Any]] | None = None,
) -> set[str]:
    """Runs the report is about: the engagement's own, never the tenant's.

    Measured in rerun 11 (``run_30bfde08…``): the report declared the runs of
    *another* engagement (rerun 10 attacked the same IP and both scopes covered
    it) plus a run from two hours before the engagement existed, because the
    selection fell back to "a run whose targets match this scope". Two rules now
    bound it (V1-42):

    * the runs the record attributes to this engagement are the selection, and
    * a run the record attributes to *another* engagement is never included.

    The target heuristic only remains for a record that attributes no run at all
    (an engagement whose runs were launched before the context carried it): with
    no attribution to contradict it, matching the signed scope is the best
    evidence available, and dropping it would report nothing for such data.
    """
    if run_ids is not None:
        return {str(item) for item in run_ids}
    attributed = engagement_runs(runs, events, scope.engagement_id)
    if attributed:
        return attributed
    selected = _run_targets(observations, scope)
    for event in events:
        payload = event.get("payload") or {}
        if str(payload.get("engagement_id") or "") == scope.engagement_id:
            # The REPL records ``session.command`` with the live engagement, and
            # a session command has no target of its own to match against.
            selected.add(str(event.get("trace_id") or ""))
    selected -= _foreign_runs(runs, events, scope.engagement_id)
    selected.discard("")
    return selected


def _excerpt(value: Any, limit: int = MAX_EXCERPT_CHARS) -> str:
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        except (TypeError, ValueError):
            text = str(value)
    return text[:limit]


def _artifact_refs(artifacts: list[dict[str, Any]], run_id: str) -> list[dict[str, Any]]:
    return [item for item in artifacts if str(item.get("run_id") or "") == run_id]


def _evidence_for(
    observation: Observation,
    context: _Context,
    *,
    excerpt: Any = None,
    extra_events: Iterable[dict[str, Any]] = (),
) -> tuple[Evidence, ...]:
    """Chain of custody of one finding: ToolResult, completion event, artifacts."""
    items: list[Evidence] = [
        Evidence(
            kind=TOOL_RESULT,
            ref_id=observation.message_id,
            sha256=observation.raw_output_sha256,
            excerpt=_excerpt(excerpt if excerpt is not None else observation.output),
            created_at=observation.created_at,
        )
    ]
    completion = context.completion_event(observation)
    events = list(extra_events) or ([completion] if completion else [])
    for event in events[:3]:
        items.append(
            Evidence(
                kind=AUDIT_EVENT,
                ref_id=str(event.get("event_id") or ""),
                sha256=str(event.get("event_hash") or "") or None,
                excerpt=_excerpt(event.get("payload"), 1000),
                created_at=str(event.get("created_at") or ""),
            )
        )
    for artifact in _artifact_refs(context.artifact_refs, observation.run_id)[:2]:
        items.append(
            Evidence(
                kind=ARTIFACT,
                ref_id=str(artifact.get("id") or ""),
                sha256=str(artifact.get("sha256") or "") or None,
                excerpt=str(artifact.get("media_type") or ""),
                created_at=str(artifact.get("created_at") or ""),
            )
        )
    return tuple(items)


def _finding_id(kind: str, observation: Observation, suffix: str = "") -> str:
    import hashlib

    seed = f"{kind}|{observation.tool_id}|{observation.run_id}|{observation.message_id}|{suffix}"
    return "finding_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def _as_dict(value: object) -> dict:
    """Return ``value`` when it is a mapping, else an empty one.

    Tool output is untrusted JSON: reading a field meant repeating
    ``x.get(k) if isinstance(x.get(k), dict) else {}``, which calls ``get`` twice
    and defeats static narrowing. Binding it once keeps the defensive read *and*
    lets the type checker follow the rest of the builder.
    """
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list:
    """Return ``value`` when it is a list, else an empty one."""
    return value if isinstance(value, list) else []


def _report_item(
    *,
    kind: str,
    title: str,
    detail: dict[str, Any],
    observation: Observation,
    context: _Context,
    targets: Iterable[str] = (),
    excerpt: Any = None,
) -> ReportItem:
    """Build a non-finding report item with its chain of custody."""
    return ReportItem(
        kind=kind,
        title=title,
        detail=detail,
        discovered_by_tool=observation.tool_id,
        discovered_at=observation.created_at,
        affected_targets=tuple(str(item) for item in targets if str(item or "").strip()),
        mitre_techniques=mitre.techniques_for_tool(observation.tool_id),
        evidence=_evidence_for(
            observation,
            context,
            excerpt=excerpt if excerpt is not None else (observation.output or {}),
        ),
    )


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Merge identical observations within :data:`DEDUP_WINDOW_SECONDS`."""
    merged: list[Finding] = []
    # The key has four components (kind, title, targets, verification status);
    # the annotation used to declare only three.
    index: dict[tuple[str, str, tuple[str, ...], str], Finding] = {}
    for finding in findings:
        key: tuple[str, str, tuple[str, ...], str] = (
            finding.kind,
            finding.title,
            finding.affected_targets,
            finding.verification_status,
        )
        previous = index.get(key)
        if previous is not None and _within_window(previous.discovered_at, finding.discovered_at):
            from dataclasses import replace

            updated = replace(
                previous,
                reproductions=previous.reproductions + 1,
                evidence=previous.evidence + finding.evidence,
                run_ids=tuple(dict.fromkeys((*previous.run_ids, *finding.run_ids))),
            )
            index[key] = updated
            merged[merged.index(previous)] = updated
            continue
        index[key] = finding
        merged.append(finding)
    return merged


def _within_window(first: str, second: str) -> bool:
    from datetime import datetime, timezone

    def _parse(value: str):
        text = str(value or "").replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    left, right = _parse(first), _parse(second)
    if left is None or right is None:
        return False
    return abs((right - left).total_seconds()) <= DEDUP_WINDOW_SECONDS


@dataclass
class _Collection:
    """Everything one extraction reads from the durable record (loaded once)."""

    scope: EngagementScope
    events: list[dict[str, Any]]
    scoped_events: list[dict[str, Any]]
    observations: list[Observation]
    selected: set[str]
    context: _Context
    undecodable: int
    #: ``created_at`` of the first selected run, when the record knows its runs
    #: (V1-42). The report started when the engagement's first run started, not
    #: when some other run of the tenant happened to write an event.
    first_run_at: str = ""


def _collect(
    store: Any,
    tenant_id: str,
    engagement_id: str,
    run_ids: list[str] | None = None,
) -> _Collection:
    """Load the durable record once and select the runs of the engagement."""
    scope = EngagementStore(store).get(tenant_id, engagement_id)
    if scope is None:
        raise KeyError(f"engagement not found: {engagement_id}")
    repository = ReportRepository(store)
    events = repository.events(tenant_id)
    messages = repository.messages(tenant_id)
    runs = repository.runs(tenant_id)
    observations, undecodable = _observations(messages)
    selected = _select_runs(events, observations, scope, run_ids, runs)
    scoped_events = [event for event in events if str(event.get("trace_id") or "") in selected]
    event_by_run: dict[str, list[dict[str, Any]]] = {}
    completion_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for event in scoped_events:
        run_id = str(event.get("trace_id") or "")
        event_by_run.setdefault(run_id, []).append(event)
        if str(event.get("action") or "") in _COMPLETION_ACTIONS:
            completion_by_key.setdefault((run_id, str(event.get("resource_id") or "")), []).append(
                event
            )
    return _Collection(
        scope=scope,
        events=events,
        scoped_events=scoped_events,
        observations=observations,
        selected=selected,
        context=_Context(
            scope=scope,
            event_by_run=event_by_run,
            artifact_refs=repository.artifacts(tenant_id),
            completion_by_key=completion_by_key,
        ),
        undecodable=undecodable,
        first_run_at=min(
            (
                str(run.get("created_at") or "")
                for run in runs
                if str(run.get("id") or run.get("run_id") or "") in selected
                and str(run.get("created_at") or "")
            ),
            default="",
        ),
    )
